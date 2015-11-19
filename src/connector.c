/*
 * Copyright 2014-2015 Con Kolivas
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#include "config.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <string.h>
#include <unistd.h>

#include "ckpool.h"
#include "libckpool.h"
#include "uthash.h"
#include "utlist.h"

#define MAX_MSGSIZE 1024

typedef struct client_instance client_instance_t;
typedef struct sender_send sender_send_t;

struct client_instance {
	/* For clients hashtable */
	UT_hash_handle hh;
	int64_t id;

	/* fd cannot be changed while a ref is held */
	int fd;

	/* Reference count for when this instance is used outside of the
	 * connector_data lock */
	int ref;

	/* Have we disabled this client to be removed when there are no refs? */
	bool invalid;

	/* For dead_clients list */
	client_instance_t *next;
	client_instance_t *prev;

	struct sockaddr address;
	char address_name[INET6_ADDRSTRLEN];

	/* Which serverurl is this instance connected to */
	int server;

	char buf[PAGESIZE];
	int bufofs;

	/* Are we currently sending a blocked message from this client */
	sender_send_t *sending;
	bool passthrough;

	/* Time this client started blocking, 0 when not blocked */
	time_t blocked_time;
};

struct sender_send {
	struct sender_send *next;
	struct sender_send *prev;

	client_instance_t *client;
	char *buf;
	int len;
	int ofs;
};

/* Private data for the connector */
struct connector_data {
	ckpool_t *ckp;
	cklock_t lock;
	proc_instance_t *pi;

	time_t start_time;

	/* Array of server fds */
	int *serverfd;
	/* All time count of clients connected */
	int nfds;
	/* The epoll fd */
	int epfd;

	bool accept;
	pthread_t pth_sender;
	pthread_t pth_receiver;

	/* For the hashtable of all clients */
	client_instance_t *clients;
	/* Linked list of dead clients no longer in use but may still have references */
	client_instance_t *dead_clients;
	/* Linked list of client structures we can reuse */
	client_instance_t *recycled_clients;

	int clients_generated;
	int dead_generated;

	int64_t client_id;

	/* For the linked list of pending sends */
	sender_send_t *sender_sends;

	int64_t sends_generated;
	int64_t sends_delayed;
	int64_t sends_queued;
	int64_t sends_size;

	/* For protecting the pending sends list */
	mutex_t sender_lock;
	pthread_cond_t sender_cond;
};

typedef struct connector_data cdata_t;

/* Increase the reference count of instance */
static void __inc_instance_ref(client_instance_t *client)
{
	client->ref++;
}

/* Increase the reference count of instance */
static void __dec_instance_ref(client_instance_t *client)
{
	client->ref--;
}

static void dec_instance_ref(cdata_t *cdata, client_instance_t *client)
{
	ck_wlock(&cdata->lock);
	__dec_instance_ref(client);
	ck_wunlock(&cdata->lock);
}

/* Recruit a client structure from a recycled one if available, creating a
 * new structure only if we have none to reuse. */
static client_instance_t *recruit_client(cdata_t *cdata)
{
	client_instance_t *client = NULL;

	ck_wlock(&cdata->lock);
	if (cdata->recycled_clients) {
		client = cdata->recycled_clients;
		DL_DELETE(cdata->recycled_clients, client);
	} else
		cdata->clients_generated++;
	ck_wunlock(&cdata->lock);

	if (!client) {
		LOGDEBUG("Connector created new client instance");
		client = ckzalloc(sizeof(client_instance_t));
	} else
		LOGDEBUG("Connector recycled client instance");
	return client;
}

static void __recycle_client(cdata_t *cdata, client_instance_t *client)
{
	memset(client, 0, sizeof(client_instance_t));
	client->id = -1;
	DL_APPEND(cdata->recycled_clients, client);
}

static void recycle_client(cdata_t *cdata, client_instance_t *client)
{
	ck_wlock(&cdata->lock);
	__recycle_client(cdata, client);
	ck_wunlock(&cdata->lock);
}

/* Accepts incoming connections on the server socket and generates client
 * instances */
static int accept_client(cdata_t *cdata, const int epfd, const uint64_t server)
{
	int fd, port, no_clients, sockd;
	ckpool_t *ckp = cdata->ckp;
	client_instance_t *client;
	struct epoll_event event;
	socklen_t address_len;

	ck_rlock(&cdata->lock);
	no_clients = HASH_COUNT(cdata->clients);
	ck_runlock(&cdata->lock);

	if (unlikely(ckp->maxclients && no_clients >= ckp->maxclients)) {
		LOGWARNING("Server full with %d clients", no_clients);
		return 0;
	}

	sockd = cdata->serverfd[server];
	client = recruit_client(cdata);
	client->server = server;
	address_len = sizeof(client->address);
	fd = accept(sockd, &client->address, &address_len);
	if (unlikely(fd < 0)) {
		/* Handle these errors gracefully should we ever share this
		 * socket */
		if (errno == EAGAIN || errno == EWOULDBLOCK || errno == ECONNABORTED) {
			LOGERR("Recoverable error on accept in accept_client");
			return 0;
		}
		LOGERR("Failed to accept on socket %d in acceptor", sockd);
		recycle_client(cdata, client);
		return -1;
	}

	switch (client->address.sa_family) {
		const struct sockaddr_in *inet4_in;
		const struct sockaddr_in6 *inet6_in;

		case AF_INET:
			inet4_in = (struct sockaddr_in *)&client->address;
			inet_ntop(AF_INET, &inet4_in->sin_addr, client->address_name, INET6_ADDRSTRLEN);
			port = htons(inet4_in->sin_port);
			break;
		case AF_INET6:
			inet6_in = (struct sockaddr_in6 *)&client->address;
			inet_ntop(AF_INET6, &inet6_in->sin6_addr, client->address_name, INET6_ADDRSTRLEN);
			port = htons(inet6_in->sin6_port);
			break;
		default:
			LOGWARNING("Unknown INET type for client %d on socket %d",
				   cdata->nfds, fd);
			Close(fd);
			recycle_client(cdata, client);
			return 0;
	}

	keep_sockalive(fd);
	noblock_socket(fd);

	LOGINFO("Connected new client %d on socket %d to %d active clients from %s:%d",
		cdata->nfds, fd, no_clients, client->address_name, port);

	ck_wlock(&cdata->lock);
	client->id = cdata->client_id++;
	HASH_ADD_I64(cdata->clients, id, client);
	cdata->nfds++;
	ck_wunlock(&cdata->lock);

	event.data.u64 = client->id;
	event.events = EPOLLIN | EPOLLRDHUP;
	if (unlikely(epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &event) < 0)) {
		LOGERR("Failed to epoll_ctl add in accept_client");
		return 0;
	}

	/* We increase the ref count on this client as epoll creates a pointer
	 * to it. We drop that reference when the socket is closed which
	 * removes it automatically from the epoll list. */
	__inc_instance_ref(client);
	client->fd = fd;

	return 1;
}

/* Client must hold a reference count */
static int drop_client(cdata_t *cdata, client_instance_t *client)
{
	int64_t client_id = 0;
	int fd = -1;

	ck_wlock(&cdata->lock);
	if (!client->invalid) {
		client->invalid = true;
		client_id = client->id;
		fd = client->fd;
		epoll_ctl(cdata->epfd, EPOLL_CTL_DEL, fd, NULL);
		HASH_DEL(cdata->clients, client);
		DL_APPEND(cdata->dead_clients, client);
		/* This is the reference to this client's presence in the
		 * epoll list. */
		__dec_instance_ref(client);
		cdata->dead_generated++;
	}
	ck_wunlock(&cdata->lock);

	if (fd > -1)
		LOGINFO("Connector dropped client %"PRId64" fd %d", client_id, fd);

	return fd;
}

/* For sending the drop command to the upstream pool in passthrough mode */
static void generator_drop_client(ckpool_t *ckp, const client_instance_t *client)
{
	json_t *val;
	char *s;

	JSON_CPACK(val, "{si,sI:ss:si:ss:s[]}", "id", 42, "client_id", client->id, "address",
		   client->address_name, "server", client->server, "method", "mining.term",
		   "params");
	s = json_dumps(val, 0);
	json_decref(val);
	send_proc(ckp->generator, s);
	free(s);
}

static void stratifier_drop_id(ckpool_t *ckp, const int64_t id)
{
	char buf[256];

	sprintf(buf, "dropclient=%"PRId64, id);
	send_proc(ckp->stratifier, buf);
}

static void stratifier_drop_client(ckpool_t *ckp, const client_instance_t *client)
{
	stratifier_drop_id(ckp, client->id);
}

/* Invalidate this instance. Remove them from the hashtables we look up
 * regularly but keep the instances in a linked list until their ref count
 * drops to zero when we can remove them lazily. Client must hold a reference
 * count. */
static int invalidate_client(ckpool_t *ckp, cdata_t *cdata, client_instance_t *client)
{
	client_instance_t *tmp;
	int ret;

	ret = drop_client(cdata, client);
	if (!ckp->passthrough && !client->passthrough)
		stratifier_drop_client(ckp, client);
	else if (ckp->passthrough)
		generator_drop_client(ckp, client);

	/* Cull old unused clients lazily when there are no more reference
	 * counts for them. */
	ck_wlock(&cdata->lock);
	DL_FOREACH_SAFE(cdata->dead_clients, client, tmp) {
		if (!client->ref) {
			DL_DELETE(cdata->dead_clients, client);
			LOGINFO("Connector recycling client %"PRId64, client->id);
			/* We only close the client fd once we're sure there
			 * are no references to it left to prevent fds being
			 * reused on new and old clients. */
			nolinger_socket(client->fd);
			Close(client->fd);
			__recycle_client(cdata, client);
		}
	}
	ck_wunlock(&cdata->lock);

	return ret;
}

static void send_client(cdata_t *cdata, int64_t id, char *buf);

/* Client is holding a reference count from being on the epoll list */
static void parse_client_msg(cdata_t *cdata, client_instance_t *client)
{
	ckpool_t *ckp = cdata->ckp;
	char msg[PAGESIZE], *eol;
	int buflen, ret;
	json_t *val;

retry:
	if (unlikely(client->bufofs > MAX_MSGSIZE)) {
		LOGNOTICE("Client id %"PRId64" fd %d overloaded buffer without EOL, disconnecting",
			  client->id, client->fd);
		invalidate_client(ckp, cdata, client);
		return;
	}
	buflen = PAGESIZE - client->bufofs;
	/* This read call is non-blocking since the socket is set to O_NOBLOCK */
	ret = read(client->fd, client->buf + client->bufofs, buflen);
	if (ret < 1) {
		if (likely(errno == EAGAIN || errno == EWOULDBLOCK || !ret))
			return;
		LOGINFO("Client id %"PRId64" fd %d disconnected - recv fail with bufofs %d ret %d errno %d %s",
			client->id, client->fd, client->bufofs, ret, errno, ret && errno ? strerror(errno) : "");
		invalidate_client(ckp, cdata, client);
		return;
	}
	client->bufofs += ret;
reparse:
	eol = memchr(client->buf, '\n', client->bufofs);
	if (!eol)
		goto retry;

	/* Do something useful with this message now */
	buflen = eol - client->buf + 1;
	if (unlikely(buflen > MAX_MSGSIZE)) {
		LOGNOTICE("Client id %"PRId64" fd %d message oversize, disconnecting", client->id, client->fd);
		invalidate_client(ckp, cdata, client);
		return;
	}
	memcpy(msg, client->buf, buflen);
	msg[buflen] = '\0';
	client->bufofs -= buflen;
	memmove(client->buf, client->buf + buflen, client->bufofs);
	client->buf[client->bufofs] = '\0';
	if (!(val = json_loads(msg, 0, NULL))) {
		char *buf = strdup("Invalid JSON, disconnecting\n");

		LOGINFO("Client id %"PRId64" sent invalid json message %s", client->id, msg);
		send_client(cdata, client->id, buf);
		invalidate_client(ckp, cdata, client);
		return;
	} else {
		int64_t passthrough_id;
		char *s;

		if (client->passthrough) {
			passthrough_id = json_integer_value(json_object_get(val, "client_id"));
			json_object_del(val, "client_id");
			passthrough_id = (client->id << 32) | passthrough_id;
			json_object_set_new_nocheck(val, "client_id", json_integer(passthrough_id));
		} else {
			json_object_set_new_nocheck(val, "client_id", json_integer(client->id));
			json_object_set_new_nocheck(val, "address", json_string(client->address_name));
		}
		json_object_set_new_nocheck(val, "server", json_integer(client->server));
		s = json_dumps(val, 0);

		/* Do not send messages of clients we've already dropped. We
		 * do this unlocked as the occasional false negative can be
		 * filtered by the stratifier. */
		if (likely(!client->invalid)) {
			if (ckp->passthrough)
				send_proc(ckp->generator, s);
			else
				send_proc(ckp->stratifier, s);
		}

		free(s);
		json_decref(val);
	}

	if (client->bufofs)
		goto reparse;
	goto retry;
}

static client_instance_t *ref_client_by_id(cdata_t *cdata, int64_t id)
{
	client_instance_t *client;

	ck_wlock(&cdata->lock);
	HASH_FIND_I64(cdata->clients, &id, client);
	if (client) {
		if (!client->invalid)
			__inc_instance_ref(client);
		else
			client = NULL;
	}
	ck_wunlock(&cdata->lock);

	return client;
}

/* Waits on fds ready to read on from the list stored in conn_instance and
 * handles the incoming messages */
void *receiver(void *arg)
{
	cdata_t *cdata = (cdata_t *)arg;
	struct epoll_event event;
	uint64_t serverfds, i;
	int ret, epfd;

	rename_proc("creceiver");

	epfd = cdata->epfd = epoll_create1(EPOLL_CLOEXEC);
	if (epfd < 0) {
		LOGEMERG("FATAL: Failed to create epoll in receiver");
		goto out;
	}
	serverfds = cdata->ckp->serverurls;
	/* Add all the serverfds to the epoll */
	for (i = 0; i < serverfds; i++) {
		/* The small values will be less than the first client ids */
		event.data.u64 = i;
		event.events = EPOLLIN;
		ret = epoll_ctl(epfd, EPOLL_CTL_ADD, cdata->serverfd[i], &event);
		if (ret < 0) {
			LOGEMERG("FATAL: Failed to add epfd %d to epoll_ctl", epfd);
			goto out;
		}
	}

	while (!cdata->accept)
		cksleep_ms(1);

	while (42) {
		client_instance_t *client;

		while (unlikely(!cdata->accept))
			cksleep_ms(10);
		ret = epoll_wait(epfd, &event, 1, 1000);
		if (unlikely(ret < 1)) {
			if (unlikely(ret == -1)) {
				LOGEMERG("FATAL: Failed to epoll_wait in receiver");
				break;
			}
			/* Nothing to service, still very unlikely */
			continue;
		}
		if (event.data.u64 < serverfds) {
			ret = accept_client(cdata, epfd, event.data.u64);
			if (unlikely(ret < 0)) {
				LOGEMERG("FATAL: Failed to accept_client in receiver");
				break;
			}
			continue;
		}
		client = ref_client_by_id(cdata, event.data.u64);
		if (unlikely(!client)) {
			LOGNOTICE("Failed to find client by id %"PRId64" in receiver!", event.data.u64);
			continue;
		}
		if (unlikely(client->invalid))
			goto noparse;
		/* We can have both messages and read hang ups so process the
		 * message first. */
		if (likely(event.events & EPOLLIN))
			parse_client_msg(cdata, client);
		if (unlikely(client->invalid))
			goto noparse;
		if (unlikely(event.events & EPOLLERR)) {
			socklen_t errlen = sizeof(int);
			int error = 0;

			/* See what type of error this is and raise the log
			 * level of the message if it's unexpected. */
			getsockopt(client->fd, SOL_SOCKET, SO_ERROR, (void *)&error, &errlen);
			if (error != 104) {
				LOGNOTICE("Client id %"PRId64" fd %d epollerr HUP in epoll with errno %d: %s",
					  client->id, client->fd, error, strerror(error));
			} else {
				LOGINFO("Client id %"PRId64" fd %d epollerr HUP in epoll with errno %d: %s",
					client->id, client->fd, error, strerror(error));
			}
			invalidate_client(cdata->pi->ckp, cdata, client);
		} else if (unlikely(event.events & EPOLLHUP)) {
			/* Client connection reset by peer */
			LOGINFO("Client id %"PRId64" fd %d HUP in epoll", client->id, client->fd);
			invalidate_client(cdata->pi->ckp, cdata, client);
		} else if (unlikely(event.events & EPOLLRDHUP)) {
			/* Client disconnected by peer */
			LOGINFO("Client id %"PRId64" fd %d RDHUP in epoll", client->id, client->fd);
			invalidate_client(cdata->pi->ckp, cdata, client);
		}
noparse:
		dec_instance_ref(cdata, client);
	}
out:
	/* We shouldn't get here unless there's an error */
	childsighandler(15);
	return NULL;
}

/* Send a sender_send message and return true if we've finished sending it or
 * are unable to send any more. */
static bool send_sender_send(ckpool_t *ckp, cdata_t *cdata, sender_send_t *sender_send)
{
	client_instance_t *client = sender_send->client;
	time_t now_t;

	if (unlikely(client->invalid))
		goto out_true;

	/* Make sure we only send one message at a time to each client */
	if (unlikely(client->sending && client->sending != sender_send))
		return false;

	client->sending = sender_send;
	now_t = time(NULL);

	while (sender_send->len) {
		int ret = write(client->fd, sender_send->buf + sender_send->ofs, sender_send->len);

		if (unlikely(ret < 1)) {
			/* Invalidate clients that block for more than 60 seconds */
			if (unlikely(client->blocked_time && now_t - client->blocked_time >= 60)) {
				LOGNOTICE("Client id %"PRId64" fd %d blocked for >60 seconds, disconnecting",
					  client->id, client->fd);
				invalidate_client(ckp, cdata, client);
				goto out_true;
			}
			if (errno == EAGAIN || errno == EWOULDBLOCK || !ret) {
				if (!client->blocked_time)
					client->blocked_time = now_t;
				return false;
			}
			LOGINFO("Client id %"PRId64" fd %d disconnected with write errno %d:%s",
				client->id, client->fd, errno, strerror(errno));
			invalidate_client(ckp, cdata, client);
			goto out_true;
		}
		sender_send->ofs += ret;
		sender_send->len -= ret;
		client->blocked_time = 0;
	}
out_true:
	client->sending = NULL;
	return true;
}

static void clear_sender_send(sender_send_t *sender_send, cdata_t *cdata)
{
	dec_instance_ref(cdata, sender_send->client);
	free(sender_send->buf);
	free(sender_send);
}

/* Use a thread to send queued messages, appending them to the sends list and
 * iterating over all of them, attempting to send them all non-blocking to
 * only send to those clients ready to receive data. */
static void *sender(void *arg)
{
	cdata_t *cdata = (cdata_t *)arg;
	sender_send_t *sends = NULL;
	ckpool_t *ckp = cdata->ckp;

	rename_proc("csender");

	while (42) {
		int64_t sends_queued = 0, sends_size = 0;
		sender_send_t *sending, *tmp;

		/* Check all sends to see if they can be written out */
		DL_FOREACH_SAFE(sends, sending, tmp) {
			if (send_sender_send(ckp, cdata, sending)) {
				DL_DELETE(sends, sending);
				clear_sender_send(sending, cdata);
			} else {
				sends_queued++;
				sends_size += sizeof(sender_send_t) + sending->len + 1;
			}
		}

		mutex_lock(&cdata->sender_lock);
		cdata->sends_delayed += sends_queued;
		cdata->sends_queued = sends_queued;
		cdata->sends_size = sends_size;
		/* Poll every 10ms if there are no new sends. */
		if (!cdata->sender_sends) {
			const ts_t polltime = {0, 10000000};
			ts_t timeout_ts;

			ts_realtime(&timeout_ts);
			timeraddspec(&timeout_ts, &polltime);
			cond_timedwait(&cdata->sender_cond, &cdata->sender_lock, &timeout_ts);
		}
		if (cdata->sender_sends) {
			DL_CONCAT(sends, cdata->sender_sends);
			cdata->sender_sends = NULL;
		}
		mutex_unlock(&cdata->sender_lock);
	}
	/* We shouldn't get here unless there's an error */
	childsighandler(15);
	return NULL;
}

/* Send a client by id a heap allocated buffer, allowing this function to
 * free the ram. */
static void send_client(cdata_t *cdata, const int64_t id, char *buf)
{
	ckpool_t *ckp = cdata->ckp;
	sender_send_t *sender_send;
	client_instance_t *client;
	int len;

	if (unlikely(!buf)) {
		LOGWARNING("Connector send_client sent a null buffer");
		return;
	}
	len = strlen(buf);
	if (unlikely(!len)) {
		LOGWARNING("Connector send_client sent a zero length buffer");
		free(buf);
		return;
	}

	/* Grab a reference to this client until the sender_send has
	 * completed processing. Is this a passthrough subclient ? */
	if (id > 0xffffffffll) {
		int64_t client_id, pass_id;

		client_id = id & 0xffffffffll;
		pass_id = id >> 32;
		/* Make sure the passthrough exists for passthrough subclients */
		client = ref_client_by_id(cdata, pass_id);
		if (unlikely(!client)) {
			LOGINFO("Connector failed to find passthrough id %"PRId64" of client id %"PRId64" to send to",
				pass_id, client_id);
			/* Now see if the subclient exists */
			client = ref_client_by_id(cdata, client_id);
			if (client) {
				invalidate_client(ckp, cdata, client);
				dec_instance_ref(cdata, client);
			} else
				stratifier_drop_id(ckp, id);
			free(buf);
			return;
		}
	} else {
		client = ref_client_by_id(cdata, id);
		if (unlikely(!client)) {
			LOGINFO("Connector failed to find client id %"PRId64" to send to", id);
			stratifier_drop_id(ckp, id);
			free(buf);
			return;
		}
	}

	sender_send = ckzalloc(sizeof(sender_send_t));
	sender_send->client = client;
	sender_send->buf = buf;
	sender_send->len = len;

	mutex_lock(&cdata->sender_lock);
	cdata->sends_generated++;
	DL_APPEND(cdata->sender_sends, sender_send);
	pthread_cond_signal(&cdata->sender_cond);
	mutex_unlock(&cdata->sender_lock);
}

static void passthrough_client(cdata_t *cdata, client_instance_t *client)
{
	char *buf;

	LOGINFO("Connector adding passthrough client %"PRId64, client->id);
	client->passthrough = true;
	ASPRINTF(&buf, "{\"result\": true}\n");
	send_client(cdata, client->id, buf);
}

static void process_client_msg(cdata_t *cdata, const char *buf)
{
	int64_t client_id;
	json_t *json_msg;
	char *msg;

	json_msg = json_loads(buf, 0, NULL);
	if (unlikely(!json_msg)) {
		LOGWARNING("Invalid json message: %s", buf);
		return;
	}

	/* Extract the client id from the json message and remove its entry */
	client_id = json_integer_value(json_object_get(json_msg, "client_id"));
	json_object_del(json_msg, "client_id");
	/* Put client_id back in for a passthrough subclient, passing its
	 * upstream client_id instead of the passthrough's. */
	if (client_id > 0xffffffffll)
		json_object_set_new_nocheck(json_msg, "client_id", json_integer(client_id & 0xffffffffll));
	msg = json_dumps(json_msg, JSON_EOL);
	send_client(cdata, client_id, msg);
	json_decref(json_msg);
}

static char *connector_stats(cdata_t *cdata, const int runtime)
{
	json_t *val = json_object(), *subval;
	client_instance_t *client;
	int objects, generated;
	sender_send_t *send;
	int64_t memsize;
	char *buf;

	/* If called in passthrough mode we log stats instead of the stratifier */
	if (runtime)
		json_set_int(val, "runtime", runtime);

	ck_rlock(&cdata->lock);
	objects = HASH_COUNT(cdata->clients);
	memsize = SAFE_HASH_OVERHEAD(cdata->clients) + sizeof(client_instance_t) * objects;
	generated = cdata->clients_generated;
	ck_runlock(&cdata->lock);

	JSON_CPACK(subval, "{si,si,si}", "count", objects, "memory", memsize, "generated", generated);
	json_set_object(val, "clients", subval);

	ck_rlock(&cdata->lock);
	DL_COUNT(cdata->dead_clients, client, objects);
	generated = cdata->dead_generated;
	ck_runlock(&cdata->lock);

	memsize = objects * sizeof(client_instance_t);
	JSON_CPACK(subval, "{si,si,si}", "count", objects, "memory", memsize, "generated", generated);
	json_set_object(val, "dead", subval);

	objects = 0;
	memsize = 0;

	mutex_lock(&cdata->sender_lock);
	DL_FOREACH(cdata->sender_sends, send) {
		objects++;
		memsize += sizeof(sender_send_t) + send->len + 1;
	}
	JSON_CPACK(subval, "{si,si,si}", "count", objects, "memory", memsize, "generated", cdata->sends_generated);
	json_set_object(val, "sends", subval);

	JSON_CPACK(subval, "{si,si,si}", "count", cdata->sends_queued, "memory", cdata->sends_size, "generated", cdata->sends_delayed);
	mutex_unlock(&cdata->sender_lock);

	json_set_object(val, "delays", subval);

	buf = json_dumps(val, JSON_NO_UTF8 | JSON_PRESERVE_ORDER);
	json_decref(val);
	if (runtime)
		LOGNOTICE("Passthrough:%s", buf);
	else
		LOGNOTICE("Connector stats: %s", buf);
	return buf;
}

static int connector_loop(proc_instance_t *pi, cdata_t *cdata)
{
	unix_msg_t *umsg = NULL;
	ckpool_t *ckp = pi->ckp;
	time_t last_stats;
	int64_t client_id;
	int ret = 0;
	char *buf;

	LOGWARNING("%s connector ready", ckp->name);
	last_stats = cdata->start_time;

retry:
	if (ckp->passthrough) {
		time_t diff = time(NULL);

		if (diff - last_stats >= 60) {
			last_stats = diff;
			diff -= cdata->start_time;
			buf = connector_stats(cdata, diff);
			dealloc(buf);
		}
	}

	if (umsg) {
		Close(umsg->sockd);
		free(umsg->buf);
		dealloc(umsg);
	}

	do {
		umsg = get_unix_msg(pi);
	} while (!umsg);

	buf = umsg->buf;
	LOGDEBUG("Connector received message: %s", buf);
	/* The bulk of the messages will be json messages to send to clients
	 * so look for them first. */
	if (likely(buf[0] == '{')) {
		process_client_msg(cdata, buf);
	} else if (cmdmatch(buf, "dropclient")) {
		client_instance_t *client;

		ret = sscanf(buf, "dropclient=%"PRId64, &client_id);
		if (ret < 0) {
			LOGDEBUG("Connector failed to parse dropclient command: %s", buf);
			goto retry;
		}
		/* A passthrough client, we can't drop this yet */
		if (client_id > 0xffffffffll)
			goto retry;
		client = ref_client_by_id(cdata, client_id);
		if (unlikely(!client)) {
			LOGINFO("Connector failed to find client id %"PRId64" to drop", client_id);
			goto retry;
		}
		ret = invalidate_client(ckp, cdata, client);
		dec_instance_ref(cdata, client);
		if (ret >= 0)
			LOGINFO("Connector dropped client id: %"PRId64, client_id);
	} else if (cmdmatch(buf, "ping")) {
		LOGDEBUG("Connector received ping request");
		send_unix_msg(umsg->sockd, "pong");
	} else if (cmdmatch(buf, "accept")) {
		LOGDEBUG("Connector received accept signal");
		cdata->accept = true;
	} else if (cmdmatch(buf, "reject")) {
		LOGDEBUG("Connector received reject signal");
		cdata->accept = false;
		send_proc(ckp->stratifier, "dropall");
	} else if (cmdmatch(buf, "stats")) {
		char *msg;

		LOGDEBUG("Connector received stats request");
		msg = connector_stats(cdata, 0);
		send_unix_msg(umsg->sockd, msg);
	} else if (cmdmatch(buf, "loglevel")) {
		sscanf(buf, "loglevel=%d", &ckp->loglevel);
	} else if (cmdmatch(buf, "shutdown")) {
		goto out;
	} else if (cmdmatch(buf, "passthrough")) {
		client_instance_t *client;

		ret = sscanf(buf, "passthrough=%"PRId64, &client_id);
		if (ret < 0) {
			LOGDEBUG("Connector failed to parse passthrough command: %s", buf);
			goto retry;
		}
		client = ref_client_by_id(cdata, client_id);
		if (unlikely(!client)) {
			LOGINFO("Connector failed to find client id %"PRId64" to pass through", client_id);
			goto retry;
		}
		passthrough_client(cdata, client);
		dec_instance_ref(cdata, client);
	} else if (cmdmatch(buf, "getxfd")) {
		int fdno = -1;

		sscanf(buf, "getxfd%d", &fdno);
		if (fdno > -1 && fdno < ckp->serverurls)
			send_fd(cdata->serverfd[fdno], umsg->sockd);
	} else
		LOGWARNING("Unhandled connector message: %s", buf);
	goto retry;
out:
	return ret;
}

int connector(proc_instance_t *pi)
{
	cdata_t *cdata = ckzalloc(sizeof(cdata_t));
	ckpool_t *ckp = pi->ckp;
	int sockd, ret = 0, i;
	const int on = 1;
	int tries = 0;

	LOGWARNING("%s connector starting", ckp->name);
	ckp->data = cdata;
	cdata->ckp = ckp;

	if (!ckp->serverurls)
		cdata->serverfd = ckalloc(sizeof(int *));
	else
		cdata->serverfd = ckalloc(sizeof(int *) * ckp->serverurls);

	if (!ckp->serverurls) {
		/* No serverurls have been specified. Bind to all interfaces
		 * on default sockets. */
		struct sockaddr_in serv_addr;

		sockd = socket(AF_INET, SOCK_STREAM, 0);
		if (sockd < 0) {
			LOGERR("Connector failed to open socket");
			ret = 1;
			goto out;
		}
		setsockopt(sockd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
		memset(&serv_addr, 0, sizeof(serv_addr));
		serv_addr.sin_family = AF_INET;
		serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
		serv_addr.sin_port = htons(ckp->proxy ? 3334 : 3333);
		do {
			ret = bind(sockd, (struct sockaddr*)&serv_addr, sizeof(serv_addr));
			if (!ret)
				break;
			LOGWARNING("Connector failed to bind to socket, retrying in 5s");
			sleep(5);
		} while (++tries < 25);
		if (ret < 0) {
			LOGERR("Connector failed to bind to socket for 2 minutes");
			Close(sockd);
			goto out;
		}
		/* Set listen backlog to larger than SOMAXCONN in case the
		 * system configuration supports it */
		if (listen(sockd, 8192) < 0) {
			LOGERR("Connector failed to listen on socket");
			Close(sockd);
			goto out;
		}
		cdata->serverfd[0] = sockd;
		ckp->serverurls = 1;
	} else {
		for (i = 0; i < ckp->serverurls; i++) {
			char oldurl[INET6_ADDRSTRLEN], oldport[8];
			char newurl[INET6_ADDRSTRLEN], newport[8];
			char *serverurl = ckp->serverurl[i];

			if (!url_from_serverurl(serverurl, newurl, newport)) {
				LOGWARNING("Failed to extract resolved url from %s", serverurl);
				ret = 1;
				goto out;
			}
			sockd = ckp->oldconnfd[i];
			if (url_from_socket(sockd, oldurl, oldport)) {
				if (strcmp(newurl, oldurl) || strcmp(newport, oldport)) {
					LOGWARNING("Handed over socket url %s:%s does not match config %s:%s, creating new socket",
						   oldurl, oldport, newurl, newport);
					Close(sockd);
				}
			}

			do {
				if (sockd > 0)
					break;
				sockd = bind_socket(newurl, newport);
				if (sockd > 0)
					break;
				LOGWARNING("Connector failed to bind to socket, retrying in 5s");
				sleep(5);
			} while (++tries < 25);

			if (sockd < 0) {
				LOGERR("Connector failed to bind to socket for 2 minutes");
				ret = 1;
				goto out;
			}
			if (listen(sockd, 8192) < 0) {
				LOGERR("Connector failed to listen on socket");
				Close(sockd);
				goto out;
			}
			cdata->serverfd[i] = sockd;
		}
	}

	if (tries)
		LOGWARNING("Connector successfully bound to socket");

	cklock_init(&cdata->lock);
	cdata->pi = pi;
	cdata->nfds = 0;
	/* Set the client id to the highest serverurl count to distinguish
	 * them from the server fds in epoll. */
	cdata->client_id = ckp->serverurls;
	mutex_init(&cdata->sender_lock);
	cond_init(&cdata->sender_cond);
	create_pthread(&cdata->pth_sender, sender, cdata);
	create_pthread(&cdata->pth_receiver, receiver, cdata);
	cdata->start_time = time(NULL);

	create_unix_receiver(pi);

	ret = connector_loop(pi, cdata);
out:
	dealloc(ckp->data);
	return process_exit(ckp, pi, ret);
}
