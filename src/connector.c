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
#define SOI (sizeof(int))

struct client_instance {
	/* For clients hashtable */
	UT_hash_handle hh;
	int64_t id;
	int fd;

	/* Reference count for when this instance is used outside of the
	 * connector_data lock */
	int ref;

	/* For dead_clients list */
	struct client_instance *next;

	struct sockaddr address;
	char address_name[INET6_ADDRSTRLEN];

	/* Which serverurl is this instance connected to */
	int server;

	char buf[PAGESIZE];
	int bufofs;

	bool passthrough;
};

typedef struct client_instance client_instance_t;

struct sender_send {
	struct sender_send *next;
	struct sender_send *prev;

	client_instance_t *client;
	char *buf;
	int len;
};

typedef struct sender_send sender_send_t;

/* Private data for the connector */
struct connector_data {
	ckpool_t *ckp;
	cklock_t lock;
	proc_instance_t *pi;

	/* Array of server fds */
	int *serverfd;
	/* All time count of clients connected */
	int nfds;

	bool accept;
	pthread_t pth_sender;
	pthread_t pth_receiver;

	/* For the hashtable of all clients */
	client_instance_t *clients;
	/* Linked list of dead clients no longer in use but may still have references */
	client_instance_t *dead_clients;

	int64_t client_id;

	/* For the linked list of pending sends */
	sender_send_t *sender_sends;
	sender_send_t *delayed_sends;

	/* For protecting the pending sends list */
	pthread_mutex_t sender_lock;
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
	client = ckzalloc(sizeof(client_instance_t));
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
		dealloc(client);
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
			free(client);
			return 0;
	}

	keep_sockalive(fd);
	nolinger_socket(fd);

	LOGINFO("Connected new client %d on socket %d to %d active clients from %s:%d",
		cdata->nfds, fd, no_clients, client->address_name, port);

	client->fd = fd;
	event.data.ptr = client;
	event.events = EPOLLIN;
	if (unlikely(epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &event) < 0)) {
		LOGERR("Failed to epoll_ctl add in accept_client");
		free(client);
		return 0;
	}

	/* We increase the ref count on this client as epoll creates a pointer
	 * to it. We drop that reference when the socket is closed which
	 * removes it automatically from the epoll list. */
	__inc_instance_ref(client);

	ck_wlock(&cdata->lock);
	client->id = cdata->client_id++;
	HASH_ADD_I64(cdata->clients, id, client);
	cdata->nfds++;
	ck_wunlock(&cdata->lock);

	return 1;
}

/* Client must hold a reference count */
static int drop_client(cdata_t *cdata, client_instance_t *client)
{
	int fd;

	ck_wlock(&cdata->lock);
	fd = client->fd;
	if (fd != -1) {
		Close(client->fd);
		HASH_DEL(cdata->clients, client);
		LL_PREPEND(cdata->dead_clients, client);
		/* This is the reference to this client's presence in the
		 * epoll list. */
		__dec_instance_ref(client);
	}
	ck_wunlock(&cdata->lock);

	if (fd > -1)
		LOGINFO("Connector dropped client %"PRId64" fd %d", client->id, fd);

	return fd;
}

static void stratifier_drop_client(ckpool_t *ckp, int64_t id)
{
	char buf[256];

	sprintf(buf, "dropclient=%ld", id);
	send_proc(ckp->stratifier, buf);
}

/* Invalidate this instance. Remove them from the hashtables we look up
 * regularly but keep the instances in a linked list until their ref count
 * drops to zero when we can remove them lazily. Client must hold a reference
 * count. */
static void invalidate_client(ckpool_t *ckp, cdata_t *cdata, client_instance_t *client)
{
	client_instance_t *tmp;

	drop_client(cdata, client);
	if (ckp->passthrough)
		return;
	stratifier_drop_client(ckp, client->id);

	/* Cull old unused clients lazily when there are no more reference
	 * counts for them. */
	ck_wlock(&cdata->lock);
	LL_FOREACH_SAFE(cdata->dead_clients, client, tmp) {
		if (!client->ref) {
			LL_DELETE(cdata->dead_clients, client);
			LOGINFO("Connector discarding client %ld", client->id);
			free(client);
		}
	}
	ck_wunlock(&cdata->lock);
}

static void send_client(cdata_t *cdata, int64_t id, char *buf);

/* Client is holding a reference count from being on the epoll list */
static void parse_client_msg(cdata_t *cdata, client_instance_t *client)
{
	int buflen, ret, selfail = 0;
	ckpool_t *ckp = cdata->ckp;
	char msg[PAGESIZE], *eol;
	json_t *val;

retry:
	/* Select should always return positive after poll unless we have
	 * been disconnected. On retries, decdatade whether we should do further
	 * reads based on select readiness and only fail if we get an error. */
	ret = wait_read_select(client->fd, 0);
	if (ret < 1) {
		if (ret > selfail)
			return;
		LOGINFO("Client fd %d disconnected - select fail with bufofs %d ret %d errno %d %s",
			client->fd, client->bufofs, ret, errno, ret && errno ? strerror(errno) : "");
		invalidate_client(ckp, cdata, client);
		return;
	}
	selfail = -1;
	buflen = PAGESIZE - client->bufofs;
	ret = recv(client->fd, client->buf + client->bufofs, buflen, 0);
	if (ret < 1) {
		/* We should have something to read if called since poll set
		 * this fd's revents status so if there's nothing it means the
		 * client has disconnected. */
		LOGINFO("Client fd %d disconnected - recv fail with bufofs %d ret %d errno %d %s",
			client->fd, client->bufofs, ret, errno, ret && errno ? strerror(errno) : "");
		invalidate_client(ckp, cdata, client);
		return;
	}
	client->bufofs += ret;
reparse:
	eol = memchr(client->buf, '\n', client->bufofs);
	if (!eol) {
		if (unlikely(client->bufofs > MAX_MSGSIZE)) {
			LOGWARNING("Client fd %d overloaded buffer without EOL, disconnecting", client->fd);
			invalidate_client(ckp, cdata, client);
			return;
		}
		goto retry;
	}

	/* Do something useful with this message now */
	buflen = eol - client->buf + 1;
	if (unlikely(buflen > MAX_MSGSIZE)) {
		LOGWARNING("Client fd %d message oversize, disconnecting", client->fd);
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

		LOGINFO("Client id %ld sent invalid json message %s", client->id, msg);
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
		} else
			json_object_set_new_nocheck(val, "client_id", json_integer(client->id));
		json_object_set_new_nocheck(val, "address", json_string(client->address_name));
		json_object_set_new_nocheck(val, "server", json_integer(client->server));
		s = json_dumps(val, 0);
		if (ckp->passthrough)
			send_proc(ckp->generator, s);
		else
			send_proc(ckp->stratifier, s);
		free(s);
		json_decref(val);
	}

	if (client->bufofs)
		goto reparse;
	goto retry;
}

/* Waits on fds ready to read on from the list stored in conn_instance and
 * handles the incoming messages */
void *receiver(void *arg)
{
	cdata_t *cdata = (cdata_t *)arg;
	int ret, epfd, i, serverfds;
	struct epoll_event event;

	rename_proc("creceiver");

	epfd = epoll_create1(EPOLL_CLOEXEC);
	if (epfd < 0) {
		LOGEMERG("FATAL: Failed to create epoll in receiver");
		return NULL;
	}
	serverfds = cdata->ckp->serverurls;
	/* Add all the serverfds to the epoll */
	for (i = 0; i < serverfds; i++) {
		/* The small values will be easily identifiable compared to
		 * pointers */
		event.data.u64 = i;
		event.events = EPOLLIN;
		ret = epoll_ctl(epfd, EPOLL_CTL_ADD, cdata->serverfd[i], &event);
		if (ret < 0) {
			LOGEMERG("FATAL: Failed to add epfd %d to epoll_ctl", epfd);
			return NULL;
		}
		/* When we first start we listen to as many connections as
		 * possible. Once we start polling we drop the listen to the
		 * minimum to effectively ratelimit how fast we can receive
		 * connections. */
		LOGDEBUG("Dropping listen backlog to 0");
		listen(cdata->serverfd[i], 0);
	}

	while (42) {
		client_instance_t *client;

		while (unlikely(!cdata->accept))
			cksleep_ms(100);
		ret = epoll_wait(epfd, &event, 1, 1000);
		if (unlikely(ret == -1)) {
			LOGEMERG("FATAL: Failed to epoll_wait in receiver");
			break;
		}
		if (unlikely(!ret))
			continue;
		if (event.data.u64 < (uint64_t)serverfds) {
			ret = accept_client(cdata, epfd, event.data.u64);
			if (unlikely(ret < 0)) {
				LOGEMERG("FATAL: Failed to accept_client in receiver");
				break;
			}
			continue;
		}
		client = event.data.ptr;
		if ((event.events & EPOLLERR) || (event.events & EPOLLHUP)) {
			/* Client disconnected */
			LOGDEBUG("Client fd %d HUP in epoll", client->fd);
			invalidate_client(cdata->pi->ckp, cdata, client);
			continue;
		}
		parse_client_msg(cdata, client);
	}
	return NULL;
}

/* Use a thread to send queued messages, using select() to only send to sockets
 * ready for writing immediately to not delay other messages. */
void *sender(void *arg)
{
	cdata_t *cdata = (cdata_t *)arg;
	ckpool_t *ckp = cdata->ckp;
	bool sent = false;

	rename_proc("csender");

	while (42) {
		sender_send_t *sender_send;
		client_instance_t *client;
		int ret, fd, ofs = 0;

		mutex_lock(&cdata->sender_lock);
		/* Poll every 100ms if there are no new sends. Re-examine
		 * delayed sends immediately after a successful send in case
		 * endless new sends more frequently end up starving the
		 * delayed sends. */
		if (!cdata->sender_sends && !sent) {
			const ts_t polltime = {0, 100000000};
			ts_t timeout_ts;

			ts_realtime(&timeout_ts);
			timeraddspec(&timeout_ts, &polltime);
			pthread_cond_timedwait(&cdata->sender_cond, &cdata->sender_lock, &timeout_ts);
		}
		sender_send = cdata->sender_sends;
		if (sender_send)
			DL_DELETE(cdata->sender_sends, sender_send);
		mutex_unlock(&cdata->sender_lock);

		sent = false;

		/* Service delayed sends only if we have timed out on the
		 * conditional with no new sends appearing or have just
		 * serviced another message successfully. */
		if (!sender_send) {
			if (!cdata->delayed_sends)
				continue;
			sender_send = cdata->delayed_sends;
			DL_DELETE(cdata->delayed_sends, sender_send);
		}

		client = sender_send->client;

		ck_rlock(&cdata->lock);
		fd = client->fd;
		ck_runlock(&cdata->lock);

		if (fd == -1) {
			LOGDEBUG("Discarding message sent to invalidated client");
			goto contfree;
		}
		/* If this socket is not ready to receive data from us, put the
		 * send back on the tail of the list and decrease the timeout
		 * to poll to either look for a client that is ready or poll
		 * select on this one */
		ret = wait_write_select(fd, 0);
		if (ret < 1) {
			if (ret < 0) {
				LOGINFO("Client id %ld fd %d interrupted", client->id, fd);
				invalidate_client(ckp, cdata, client);
				goto contfree;
			}
			LOGDEBUG("Client %"PRId64" not ready for writes", client->id);

			/* Append it to the tail of the delayed sends list.
			 * This is the only function that alters it so no
			 * locking is required. Keep the client ref. */
			DL_APPEND(cdata->delayed_sends, sender_send);
			continue;
		}
		sent = true;
		while (sender_send->len) {
			ret = send(fd, sender_send->buf + ofs, sender_send->len , 0);
			if (unlikely(ret < 0)) {
				LOGINFO("Client id %ld fd %d disconnected", client->id, fd);
				invalidate_client(ckp, cdata, client);
				break;
			}
			ofs += ret;
			sender_send->len -= ret;
		}
contfree:
		free(sender_send->buf);
		free(sender_send);
		dec_instance_ref(cdata, client);
	}

	return NULL;
}

/* Send a client by id a heap allocated buffer, allowing this function to
 * free the ram. */
static void send_client(cdata_t *cdata, int64_t id, char *buf)
{
	sender_send_t *sender_send;
	client_instance_t *client;
	int fd = -1, len;

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

	ck_ilock(&cdata->lock);
	HASH_FIND_I64(cdata->clients, &id, client);
	if (likely(client)) {
		ck_ulock(&cdata->lock);
		fd = client->fd;
		/* Grab a reference to this client until the sender_send has
		 * completed processing. */
		__inc_instance_ref(client);
		ck_dwilock(&cdata->lock);
	}
	ck_uilock(&cdata->lock);

	if (unlikely(fd == -1)) {
		ckpool_t *ckp = cdata->ckp;

		if (client) {
			/* This shouldn't happen */
			LOGWARNING("Client id %ld disconnected but fd already invalidated!", id);
			invalidate_client(ckp, cdata, client);
		} else {
			LOGINFO("Connector failed to find client id %ld to send to", id);
			stratifier_drop_client(ckp, id);
		}
		free(buf);
		return;
	}

	sender_send = ckzalloc(sizeof(sender_send_t));
	sender_send->client = client;
	sender_send->buf = buf;
	sender_send->len = len;

	mutex_lock(&cdata->sender_lock);
	DL_APPEND(cdata->sender_sends, sender_send);
	pthread_cond_signal(&cdata->sender_cond);
	mutex_unlock(&cdata->sender_lock);
}

static client_instance_t *ref_client_by_id(cdata_t *cdata, int64_t id)
{
	client_instance_t *client;

	ck_ilock(&cdata->lock);
	HASH_FIND_I64(cdata->clients, &id, client);
	if (client) {
		ck_ulock(&cdata->lock);
		__inc_instance_ref(client);
		ck_dwilock(&cdata->lock);
	}
	ck_uilock(&cdata->lock);

	return client;
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
	int64_t client_id64, client_id;
	json_t *json_msg;
	char *msg;

	json_msg = json_loads(buf, 0, NULL);
	if (unlikely(!json_msg)) {
		LOGWARNING("Invalid json message: %s", buf);
		return;
	}

	/* Extract the client id from the json message and remove its entry */
	client_id64 = json_integer_value(json_object_get(json_msg, "client_id"));
	json_object_del(json_msg, "client_id");
	if (client_id64 > 0xffffffffll) {
		int64_t passthrough_id;

		passthrough_id = client_id64 & 0xffffffffll;
		client_id = client_id64 >> 32;
		json_object_set_new_nocheck(json_msg, "client_id", json_integer(passthrough_id));
	} else
		client_id = client_id64;
	msg = json_dumps(json_msg, JSON_EOL);
	send_client(cdata, client_id, msg);
	json_decref(json_msg);
}

static int connector_loop(proc_instance_t *pi, cdata_t *cdata)
{
	int sockd = -1,  ret = 0, selret;
	int64_t client_id64, client_id;
	unixsock_t *us = &pi->us;
	ckpool_t *ckp = pi->ckp;
	char *buf = NULL;

	do {
		selret = wait_read_select(us->sockd, 5);
		if (!selret && !ping_main(ckp)) {
			LOGEMERG("Connector failed to ping main process, exiting");
			ret = 1;
			goto out;
		}
	} while (selret < 1);

	LOGWARNING("%s connector ready", ckp->name);

retry:
	if (unlikely(!pthread_tryjoin_np(cdata->pth_sender, NULL))) {
		LOGEMERG("Connector sender thread shutdown, exiting");
		ret = 1;
		goto out;
	}
	if (unlikely(!pthread_tryjoin_np(cdata->pth_receiver, NULL))) {
		LOGEMERG("Connector receiver thread shutdown, exiting");
		ret = 1;
		goto out;
	}

	Close(sockd);
	sockd = accept(us->sockd, NULL, NULL);
	if (sockd < 0) {
		LOGEMERG("Failed to accept on connector socket, exiting");
		ret = 1;
		goto out;
	}

	dealloc(buf);
	buf = recv_unix_msg(sockd);
	if (!buf) {
		LOGWARNING("Failed to get message in connector_loop");
		goto retry;
	}

	LOGDEBUG("Connector received message: %s", buf);
	/* The bulk of the messages will be json messages to send to clients
	 * so look for them first. */
	if (likely(buf[0] == '{')) {
		process_client_msg(cdata, buf);
	} else if (cmdmatch(buf, "ping")) {
		LOGDEBUG("Connector received ping request");
		send_unix_msg(sockd, "pong");
	} else if (cmdmatch(buf, "accept")) {
		LOGDEBUG("Connector received accept signal");
		cdata->accept = true;
	} else if (cmdmatch(buf, "reject")) {
		LOGDEBUG("Connector received reject signal");
		cdata->accept = false;
	} else if (cmdmatch(buf, "loglevel")) {
		sscanf(buf, "loglevel=%d", &ckp->loglevel);
	} else if (cmdmatch(buf, "shutdown")) {
		goto out;
	} else if (cmdmatch(buf, "dropclient")) {
		client_instance_t *client;

		ret = sscanf(buf, "dropclient=%ld", &client_id64);
		if (ret < 0) {
			LOGDEBUG("Connector failed to parse dropclient command: %s", buf);
			goto retry;
		}
		client_id = client_id64 & 0xffffffffll;
		client = ref_client_by_id(cdata, client_id);
		if (unlikely(!client)) {
			LOGINFO("Connector failed to find client id %ld to drop", client_id);
			goto retry;
		}
		ret = drop_client(cdata, client);
		dec_instance_ref(cdata, client);
		if (ret >= 0)
			LOGINFO("Connector dropped client id: %ld", client_id);
	} else if (cmdmatch(buf, "passthrough")) {
		client_instance_t *client;

		ret = sscanf(buf, "passthrough=%ld", &client_id);
		if (ret < 0) {
			LOGDEBUG("Connector failed to parse passthrough command: %s", buf);
			goto retry;
		}
		client = ref_client_by_id(cdata, client_id);
		if (unlikely(!client)) {
			LOGINFO("Connector failed to find client id %ld to pass through", client_id);
			goto retry;
		}
		passthrough_client(cdata, client);
		dec_instance_ref(cdata, client);
	} else if (cmdmatch(buf, "getxfd")) {
		int fdno = -1;

		sscanf(buf, "getxfd%d", &fdno);
		if (fdno > -1 && fdno < ckp->serverurls)
			send_fd(cdata->serverfd[fdno], sockd);
	} else
		LOGWARNING("Unhandled connector message: %s", buf);
	goto retry;
out:
	Close(sockd);
	dealloc(buf);
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
		if (listen(sockd, SOMAXCONN) < 0) {
			LOGERR("Connector failed to listen on socket");
			Close(sockd);
			goto out;
		}
		cdata->serverfd[0] = sockd;
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
			if (listen(sockd, SOMAXCONN) < 0) {
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
	cdata->client_id = 1;
	mutex_init(&cdata->sender_lock);
	cond_init(&cdata->sender_cond);
	create_pthread(&cdata->pth_sender, sender, cdata);
	create_pthread(&cdata->pth_receiver, receiver, cdata);

	ret = connector_loop(pi, cdata);
out:
	dealloc(ckp->data);
	return process_exit(ckp, pi, ret);
}
