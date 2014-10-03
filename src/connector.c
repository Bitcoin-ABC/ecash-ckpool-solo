/*
 * Copyright 2014 Con Kolivas
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#include "config.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <string.h>
#include <unistd.h>

#include "ckpool.h"
#include "libckpool.h"
#include "uthash.h"
#include "utlist.h"

#define MAX_MSGSIZE 1024
#define SOI (sizeof(int))

struct connector_instance {
	cklock_t lock;
	proc_instance_t *pi;
	int serverfd;
	int nfds;
	bool accept;
};

typedef struct connector_instance conn_instance_t;

struct client_instance {
	/* For clients hashtable */
	UT_hash_handle hh;
	int64_t id;

	/* For fdclients hashtable */
	UT_hash_handle fdhh;
	int fd;

	/* For dead_clients list */
	struct client_instance *next;

	struct sockaddr address;
	char address_name[INET6_ADDRSTRLEN];

	char buf[PAGESIZE];
	int bufofs;

	bool passthrough;
};

typedef struct client_instance client_instance_t;

/* For the hashtable of all clients */
static client_instance_t *clients;
/* A hashtable of the clients sorted by fd */
static client_instance_t *fdclients;
/* Linked list of dead clients no longer in use but may still have references */
static client_instance_t *dead_clients;

static int64_t client_id = 1;

struct sender_send {
	struct sender_send *next;
	struct sender_send *prev;

	client_instance_t *client;
	char *buf;
	int len;
};

typedef struct sender_send sender_send_t;

/* For the linked list of pending sends */
static sender_send_t *sender_sends;
static sender_send_t *delayed_sends;

/* For protecting the pending sends list */
static pthread_mutex_t sender_lock;
static pthread_cond_t sender_cond;

/* Accepts incoming connections to the server socket and generates client
 * instances */
void *acceptor(void *arg)
{
	conn_instance_t *ci = (conn_instance_t *)arg;
	client_instance_t *client, *old_client;
	socklen_t address_len;
	int fd;

	rename_proc("acceptor");

retry:
	client = ckzalloc(sizeof(client_instance_t));
	address_len = sizeof(client->address);
	while (!ci->accept)
		sleep(1);
	fd = accept(ci->serverfd, &client->address, &address_len);
	if (unlikely(fd < 0)) {
		LOGERR("Failed to accept on socket %d in acceptor", ci->serverfd);
		dealloc(client);
		goto out;
	}

	switch (client->address.sa_family) {
		const struct sockaddr_in *inet4_in;
		const struct sockaddr_in6 *inet6_in;

		case AF_INET:
			inet4_in = (struct sockaddr_in *)&client->address;
			inet_ntop(AF_INET, &inet4_in->sin_addr, client->address_name, INET6_ADDRSTRLEN);
			break;
		case AF_INET6:
			inet6_in = (struct sockaddr_in6 *)&client->address;
			inet_ntop(AF_INET6, &inet6_in->sin6_addr, client->address_name, INET6_ADDRSTRLEN);
			break;
		default:
			LOGWARNING("Unknown INET type for client %d on socket %d",
				   ci->nfds, fd);
			close(fd);
			free(client);
			goto retry;
	}

	keep_sockalive(fd);

	LOGINFO("Connected new client %d on socket %d from %s", ci->nfds, fd, client->address_name);

	client->fd = fd;

	ck_wlock(&ci->lock);
	client->id = client_id++;
	HASH_ADD_I64(clients, id, client);
	HASH_REPLACE(fdhh, fdclients, fd, SOI, client, old_client);
	ci->nfds++;
	ck_wunlock(&ci->lock);

	goto retry;
out:
	return NULL;
}

static int drop_client(conn_instance_t *ci, client_instance_t *client)
{
	int fd;

	ck_wlock(&ci->lock);
	fd = client->fd;
	if (fd != -1) {
		close(fd);
		HASH_DEL(clients, client);
		HASH_DELETE(fdhh, fdclients, client);
		LL_PREPEND(dead_clients, client);
		client->fd = -1;
	}
	ck_wunlock(&ci->lock);

	return fd;
}

/* Invalidate this instance. Remove them from the hashtables we look up
 * regularly but keep the instances in a linked list indefinitely in case we
 * still reference any of its members. */
static void invalidate_client(ckpool_t *ckp, conn_instance_t *ci, client_instance_t *client)
{
	char buf[256];
	int fd;

	fd = drop_client(ci, client);
	if (fd == -1)
		return;
	if (ckp->passthrough)
		return;
	sprintf(buf, "dropclient=%ld", client->id);
	send_proc(ckp->stratifier, buf);
}

static void send_client(conn_instance_t *ci, int64_t id, char *buf);

static void parse_client_msg(conn_instance_t *ci, client_instance_t *client)
{
	int buflen, ret, selfail = 0;
	ckpool_t *ckp = ci->pi->ckp;
	char msg[PAGESIZE], *eol;
	json_t *val;

retry:
	/* Select should always return positive after poll unless we have
	 * been disconnected. On retries, decide whether we should do further
	 * reads based on select readiness and only fail if we get an error. */
	ret = wait_read_select(client->fd, 0);
	if (ret < 1) {
		if (ret > selfail)
			return;
		LOGINFO("Client fd %d disconnected - select fail with bufofs %d ret %d errno %d %s",
			client->fd, client->bufofs, ret, errno, ret && errno ? strerror(errno) : "");
		invalidate_client(ckp, ci, client);
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
		invalidate_client(ckp, ci, client);
		return;
	}
	client->bufofs += ret;
reparse:
	eol = memchr(client->buf, '\n', client->bufofs);
	if (!eol) {
		if (unlikely(client->bufofs > MAX_MSGSIZE)) {
			LOGWARNING("Client fd %d overloaded buffer without EOL, disconnecting", client->fd);
			invalidate_client(ckp, ci, client);
			return;
		}
		goto retry;
	}

	/* Do something useful with this message now */
	buflen = eol - client->buf + 1;
	if (unlikely(buflen > MAX_MSGSIZE)) {
		LOGWARNING("Client fd %d message oversize, disconnecting", client->fd);
		invalidate_client(ckp, ci, client);
		return;
	}
	memcpy(msg, client->buf, buflen);
	msg[buflen] = '\0';
	client->bufofs -= buflen;
	memmove(client->buf, client->buf + buflen, client->bufofs);
	client->buf[client->bufofs] = '\0';
	if (!(val = json_loads(msg, 0, NULL))) {
		char *buf = strdup("Invalid JSON, disconnecting\n");

		LOGINFO("Client id %d sent invalid json message %s", client->id, msg);
		send_client(ci, client->id, buf);
		invalidate_client(ckp, ci, client);
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
	conn_instance_t *ci = (conn_instance_t *)arg;
	client_instance_t *client, *tmp;
	struct pollfd fds[65536];
	int ret, nfds, i;

	rename_proc("creceiver");

retry:
	nfds = 0;
	while (!ci->accept)
		sleep(1);

	ck_rlock(&ci->lock);
	HASH_ITER(fdhh, fdclients, client, tmp) {
		fds[nfds].fd = client->fd;
		fds[nfds].events = POLLIN;
		fds[nfds].revents = 0;
		nfds++;
	}
	ck_runlock(&ci->lock);

	if (!nfds) {
		cksleep_ms(100);
		goto retry;
	}
	ret = poll(fds, nfds, 1000);
	if (unlikely(ret < 0)) {
		LOGERR("Failed to poll in receiver");
		goto out;
	}
	if (!ret)
		goto retry;
	for (i = 0; i < nfds; i++) {
		int fd;

		if (!fds[i].revents)
			continue;

		client = NULL;
		fd = fds[i].fd;

		ck_rlock(&ci->lock);
		HASH_FIND(fdhh, fdclients, &fd, SOI, client);
		ck_runlock(&ci->lock);

		if (!client) {
			/* Probably already removed */
			LOGDEBUG("Failed to find client with polled fd %d in hashtable",
				 fd);
		} else
			parse_client_msg(ci, client);

		if (--ret < 1)
			break;
	}
	goto retry;

out:
	return NULL;
}

/* Use a thread to send queued messages, using select() to only send to sockets
 * ready for writing immediately to not delay other messages. */
void *sender(void *arg)
{
	conn_instance_t *ci = (conn_instance_t *)arg;
	ckpool_t *ckp = ci->pi->ckp;
	bool sent = false;

	rename_proc("csender");

	while (42) {
		sender_send_t *sender_send;
		client_instance_t *client;
		int ret, fd, ofs = 0;

		mutex_lock(&sender_lock);
		/* Poll every 100ms if there are no new sends. Re-examine
		 * delayed sends immediately after a successful send in case
		 * endless new sends more frequently end up starving the
		 * delayed sends. */
		if (!sender_sends && !sent) {
			const ts_t polltime = {0, 100000000};
			ts_t timeout_ts;

			ts_realtime(&timeout_ts);
			timeraddspec(&timeout_ts, &polltime);
			pthread_cond_timedwait(&sender_cond, &sender_lock, &timeout_ts);
		}
		sender_send = sender_sends;
		if (sender_send)
			DL_DELETE(sender_sends, sender_send);
		mutex_unlock(&sender_lock);

		sent = false;

		/* Service delayed sends only if we have timed out on the
		 * conditional with no new sends appearing or have just
		 * serviced another message successfully. */
		if (!sender_send) {
			if (!delayed_sends)
				continue;
			sender_send = delayed_sends;
			DL_DELETE(delayed_sends, sender_send);
		}

		client = sender_send->client;

		ck_rlock(&ci->lock);
		fd = client->fd;
		ck_runlock(&ci->lock);

		if (fd == -1) {
			LOGDEBUG("Discarding message sent to invalidated client");
			free(sender_send->buf);
			free(sender_send);
			continue;
		}
		/* If this socket is not ready to receive data from us, put the
		 * send back on the tail of the list and decrease the timeout
		 * to poll to either look for a client that is ready or poll
		 * select on this one */
		ret = wait_write_select(fd, 0);
		if (ret < 1) {
			if (ret < 0) {
				LOGINFO("Client id %d fd %d interrupted", client->id, fd);
				invalidate_client(ckp, ci, client);
				free(sender_send->buf);
				free(sender_send);
				continue;
			}
			LOGDEBUG("Client %d not ready for writes", client->id);

			/* Append it to the tail of the delayed sends list.
			 * This is the only function that alters it so no
			 * locking is required. */
			DL_APPEND(delayed_sends, sender_send);
			continue;
		}
		sent = true;
		while (sender_send->len) {
			ret = send(fd, sender_send->buf + ofs, sender_send->len , 0);
			if (unlikely(ret < 0)) {
				LOGINFO("Client id %d fd %d disconnected", client->id, fd);
				invalidate_client(ckp, ci, client);
				break;
			}
			ofs += ret;
			sender_send->len -= ret;
		}
		free(sender_send->buf);
		free(sender_send);
	}

	return NULL;
}

/* Send a client by id a heap allocated buffer, allowing this function to
 * free the ram. */
static void send_client(conn_instance_t *ci, int64_t id, char *buf)
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

	ck_rlock(&ci->lock);
	HASH_FIND_I64(clients, &id, client);
	if (likely(client))
		fd = client->fd;
	ck_runlock(&ci->lock);

	if (unlikely(fd == -1)) {
		if (client) {
			LOGINFO("Client id %ld disconnected", id);
			invalidate_client(ci->pi->ckp, ci, client);
		} else
			LOGINFO("Connector failed to find client id %ld to send to", id);
		free(buf);
		return;
	}

	sender_send = ckzalloc(sizeof(sender_send_t));
	sender_send->client = client;
	sender_send->buf = buf;
	sender_send->len = len;

	mutex_lock(&sender_lock);
	DL_APPEND(sender_sends, sender_send);
	pthread_cond_signal(&sender_cond);
	mutex_unlock(&sender_lock);
}

static client_instance_t *client_by_id(conn_instance_t *ci, int64_t id)
{
	client_instance_t *client;

	ck_rlock(&ci->lock);
	HASH_FIND_I64(clients, &id, client);
	ck_runlock(&ci->lock);

	return client;
}

static void passthrough_client(conn_instance_t *ci, client_instance_t *client)
{
	char *buf;

	LOGINFO("Connector adding passthrough client %d", client->id);
	client->passthrough = true;
	ASPRINTF(&buf, "{\"result\": true}\n");
	send_client(ci, client->id, buf);
}

static int connector_loop(proc_instance_t *pi, conn_instance_t *ci)
{
	int sockd = -1,  ret = 0, selret;
	int64_t client_id64, client_id;
	unixsock_t *us = &pi->us;
	ckpool_t *ckp = pi->ckp;
	char *buf = NULL;
	json_t *json_msg;

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
	close(sockd);
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
	if (cmdmatch(buf, "ping")) {
		LOGDEBUG("Connector received ping request");
		send_unix_msg(sockd, "pong");
		goto retry;
	}
	if (cmdmatch(buf, "accept")) {
		LOGDEBUG("Connector received accept signal");
		ci->accept = true;
		goto retry;
	}
	if (cmdmatch(buf, "reject")) {
		LOGDEBUG("Connector received reject signal");
		ci->accept = false;
		goto retry;
	}
	if (cmdmatch(buf, "loglevel")) {
		sscanf(buf, "loglevel=%d", &ckp->loglevel);
		goto retry;
	}

	if (cmdmatch(buf, "shutdown"))
		goto out;
	if (cmdmatch(buf, "dropclient")) {
		client_instance_t *client;

		ret = sscanf(buf, "dropclient=%ld", &client_id64);
		if (ret < 0) {
			LOGDEBUG("Connector failed to parse dropclient command: %s", buf);
			goto retry;
		}
		client_id = client_id64 & 0xffffffffll;
		client = client_by_id(ci, client_id);
		if (unlikely(!client)) {
			LOGINFO("Connector failed to find client id %ld to drop", client_id);
			goto retry;
		}
		ret = drop_client(ci, client);
		if (ret >= 0)
			LOGINFO("Connector dropped client id: %ld", client_id);
		goto retry;
	}
	if (cmdmatch(buf, "passthrough")) {
		client_instance_t *client;

		ret = sscanf(buf, "passthrough=%ld", &client_id);
		if (ret < 0) {
			LOGDEBUG("Connector failed to parse passthrough command: %s", buf);
			goto retry;
		}
		client = client_by_id(ci, client_id);
		if (unlikely(!client)) {
			LOGINFO("Connector failed to find client id %ld to pass through", client_id);
			goto retry;
		}
		passthrough_client(ci, client);
		goto retry;
	}
	if (cmdmatch(buf, "getfd")) {
		send_fd(ci->serverfd, sockd);
		goto retry;
	}

	/* Anything else should be a json message to send to a client */
	json_msg = json_loads(buf, 0, NULL);
	if (unlikely(!json_msg)) {
		LOGWARNING("Invalid json message: %s", buf);
		goto retry;
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
	dealloc(buf);
	buf = json_dumps(json_msg, 0);
	realloc_strcat(&buf, "\n");
	send_client(ci, client_id, buf);
	json_decref(json_msg);
	buf = NULL;

	goto retry;
out:
	close(sockd);
	dealloc(buf);
	return ret;
}

int connector(proc_instance_t *pi)
{
	pthread_t pth_sender, pth_acceptor, pth_receiver;
	char *url = NULL, *port = NULL;
	ckpool_t *ckp = pi->ckp;
	int sockd, ret = 0;
	conn_instance_t ci;
	const int on = 1;
	int tries = 0;

	LOGWARNING("%s connector starting", ckp->name);

	if (ckp->oldconnfd > 0) {
		sockd = ckp->oldconnfd;
	} else if (ckp->serverurl) {
		if (!extract_sockaddr(ckp->serverurl, &url, &port)) {
			LOGWARNING("Failed to extract server address from %s", ckp->serverurl);
			ret = 1;
			goto out;
		}
		do {
			sockd = bind_socket(url, port);
			if (sockd > 0)
				break;
			LOGWARNING("Connector failed to bind to socket, retrying in 5s");
			sleep(5);
		} while (++tries < 25);

		dealloc(url);
		dealloc(port);
		if (sockd < 0) {
			LOGERR("Connector failed to bind to socket for 2 minutes");
			ret = 1;
			goto out;
		}
	} else {
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
			close(sockd);
			goto out;
		}
	}
	if (tries)
		LOGWARNING("Connector successfully bound to socket");

	ret = listen(sockd, 10);
	if (ret < 0) {
		LOGERR("Connector failed to listen on socket");
		close(sockd);
		goto out;
	}

	cklock_init(&ci.lock);
	memset(&ci, 0, sizeof(ci));
	ci.pi = pi;
	ci.serverfd = sockd;
	ci.nfds = 0;
	mutex_init(&sender_lock);
	cond_init(&sender_cond);
	create_pthread(&pth_sender, sender, &ci);
	create_pthread(&pth_acceptor, acceptor, &ci);
	create_pthread(&pth_receiver, receiver, &ci);

	ret = connector_loop(pi, &ci);

	//join_pthread(pth_acceptor);
out:
	return process_exit(ckp, pi, ret);
}
