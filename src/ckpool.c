/*
 * Copyright 2014 Con Kolivas
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#include "config.h"

#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <ctype.h>
#include <fenv.h>
#include <getopt.h>
#include <grp.h>
#include <jansson.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ckpool.h"
#include "libckpool.h"
#include "generator.h"
#include "stratifier.h"
#include "connector.h"

ckpool_t *global_ckp;

static void proclog(ckpool_t *ckp, char *msg)
{
	FILE *LOGFP;
	int logfd;

	if (unlikely(!msg)) {
		fprintf(stderr, "Proclog received null message");
		return;
	}
	if (unlikely(!strlen(msg))) {
		fprintf(stderr, "Proclog received zero length message");
		free(msg);
		return;
	}
	LOGFP = ckp->logfp;
	logfd = ckp->logfd;

	flock(logfd, LOCK_EX);
	fprintf(LOGFP, "%s", msg);
	flock(logfd, LOCK_UN);

	free(msg);
}

/* Log everything to the logfile, but display warnings on the console as well */
void logmsg(int loglevel, const char *fmt, ...) {
	if (global_ckp->loglevel >= loglevel && fmt) {
		int logfd = global_ckp->logfd;
		char *buf = NULL;
		struct tm tm;
		time_t now_t;
		va_list ap;
		char stamp[128];

		va_start(ap, fmt);
		VASPRINTF(&buf, fmt, ap);
		va_end(ap);

		now_t = time(NULL);
		localtime_r(&now_t, &tm);
		sprintf(stamp, "[%d-%02d-%02d %02d:%02d:%02d]",
				tm.tm_year + 1900,
				tm.tm_mon + 1,
				tm.tm_mday,
				tm.tm_hour,
				tm.tm_min,
				tm.tm_sec);
		if (logfd) {
			char *msg;

			if (loglevel <= LOG_ERR && errno != 0)
				ASPRINTF(&msg, "%s %s with errno %d: %s\n", stamp, buf, errno, strerror(errno));
			else
				ASPRINTF(&msg, "%s %s\n", stamp, buf);
			ckmsgq_add(global_ckp->logger, msg);
		}
		if (loglevel <= LOG_WARNING) {\
			if (loglevel <= LOG_ERR && errno != 0)
				fprintf(stderr, "%s %s with errno %d: %s\n", stamp, buf, errno, strerror(errno));
			else
				fprintf(stderr, "%s %s\n", stamp, buf);
			fflush(stderr);
		}
		free(buf);
	}
}

/* Generic function for creating a message queue receiving and parsing thread */
static void *ckmsg_queue(void *arg)
{
	ckmsgq_t *ckmsgq = (ckmsgq_t *)arg;
	ckpool_t *ckp = ckmsgq->ckp;

	pthread_detach(pthread_self());
	rename_proc(ckmsgq->name);

	while (42) {
		ckmsg_t *msg;
		tv_t now;
		ts_t abs;

		mutex_lock(&ckmsgq->lock);
		tv_time(&now);
		tv_to_ts(&abs, &now);
		abs.tv_sec++;
		if (!ckmsgq->msgs)
			pthread_cond_timedwait(&ckmsgq->cond, &ckmsgq->lock, &abs);
		msg = ckmsgq->msgs;
		if (msg)
			DL_DELETE(ckmsgq->msgs, msg);
		mutex_unlock(&ckmsgq->lock);

		if (!msg)
			continue;
		ckmsgq->func(ckp, msg->data);
		free(msg);
	}
	return NULL;
}

ckmsgq_t *create_ckmsgq(ckpool_t *ckp, const char *name, const void *func)
{
	ckmsgq_t *ckmsgq = ckzalloc(sizeof(ckmsgq_t));

	strncpy(ckmsgq->name, name, 15);
	ckmsgq->func = func;
	ckmsgq->ckp = ckp;
	mutex_init(&ckmsgq->lock);
	cond_init(&ckmsgq->cond);
	create_pthread(&ckmsgq->pth, ckmsg_queue, ckmsgq);

	return ckmsgq;
}

/* Generic function for adding messages to a ckmsgq linked list and signal the ckmsgq
 * parsing thread to wake up and process it. */
void ckmsgq_add(ckmsgq_t *ckmsgq, void *data)
{
	ckmsg_t *msg = ckalloc(sizeof(ckmsg_t));

	msg->data = data;

	mutex_lock(&ckmsgq->lock);
	DL_APPEND(ckmsgq->msgs, msg);
	pthread_cond_signal(&ckmsgq->cond);
	mutex_unlock(&ckmsgq->lock);
}

static void broadcast_proc(ckpool_t *ckp, const char *buf)
{
	int i;

	for (i = 0; i < ckp->proc_instances; i++) {
		proc_instance_t *pi = ckp->children[i];

		send_proc(pi, buf);
	}
}

/* Put a sanity check on kill calls to make sure we are not sending them to
 * pid 0. */
static int kill_pid(int pid, int sig)
{
	if (pid < 1)
		return -1;
	return kill(pid, sig);
}

static int send_procmsg(proc_instance_t *pi, const char *buf)
{
	char *path = pi->us.path;
	int ret = -1;
	int sockd;

	if (unlikely(!path || !strlen(path))) {
		LOGERR("Attempted to send message %s to null path in send_proc", buf ? buf : "");
		goto out;
	}
	if (unlikely(!buf || !strlen(buf))) {
		LOGERR("Attempted to send null message to socket %s in send_proc", path);
		goto out;
	}
	if (unlikely(kill_pid(pi->pid, 0))) {
		LOGALERT("Attempting to send message %s to dead process %s", buf, pi->processname);
		goto out;
	}
	sockd = open_unix_client(path);
	if (unlikely(sockd < 0)) {
		LOGWARNING("Failed to open socket %s in send_recv_proc", path);
		goto out;
	}
	if (unlikely(!send_unix_msg(sockd, buf)))
		LOGWARNING("Failed to send %s to socket %s", buf, path);
	else
		ret = sockd;
out:
	if (unlikely(ret == -1))
		LOGERR("Failure in send_procmsg");
	return ret;
}

/* Listen for incoming global requests. Always returns a response if possible */
static void *listener(void *arg)
{
	proc_instance_t *pi = (proc_instance_t *)arg;
	unixsock_t *us = &pi->us;
	ckpool_t *ckp = pi->ckp;
	char *buf = NULL;
	int sockd;

	rename_proc(pi->sockname);
retry:
	dealloc(buf);
	sockd = accept(us->sockd, NULL, NULL);
	if (sockd < 0) {
		LOGERR("Failed to accept on socket in listener");
		goto out;
	}

	buf = recv_unix_msg(sockd);
	if (!buf) {
		LOGWARNING("Failed to get message in listener");
		send_unix_msg(sockd, "failed");
	} else if (cmdmatch(buf, "shutdown")) {
		LOGWARNING("Listener received shutdown message, terminating ckpool");
		send_unix_msg(sockd, "exiting");
		goto out;
	} else if (cmdmatch(buf, "ping")) {
		LOGDEBUG("Listener received ping request");
		send_unix_msg(sockd, "pong");
	} else if (cmdmatch(buf, "loglevel")) {
		int loglevel;

		if (sscanf(buf, "loglevel=%d", &loglevel) != 1) {
			LOGWARNING("Failed to parse loglevel message %s", buf);
			send_unix_msg(sockd, "Failed");
		} else if (loglevel < LOG_EMERG || loglevel > LOG_DEBUG) {
			LOGWARNING("Invalid loglevel %d sent", loglevel);
			send_unix_msg(sockd, "Invalid");
		} else {
			ckp->loglevel = loglevel;
			broadcast_proc(ckp, buf);
			send_unix_msg(sockd, "success");
		}
	} else if (cmdmatch(buf, "getfd")) {
		int connfd = send_procmsg(ckp->connector, "getfd");

		if (connfd > 0) {
			int newfd = get_fd(connfd);

			if (newfd > 0) {
				LOGDEBUG("Sending new fd %d", newfd);
				send_fd(newfd, sockd);
				close(newfd);
			} else
				LOGWARNING("Failed to get_fd");
			close(connfd);
		} else
			LOGWARNING("Failed to send_procmsg to connector");
	} else if (cmdmatch(buf, "restart")) {
		if (!fork()) {
			if (!ckp->handover) {
				ckp->initial_args[ckp->args++] = strdup("-H");
				ckp->initial_args[ckp->args] = NULL;
			}
			execv(ckp->initial_args[0], (char *const *)ckp->initial_args);
		}
	} else {
		LOGINFO("Listener received unhandled message: %s", buf);
		send_unix_msg(sockd, "unknown");
	}
	close(sockd);
	goto retry;
out:
	dealloc(buf);
	close_unix_socket(us->sockd, us->path);
	return NULL;
}

bool ping_main(ckpool_t *ckp)
{
	char *buf;

	buf = send_recv_proc(&ckp->main, "ping");
	if (!buf)
		return false;
	free(buf);
	return true;
}

void empty_buffer(connsock_t *cs)
{
	cs->buflen = cs->bufofs = 0;
}

/* Read from a socket into cs->buf till we get an '\n', converting it to '\0'
 * and storing how much extra data we've received, to be moved to the beginning
 * of the buffer for use on the next receive. */
int read_socket_line(connsock_t *cs, int timeout)
{
	char *eom = NULL;
	size_t buflen;
	int ret = -1;

	if (unlikely(cs->fd < 0))
		goto out;

	if (unlikely(!cs->buf))
		cs->buf = ckzalloc(PAGESIZE);
	else if (cs->buflen) {
		memmove(cs->buf, cs->buf + cs->bufofs, cs->buflen);
		memset(cs->buf + cs->buflen, 0, cs->bufofs);
		cs->bufofs = cs->buflen;
		cs->buflen = 0;
		cs->buf[cs->bufofs] = '\0';
		eom = strchr(cs->buf, '\n');
	}

	while (42) {
		char readbuf[PAGESIZE] = {};

		ret = wait_read_select(cs->fd, eom ? 0 : timeout);
		if (eom && !ret)
			break;
		if (ret < 1) {
			if (!ret)
				LOGDEBUG("Select timed out in read_socket_line");
			else
				LOGERR("Select failed in read_socket_line");
			goto out;
		}
		ret = recv(cs->fd, readbuf, PAGESIZE - 4, 0);
		if (ret < 1) {
			LOGERR("Failed to recv in read_socket_line");
			ret = -1;
			goto out;
		}
		buflen = cs->bufofs + ret + 1;
		cs->buf = realloc(cs->buf, buflen);
		if (unlikely(!cs->buf))
			quit(1, "Failed to alloc buf of %d bytes in read_socket_line", (int)buflen);
		memcpy(cs->buf + cs->bufofs, readbuf, ret);
		cs->bufofs += ret;
		cs->buf[cs->bufofs] = '\0';
		eom = strchr(cs->buf, '\n');
	}
	ret = eom - cs->buf;

	cs->buflen = cs->buf + cs->bufofs - eom - 1;
	if (cs->buflen)
		cs->bufofs = eom - cs->buf + 1;
	else
		cs->bufofs = 0;
	*eom = '\0';
out:
	if (ret < 0) {
		dealloc(cs->buf);
		if (cs->fd > 0) {
			close(cs->fd);
			cs->fd = -1;
		}
	}
	return ret;
}

static void childsighandler(int sig);

static int get_proc_pid(proc_instance_t *pi)
{
	int ret, pid = 0;
	char path[256];
	FILE *fp;

	sprintf(path, "%s%s.pid", pi->ckp->socket_dir, pi->processname);
	fp = fopen(path, "re");
	if (!fp)
		goto out;
	ret = fscanf(fp, "%d", &pid);
	if (ret < 1)
		pid = 0;
	fclose(fp);
out:
	return pid;
}

/* Send a single message to a process instance when there will be no response,
 * closing the socket immediately. */
bool _send_proc(proc_instance_t *pi, const char *msg, const char *file, const char *func, const int line)
{
	char *path = pi->us.path;
	bool ret = false;
	int sockd;

	if (unlikely(!path || !strlen(path))) {
		LOGERR("Attempted to send message %s to null path in send_proc", msg ? msg : "");
		goto out;
	}
	if (unlikely(!msg || !strlen(msg))) {
		LOGERR("Attempted to send null message to socket %s in send_proc", path);
		goto out;
	}
	/* At startup the pid fields are not set up before some processes are
	 * forked so they never inherit them. */
	if (unlikely(!pi->pid))
		pi->pid = get_proc_pid(pi);
	if (unlikely(kill_pid(pi->pid, 0))) {
		LOGALERT("Attempting to send message %s to non existent process %s", msg, pi->processname);
		goto out;
	}
	sockd = open_unix_client(path);
	if (unlikely(sockd < 0)) {
		LOGWARNING("Failed to open socket %s", path);
		goto out;
	}
	if (unlikely(!send_unix_msg(sockd, msg)))
		LOGWARNING("Failed to send %s to socket %s", msg, path);
	else
		ret = true;
	close(sockd);
out:
	if (unlikely(!ret)) {
		LOGERR("Failure in send_proc from %s %s:%d", file, func, line);
		childsighandler(15);
	}
	return ret;
}

/* Send a single message to a process instance and retrieve the response, then
 * close the socket. */
char *_send_recv_proc(proc_instance_t *pi, const char *msg, const char *file, const char *func, const int line)
{
	char *path = pi->us.path, *buf = NULL;
	int sockd;

	if (unlikely(!path || !strlen(path))) {
		LOGERR("Attempted to send message %s to null path in send_proc", msg ? msg : "");
		goto out;
	}
	if (unlikely(!msg || !strlen(msg))) {
		LOGERR("Attempted to send null message to socket %s in send_proc", path);
		goto out;
	}
	if (unlikely(kill_pid(pi->pid, 0))) {
		LOGALERT("Attempting to send message %s to dead process %s", msg, pi->processname);
		goto out;
	}
	sockd = open_unix_client(path);
	if (unlikely(sockd < 0)) {
		LOGWARNING("Failed to open socket %s in send_recv_proc", path);
		goto out;
	}
	if (unlikely(!send_unix_msg(sockd, msg)))
		LOGWARNING("Failed to send %s to socket %s", msg, path);
	else
		buf = recv_unix_msg(sockd);
	close(sockd);
out:
	if (unlikely(!buf))
		LOGERR("Failure in send_recv_proc from %s %s:%d", file, func, line);
	return buf;
}

/* As send_recv_proc but only to ckdb */
char *_send_recv_ckdb(const ckpool_t *ckp, const char *msg, const char *file, const char *func, const int line)
{
	const char *path = ckp->ckdb_sockname;
	char *buf = NULL;
	int sockd;

	if (unlikely(!path || !strlen(path))) {
		LOGERR("Attempted to send message %s to null path in send_recv_ckdb", msg ? msg : "");
		goto out;
	}
	if (unlikely(!msg || !strlen(msg))) {
		LOGERR("Attempted to send null message to ckdb in send_recv_ckdb");
		goto out;
	}
	sockd = open_unix_client(path);
	if (unlikely(sockd < 0)) {
		LOGWARNING("Failed to open socket %s in send_recv_ckdb", path);
		goto out;
	}
	if (unlikely(!send_unix_msg(sockd, msg)))
		LOGWARNING("Failed to send %s to ckdb", msg);
	else
		buf = recv_unix_msg(sockd);
	close(sockd);
out:
	if (unlikely(!buf))
		LOGERR("Failure in send_recv_ckdb from %s %s:%d", file, func, line);
	return buf;
}

/* Send a json msg to ckdb and return the response */
char *_ckdb_msg_call(const ckpool_t *ckp, char *msg,  const char *file, const char *func,
		     const int line)
{
	char *buf = NULL;

	LOGDEBUG("Sending ckdb: %s", msg);
	buf = _send_recv_ckdb(ckp, msg, file, func, line);
	LOGDEBUG("Received from ckdb: %s", buf);
	return buf;
}

json_t *json_rpc_call(connsock_t *cs, const char *rpc_req)
{
	char *http_req = NULL;
	json_error_t err_val;
	json_t *val = NULL;
	int len, ret;

	if (unlikely(cs->fd < 0)) {
		LOGWARNING("FD %d invalid in json_rpc_call", cs->fd);
		goto out;
	}
	if (unlikely(!cs->url)) {
		LOGWARNING("No URL in json_rpc_call");
		goto out;
	}
	if (unlikely(!cs->port)) {
		LOGWARNING("No port in json_rpc_call");
		goto out;
	}
	if (unlikely(!cs->auth)) {
		LOGWARNING("No auth in json_rpc_call");
		goto out;
	}
	if (unlikely(!rpc_req)) {
		LOGWARNING("Null rpc_req passed to json_rpc_call");
		goto out;
	}
	len = strlen(rpc_req);
	if (unlikely(!len)) {
		LOGWARNING("Zero length rpc_req passed to json_rpc_call");
		goto out;
	}
	http_req = ckalloc(len + 256); // Leave room for headers
	sprintf(http_req,
		 "POST / HTTP/1.1\n"
		 "Authorization: Basic %s\n"
		 "Host: %s:%s\n"
		 "Content-type: application/json\n"
		 "Content-Length: %d\n\n%s",
		 cs->auth, cs->url, cs->port, len, rpc_req);

	len = strlen(http_req);
	ret = write_socket(cs->fd, http_req, len);
	if (ret != len) {
		LOGWARNING("Failed to write to socket in json_rpc_call");
		goto out_empty;
	}
	ret = read_socket_line(cs, 5);
	if (ret < 1) {
		LOGWARNING("Failed to read socket line in json_rpc_call");
		goto out_empty;
	}
	if (strncasecmp(cs->buf, "HTTP/1.1 200 OK", 15)) {
		LOGWARNING("HTTP response not ok: %s", cs->buf);
		goto out_empty;
	}
	do {
		ret = read_socket_line(cs, 5);
		if (ret < 1) {
			LOGWARNING("Failed to read http socket lines in json_rpc_call");
			goto out_empty;
		}
	} while (strncmp(cs->buf, "{", 1));

	val = json_loads(cs->buf, 0, &err_val);
	if (!val)
		LOGWARNING("JSON decode failed(%d): %s", err_val.line, err_val.text);
out_empty:
	empty_socket(cs->fd);
	empty_buffer(cs);
	if (!val) {
		/* Assume that a failed request means the socket will be closed
		 * and reopen it */
		LOGWARNING("Reopening socket to %s:%s", cs->url, cs->port);
		close(cs->fd);
		cs->fd = connect_socket(cs->url, cs->port);
	}
out:
	free(http_req);
	dealloc(cs->buf);
	return val;
}


/* Open the file in path, check if there is a pid in there that still exists
 * and if not, write the pid into that file. */
static bool write_pid(ckpool_t *ckp, const char *path, pid_t pid)
{
	struct stat statbuf;
	FILE *fp;
	int ret;

	if (!stat(path, &statbuf)) {
		int oldpid;

		LOGNOTICE("File %s exists", path);
		fp = fopen(path, "re");
		if (!fp) {
			LOGEMERG("Failed to open file %s", path);
			return false;
		}
		ret = fscanf(fp, "%d", &oldpid);
		fclose(fp);
		if (ret == 1 && !(kill_pid(oldpid, 0))) {
			if (!ckp->killold) {
				LOGEMERG("Process %s pid %d still exists, start ckpool with -k if you wish to kill it",
					 path, oldpid);
				return false;
			}
			if (kill_pid(oldpid, 9)) {
				LOGEMERG("Unable to kill old process %s pid %d", path, oldpid);
				return false;
			}
			LOGWARNING("Killing off old process %s pid %d", path, oldpid);
		}
	}
	fp = fopen(path, "we");
	if (!fp) {
		LOGERR("Failed to open file %s", path);
		return false;
	}
	fprintf(fp, "%d", pid);
	fclose(fp);

	return true;
}

static void name_process_sockname(unixsock_t *us, proc_instance_t *pi)
{
	us->path = strdup(pi->ckp->socket_dir);
	realloc_strcat(&us->path, pi->sockname);
}

static void open_process_sock(ckpool_t *ckp, proc_instance_t *pi, unixsock_t *us)
{
	LOGDEBUG("Opening %s", us->path);
	us->sockd = open_unix_server(us->path);
	if (unlikely(us->sockd < 0))
		quit(1, "Failed to open %s socket", pi->sockname);
	if (chown(us->path, -1, ckp->gr_gid))
		quit(1, "Failed to set %s to group id %d", us->path, ckp->gr_gid);
}

static void create_process_unixsock(proc_instance_t *pi)
{
	unixsock_t *us = &pi->us;
	ckpool_t *ckp = pi->ckp;

	name_process_sockname(us, pi);
	open_process_sock(ckp, pi, us);
}

static void write_namepid(proc_instance_t *pi)
{
	char s[256];

	pi->pid = getpid();
	sprintf(s, "%s%s.pid", pi->ckp->socket_dir, pi->processname);
	if (!write_pid(pi->ckp, s, pi->pid))
		quit(1, "Failed to write %s pid %d", pi->processname, pi->pid);
}

static void rm_namepid(proc_instance_t *pi)
{
	char s[256];

	sprintf(s, "%s%s.pid", pi->ckp->socket_dir, pi->processname);
	unlink(s);
}

/* Disable signal handlers for child processes, but simply pass them onto the
 * parent process to shut down cleanly. */
static void childsighandler(int sig)
{
	signal(sig, SIG_IGN);
	signal(SIGTERM, SIG_IGN);
	if (sig != SIGUSR1) {
		pid_t ppid = getppid();

		LOGWARNING("Child process received signal %d, forwarding signal to %s main process",
			sig, global_ckp->name);
		kill_pid(ppid, sig);
	}
	exit(0);
}

static void launch_logger(proc_instance_t *pi)
{
	ckpool_t *ckp = pi->ckp;
	char loggername[16];

	/* Note that the logger is unique per process so it is the only value
	 * in ckp that differs between processes */
	snprintf(loggername, 15, "%clogger", pi->processname[0]);
	ckp->logger = create_ckmsgq(ckp, loggername, &proclog);
}

static void launch_process(proc_instance_t *pi)
{
	pid_t pid;

	pid = fork();
	if (pid < 0)
		quit(1, "Failed to fork %s in launch_process", pi->processname);
	if (!pid) {
		struct sigaction handler;
		int ret;

		launch_logger(pi);
		handler.sa_handler = &childsighandler;
		handler.sa_flags = 0;
		sigemptyset(&handler.sa_mask);
		sigaction(SIGTERM, &handler, NULL);
		signal(SIGINT, SIG_IGN);
		signal(SIGQUIT, SIG_IGN);

		rename_proc(pi->processname);
		write_namepid(pi);
		ret = pi->process(pi);
		close_unix_socket(pi->us.sockd, pi->us.path);
		rm_namepid(pi);
		exit(ret);
	}
	pi->pid = pid;
}

static void launch_processes(ckpool_t *ckp)
{
	int i;

	for (i = 0; i < ckp->proc_instances; i++)
		launch_process(ckp->children[i]);
}

int process_exit(ckpool_t *ckp, proc_instance_t *pi, int ret)
{
	if (ret) {
		/* Abnormal termination, kill entire process */
		LOGWARNING("%s %s exiting with return code %d, shutting down!",
			   ckp->name, pi->processname, ret);
		send_proc(&ckp->main, "shutdown");
		sleep(1);
		ret = 1;
	} else /* Should be part of a normal shutdown */
		LOGNOTICE("%s %s exited normally", ckp->name, pi->processname);

	return ret;
}

static void clean_up(ckpool_t *ckp)
{
	int i, children = ckp->proc_instances;

	rm_namepid(&ckp->main);
	dealloc(ckp->socket_dir);
	ckp->proc_instances = 0;
	for (i = 0; i < children; i++)
		dealloc(ckp->children[i]);
	dealloc(ckp->children);
}

static void cancel_join_pthread(pthread_t *pth)
{
	if (!*pth)
		return;
	pthread_cancel(*pth);
	join_pthread(*pth);
	pth = NULL;
}

static void cancel_pthread(pthread_t *pth)
{
	if (!*pth)
		return;
	pthread_cancel(*pth);
	pth = NULL;
}

static void __shutdown_children(ckpool_t *ckp, int sig)
{
	int i;

	cancel_join_pthread(&ckp->pth_watchdog);

	for (i = 0; i < ckp->proc_instances; i++) {
		pid_t pid = ckp->children[i]->pid;
		if (!kill_pid(pid, 0))
			kill_pid(pid, sig);
	}
}

static void shutdown_children(ckpool_t *ckp, int sig)
{
	cancel_join_pthread(&ckp->pth_watchdog);

	__shutdown_children(ckp, sig);
}

static void sighandler(int sig)
{
	ckpool_t *ckp = global_ckp;

	signal(sig, SIG_IGN);
	signal(SIGTERM, SIG_IGN);
	LOGWARNING("Parent process %s received signal %d, shutting down",
		   ckp->name, sig);
	cancel_join_pthread(&ckp->pth_watchdog);

	__shutdown_children(ckp, SIGUSR1);
	/* Wait a second, then send SIGKILL */
	sleep(1);
	__shutdown_children(ckp, SIGKILL);
	cancel_pthread(&ckp->pth_listener);
	exit(0);
}

static void json_get_string(char **store, json_t *val, const char *res)
{
	json_t *entry = json_object_get(val, res);
	const char *buf;

	*store = NULL;
	if (!entry || json_is_null(entry)) {
		LOGDEBUG("Json did not find entry %s", res);
		return;
	}
	if (!json_is_string(entry)) {
		LOGWARNING("Json entry %s is not a string", res);
		return;
	}
	buf = json_string_value(entry);
	LOGDEBUG("Json found entry %s: %s", res, buf);
	*store = strdup(buf);
}

static void json_get_int64(int64_t *store, json_t *val, const char *res)
{
	json_t *entry = json_object_get(val, res);

	if (!entry) {
		LOGDEBUG("Json did not find entry %s", res);
		return;
	}
	if (!json_is_integer(entry)) {
		LOGWARNING("Json entry %s is not an integer", res);
		return;
	}
	*store = json_integer_value(entry);
}

static void json_get_int(int *store, json_t *val, const char *res)
{
	json_t *entry = json_object_get(val, res);

	if (!entry) {
		LOGDEBUG("Json did not find entry %s", res);
		return;
	}
	if (!json_is_integer(entry)) {
		LOGWARNING("Json entry %s is not an integer", res);
		return;
	}
	*store = json_integer_value(entry);
}

static void parse_btcds(ckpool_t *ckp, json_t *arr_val, int arr_size)
{
	json_t *val;
	int i;

	ckp->btcds = arr_size;
	ckp->btcdurl = ckzalloc(sizeof(char *) * arr_size);
	ckp->btcdauth = ckzalloc(sizeof(char *) * arr_size);
	ckp->btcdpass = ckzalloc(sizeof(char *) * arr_size);
	for (i = 0; i < arr_size; i++) {
		val = json_array_get(arr_val, i);
		json_get_string(&ckp->btcdurl[i], val, "url");
		json_get_string(&ckp->btcdauth[i], val, "auth");
		json_get_string(&ckp->btcdpass[i], val, "pass");
	}
}

static void parse_proxies(ckpool_t *ckp, json_t *arr_val, int arr_size)
{
	json_t *val;
	int i;

	ckp->proxies = arr_size;
	ckp->proxyurl = ckzalloc(sizeof(char *) * arr_size);
	ckp->proxyauth = ckzalloc(sizeof(char *) * arr_size);
	ckp->proxypass = ckzalloc(sizeof(char *) * arr_size);
	for (i = 0; i < arr_size; i++) {
		val = json_array_get(arr_val, i);
		json_get_string(&ckp->proxyurl[i], val, "url");
		json_get_string(&ckp->proxyauth[i], val, "auth");
		json_get_string(&ckp->proxypass[i], val, "pass");
	}
}

static void parse_config(ckpool_t *ckp)
{
	json_t *json_conf, *arr_val;
	json_error_t err_val;

	json_conf = json_load_file(ckp->config, JSON_DISABLE_EOF_CHECK, &err_val);
	if (!json_conf) {
		LOGWARNING("Json decode error for config file %s: (%d): %s", ckp->config,
			   err_val.line, err_val.text);
		return;
	}
	arr_val = json_object_get(json_conf, "btcd");
	if (arr_val && json_is_array(arr_val)) {
		int arr_size = json_array_size(arr_val);

		if (arr_size)
			parse_btcds(ckp, arr_val, arr_size);
	}
	json_get_string(&ckp->btcaddress, json_conf, "btcaddress");
	json_get_string(&ckp->btcsig, json_conf, "btcsig");
	if (ckp->btcsig && strlen(ckp->btcsig) > 38) {
		LOGWARNING("Signature %s too long, truncating to 38 bytes", ckp->btcsig);
		ckp->btcsig[38] = '\0';
	}
	json_get_int(&ckp->blockpoll, json_conf, "blockpoll");
	json_get_int(&ckp->update_interval, json_conf, "update_interval");
	json_get_string(&ckp->serverurl, json_conf, "serverurl");
	json_get_int64(&ckp->mindiff, json_conf, "mindiff");
	json_get_int64(&ckp->startdiff, json_conf, "startdiff");
	json_get_string(&ckp->logdir, json_conf, "logdir");
	arr_val = json_object_get(json_conf, "proxy");
	if (arr_val && json_is_array(arr_val)) {
		int arr_size = json_array_size(arr_val);

		if (arr_size)
			parse_proxies(ckp, arr_val, arr_size);
	}
	json_decref(json_conf);
}

static proc_instance_t *prepare_child(ckpool_t *ckp, int (*process)(), char *name)
{
	proc_instance_t *pi = ckzalloc(sizeof(proc_instance_t));

	ckp->children = realloc(ckp->children, sizeof(proc_instance_t *) * (ckp->proc_instances + 1));
	ckp->children[ckp->proc_instances++] = pi;
	pi->ckp = ckp;
	pi->processname = name;
	pi->sockname = pi->processname;
	pi->process = process;
	create_process_unixsock(pi);
	return pi;
}

static proc_instance_t *child_by_pid(ckpool_t *ckp, pid_t pid)
{
	proc_instance_t *pi = NULL;
	int i;

	for (i = 0; i < ckp->proc_instances; i++) {
		if (ckp->children[i]->pid == pid) {
			pi = ckp->children[i];
			break;
		}
	}
	return pi;
}

static void *watchdog(void *arg)
{
	time_t last_relaunch_t = time(NULL);
	ckpool_t *ckp = (ckpool_t *)arg;

	rename_proc("watchdog");
	sleep(1);
	while (42) {
		proc_instance_t *pi;
		time_t relaunch_t;
		int pid, status;

		pid = waitpid(0, &status, 0);
		pi = child_by_pid(ckp, pid);
		if (pi && WIFEXITED(status)) {
			LOGWARNING("Child process %s exited, terminating!", pi->processname);
			break;
		}
		relaunch_t = time(NULL);
		if (relaunch_t == last_relaunch_t) {
			LOGEMERG("Respawning processes too fast, exiting!");
			break;
		}
		last_relaunch_t = relaunch_t;
		if (pi) {
			LOGERR("%s process dead! Relaunching", pi->processname);
			launch_process(pi);
		} else {
			LOGEMERG("Unknown child process %d dead, exiting!", pid);
			break;
		}
	}
	send_proc(&ckp->main, "shutdown");
	return NULL;
}

static struct option long_options[] = {
	{"standalone",	no_argument,		0,	'A'},
	{"btcsolo",	no_argument,		0,	'B'},
	{"config",	required_argument,	0,	'c'},
	{"ckdb-name",	required_argument,	0,	'd'},
	{"group",	required_argument,	0,	'g'},
	{"handover",	no_argument,		0,	'H'},
	{"help",	no_argument,		0,	'h'},
	{"killold",	no_argument,		0,	'k'},
	{"log-shares",	no_argument,		0,	'L'},
	{"loglevel",	required_argument,	0,	'l'},
	{"name",	required_argument,	0,	'n'},
	{"passthrough",	no_argument,		0,	'P'},
	{"proxy",	no_argument,		0,	'p'},
	{"ckdb-sockdir",required_argument,	0,	'S'},
	{"sockdir",	required_argument,	0,	's'},
	{0, 0, 0, 0}
};

int main(int argc, char **argv)
{
	struct sigaction handler;
	int c, ret, i = 0, j;
	char buf[512] = {};
	ckpool_t ckp;

	/* Make significant floating point errors fatal to avoid subtle bugs being missed */
	feenableexcept(FE_DIVBYZERO | FE_INVALID | FE_OVERFLOW );

	global_ckp = &ckp;
	memset(&ckp, 0, sizeof(ckp));
	ckp.loglevel = LOG_NOTICE;
	ckp.initial_args = ckalloc(sizeof(char *) * (argc + 2)); /* Leave room for extra -H */
	for (ckp.args = 0; ckp.args < argc; ckp.args++)
		ckp.initial_args[ckp.args] = strdup(argv[ckp.args]);
	ckp.initial_args[ckp.args] = NULL;

	while ((c = getopt_long(argc, argv, "ABc:d:g:HhkLl:n:PpS:s:", long_options, &i)) != -1) {
		switch (c) {
			case 'A':
				ckp.standalone = true;
				break;
			case 'B':
				if (ckp.proxy || ckp.passthrough)
					quit(1, "Cannot set both proxy and btcsolo mode");
				ckp.btcsolo = true;
				ckp.standalone = true;
				break;
			case 'c':
				ckp.config = optarg;
				break;
			case 'd':
				ckp.ckdb_name = optarg;
				break;
			case 'g':
				ckp.grpnam = optarg;
				break;
			case 'H':
				ckp.handover = true;
				ckp.killold = true;
				break;
			case 'h':
				for (j = 0; long_options[j].val; j++) {
					struct option *jopt = &long_options[j];

					if (jopt->has_arg) {
						char *upper = alloca(strlen(jopt->name) + 1);
						int offset = 0;

						do {
							upper[offset] = toupper(jopt->name[offset]);
						} while (upper[offset++] != '\0');
						printf("-%c %s | --%s %s\n", jopt->val,
						       upper, jopt->name, upper);
					} else
						printf("-%c | --%s\n", jopt->val, jopt->name);
				}
				exit(0);
			case 'k':
				ckp.killold = true;
				break;
			case 'L':
				ckp.logshares = true;
				break;
			case 'l':
				ckp.loglevel = atoi(optarg);
				if (ckp.loglevel < LOG_EMERG || ckp.loglevel > LOG_DEBUG) {
					quit(1, "Invalid loglevel (range %d - %d): %d",
					     LOG_EMERG, LOG_DEBUG, ckp.loglevel);
				}
				break;
			case 'n':
				ckp.name = optarg;
				break;
			case 'P':
				if (ckp.proxy)
					quit(1, "Cannot set both proxy and passthrough mode");
				ckp.standalone = ckp.proxy = ckp.passthrough = true;
				break;
			case 'p':
				if (ckp.passthrough)
					quit(1, "Cannot set both passthrough and proxy mode");
				ckp.proxy = true;
				break;
			case 'S':
				ckp.ckdb_sockdir = strdup(optarg);
				break;
			case 's':
				ckp.socket_dir = strdup(optarg);
				break;
		}
	}

	if (!ckp.name) {
		if (ckp.proxy)
			ckp.name = "ckproxy";
		else
			ckp.name = "ckpool";
	}
	snprintf(buf, 15, "%s", ckp.name);
	prctl(PR_SET_NAME, buf, 0, 0, 0);
	memset(buf, 0, 15);

	if (ckp.grpnam) {
		struct group *group = getgrnam(ckp.grpnam);

		if (!group)
			quit(1, "Failed to find group %s", ckp.grpnam);
		ckp.gr_gid = group->gr_gid;
	} else
		ckp.gr_gid = getegid();

	if (!ckp.config) {
		ckp.config = strdup(ckp.name);
		realloc_strcat(&ckp.config, ".conf");
	}
	if (!ckp.socket_dir) {
		ckp.socket_dir = strdup("/tmp/");
		realloc_strcat(&ckp.socket_dir, ckp.name);
	}
	trail_slash(&ckp.socket_dir);

	if (!ckp.standalone) {
		if (!ckp.ckdb_name)
			ckp.ckdb_name = "ckdb";
		if (!ckp.ckdb_sockdir) {
			ckp.ckdb_sockdir = strdup("/opt/");
			realloc_strcat(&ckp.ckdb_sockdir, ckp.ckdb_name);
		}
		trail_slash(&ckp.ckdb_sockdir);

		ret = mkdir(ckp.ckdb_sockdir, 0750);
		if (ret && errno != EEXIST)
			quit(1, "Failed to make directory %s", ckp.ckdb_sockdir);

		ckp.ckdb_sockname = ckp.ckdb_sockdir;
		realloc_strcat(&ckp.ckdb_sockname, "listener");
	}

	/* Ignore sigpipe */
	signal(SIGPIPE, SIG_IGN);

	ret = mkdir(ckp.socket_dir, 0750);
	if (ret && errno != EEXIST)
		quit(1, "Failed to make directory %s", ckp.socket_dir);

	parse_config(&ckp);
	/* Set defaults if not found in config file */
	if (!ckp.btcds && !ckp.proxy) {
		ckp.btcds = 1;
		ckp.btcdurl = ckzalloc(sizeof(char *));
		ckp.btcdauth = ckzalloc(sizeof(char *));
		ckp.btcdpass = ckzalloc(sizeof(char *));
	}
	if (ckp.btcds) {
		for (i = 0; i < ckp.btcds; i++) {
			if (!ckp.btcdurl[i])
				ckp.btcdurl[i] = strdup("localhost:8332");
			if (!ckp.btcdauth[i])
				ckp.btcdauth[i] = strdup("user");
			if (!ckp.btcdpass[i])
				ckp.btcdpass[i] = strdup("pass");
		}
	}

	ckp.donaddress = "14BMjogz69qe8hk9thyzbmR5pg34mVKB1e";
	if (!ckp.btcaddress)
		ckp.btcaddress = ckp.donaddress;
	if (!ckp.blockpoll)
		ckp.blockpoll = 500;
	if (!ckp.update_interval)
		ckp.update_interval = 30;
	if (!ckp.mindiff)
		ckp.mindiff = 1;
	if (!ckp.startdiff)
		ckp.startdiff = 42;
	if (!ckp.logdir)
		ckp.logdir = strdup("logs");
	if (ckp.proxy && !ckp.proxies)
		quit(0, "No proxy entries found in config file %s", ckp.config);

	/* Create the log directory */
	trail_slash(&ckp.logdir);
	ret = mkdir(ckp.logdir, 0750);
	if (ret && errno != EEXIST)
		quit(1, "Failed to make log directory %s", ckp.logdir);

	/* Create the user logdir */
	sprintf(buf, "%s/users", ckp.logdir);
	ret = mkdir(buf, 0750);
	if (ret && errno != EEXIST)
		quit(1, "Failed to make user log directory %s", buf);

	/* Create the pool logdir */
	sprintf(buf, "%s/pool", ckp.logdir);
	ret = mkdir(buf, 0750);
	if (ret && errno != EEXIST)
		quit(1, "Failed to make pool log directory %s", buf);

	/* Create the logfile */
	sprintf(buf, "%s%s.log", ckp.logdir, ckp.name);
	ckp.logfp = fopen(buf, "ae");
	if (!ckp.logfp)
		quit(1, "Failed to make open log file %s", buf);
	/* Make logging line buffered */
	setvbuf(ckp.logfp, NULL, _IOLBF, 0);

	ckp.main.ckp = &ckp;
	ckp.main.processname = strdup("main");
	ckp.main.sockname = strdup("listener");
	name_process_sockname(&ckp.main.us, &ckp.main);
	if (ckp.handover) {
		int sockd = open_unix_client(ckp.main.us.path);

		if (sockd > 0 && send_unix_msg(sockd, "getfd")) {
			ckp.oldconnfd = get_fd(sockd);

			close(sockd);
			sockd = open_unix_client(ckp.main.us.path);
			send_unix_msg(sockd, "shutdown");
			if (ckp.oldconnfd > 0)
				LOGWARNING("Inherited old socket with new file descriptor %d!", ckp.oldconnfd);
			close(sockd);
		}
	}

	write_namepid(&ckp.main);
	open_process_sock(&ckp, &ckp.main, &ckp.main.us);
	launch_logger(&ckp.main);
	ckp.logfd = fileno(ckp.logfp);

	create_pthread(&ckp.pth_listener, listener, &ckp.main);

	/* Launch separate processes from here */
	ckp.generator = prepare_child(&ckp, &generator, "generator");
	ckp.stratifier = prepare_child(&ckp, &stratifier, "stratifier");
	ckp.connector = prepare_child(&ckp, &connector, "connector");

	launch_processes(&ckp);

	create_pthread(&ckp.pth_watchdog, watchdog, &ckp);

	handler.sa_handler = &sighandler;
	handler.sa_flags = 0;
	sigemptyset(&handler.sa_mask);
	sigaction(SIGTERM, &handler, NULL);
	sigaction(SIGINT, &handler, NULL);

	/* Shutdown from here if the listener is sent a shutdown message */
	if (ckp.pth_listener)
		join_pthread(ckp.pth_listener);

	shutdown_children(&ckp, SIGTERM);
	clean_up(&ckp);

	return 0;
}
