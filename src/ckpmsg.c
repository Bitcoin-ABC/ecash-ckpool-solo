/*
 * Copyright 2014-2015 Con Kolivas
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#include "config.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "libckpool.h"

void mkstamp(char *stamp, size_t siz)
{
	long minoff, hroff;
	char tzinfo[16];
	time_t now_t;
	struct tm tm;
	char tzch;

	now_t = time(NULL);
	localtime_r(&now_t, &tm);
	minoff = tm.tm_gmtoff / 60;
	if (minoff < 0) {
		tzch = '-';
		minoff *= -1;
	} else
		tzch = '+';
	hroff = minoff / 60;
	if (minoff % 60) {
		snprintf(tzinfo, sizeof(tzinfo),
			 "%c%02ld:%02ld",
			 tzch, hroff, minoff % 60);
	} else {
		snprintf(tzinfo, sizeof(tzinfo),
			 "%c%02ld",
			 tzch, hroff);
	}
	snprintf(stamp, siz,
			"[%d-%02d-%02d %02d:%02d:%02d%s]",
			tm.tm_year + 1900,
			tm.tm_mon + 1,
			tm.tm_mday,
			tm.tm_hour,
			tm.tm_min,
			tm.tm_sec,
			tzinfo);
}

int main(int argc, char **argv)
{
	char *name = NULL, *socket_dir = NULL, *buf = NULL, *sockname = "listener";
	int tmo1 = RECV_UNIX_TIMEOUT1;
	int tmo2 = RECV_UNIX_TIMEOUT2;
	bool proxy = false;
	char stamp[128];
	int c;

	while ((c = getopt(argc, argv, "N:n:s:pt:T:")) != -1) {
		switch(c) {
			/* Allows us to specify which process or socket to
			 * talk to. */
			case 'N':
				sockname = strdup(optarg);
				break;
			case 'n':
				name = strdup(optarg);
				break;
			case 's':
				socket_dir = strdup(optarg);
				break;
			case 'p':
				proxy = true;
				break;
			case 't':
				tmo1 = atoi(optarg);
				break;
			case 'T':
				tmo2 = atoi(optarg);
				break;
		}
	}
	if (!socket_dir)
		socket_dir = strdup("/tmp");
	trail_slash(&socket_dir);
	if (!name) {
		if (proxy)
			name = strdup("ckproxy");
		else
			name = strdup("ckpool");
	}
	realloc_strcat(&socket_dir, name);
	dealloc(name);
	trail_slash(&socket_dir);
	realloc_strcat(&socket_dir, sockname);

	while (42) {
		int sockd, len;
		size_t n;

		dealloc(buf);
		len = getline(&buf, &n, stdin);
		if (len == -1) {
			LOGERR("Failed to get a valid line");
			break;
		}
		mkstamp(stamp, sizeof(stamp));
		len = strlen(buf);
		if (len < 2) {
			LOGERR("%s No message", stamp);
			continue;
		}
		buf[len - 1] = '\0'; // Strip /n
		if (buf[0] == '#') {
			LOGDEBUG("%s Got comment: %s", stamp, buf);
			continue;
		}
		LOGDEBUG("%s Got message: %s", stamp, buf);

		sockd = open_unix_client(socket_dir);
		if (sockd < 0) {
			LOGERR("Failed to open socket: %s", socket_dir);
			break;
		}
		if (!send_unix_msg(sockd, buf)) {
			LOGERR("Failed to send unix msg: %s", buf);
			break;
		}
		dealloc(buf);
		buf = recv_unix_msg_tmo2(sockd, tmo1, tmo2);
		close(sockd);
		if (!buf) {
			LOGERR("Received empty message");
			continue;
		}
		mkstamp(stamp, sizeof(stamp));
		LOGMSGSIZ(65536, LOG_NOTICE, "%s Received response: %s", stamp, buf);
	}

	dealloc(buf);
	dealloc(socket_dir);
	return 0;
}
