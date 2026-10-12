/*
 * Copyright 2026 Con Kolivas
 *
 * Unit tests for SV2 pre-session idle deadlines (sv2_pre_session_expired):
 *  - incomplete Noise: 10s from accept
 *  - Noise done, no SetupConnection: 60s from accept
 *  - SetupConnection.Success, no channel/token: 60s from Success
 *  - channel/token opened: never
 */

#include "config.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "libckpool.h"
#include "sv2_conn.h"

static int fails;

static void expect(bool cond, const char *msg)
{
	if (!cond) {
		fprintf(stderr, "FAIL: %s\n", msg);
		fails++;
	} else {
		printf("ok: %s\n", msg);
	}
}

int main(void)
{
	int timeout = -1;
	time_t accept = 1000;

	fails = 0;

	expect(!sv2_pre_session_expired(true, 0, false, accept, accept + 10,
					&timeout),
	       "handshake not expired at 10s");
	expect(timeout == SV2_IDLE_HANDSHAKE_TIMEOUT,
	       "handshake timeout is 10s");
	expect(sv2_pre_session_expired(true, 0, false, accept, accept + 11,
				       &timeout),
	       "handshake expired at 11s");

	timeout = -1;
	expect(!sv2_pre_session_expired(false, 0, false, accept, accept + 60,
					&timeout),
	       "pre-SetupConnection not expired at 60s");
	expect(timeout == SV2_IDLE_SETUP_TIMEOUT,
	       "pre-SetupConnection timeout is 60s");
	expect(sv2_pre_session_expired(false, 0, false, accept, accept + 61,
				       &timeout),
	       "pre-SetupConnection expired at 61s");
	expect(!sv2_pre_session_expired(false, 0, false, accept, accept + 11,
					&timeout),
	       "pre-SetupConnection not reaped on handshake clock");

	timeout = -1;
	expect(!sv2_pre_session_expired(false, accept + 50, false, accept,
					accept + 110, &timeout),
	       "post-Success not expired at 60s");
	expect(timeout == SV2_IDLE_CHANNEL_TIMEOUT,
	       "post-Success timeout is 60s from Success");
	expect(sv2_pre_session_expired(false, accept + 50, false, accept,
				       accept + 111, &timeout),
	       "post-Success expired at 61s from Success");
	expect(!sv2_pre_session_expired(false, accept + 50, false, accept,
					accept + 61, &timeout),
	       "post-Success not reaped on accept clock");

	timeout = -1;
	expect(!sv2_pre_session_expired(false, accept + 50, true, accept,
					accept + 10000, &timeout),
	       "open channel/token is never idle-reaped");
	expect(timeout == -1, "established session leaves timeout untouched");

	if (fails) {
		fprintf(stderr, "sv2_idle: %d FAIL\n", fails);
		return 1;
	}
	printf("sv2_idle: all OK\n");
	return 0;
}
