/*
 * Copyright 1995-2014 Andrew Smith
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#include "ckdb.h"

static char *cmd_adduser(PGconn *conn, char *cmd, char *id, tv_t *now, char *by,
			 char *code, char *inet, __maybe_unused tv_t *notcd,
			 K_TREE *trf_root)
{
	char reply[1024] = "";
	size_t siz = sizeof(reply);
	K_ITEM *i_username, *i_emailaddress, *i_passwordhash, *u_item;

	LOGDEBUG("%s(): cmd '%s'", __func__, cmd);

	i_username = require_name(trf_root, "username", 3, (char *)userpatt, reply, siz);
	if (!i_username)
		return strdup(reply);

	i_emailaddress = require_name(trf_root, "emailaddress", 7, (char *)mailpatt, reply, siz);
	if (!i_emailaddress)
		return strdup(reply);

	i_passwordhash = require_name(trf_root, "passwordhash", 64, (char *)hashpatt, reply, siz);
	if (!i_passwordhash)
		return strdup(reply);

	u_item = users_add(conn, transfer_data(i_username),
				 transfer_data(i_emailaddress),
				 transfer_data(i_passwordhash),
				 by, code, inet, now, trf_root);

	if (!u_item) {
		LOGERR("%s() %s.failed.DBE", __func__, id);
		return strdup("failed.DBE");
	}
	LOGDEBUG("%s.ok.added %s", id, transfer_data(i_username));
	snprintf(reply, siz, "ok.added %s", transfer_data(i_username));
	return strdup(reply);
}

static char *cmd_newpass(__maybe_unused PGconn *conn, char *cmd, char *id,
			 tv_t *now, char *by, char *code, char *inet,
			 __maybe_unused tv_t *cd, K_TREE *trf_root)
{
	K_ITEM *i_username, *i_oldhash, *i_newhash, *u_item;
	char reply[1024] = "";
	size_t siz = sizeof(reply);
	bool ok = true;
	char *oldhash;

	LOGDEBUG("%s(): cmd '%s'", __func__, cmd);

	i_username = require_name(trf_root, "username", 3, (char *)userpatt,
				  reply, siz);
	if (!i_username)
		return strdup(reply);

	i_oldhash = optional_name(trf_root, "oldhash", 64, (char *)hashpatt,
				  reply, siz);
	if (i_oldhash)
		oldhash = transfer_data(i_oldhash);
	else {
		// fail if the oldhash is invalid
		if (*reply)
			ok = false;
		oldhash = EMPTY;
	}

	if (ok) {
		i_newhash = require_name(trf_root, "newhash",
					 64, (char *)hashpatt,
					 reply, siz);
		if (!i_newhash)
			return strdup(reply);

		K_RLOCK(users_free);
		u_item = find_users(transfer_data(i_username));
		K_RUNLOCK(users_free);

		if (u_item) {
			ok = users_pass_email(NULL, u_item,
						    oldhash,
						    transfer_data(i_newhash),
						    NULL,
						    by, code, inet, now,
						    trf_root);
		} else
			ok = false;
	}

	if (!ok) {
		LOGERR("%s.failed.%s", id, transfer_data(i_username));
		return strdup("failed.");
	}
	LOGDEBUG("%s.ok.%s", id, transfer_data(i_username));
	return strdup("ok.");
}

static char *cmd_chkpass(__maybe_unused PGconn *conn, char *cmd, char *id,
			 __maybe_unused tv_t *now, __maybe_unused char *by,
			 __maybe_unused char *code, __maybe_unused char *inet,
			 __maybe_unused tv_t *notcd, K_TREE *trf_root)
{
	K_ITEM *i_username, *i_passwordhash, *u_item;
	char reply[1024] = "";
	size_t siz = sizeof(reply);
	USERS *users;
	bool ok;

	LOGDEBUG("%s(): cmd '%s'", __func__, cmd);

	i_username = require_name(trf_root, "username", 3, (char *)userpatt, reply, siz);
	if (!i_username)
		return strdup(reply);

	i_passwordhash = require_name(trf_root, "passwordhash", 64, (char *)hashpatt, reply, siz);
	if (!i_passwordhash)
		return strdup(reply);

	K_RLOCK(users_free);
	u_item = find_users(transfer_data(i_username));
	K_RUNLOCK(users_free);

	if (!u_item)
		ok = false;
	else {
		DATA_USERS(users, u_item);
		ok = check_hash(users, transfer_data(i_passwordhash));
	}

	if (!ok) {
		LOGERR("%s.failed.%s", id, transfer_data(i_username));
		return strdup("failed.");
	}
	LOGDEBUG("%s.ok.%s", id, transfer_data(i_username));
	return strdup("ok.");
}

static char *cmd_userset(PGconn *conn, char *cmd, char *id,
			 __maybe_unused tv_t *now, __maybe_unused char *by,
			 __maybe_unused char *code, __maybe_unused char *inet,
			 __maybe_unused tv_t *notcd, K_TREE *trf_root)
{
	K_ITEM *i_username, *i_passwordhash, *i_address, *i_email, *u_item, *pa_item;
	char *email, *address;
	char reply[1024] = "";
	size_t siz = sizeof(reply);
	char tmp[1024];
	PAYMENTADDRESSES *paymentaddresses;
	USERS *users;
	char *reason = NULL;
	char *answer = NULL;
	size_t len, off;
	bool ok;

	LOGDEBUG("%s(): cmd '%s'", __func__, cmd);

	i_username = require_name(trf_root, "username", 3, (char *)userpatt, reply, siz);
	if (!i_username) {
		// For web this message is detailed enough
		reason = "System error";
		goto struckout;
	}

	K_RLOCK(users_free);
	u_item = find_users(transfer_data(i_username));
	K_RUNLOCK(users_free);

	if (!u_item) {
		reason = "Unknown user";
		goto struckout;
	} else {
		DATA_USERS(users, u_item);
		i_passwordhash = optional_name(trf_root, "passwordhash",
						64, (char *)hashpatt,
						reply, siz);
		if (*reply) {
			reason = "Invalid data";
			goto struckout;
		}

		if (!i_passwordhash) {
			APPEND_REALLOC_INIT(answer, off, len);
			snprintf(tmp, sizeof(tmp), "email=%s%c",
				 users->emailaddress, FLDSEP);
			APPEND_REALLOC(answer, off, len, tmp);

			K_RLOCK(paymentaddresses_free);
			pa_item = find_paymentaddresses(users->userid);
			K_RUNLOCK(paymentaddresses_free);

			if (pa_item) {
				DATA_PAYMENTADDRESSES(paymentaddresses, pa_item);
				snprintf(tmp, sizeof(tmp), "addr=%s",
					 paymentaddresses->payaddress);
				APPEND_REALLOC(answer, off, len, tmp);
			} else {
				snprintf(tmp, sizeof(tmp), "addr=");
				APPEND_REALLOC(answer, off, len, tmp);
			}
		} else {
			if (!check_hash(users, transfer_data(i_passwordhash))) {
				reason = "Incorrect password";
				goto struckout;
			}
			i_email = optional_name(trf_root, "email",
						1, (char *)mailpatt,
						reply, siz);
			if (i_email)
				email = transfer_data(i_email);
			else {
				if (*reply) {
					reason = "Invalid email";
					goto struckout;
				}
				email = NULL;
			}
			i_address = optional_name(trf_root, "address",
						  27, (char *)addrpatt,
						  reply, siz);
			if (i_address)
				address = transfer_data(i_address);
			else {
				if (*reply) {
					reason = "Invalid address";
					goto struckout;
				}
				address = NULL;
			}
			if ((email == NULL || *email == '\0') &&
			    (address == NULL || *address == '\0')) {
				reason = "Missing/Invalid value";
				goto struckout;
			}

			if (address && *address) {
				if (!btc_valid_address(address)) {
					reason = "Invalid BTC address";
					goto struckout;
				}
			}

			if (email && *email) {
				ok = users_pass_email(conn, u_item, NULL,
							    NULL, email,
							    by, code, inet,
							    now, trf_root);
				if (!ok) {
					reason = "email error";
					goto struckout;
				}
			}

			if (address && *address) {
				ok = paymentaddresses_set(conn, users->userid,
								address, by,
								code, inet,
								now, trf_root);
				if (!ok) {
					reason = "address error";
					goto struckout;
				}
			}
			answer = strdup("updated");
		}
	}

struckout:
	if (reason) {
		snprintf(reply, siz, "ERR.%s", reason);
		LOGERR("%s.%s.%s", cmd, id, reply);
		return strdup(reply);
	}
	snprintf(reply, siz, "ok.%s", answer);
	LOGDEBUG("%s.%s", id, answer);
	free(answer);
	return strdup(reply);
}

static char *cmd_workerset(PGconn *conn, char *cmd, char *id, tv_t *now,
			   char *by, char *code, char *inet,
			   __maybe_unused tv_t *notcd, K_TREE *trf_root)
{
	K_ITEM *i_username, *i_workername, *i_diffdef, *u_item, *w_item;
	HEARTBEATQUEUE *heartbeatqueue;
	K_ITEM *hq_item;
	char workername_buf[32]; // 'workername:' + digits
	char diffdef_buf[32]; // 'difficultydefault:' + digits
	char reply[1024] = "";
	size_t siz = sizeof(reply);
	WORKERS *workers;
	USERS *users;
	int32_t difficultydefault;
	char *reason = NULL;
	char *answer = NULL;
	int workernum;
	bool ok;

	LOGDEBUG("%s(): cmd '%s'", __func__, cmd);

	i_username = require_name(trf_root, "username", 3, (char *)userpatt, reply, siz);
	if (!i_username) {
		// For web this message is detailed enough
		reason = "System error";
		goto struckout;
	}

	K_RLOCK(users_free);
	u_item = find_users(transfer_data(i_username));
	K_RUNLOCK(users_free);

	if (!u_item) {
		reason = "Unknown user";
		goto struckout;
	} else {
		DATA_USERS(users, u_item);

		// Default answer if no problems
		answer = strdup("updated");

		// Loop through the list of workers and do any changes
		for (workernum = 0; workernum < 9999; workernum++) {
			snprintf(workername_buf, sizeof(workername_buf),
				 "workername:%d", workernum);

			i_workername = optional_name(trf_root, workername_buf,
							1, NULL, reply, siz);
			if (!i_workername)
				break;

			w_item = find_workers(users->userid,
					      transfer_data(i_workername));
			// Abort if any dont exist
			if (!w_item) {
				reason = "Unknown worker";
				break;
			}

			DATA_WORKERS(workers, w_item);

			snprintf(diffdef_buf, sizeof(diffdef_buf),
				 "difficultydefault:%d", workernum);

			i_diffdef = optional_name(trf_root, diffdef_buf,
						    1, (char *)intpatt,
						    reply, siz);

			// Abort if any are invalid
			if (*reply) {
				reason = "Invalid diff";
				break;
			}

			if (!i_diffdef)
				continue;

			difficultydefault = atoi(transfer_data(i_diffdef));
			if (difficultydefault != 0) {
				if (difficultydefault < DIFFICULTYDEFAULT_MIN)
					difficultydefault = DIFFICULTYDEFAULT_MIN;
				if (difficultydefault > DIFFICULTYDEFAULT_MAX)
					difficultydefault = DIFFICULTYDEFAULT_MAX;
			}

			if (workers->difficultydefault != difficultydefault) {
				/* This uses a seperate txn per update
				    thus will update all up to a failure
				   Since the web then re-gets the values,
				    it will show what was updated */
				workers->difficultydefault = difficultydefault;
				ok = workers_update(conn, w_item, NULL, NULL,
							  NULL, by, code, inet,
							  now, trf_root, false);
				if (!ok) {
					reason = "DB error";
					break;
				}

				/* workerset is not from a log file,
				   so always queue it */
				K_WLOCK(heartbeatqueue_free);
				hq_item = k_unlink_head(heartbeatqueue_free);
				K_WUNLOCK(heartbeatqueue_free);

				DATA_HEARTBEATQUEUE(heartbeatqueue, hq_item);
				STRNCPY(heartbeatqueue->workername, workers->workername);
				heartbeatqueue->difficultydefault = workers->difficultydefault;
				copy_tv(&(heartbeatqueue->createdate), now);

				K_WLOCK(heartbeatqueue_free);
				k_add_tail(heartbeatqueue_store, hq_item);
				K_WUNLOCK(heartbeatqueue_free);
			}
		}
	}

struckout:
	if (reason) {
		if (answer)
			free(answer);
		snprintf(reply, siz, "ERR.%s", reason);
		LOGERR("%s.%s.%s", cmd, id, reply);
		return strdup(reply);
	}
	snprintf(reply, siz, "ok.%s", answer);
	LOGDEBUG("%s.%s", id, answer);
	free(answer);
	return strdup(reply);
}

static char *cmd_poolstats_do(PGconn *conn, char *cmd, char *id, char *by,
			      char *code, char *inet, tv_t *cd, bool igndup,
			      K_TREE *trf_root)
{
	char reply[1024] = "";
	size_t siz = sizeof(reply);
	K_TREE_CTX ctx[1];
	bool store;

	// log to logfile

	K_ITEM *i_poolinstance, *i_elapsed, *i_users, *i_workers;
	K_ITEM *i_hashrate, *i_hashrate5m, *i_hashrate1hr, *i_hashrate24hr;
	K_ITEM look, *ps;
	POOLSTATS row, *poolstats;
	bool ok = false;

	LOGDEBUG("%s(): cmd '%s'", __func__, cmd);

	i_poolinstance = require_name(trf_root, "poolinstance", 1, NULL, reply, siz);
	if (!i_poolinstance)
		return strdup(reply);

	i_elapsed = optional_name(trf_root, "elapsed", 1, NULL, reply, siz);
	if (!i_elapsed)
		i_elapsed = &poolstats_elapsed;

	i_users = require_name(trf_root, "users", 1, NULL, reply, siz);
	if (!i_users)
		return strdup(reply);

	i_workers = require_name(trf_root, "workers", 1, NULL, reply, siz);
	if (!i_workers)
		return strdup(reply);

	i_hashrate = require_name(trf_root, "hashrate", 1, NULL, reply, siz);
	if (!i_hashrate)
		return strdup(reply);

	i_hashrate5m = require_name(trf_root, "hashrate5m", 1, NULL, reply, siz);
	if (!i_hashrate5m)
		return strdup(reply);

	i_hashrate1hr = require_name(trf_root, "hashrate1hr", 1, NULL, reply, siz);
	if (!i_hashrate1hr)
		return strdup(reply);

	i_hashrate24hr = require_name(trf_root, "hashrate24hr", 1, NULL, reply, siz);
	if (!i_hashrate24hr)
		return strdup(reply);

	STRNCPY(row.poolinstance, transfer_data(i_poolinstance));
	row.createdate.tv_sec = date_eot.tv_sec;
	row.createdate.tv_usec = date_eot.tv_usec;
	INIT_POOLSTATS(&look);
	look.data = (void *)(&row);
	ps = find_before_in_ktree(poolstats_root, &look, cmp_poolstats, ctx);
	if (!ps)
		store = true;
	else {
		DATA_POOLSTATS(poolstats, ps);
		// Find last stored matching the poolinstance and less than STATS_PER old
		while (ps && !poolstats->stored &&
		       strcmp(row.poolinstance, poolstats->poolinstance) == 0 &&
		       tvdiff(cd, &(poolstats->createdate)) < STATS_PER) {
				ps = prev_in_ktree(ctx);
				DATA_POOLSTATS_NULL(poolstats, ps);
		}

		if (!ps || !poolstats->stored ||
		    strcmp(row.poolinstance, poolstats->poolinstance) != 0 ||
		    tvdiff(cd, &(poolstats->createdate)) >= STATS_PER)
			store = true;
		else
			store = false;
	}

	ok = poolstats_add(conn, store, transfer_data(i_poolinstance),
					transfer_data(i_elapsed),
					transfer_data(i_users),
					transfer_data(i_workers),
					transfer_data(i_hashrate),
					transfer_data(i_hashrate5m),
					transfer_data(i_hashrate1hr),
					transfer_data(i_hashrate24hr),
					by, code, inet, cd, igndup, trf_root);

	if (!ok) {
		LOGERR("%s() %s.failed.DBE", __func__, id);
		return strdup("failed.DBE");
	}
	LOGDEBUG("%s.ok.", id);
	snprintf(reply, siz, "ok.");
	return strdup(reply);
}

static char *cmd_poolstats(PGconn *conn, char *cmd, char *id,
			   __maybe_unused tv_t *notnow, char *by,
			   char *code, char *inet, tv_t *cd,
			   K_TREE *trf_root)
{
	bool igndup = false;

	// confirm_summaries() doesn't call this
	if (reloading) {
		if (tv_equal(cd, &(dbstatus.newest_createdate_blocks)))
			igndup = true;
		else if (tv_newer(cd, &(dbstatus.newest_createdate_blocks)))
			return NULL;
	}

	return cmd_poolstats_do(conn, cmd, id, by, code, inet, cd, igndup, trf_root);
}

static char *cmd_userstats(__maybe_unused PGconn *conn, char *cmd, char *id,
			   __maybe_unused tv_t *notnow, char *by, char *code,
			   char *inet, tv_t *cd, K_TREE *trf_root)
{
	char reply[1024] = "";
	size_t siz = sizeof(reply);

	// log to logfile

	K_ITEM *i_poolinstance, *i_elapsed, *i_username, *i_workername;
	K_ITEM *i_hashrate, *i_hashrate5m, *i_hashrate1hr, *i_hashrate24hr;
	K_ITEM *i_eos, *i_idle;
	bool ok = false, idle, eos;

	LOGDEBUG("%s(): cmd '%s'", __func__, cmd);

	i_poolinstance = require_name(trf_root, "poolinstance", 1, NULL, reply, siz);
	if (!i_poolinstance)
		return strdup(reply);

	i_elapsed = optional_name(trf_root, "elapsed", 1, NULL, reply, siz);
	if (!i_elapsed)
		i_elapsed = &userstats_elapsed;

	i_username = require_name(trf_root, "username", 1, NULL, reply, siz);
	if (!i_username)
		return strdup(reply);

	i_workername = optional_name(trf_root, "workername", 1, NULL, reply, siz);
	if (!i_workername)
		i_workername = &userstats_workername;

	i_hashrate = require_name(trf_root, "hashrate", 1, NULL, reply, siz);
	if (!i_hashrate)
		return strdup(reply);

	i_hashrate5m = require_name(trf_root, "hashrate5m", 1, NULL, reply, siz);
	if (!i_hashrate5m)
		return strdup(reply);

	i_hashrate1hr = require_name(trf_root, "hashrate1hr", 1, NULL, reply, siz);
	if (!i_hashrate1hr)
		return strdup(reply);

	i_hashrate24hr = require_name(trf_root, "hashrate24hr", 1, NULL, reply, siz);
	if (!i_hashrate24hr)
		return strdup(reply);

	i_idle = optional_name(trf_root, "idle", 1, NULL, reply, siz);
	if (!i_idle)
		i_idle = &userstats_idle;

	idle = (strcasecmp(transfer_data(i_idle), TRUE_STR) == 0);

	i_eos = optional_name(trf_root, "eos", 1, NULL, reply, siz);
	if (!i_eos)
		i_eos = &userstats_eos;

	eos = (strcasecmp(transfer_data(i_eos), TRUE_STR) == 0);

	ok = userstats_add(transfer_data(i_poolinstance),
			   transfer_data(i_elapsed),
			   transfer_data(i_username),
			   transfer_data(i_workername),
			   transfer_data(i_hashrate),
			   transfer_data(i_hashrate5m),
			   transfer_data(i_hashrate1hr),
			   transfer_data(i_hashrate24hr),
			   idle, eos, by, code, inet, cd, trf_root);

	if (!ok) {
		LOGERR("%s() %s.failed.DATA", __func__, id);
		return strdup("failed.DATA");
	}
	LOGDEBUG("%s.ok.", id);
	snprintf(reply, siz, "ok.");
	return strdup(reply);
}

static char *cmd_blocklist(__maybe_unused PGconn *conn, char *cmd, char *id,
			   __maybe_unused tv_t *now, __maybe_unused char *by,
			   __maybe_unused char *code, __maybe_unused char *inet,
			   __maybe_unused tv_t *notcd,
			   __maybe_unused K_TREE *trf_root)
{
	K_TREE_CTX ctx[1];
	K_ITEM *b_item, *w_item;
	BLOCKS *blocks;
	char reply[1024] = "";
	char tmp[1024];
	char *buf;
	size_t len, off;
	int32_t height = -1;
	tv_t first_cd = {0,0};
	int rows;

	LOGDEBUG("%s(): cmd '%s'", __func__, cmd);

	APPEND_REALLOC_INIT(buf, off, len);
	APPEND_REALLOC(buf, off, len, "ok.");
	rows = 0;
	K_RLOCK(blocks_free);
	b_item = last_in_ktree(blocks_root, ctx);
	while (b_item && rows < 42) {
		DATA_BLOCKS(blocks, b_item);
		if (height != blocks->height) {
			height = blocks->height;
			copy_tv(&first_cd, &(blocks->createdate));
		}
		if (CURRENT(&(blocks->expirydate))) {
			int_to_buf(blocks->height, reply, sizeof(reply));
			snprintf(tmp, sizeof(tmp), "height:%d=%s%c", rows, reply, FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);

			str_to_buf(blocks->blockhash, reply, sizeof(reply));
			snprintf(tmp, sizeof(tmp), "blockhash:%d=%s%c", rows, reply, FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);

			str_to_buf(blocks->nonce, reply, sizeof(reply));
			snprintf(tmp, sizeof(tmp), "nonce:%d=%s%c", rows, reply, FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);

			bigint_to_buf(blocks->reward, reply, sizeof(reply));
			snprintf(tmp, sizeof(tmp), "reward:%d=%s%c", rows, reply, FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);

			str_to_buf(blocks->workername, reply, sizeof(reply));
			snprintf(tmp, sizeof(tmp), "workername:%d=%s%c", rows, reply, FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);

			snprintf(tmp, sizeof(tmp),
				 "firstcreatedate:%d=%ld%c", rows,
				 first_cd.tv_sec, FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);

			snprintf(tmp, sizeof(tmp),
				 "createdate:%d=%ld%c", rows,
				 blocks->createdate.tv_sec, FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);

			snprintf(tmp, sizeof(tmp),
				 "status:%d=%s%c", rows,
				 blocks_confirmed(blocks->confirmed), FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);

			double_to_buf(blocks->diffacc, reply, sizeof(reply));
			snprintf(tmp, sizeof(tmp), "diffacc:%d=%s%c", rows, reply, FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);

			double_to_buf(blocks->diffinv, reply, sizeof(reply));
			snprintf(tmp, sizeof(tmp), "diffinv:%d=%s%c", rows, reply, FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);

			double_to_buf(blocks->shareacc, reply, sizeof(reply));
			snprintf(tmp, sizeof(tmp), "shareacc:%d=%s%c", rows, reply, FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);

			double_to_buf(blocks->shareinv, reply, sizeof(reply));
			snprintf(tmp, sizeof(tmp), "shareinv:%d=%s%c", rows, reply, FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);

			bigint_to_buf(blocks->elapsed, reply, sizeof(reply));
			snprintf(tmp, sizeof(tmp), "elapsed:%d=%s%c", rows, reply, FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);

			w_item = find_workinfo(blocks->workinfoid);
			if (w_item) {
					char wdiffbin[TXT_SML+1];
					double wdiff;
					WORKINFO *workinfo;
					DATA_WORKINFO(workinfo, w_item);
					hex2bin(wdiffbin, workinfo->bits, 4);
					wdiff = diff_from_nbits(wdiffbin);
					snprintf(tmp, sizeof(tmp),
						 "netdiff:%d=%.1f%c",
						 rows, wdiff, FLDSEP);
					APPEND_REALLOC(buf, off, len, tmp);
			} else {
				snprintf(tmp, sizeof(tmp),
					 "netdiff:%d=?%c", rows, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);
			}

			rows++;
		}
		b_item = prev_in_ktree(ctx);
	}
	K_RUNLOCK(blocks_free);
	snprintf(tmp, sizeof(tmp),
		 "rows=%d%cflds=%s%c",
		 rows, FLDSEP,
		 "height,blockhash,nonce,reward,workername,firstcreatedate,"
		 "createdate,status,diffacc,diffinv,shareacc,shareinv,elapsed,"
		 "netdiff", FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);

	snprintf(tmp, sizeof(tmp), "arn=%s%carp=%s", "Blocks", FLDSEP, "");
	APPEND_REALLOC(buf, off, len, tmp);

	LOGDEBUG("%s.ok.%d_blocks", id, rows);
	return buf;
}

static char *cmd_blockstatus(__maybe_unused PGconn *conn, char *cmd, char *id,
			     tv_t *now, char *by, char *code, char *inet,
			     __maybe_unused tv_t *cd, K_TREE *trf_root)
{
	K_ITEM *i_height, *i_blockhash, *i_action;
	char reply[1024] = "";
	size_t siz = sizeof(reply);
	K_ITEM *b_item;
	BLOCKS *blocks;
	int32_t height;
	char *action;
	bool ok = false;

	LOGDEBUG("%s(): cmd '%s'", __func__, cmd);

	i_height = require_name(trf_root, "height", 1, NULL, reply, siz);
	if (!i_height)
		return strdup(reply);

	TXT_TO_INT("height", transfer_data(i_height), height);

	i_blockhash = require_name(trf_root, "blockhash", 1, NULL, reply, siz);
	if (!i_blockhash)
		return strdup(reply);

	i_action = require_name(trf_root, "action", 1, NULL, reply, siz);
	if (!i_action)
		return strdup(reply);

	action = transfer_data(i_action);

	K_RLOCK(blocks_free);
	b_item = find_blocks(height, transfer_data(i_blockhash));
	K_RUNLOCK(blocks_free);

	if (!b_item) {
		snprintf(reply, siz, "ERR.unknown block");
		LOGERR("%s.%s", id, reply);
		return strdup(reply);
	}

	DATA_BLOCKS(blocks, b_item);

	if (strcasecmp(action, "orphan") == 0) {
		switch (blocks->confirmed[0]) {
			case BLOCKS_NEW:
			case BLOCKS_CONFIRM:
				ok = blocks_add(conn, transfer_data(i_height),
						      blocks->blockhash,
						      BLOCKS_ORPHAN_STR,
						      EMPTY, EMPTY, EMPTY, EMPTY,
						      EMPTY, EMPTY, EMPTY, EMPTY,
						      by, code, inet, now, false, id,
						      trf_root);
				if (!ok) {
					snprintf(reply, siz,
						 "DBE.action '%s'",
						 action);
					LOGERR("%s.%s", id, reply);
					return strdup(reply);
				}
				// TODO: reset the share counter?
				break;
			default:
				snprintf(reply, siz,
					 "ERR.invalid action '%.*s%s' for block state '%s'",
					 CMD_SIZ, action,
					 (strlen(action) > CMD_SIZ) ? "..." : "",
					 blocks_confirmed(blocks->confirmed));
				LOGERR("%s.%s", id, reply);
				return strdup(reply);
		}
	} else if (strcasecmp(action, "confirm") == 0) {
		// Confirm a new block that wasn't confirmed due to some bug
		switch (blocks->confirmed[0]) {
			case BLOCKS_NEW:
				ok = blocks_add(conn, transfer_data(i_height),
						      blocks->blockhash,
						      BLOCKS_CONFIRM_STR,
						      EMPTY, EMPTY, EMPTY, EMPTY,
						      EMPTY, EMPTY, EMPTY, EMPTY,
						      by, code, inet, now, false, id,
						      trf_root);
				if (!ok) {
					snprintf(reply, siz,
						 "DBE.action '%s'",
						 action);
					LOGERR("%s.%s", id, reply);
					return strdup(reply);
				}
				// TODO: reset the share counter?
				break;
			default:
				snprintf(reply, siz,
					 "ERR.invalid action '%.*s%s' for block state '%s'",
					 CMD_SIZ, action,
					 (strlen(action) > CMD_SIZ) ? "..." : "",
					 blocks_confirmed(blocks->confirmed));
				LOGERR("%s.%s", id, reply);
				return strdup(reply);
		}
	} else {
		snprintf(reply, siz, "ERR.unknown action '%s'",
			 transfer_data(i_action));
		LOGERR("%s.%s", id, reply);
		return strdup(reply);
	}

	snprintf(reply, siz, "ok.%s %d", transfer_data(i_action), height);
	LOGDEBUG("%s.%s", id, reply);
	return strdup(reply);
}

static char *cmd_newid(PGconn *conn, char *cmd, char *id, tv_t *now, char *by,
			char *code, char *inet, __maybe_unused tv_t *cd,
			K_TREE *trf_root)
{
	char reply[1024] = "";
	size_t siz = sizeof(reply);
	K_ITEM *i_idname, *i_idvalue;
	bool ok;

	LOGDEBUG("%s(): cmd '%s'", __func__, cmd);

	i_idname = require_name(trf_root, "idname", 3, (char *)idpatt, reply, siz);
	if (!i_idname)
		return strdup(reply);

	i_idvalue = require_name(trf_root, "idvalue", 1, (char *)intpatt, reply, siz);
	if (!i_idvalue)
		return strdup(reply);

	ok = idcontrol_add(conn, transfer_data(i_idname),
				 transfer_data(i_idvalue),
				 by, code, inet, now, trf_root);

	if (!ok) {
		LOGERR("%s() %s.failed.DBE", __func__, id);
		return strdup("failed.DBE");
	}
	snprintf(reply, siz, "ok.added %s %s",
				transfer_data(i_idname),
				transfer_data(i_idvalue));
	LOGDEBUG("%s.%s", id, reply);
	return strdup(reply);
}

static char *cmd_payments(__maybe_unused PGconn *conn, char *cmd, char *id,
			  __maybe_unused tv_t *now, __maybe_unused char *by,
			  __maybe_unused char *code, __maybe_unused char *inet,
			  __maybe_unused tv_t *notcd,
			  __maybe_unused K_TREE *trf_root)
{
	K_ITEM *i_username, look, *u_item, *p_item;
	K_TREE_CTX ctx[1];
	PAYMENTS lookpayments, *payments;
	USERS *users;
	char reply[1024] = "";
	char tmp[1024];
	size_t siz = sizeof(reply);
	char *buf;
	size_t len, off;
	int rows;

	LOGDEBUG("%s(): cmd '%s'", __func__, cmd);

	i_username = require_name(trf_root, "username", 3, (char *)userpatt, reply, siz);
	if (!i_username)
		return strdup(reply);

	K_RLOCK(users_free);
	u_item = find_users(transfer_data(i_username));
	K_RUNLOCK(users_free);
	if (!u_item)
		return strdup("bad");
	DATA_USERS(users, u_item);

	lookpayments.userid = users->userid;
	lookpayments.paydate.tv_sec = 0;
	lookpayments.paydate.tv_usec = 0;
	INIT_PAYMENTS(&look);
	look.data = (void *)(&lookpayments);
	p_item = find_after_in_ktree(payments_root, &look, cmp_payments, ctx);
	DATA_PAYMENTS_NULL(payments, p_item);
	APPEND_REALLOC_INIT(buf, off, len);
	APPEND_REALLOC(buf, off, len, "ok.");
	rows = 0;
	while (p_item && payments->userid == users->userid) {
		tv_to_buf(&(payments->paydate), reply, sizeof(reply));
		snprintf(tmp, sizeof(tmp), "paydate:%d=%s%c", rows, reply, FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);

		str_to_buf(payments->payaddress, reply, sizeof(reply));
		snprintf(tmp, sizeof(tmp), "payaddress:%d=%s%c", rows, reply, FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);

		bigint_to_buf(payments->amount, reply, sizeof(reply));
		snprintf(tmp, sizeof(tmp), "amount:%d=%s%c", rows, reply, FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);

		rows++;
		p_item = next_in_ktree(ctx);
		DATA_PAYMENTS_NULL(payments, p_item);
	}
	snprintf(tmp, sizeof(tmp), "rows=%d%cflds=%s%c",
		 rows, FLDSEP,
		 "paydate,payaddress,amount", FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);

	snprintf(tmp, sizeof(tmp), "arn=%s%carp=%s", "Payments", FLDSEP, "");
	APPEND_REALLOC(buf, off, len, tmp);

	LOGDEBUG("%s.ok.%s", id, transfer_data(i_username));
	return buf;
}

static char *cmd_workers(__maybe_unused PGconn *conn, char *cmd, char *id,
			 __maybe_unused tv_t *now, __maybe_unused char *by,
			 __maybe_unused char *code, __maybe_unused char *inet,
			 __maybe_unused tv_t *notcd, K_TREE *trf_root)
{
	K_ITEM *i_username, *i_stats, w_look, *u_item, *w_item, us_look, *us_item, *ws_item;
	K_TREE_CTX w_ctx[1], us_ctx[1];
	WORKERS lookworkers, *workers;
	WORKERSTATUS *workerstatus;
	USERSTATS lookuserstats, *userstats;
	USERS *users;
	char reply[1024] = "";
	char tmp[1024];
	size_t siz = sizeof(reply);
	char *buf;
	size_t len, off;
	bool stats;
	int rows;

	LOGDEBUG("%s(): cmd '%s'", __func__, cmd);

	i_username = require_name(trf_root, "username", 3, (char *)userpatt, reply, siz);
	if (!i_username)
		return strdup(reply);

	K_RLOCK(users_free);
	u_item = find_users(transfer_data(i_username));
	K_RUNLOCK(users_free);
	if (!u_item)
		return strdup("bad");
	DATA_USERS(users, u_item);

	i_stats = optional_name(trf_root, "stats", 1, NULL, reply, siz);
	if (!i_stats)
		stats = false;
	else
		stats = (strcasecmp(transfer_data(i_stats), TRUE_STR) == 0);

	INIT_WORKERS(&w_look);
	INIT_USERSTATS(&us_look);

	lookworkers.userid = users->userid;
	lookworkers.workername[0] = '\0';
	lookworkers.expirydate.tv_sec = 0;
	lookworkers.expirydate.tv_usec = 0;
	w_look.data = (void *)(&lookworkers);
	w_item = find_after_in_ktree(workers_root, &w_look, cmp_workers, w_ctx);
	DATA_WORKERS_NULL(workers, w_item);
	APPEND_REALLOC_INIT(buf, off, len);
	APPEND_REALLOC(buf, off, len, "ok.");
	snprintf(tmp, sizeof(tmp), "blockacc=%.1f%c",
				   pool.diffacc, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "blockreward=%"PRId64"%c",
				   pool.reward, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);

	rows = 0;
	while (w_item && workers->userid == users->userid) {
		if (CURRENT(&(workers->expirydate))) {
			str_to_buf(workers->workername, reply, sizeof(reply));
			snprintf(tmp, sizeof(tmp), "workername:%d=%s%c", rows, reply, FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);

			int_to_buf(workers->difficultydefault, reply, sizeof(reply));
			snprintf(tmp, sizeof(tmp), "difficultydefault:%d=%s%c", rows, reply, FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);

			str_to_buf(workers->idlenotificationenabled, reply, sizeof(reply));
			snprintf(tmp, sizeof(tmp), "idlenotificationenabled:%d=%s%c", rows, reply, FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);

			int_to_buf(workers->idlenotificationtime, reply, sizeof(reply));
			snprintf(tmp, sizeof(tmp), "idlenotificationtime:%d=%s%c", rows, reply, FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);

			if (stats) {
				K_TREE *userstats_workername_root = new_ktree();
				K_TREE_CTX usw_ctx[1];
				double w_hashrate5m, w_hashrate1hr;
				double w_hashrate24hr;
				int64_t w_elapsed;
				tv_t w_lastshare;
				double w_lastdiff, w_diffacc, w_diffinv;
				double w_diffsta, w_diffdup;
				double w_diffhi, w_diffrej;
				double w_shareacc, w_shareinv;
				double w_sharesta, w_sharedup;
				double w_sharehi, w_sharerej;

				w_hashrate5m = w_hashrate1hr =
				w_hashrate24hr = 0.0;
				w_elapsed = -1;
				w_lastshare.tv_sec = 0;
				w_lastdiff = w_diffacc = w_diffinv =
				w_diffsta = w_diffdup =
				w_diffhi = w_diffrej =
				w_shareacc = w_shareinv =
				w_sharesta = w_sharedup =
				w_sharehi = w_sharerej = 0;

				ws_item = find_workerstatus(users->userid, workers->workername,
							    __FILE__, __func__, __LINE__);
				if (ws_item) {
					DATA_WORKERSTATUS(workerstatus, ws_item);
					w_lastshare.tv_sec = workerstatus->last_share.tv_sec;
					w_lastdiff = workerstatus->last_diff;
					w_diffacc = workerstatus->diffacc;
					w_diffinv = workerstatus->diffinv;
					w_diffsta = workerstatus->diffsta;
					w_diffdup = workerstatus->diffdup;
					w_diffhi  = workerstatus->diffhi;
					w_diffrej = workerstatus->diffrej;
					w_shareacc = workerstatus->shareacc;
					w_shareinv = workerstatus->shareinv;
					w_sharesta = workerstatus->sharesta;
					w_sharedup = workerstatus->sharedup;
					w_sharehi = workerstatus->sharehi;
					w_sharerej = workerstatus->sharerej;
				}

				// find last stored userid record
				lookuserstats.userid = users->userid;
				lookuserstats.statsdate.tv_sec = date_eot.tv_sec;
				lookuserstats.statsdate.tv_usec = date_eot.tv_usec;
				// find/cmp doesn't get to here
				lookuserstats.poolinstance[0] = '\0';
				lookuserstats.workername[0] = '\0';
				us_look.data = (void *)(&lookuserstats);
				K_RLOCK(userstats_free);
				us_item = find_before_in_ktree(userstats_root, &us_look, cmp_userstats, us_ctx);
				DATA_USERSTATS_NULL(userstats, us_item);
				while (us_item && userstats->userid == lookuserstats.userid) {
					if (strcmp(userstats->workername, workers->workername) == 0) {
						if (tvdiff(now, &(userstats->statsdate)) < USERSTATS_PER_S) {
							// TODO: add together the latest per pool instance (this is the latest per worker)
							if (!find_in_ktree(userstats_workername_root, us_item, cmp_userstats_workername, usw_ctx)) {
								w_hashrate5m += userstats->hashrate5m;
								w_hashrate1hr += userstats->hashrate1hr;
								w_hashrate24hr += userstats->hashrate24hr;
								if (w_elapsed == -1 || w_elapsed > userstats->elapsed)
									w_elapsed = userstats->elapsed;

								userstats_workername_root = add_to_ktree(userstats_workername_root,
													 us_item,
													 cmp_userstats_workername);
							}
						} else
							break;

					}
					us_item = prev_in_ktree(us_ctx);
					DATA_USERSTATS_NULL(userstats, us_item);
				}

				double_to_buf(w_hashrate5m, reply, sizeof(reply));
				snprintf(tmp, sizeof(tmp), "w_hashrate5m:%d=%s%c", rows, reply, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);

				double_to_buf(w_hashrate1hr, reply, sizeof(reply));
				snprintf(tmp, sizeof(tmp), "w_hashrate1hr:%d=%s%c", rows, reply, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);

				double_to_buf(w_hashrate24hr, reply, sizeof(reply));
				snprintf(tmp, sizeof(tmp), "w_hashrate24hr:%d=%s%c", rows, reply, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);

				bigint_to_buf(w_elapsed, reply, sizeof(reply));
				snprintf(tmp, sizeof(tmp), "w_elapsed:%d=%s%c", rows, reply, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);

				int_to_buf((int)(w_lastshare.tv_sec), reply, sizeof(reply));
				snprintf(tmp, sizeof(tmp), "w_lastshare:%d=%s%c", rows, reply, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);

				double_to_buf(w_lastdiff, reply, sizeof(reply));
				snprintf(tmp, sizeof(tmp), "w_lastdiff:%d=%s%c", rows, reply, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);

				double_to_buf(w_diffacc, reply, sizeof(reply));
				snprintf(tmp, sizeof(tmp), "w_diffacc:%d=%s%c", rows, reply, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);

				double_to_buf(w_diffinv, reply, sizeof(reply));
				snprintf(tmp, sizeof(tmp), "w_diffinv:%d=%s%c", rows, reply, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);

				double_to_buf(w_diffsta, reply, sizeof(reply));
				snprintf(tmp, sizeof(tmp), "w_diffsta:%d=%s%c", rows, reply, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);

				double_to_buf(w_diffdup, reply, sizeof(reply));
				snprintf(tmp, sizeof(tmp), "w_diffdup:%d=%s%c", rows, reply, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);

				double_to_buf(w_diffhi, reply, sizeof(reply));
				snprintf(tmp, sizeof(tmp), "w_diffhi:%d=%s%c", rows, reply, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);

				double_to_buf(w_diffrej, reply, sizeof(reply));
				snprintf(tmp, sizeof(tmp), "w_diffrej:%d=%s%c", rows, reply, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);

				double_to_buf(w_shareacc, reply, sizeof(reply));
				snprintf(tmp, sizeof(tmp), "w_shareacc:%d=%s%c", rows, reply, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);

				double_to_buf(w_shareinv, reply, sizeof(reply));
				snprintf(tmp, sizeof(tmp), "w_shareinv:%d=%s%c", rows, reply, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);

				double_to_buf(w_sharesta, reply, sizeof(reply));
				snprintf(tmp, sizeof(tmp), "w_sharesta:%d=%s%c", rows, reply, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);

				double_to_buf(w_sharedup, reply, sizeof(reply));
				snprintf(tmp, sizeof(tmp), "w_sharedup:%d=%s%c", rows, reply, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);

				double_to_buf(w_sharehi, reply, sizeof(reply));
				snprintf(tmp, sizeof(tmp), "w_sharehi:%d=%s%c", rows, reply, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);

				double_to_buf(w_sharerej, reply, sizeof(reply));
				snprintf(tmp, sizeof(tmp), "w_sharerej:%d=%s%c", rows, reply, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);

				userstats_workername_root = free_ktree(userstats_workername_root, NULL);
				K_RUNLOCK(userstats_free);
			}

			rows++;
		}
		w_item = next_in_ktree(w_ctx);
		DATA_WORKERS_NULL(workers, w_item);
	}
	snprintf(tmp, sizeof(tmp),
		 "rows=%d%cflds=%s%s%c",
		 rows, FLDSEP,
		 "workername,difficultydefault,idlenotificationenabled,"
		 "idlenotificationtime",
		 stats ? ",w_hashrate5m,w_hashrate1hr,w_hashrate24hr,"
		 "w_elapsed,w_lastshare,"
		 "w_lastdiff,w_diffacc,w_diffinv,"
		 "w_diffsta,w_diffdup,w_diffhi,w_diffrej,"
		 "w_shareacc,w_shareinv,"
		 "w_sharesta,w_sharedup,w_sharehi,w_sharerej" : "",
		 FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);

	snprintf(tmp, sizeof(tmp), "arn=%s%carp=%s", "Workers", FLDSEP, "");
	APPEND_REALLOC(buf, off, len, tmp);

	LOGDEBUG("%s.ok.%s", id, transfer_data(i_username));
	return buf;
}

static char *cmd_allusers(__maybe_unused PGconn *conn, char *cmd, char *id,
			  __maybe_unused tv_t *now, __maybe_unused char *by,
			  __maybe_unused char *code, __maybe_unused char *inet,
			  __maybe_unused tv_t *notcd,
			  __maybe_unused K_TREE *trf_root)
{
	K_TREE *userstats_workername_root = new_ktree();
	K_ITEM *us_item, *usw_item, *tmp_item, *u_item;
	K_TREE_CTX us_ctx[1], usw_ctx[1];
	USERSTATS *userstats, *userstats_w;
	USERS *users;
	char reply[1024] = "";
	char tmp[1024];
	char *buf;
	size_t len, off;
	int rows;
	int64_t userid = -1;
	double u_hashrate5m = 0.0;
	double u_hashrate1hr = 0.0;

	LOGDEBUG("%s(): cmd '%s'", __func__, cmd);

	// TODO: this really should just get the last value of each client_id (within the time limit)

	// Find last records for each user/worker in ALLUSERS_LIMIT_S
	// TODO: include pool_instance
	K_WLOCK(userstats_free);
	us_item = last_in_ktree(userstats_statsdate_root, us_ctx);
	DATA_USERSTATS_NULL(userstats, us_item);
	while (us_item && tvdiff(now, &(userstats->statsdate)) < ALLUSERS_LIMIT_S) {
		usw_item = find_in_ktree(userstats_workername_root, us_item, cmp_userstats_workername, usw_ctx);
		if (!usw_item) {
			usw_item = k_unlink_head(userstats_free);
			DATA_USERSTATS(userstats_w, usw_item);

			userstats_w->userid = userstats->userid;
			strcpy(userstats_w->workername, userstats->workername);
			userstats_w->hashrate5m = userstats->hashrate5m;
			userstats_w->hashrate1hr = userstats->hashrate1hr;

			userstats_workername_root = add_to_ktree(userstats_workername_root, usw_item, cmp_userstats_workername);
		}
		us_item = prev_in_ktree(us_ctx);
		DATA_USERSTATS_NULL(userstats, us_item);
	}

	APPEND_REALLOC_INIT(buf, off, len);
	APPEND_REALLOC(buf, off, len, "ok.");
	rows = 0;
	// Add up per user
	usw_item = first_in_ktree(userstats_workername_root, usw_ctx);
	while (usw_item) {
		DATA_USERSTATS(userstats_w, usw_item);
		if (userstats_w->userid != userid) {
			if (userid != -1) {
				K_RLOCK(users_free);
				u_item = find_userid(userid);
				K_RUNLOCK(users_free);
				if (!u_item) {
					LOGERR("%s() userid %"PRId64" ignored - userstats but not users",
					       __func__, userid);
				} else {
					DATA_USERS(users, u_item);
					str_to_buf(users->username, reply, sizeof(reply));
					snprintf(tmp, sizeof(tmp), "username:%d=%s%c", rows, reply, FLDSEP);
					APPEND_REALLOC(buf, off, len, tmp);

					bigint_to_buf(userid, reply, sizeof(reply));
					snprintf(tmp, sizeof(tmp), "userid:%d=%s%c", rows, reply, FLDSEP);
					APPEND_REALLOC(buf, off, len, tmp);

					double_to_buf(u_hashrate5m, reply, sizeof(reply));
					snprintf(tmp, sizeof(tmp), "u_hashrate5m:%d=%s%c", rows, reply, FLDSEP);
					APPEND_REALLOC(buf, off, len, tmp);

					double_to_buf(u_hashrate1hr, reply, sizeof(reply));
					snprintf(tmp, sizeof(tmp), "u_hashrate1hr:%d=%s%c", rows, reply, FLDSEP);
					APPEND_REALLOC(buf, off, len, tmp);

					rows++;
				}
			}
			userid = userstats_w->userid;
			u_hashrate5m = 0;
			u_hashrate1hr = 0;
		}
		u_hashrate5m += userstats_w->hashrate5m;
		u_hashrate1hr += userstats_w->hashrate1hr;

		tmp_item = usw_item;
		usw_item = next_in_ktree(usw_ctx);

		k_add_head(userstats_free, tmp_item);
	}
	if (userid != -1) {
		K_RLOCK(users_free);
		u_item = find_userid(userid);
		K_RUNLOCK(users_free);
		if (!u_item) {
			LOGERR("%s() userid %"PRId64" ignored - userstats but not users",
			       __func__, userid);
		} else {
			DATA_USERS(users, u_item);
			str_to_buf(users->username, reply, sizeof(reply));
			snprintf(tmp, sizeof(tmp), "username:%d=%s%c", rows, reply, FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);

			bigint_to_buf(userid, reply, sizeof(reply));
			snprintf(tmp, sizeof(tmp), "userid:%d=%s%c", rows, reply, FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);

			double_to_buf(u_hashrate5m, reply, sizeof(reply));
			snprintf(tmp, sizeof(tmp), "u_hashrate5m:%d=%s%c", rows, reply, FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);

			double_to_buf(u_hashrate1hr, reply, sizeof(reply));
			snprintf(tmp, sizeof(tmp), "u_hashrate1hr:%d=%s%c", rows, reply, FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);

			rows++;
		}
	}

	userstats_workername_root = free_ktree(userstats_workername_root, NULL);
	K_WUNLOCK(userstats_free);

	snprintf(tmp, sizeof(tmp),
		 "rows=%d%cflds=%s%c",
		 rows, FLDSEP,
		 "username,userid,u_hashrate5m,u_hashrate1hr", FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);

	snprintf(tmp, sizeof(tmp), "arn=%s%carp=%s", "Users", FLDSEP, "");
	APPEND_REALLOC(buf, off, len, tmp);

	LOGDEBUG("%s.ok.allusers", id);
	return buf;
}

static char *cmd_sharelog(PGconn *conn, char *cmd, char *id,
				__maybe_unused tv_t *notnow, char *by,
				char *code, char *inet, tv_t *cd,
				K_TREE *trf_root)
{
	char reply[1024] = "";
	size_t siz = sizeof(reply);
	int64_t workinfoid;

	// log to logfile with processing success/failure code

	LOGDEBUG("%s(): cmd '%s'", __func__, cmd);

	if (strcasecmp(cmd, STR_WORKINFO) == 0) {
		K_ITEM *i_workinfoid, *i_poolinstance, *i_transactiontree, *i_merklehash;
		K_ITEM *i_prevhash, *i_coinbase1, *i_coinbase2, *i_version, *i_bits;
		K_ITEM *i_ntime, *i_reward;
		bool igndup = false;

		if (reloading && !confirm_sharesummary) {
			if (tv_equal(cd, &(dbstatus.newest_createdate_workinfo)))
				igndup = true;
			else if (tv_newer(cd, &(dbstatus.newest_createdate_workinfo)))
				return NULL;
		}

		i_workinfoid = require_name(trf_root, "workinfoid", 1, NULL, reply, siz);
		if (!i_workinfoid)
			return strdup(reply);

		if (confirm_sharesummary) {
			TXT_TO_BIGINT("workinfoid", transfer_data(i_workinfoid), workinfoid);

			if (workinfoid < confirm_first_workinfoid ||
			    workinfoid > confirm_last_workinfoid)
				goto wiconf;
		}

		i_poolinstance = require_name(trf_root, "poolinstance", 1, NULL, reply, siz);
		if (!i_poolinstance)
			return strdup(reply);

		i_transactiontree = require_name(trf_root, "transactiontree", 0, NULL, reply, siz);
		if (!i_transactiontree)
			return strdup(reply);

		i_merklehash = require_name(trf_root, "merklehash", 0, NULL, reply, siz);
		if (!i_merklehash)
			return strdup(reply);

		i_prevhash = require_name(trf_root, "prevhash", 1, NULL, reply, siz);
		if (!i_prevhash)
			return strdup(reply);

		i_coinbase1 = require_name(trf_root, "coinbase1", 1, NULL, reply, siz);
		if (!i_coinbase1)
			return strdup(reply);

		i_coinbase2 = require_name(trf_root, "coinbase2", 1, NULL, reply, siz);
		if (!i_coinbase2)
			return strdup(reply);

		i_version = require_name(trf_root, "version", 1, NULL, reply, siz);
		if (!i_version)
			return strdup(reply);

		i_bits = require_name(trf_root, "bits", 1, NULL, reply, siz);
		if (!i_bits)
			return strdup(reply);

		i_ntime = require_name(trf_root, "ntime", 1, NULL, reply, siz);
		if (!i_ntime)
			return strdup(reply);

		i_reward = require_name(trf_root, "reward", 1, NULL, reply, siz);
		if (!i_reward)
			return strdup(reply);

		workinfoid = workinfo_add(conn, transfer_data(i_workinfoid),
						transfer_data(i_poolinstance),
						transfer_data(i_transactiontree),
						transfer_data(i_merklehash),
						transfer_data(i_prevhash),
						transfer_data(i_coinbase1),
						transfer_data(i_coinbase2),
						transfer_data(i_version),
						transfer_data(i_bits),
						transfer_data(i_ntime),
						transfer_data(i_reward),
						by, code, inet, cd, igndup, trf_root);

		if (workinfoid == -1) {
			LOGERR("%s(%s) %s.failed.DBE", __func__, cmd, id);
			return strdup("failed.DBE");
		}
		LOGDEBUG("%s.ok.added %"PRId64, id, workinfoid);
wiconf:
		snprintf(reply, siz, "ok.%"PRId64, workinfoid);
		return strdup(reply);
	} else if (strcasecmp(cmd, STR_SHARES) == 0) {
		K_ITEM *i_workinfoid, *i_username, *i_workername, *i_clientid, *i_errn;
		K_ITEM *i_enonce1, *i_nonce2, *i_nonce, *i_diff, *i_sdiff;
		K_ITEM *i_secondaryuserid;
		bool ok;

		// This just excludes the shares we certainly don't need
		if (reloading && !confirm_sharesummary) {
			if (tv_newer(cd, &(dbstatus.sharesummary_firstshare)))
				return NULL;
		}

		i_nonce = require_name(trf_root, "nonce", 1, NULL, reply, siz);
		if (!i_nonce)
			return strdup(reply);

		i_workinfoid = require_name(trf_root, "workinfoid", 1, NULL, reply, siz);
		if (!i_workinfoid)
			return strdup(reply);

		if (confirm_sharesummary) {
			TXT_TO_BIGINT("workinfoid", transfer_data(i_workinfoid), workinfoid);

			if (workinfoid < confirm_first_workinfoid ||
			    workinfoid > confirm_last_workinfoid)
				goto sconf;
		}

		i_username = require_name(trf_root, "username", 1, NULL, reply, siz);
		if (!i_username)
			return strdup(reply);

		i_workername = require_name(trf_root, "workername", 1, NULL, reply, siz);
		if (!i_workername)
			return strdup(reply);

		i_clientid = require_name(trf_root, "clientid", 1, NULL, reply, siz);
		if (!i_clientid)
			return strdup(reply);

		i_errn = require_name(trf_root, "errn", 1, NULL, reply, siz);
		if (!i_errn)
			return strdup(reply);

		i_enonce1 = require_name(trf_root, "enonce1", 1, NULL, reply, siz);
		if (!i_enonce1)
			return strdup(reply);

		i_nonce2 = require_name(trf_root, "nonce2", 1, NULL, reply, siz);
		if (!i_nonce2)
			return strdup(reply);

		i_diff = require_name(trf_root, "diff", 1, NULL, reply, siz);
		if (!i_diff)
			return strdup(reply);

		i_sdiff = require_name(trf_root, "sdiff", 1, NULL, reply, siz);
		if (!i_sdiff)
			return strdup(reply);

		i_secondaryuserid = optional_name(trf_root, "secondaryuserid",
						  1, NULL, reply, siz);
		if (!i_secondaryuserid)
			i_secondaryuserid = &shares_secondaryuserid;

		ok = shares_add(conn, transfer_data(i_workinfoid),
				      transfer_data(i_username),
				      transfer_data(i_workername),
				      transfer_data(i_clientid),
				      transfer_data(i_errn),
				      transfer_data(i_enonce1),
				      transfer_data(i_nonce2),
				      transfer_data(i_nonce),
				      transfer_data(i_diff),
				      transfer_data(i_sdiff),
				      transfer_data(i_secondaryuserid),
				      by, code, inet, cd, trf_root);

		if (!ok) {
			LOGERR("%s(%s) %s.failed.DATA", __func__, cmd, id);
			return strdup("failed.DATA");
		}
		LOGDEBUG("%s.ok.added %s", id, transfer_data(i_nonce));
sconf:
		snprintf(reply, siz, "ok.added %s", transfer_data(i_nonce));
		return strdup(reply);
	} else if (strcasecmp(cmd, STR_SHAREERRORS) == 0) {
		K_ITEM *i_workinfoid, *i_username, *i_workername, *i_clientid, *i_errn;
		K_ITEM *i_error, *i_secondaryuserid;
		bool ok;

		// This just excludes the shareerrors we certainly don't need
		if (reloading && !confirm_sharesummary) {
			if (tv_newer(cd, &(dbstatus.sharesummary_firstshare)))
				return NULL;
		}

		i_username = require_name(trf_root, "username", 1, NULL, reply, siz);
		if (!i_username)
			return strdup(reply);

		i_workinfoid = require_name(trf_root, "workinfoid", 1, NULL, reply, siz);
		if (!i_workinfoid)
			return strdup(reply);

		if (confirm_sharesummary) {
			TXT_TO_BIGINT("workinfoid", transfer_data(i_workinfoid), workinfoid);

			if (workinfoid < confirm_first_workinfoid ||
			    workinfoid > confirm_last_workinfoid)
				goto seconf;
		}

		i_workername = require_name(trf_root, "workername", 1, NULL, reply, siz);
		if (!i_workername)
			return strdup(reply);

		i_clientid = require_name(trf_root, "clientid", 1, NULL, reply, siz);
		if (!i_clientid)
			return strdup(reply);

		i_errn = require_name(trf_root, "errn", 1, NULL, reply, siz);
		if (!i_errn)
			return strdup(reply);

		i_error = require_name(trf_root, "error", 1, NULL, reply, siz);
		if (!i_error)
			return strdup(reply);

		i_secondaryuserid = optional_name(trf_root, "secondaryuserid",
						  1, NULL, reply, siz);
		if (!i_secondaryuserid)
			i_secondaryuserid = &shareerrors_secondaryuserid;

		ok = shareerrors_add(conn, transfer_data(i_workinfoid),
					   transfer_data(i_username),
					   transfer_data(i_workername),
					   transfer_data(i_clientid),
					   transfer_data(i_errn),
					   transfer_data(i_error),
					   transfer_data(i_secondaryuserid),
					   by, code, inet, cd, trf_root);
		if (!ok) {
			LOGERR("%s(%s) %s.failed.DATA", __func__, cmd, id);
			return strdup("failed.DATA");
		}
		LOGDEBUG("%s.ok.added %s", id, transfer_data(i_username));
seconf:
		snprintf(reply, siz, "ok.added %s", transfer_data(i_username));
		return strdup(reply);
	} else if (strcasecmp(cmd, STR_AGEWORKINFO) == 0) {
		K_ITEM *i_workinfoid, *i_poolinstance;
		int64_t ss_count, s_count, s_diff;
		tv_t ss_first, ss_last;
		bool ok;

		if (reloading && !confirm_sharesummary) {
			if (tv_newer(cd, &(dbstatus.sharesummary_firstshare)))
				return NULL;
		}

		i_workinfoid = require_name(trf_root, "workinfoid", 1, NULL, reply, siz);
		if (!i_workinfoid)
			return strdup(reply);

		if (confirm_sharesummary) {
			TXT_TO_BIGINT("workinfoid", transfer_data(i_workinfoid), workinfoid);

			if (workinfoid < confirm_first_workinfoid ||
			    workinfoid > confirm_last_workinfoid)
				goto awconf;
		}

		i_poolinstance = require_name(trf_root, "poolinstance", 1, NULL, reply, siz);
		if (!i_poolinstance)
			return strdup(reply);

		TXT_TO_BIGINT("workinfoid", transfer_data(i_workinfoid), workinfoid);

		ok = workinfo_age(conn, workinfoid,
					transfer_data(i_poolinstance),
					by, code, inet, cd,
					&ss_first, &ss_last,
					&ss_count, &s_count, &s_diff);

		if (!ok) {
			LOGERR("%s(%s) %s.failed.DATA", __func__, cmd, id);
			return strdup("failed.DATA");
		} else {
			/* Don't slow down the reload - do them later
			 * N.B. this means if you abort/shutdown the reload,
			 * next restart will again go back to the oldest
			 * unaged sharesummary due to a pool shutdown */
			if (!reloading) {
				// Aging is a queued item thus the reply is ignored
				auto_age_older(conn, workinfoid,
						     transfer_data(i_poolinstance),
						     by, code, inet, cd);
			}
		}
		LOGDEBUG("%s.ok.aged %"PRId64, id, workinfoid);
awconf:
		snprintf(reply, siz, "ok.%"PRId64, workinfoid);
		return strdup(reply);
	}

	LOGERR("%s.bad.cmd %s", cmd);
	return strdup("bad.cmd");
}

// TODO: the confirm update: identify block changes from workinfo height?
static char *cmd_blocks_do(PGconn *conn, char *cmd, char *id, char *by,
			   char *code, char *inet, tv_t *cd, bool igndup,
			   K_TREE *trf_root)
{
	char reply[1024] = "";
	size_t siz = sizeof(reply);
	K_ITEM *i_height, *i_blockhash, *i_confirmed, *i_workinfoid, *i_username;
	K_ITEM *i_workername, *i_clientid, *i_enonce1, *i_nonce2, *i_nonce, *i_reward;
	TRANSFER *transfer;
	char *msg;
	bool ok;

	LOGDEBUG("%s(): cmd '%s'", __func__, cmd);

	i_height = require_name(trf_root, "height", 1, NULL, reply, siz);
	if (!i_height)
		return strdup(reply);

	i_blockhash = require_name(trf_root, "blockhash", 1, NULL, reply, siz);
	if (!i_blockhash)
		return strdup(reply);

	i_confirmed = require_name(trf_root, "confirmed", 1, NULL, reply, siz);
	if (!i_confirmed)
		return strdup(reply);

	DATA_TRANSFER(transfer, i_confirmed);
	transfer->mvalue[0] = tolower(transfer->mvalue[0]);
	switch(transfer->mvalue[0]) {
		case BLOCKS_NEW:
			i_workinfoid = require_name(trf_root, "workinfoid", 1, NULL, reply, siz);
			if (!i_workinfoid)
				return strdup(reply);

			i_username = require_name(trf_root, "username", 1, NULL, reply, siz);
			if (!i_username)
				return strdup(reply);

			i_workername = require_name(trf_root, "workername", 1, NULL, reply, siz);
			if (!i_workername)
				return strdup(reply);

			i_clientid = require_name(trf_root, "clientid", 1, NULL, reply, siz);
			if (!i_clientid)
				return strdup(reply);

			i_enonce1 = require_name(trf_root, "enonce1", 1, NULL, reply, siz);
			if (!i_enonce1)
				return strdup(reply);

			i_nonce2 = require_name(trf_root, "nonce2", 1, NULL, reply, siz);
			if (!i_nonce2)
				return strdup(reply);

			i_nonce = require_name(trf_root, "nonce", 1, NULL, reply, siz);
			if (!i_nonce)
				return strdup(reply);

			i_reward = require_name(trf_root, "reward", 1, NULL, reply, siz);
			if (!i_reward)
				return strdup(reply);

			msg = "added";
			ok = blocks_add(conn, transfer_data(i_height),
					      transfer_data(i_blockhash),
					      transfer_data(i_confirmed),
					      transfer_data(i_workinfoid),
					      transfer_data(i_username),
					      transfer_data(i_workername),
					      transfer_data(i_clientid),
					      transfer_data(i_enonce1),
					      transfer_data(i_nonce2),
					      transfer_data(i_nonce),
					      transfer_data(i_reward),
					      by, code, inet, cd, igndup, id,
					      trf_root);
			break;
		case BLOCKS_CONFIRM:
			msg = "confirmed";
			ok = blocks_add(conn, transfer_data(i_height),
					      transfer_data(i_blockhash),
					      transfer_data(i_confirmed),
					      EMPTY, EMPTY, EMPTY, EMPTY,
					      EMPTY, EMPTY, EMPTY, EMPTY,
					      by, code, inet, cd, igndup, id,
					      trf_root);
			break;
		default:
			LOGERR("%s(): %s.failed.invalid confirm='%s'",
			       __func__, id, transfer_data(i_confirmed));
			return strdup("failed.DATA");
	}

	if (!ok) {
		/* Ignore during startup,
		 * another error should have shown if it matters */
		if (startup_complete)
			LOGERR("%s() %s.failed.DBE", __func__, id);
		return strdup("failed.DBE");
	}

	LOGDEBUG("%s.ok.blocks %s", id, msg);
	snprintf(reply, siz, "ok.%s", msg);
	return strdup(reply);
}

static char *cmd_blocks(PGconn *conn, char *cmd, char *id,
			__maybe_unused tv_t *notnow, char *by,
			char *code, char *inet, tv_t *cd,
			K_TREE *trf_root)
{
	bool igndup = false;

	// confirm_summaries() doesn't call this
	if (reloading) {
		if (tv_equal(cd, &(dbstatus.newest_createdate_blocks)))
			igndup = true;
		else if (tv_newer(cd, &(dbstatus.newest_createdate_blocks)))
			return NULL;
	}

	return cmd_blocks_do(conn, cmd, id, by, code, inet, cd, igndup, trf_root);
}

static char *cmd_auth_do(PGconn *conn, char *cmd, char *id, char *by,
				char *code, char *inet, tv_t *cd, bool igndup,
				K_TREE *trf_root)
{
	char reply[1024] = "";
	size_t siz = sizeof(reply);
	K_ITEM *i_poolinstance, *i_username, *i_workername, *i_clientid;
	K_ITEM *i_enonce1, *i_useragent, *i_preauth;
	USERS *users = NULL;
	WORKERS *workers = NULL;
	bool ok;

	LOGDEBUG("%s(): cmd '%s'", __func__, cmd);

	i_poolinstance = optional_name(trf_root, "poolinstance", 1, NULL,
					reply, siz);
	if (!i_poolinstance)
		i_poolinstance = &auth_poolinstance;

	i_username = require_name(trf_root, "username", 1, NULL, reply, siz);
	if (!i_username)
		return strdup(reply);

	i_workername = require_name(trf_root, "workername", 1, NULL, reply, siz);
	if (!i_workername)
		return strdup(reply);

	i_clientid = require_name(trf_root, "clientid", 1, NULL, reply, siz);
	if (!i_clientid)
		return strdup(reply);

	i_enonce1 = require_name(trf_root, "enonce1", 1, NULL, reply, siz);
	if (!i_enonce1)
		return strdup(reply);

	i_useragent = require_name(trf_root, "useragent", 0, NULL, reply, siz);
	if (!i_useragent)
		return strdup(reply);

	i_preauth = optional_name(trf_root, "preauth", 1, NULL, reply, siz);
	if (!i_preauth)
		i_preauth = &auth_preauth;

	ok = auths_add(conn, transfer_data(i_poolinstance),
			     transfer_data(i_username),
			     transfer_data(i_workername),
			     transfer_data(i_clientid),
			     transfer_data(i_enonce1),
			     transfer_data(i_useragent),
			     transfer_data(i_preauth),
			     by, code, inet, cd, igndup, trf_root, false,
			     &users, &workers);

	if (!ok) {
		LOGDEBUG("%s() %s.failed.DBE", __func__, id);
		return strdup("failed.DBE");
	}

	snprintf(reply, siz,
		 "ok.authorise={\"secondaryuserid\":\"%s\","
		 "\"difficultydefault\":%d}",
		 users->secondaryuserid, workers->difficultydefault);
	LOGDEBUG("%s.%s", id, reply);
	return strdup(reply);
}

static char *cmd_auth(PGconn *conn, char *cmd, char *id,
			__maybe_unused tv_t *now, char *by,
			char *code, char *inet, tv_t *cd,
			K_TREE *trf_root)
{
	bool igndup = false;

	// confirm_summaries() doesn't call this
	if (reloading) {
		if (tv_equal(cd, &(dbstatus.newest_createdate_auths)))
			igndup = true;
		else if (tv_newer(cd, &(dbstatus.newest_createdate_auths)))
			return NULL;
	}

	return cmd_auth_do(conn, cmd, id, by, code, inet, cd, igndup, trf_root);
}

static char *cmd_addrauth_do(PGconn *conn, char *cmd, char *id, char *by,
				char *code, char *inet, tv_t *cd, bool igndup,
				K_TREE *trf_root)
{
	char reply[1024] = "";
	size_t siz = sizeof(reply);
	K_ITEM *i_poolinstance, *i_username, *i_workername, *i_clientid;
	K_ITEM *i_enonce1, *i_useragent, *i_preauth;
	USERS *users = NULL;
	WORKERS *workers = NULL;
	bool ok;

	LOGDEBUG("%s(): cmd '%s'", __func__, cmd);

	i_poolinstance = optional_name(trf_root, "poolinstance", 1, NULL,
					reply, siz);
	if (!i_poolinstance)
		i_poolinstance = &auth_poolinstance;

	i_username = require_name(trf_root, "username", 1, NULL, reply, siz);
	if (!i_username)
		return strdup(reply);

	i_workername = require_name(trf_root, "workername", 1, NULL, reply, siz);
	if (!i_workername)
		return strdup(reply);

	i_clientid = require_name(trf_root, "clientid", 1, NULL, reply, siz);
	if (!i_clientid)
		return strdup(reply);

	i_enonce1 = require_name(trf_root, "enonce1", 1, NULL, reply, siz);
	if (!i_enonce1)
		return strdup(reply);

	i_useragent = require_name(trf_root, "useragent", 0, NULL, reply, siz);
	if (!i_useragent)
		return strdup(reply);

	i_preauth = require_name(trf_root, "preauth", 1, NULL, reply, siz);
	if (!i_preauth)
		return strdup(reply);

	ok = auths_add(conn, transfer_data(i_poolinstance),
			     transfer_data(i_username),
			     transfer_data(i_workername),
			     transfer_data(i_clientid),
			     transfer_data(i_enonce1),
			     transfer_data(i_useragent),
			     transfer_data(i_preauth),
			     by, code, inet, cd, igndup, trf_root, true,
			     &users, &workers);

	if (!ok) {
		LOGDEBUG("%s() %s.failed.DBE", __func__, id);
		return strdup("failed.DBE");
	}

	snprintf(reply, siz,
		 "ok.addrauth={\"secondaryuserid\":\"%s\","
		 "\"difficultydefault\":%d}",
		 users->secondaryuserid, workers->difficultydefault);
	LOGDEBUG("%s.%s", id, reply);
	return strdup(reply);
}

static char *cmd_addrauth(PGconn *conn, char *cmd, char *id,
			__maybe_unused tv_t *now, char *by,
			char *code, char *inet, tv_t *cd,
			K_TREE *trf_root)
{
	bool igndup = false;

	// confirm_summaries() doesn't call this
	if (reloading) {
		if (tv_equal(cd, &(dbstatus.newest_createdate_auths)))
			igndup = true;
		else if (tv_newer(cd, &(dbstatus.newest_createdate_auths)))
			return NULL;
	}

	return cmd_addrauth_do(conn, cmd, id, by, code, inet, cd, igndup, trf_root);
}

static char *cmd_heartbeat(__maybe_unused PGconn *conn, char *cmd, char *id,
			   __maybe_unused tv_t *now, __maybe_unused char *by,
			   __maybe_unused char *code, __maybe_unused char *inet,
			   __maybe_unused tv_t *cd,
			   __maybe_unused K_TREE *trf_root)
{
	HEARTBEATQUEUE *heartbeatqueue;
	K_STORE *hq_store;
	K_ITEM *hq_item;
	char reply[1024], tmp[1024], *buf;
	size_t siz = sizeof(reply);
	size_t len, off;
	bool first;

	// Wait until startup is complete, we get a heartbeat every second
	if (!startup_complete)
		goto pulse;

	K_WLOCK(heartbeatqueue_free);
	if (heartbeatqueue_store->count == 0) {
		K_WUNLOCK(heartbeatqueue_free);
		goto pulse;
	}

	hq_store = k_new_store(heartbeatqueue_free);
	k_list_transfer_to_head(heartbeatqueue_store, hq_store);
	K_WUNLOCK(heartbeatqueue_free);

	APPEND_REALLOC_INIT(buf, off, len);
	APPEND_REALLOC(buf, off, len, "ok.heartbeat={\"diffchange\":[");
	hq_item = hq_store->tail;
	first = true;
	while (hq_item) {
		DATA_HEARTBEATQUEUE(heartbeatqueue, hq_item);
		tvs_to_buf(&last_bc, reply, siz);
		snprintf(tmp, sizeof(tmp),
			 "%s{\"workername\":\"%s\","
			 "\"difficultydefault\":%d,"
			 "\"createdate\":\"%ld,%ld\"}",
			 first ? "" : ",",
			 heartbeatqueue->workername,
			 heartbeatqueue->difficultydefault,
			 heartbeatqueue->createdate.tv_sec,
			 heartbeatqueue->createdate.tv_usec);
		APPEND_REALLOC(buf, off, len, tmp);
		hq_item = hq_item->prev;
		first = false;
	}
	APPEND_REALLOC(buf, off, len, "]}");

	K_WLOCK(heartbeatqueue_free);
	k_list_transfer_to_head(hq_store, heartbeatqueue_free);
	K_WUNLOCK(heartbeatqueue_free);
	hq_store = k_free_store(hq_store);

	LOGDEBUG("%s.%s.%s", cmd, id, buf);
	return buf;
pulse:
	snprintf(reply, siz, "ok.pulse");
	LOGDEBUG("%s.%s.%s", cmd, id, reply);
	return strdup(reply);
}

static char *cmd_homepage(__maybe_unused PGconn *conn, char *cmd, char *id,
			  __maybe_unused tv_t *now, __maybe_unused char *by,
			  __maybe_unused char *code, __maybe_unused char *inet,
			  __maybe_unused tv_t *notcd, K_TREE *trf_root)
{
	K_ITEM *i_username, *u_item, *b_item, *p_item, *us_item, look;
	double u_hashrate5m, u_hashrate1hr;
	char reply[1024], tmp[1024], *buf;
	size_t siz = sizeof(reply);
	USERSTATS lookuserstats, *userstats;
	POOLSTATS *poolstats;
	BLOCKS *blocks;
	USERS *users;
	int64_t u_elapsed;
	K_TREE_CTX ctx[1], w_ctx[1];
	size_t len, off;
	bool has_uhr;

	LOGDEBUG("%s(): cmd '%s'", __func__, cmd);

	i_username = optional_name(trf_root, "username", 1, NULL, reply, siz);

	APPEND_REALLOC_INIT(buf, off, len);
	APPEND_REALLOC(buf, off, len, "ok.");
	if (last_bc.tv_sec) {
		tvs_to_buf(&last_bc, reply, siz);
		snprintf(tmp, sizeof(tmp), "lastbc=%s%c", reply, FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);
		K_RLOCK(workinfo_free);
		if (workinfo_current) {
			WORKINFO *wic;
			int32_t hi;
			DATA_WORKINFO(wic, workinfo_current);
			hi = coinbase1height(wic->coinbase1);
			snprintf(tmp, sizeof(tmp), "lastheight=%d%c",
						   hi-1, FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);
		} else {
			snprintf(tmp, sizeof(tmp), "lastheight=?%c", FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);
		}
		K_RUNLOCK(workinfo_free);
	} else {
		snprintf(tmp, sizeof(tmp), "lastbc=?%clastheight=?%c",
					   FLDSEP, FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);
	}

	if (current_ndiff) {
		snprintf(tmp, sizeof(tmp), "currndiff=%.1f%c", current_ndiff, FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);
	} else {
		snprintf(tmp, sizeof(tmp), "currndiff=?%c", FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);
	}

	// TODO: handle orphans
	K_RLOCK(blocks_free);
	b_item = last_in_ktree(blocks_root, ctx);
	K_RUNLOCK(blocks_free);
	if (b_item) {
		DATA_BLOCKS(blocks, b_item);
		tvs_to_buf(&(blocks->createdate), reply, siz);
		snprintf(tmp, sizeof(tmp), "lastblock=%s%cconfirmed=%s%c",
					   reply, FLDSEP,
					   blocks->confirmed, FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);
		snprintf(tmp, sizeof(tmp), "lastblockheight=%d%c",
					   blocks->height, FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);
	} else {
		snprintf(tmp, sizeof(tmp), "lastblock=?%cconfirmed=?%c"
					   "lastblockheight=?%c",
					   FLDSEP, FLDSEP, FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);
	}


	snprintf(tmp, sizeof(tmp), "blockacc=%.1f%c",
				   pool.diffacc, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);

	snprintf(tmp, sizeof(tmp), "blockerr=%.1f%c",
				   pool.diffinv, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);

	snprintf(tmp, sizeof(tmp), "blockshareacc=%.1f%c",
				   pool.shareacc, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);

	snprintf(tmp, sizeof(tmp), "blockshareinv=%.1f%c",
				   pool.shareinv, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);

	// TODO: assumes only one poolinstance (for now)
	p_item = last_in_ktree(poolstats_root, ctx);
	if (p_item) {
		DATA_POOLSTATS(poolstats, p_item);
		int_to_buf(poolstats->users, reply, siz);
		snprintf(tmp, sizeof(tmp), "users=%s%c", reply, FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);

		int_to_buf(poolstats->workers, reply, siz);
		snprintf(tmp, sizeof(tmp), "workers=%s%c", reply, FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);

		double_to_buf(poolstats->hashrate, reply, siz);
		snprintf(tmp, sizeof(tmp), "p_hashrate=%s%c", reply, FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);

		double_to_buf(poolstats->hashrate5m, reply, siz);
		snprintf(tmp, sizeof(tmp), "p_hashrate5m=%s%c", reply, FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);

		double_to_buf(poolstats->hashrate1hr, reply, siz);
		snprintf(tmp, sizeof(tmp), "p_hashrate1hr=%s%c", reply, FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);

		double_to_buf(poolstats->hashrate24hr, reply, siz);
		snprintf(tmp, sizeof(tmp), "p_hashrate24hr=%s%c", reply, FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);

		bigint_to_buf(poolstats->elapsed, reply, siz);
		snprintf(tmp, sizeof(tmp), "p_elapsed=%s%c", reply, FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);

		tvs_to_buf(&(poolstats->createdate), reply, siz);
		snprintf(tmp, sizeof(tmp), "p_statsdate=%s%c", reply, FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);
	} else {
		snprintf(tmp, sizeof(tmp), "users=?%cworkers=?%cp_hashrate=?%c"
					   "p_hashrate5m=?%cp_hashrate1hr=?%c"
					   "p_hashrate24hr=?%cp_elapsed=?%c"
					   "p_statsdate=?%c",
					   FLDSEP, FLDSEP, FLDSEP, FLDSEP,
					   FLDSEP, FLDSEP, FLDSEP, FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);
	}

	u_item = NULL;
	if (i_username) {
		K_RLOCK(users_free);
		u_item = find_users(transfer_data(i_username));
		K_RUNLOCK(users_free);
	}

	has_uhr = false;
	if (p_item && u_item) {
		DATA_USERS(users, u_item);
		K_TREE *userstats_workername_root = new_ktree();
		u_hashrate5m = u_hashrate1hr = 0.0;
		u_elapsed = -1;
		// find last stored userid record
		lookuserstats.userid = users->userid;
		lookuserstats.statsdate.tv_sec = date_eot.tv_sec;
		lookuserstats.statsdate.tv_usec = date_eot.tv_usec;
		// find/cmp doesn't get to here
		STRNCPY(lookuserstats.poolinstance, EMPTY);
		STRNCPY(lookuserstats.workername, EMPTY);
		INIT_USERSTATS(&look);
		look.data = (void *)(&lookuserstats);
		K_RLOCK(userstats_free);
		us_item = find_before_in_ktree(userstats_root, &look, cmp_userstats, ctx);
		DATA_USERSTATS_NULL(userstats, us_item);
		while (us_item && userstats->userid == lookuserstats.userid &&
		       tvdiff(now, &(userstats->statsdate)) < USERSTATS_PER_S) {
			// TODO: add the latest per pool instance (this is the latest per worker)
			// Ignore summarised data from the DB, it should be old so irrelevant
			if (userstats->poolinstance[0] &&
			    !find_in_ktree(userstats_workername_root, us_item, cmp_userstats_workername, w_ctx)) {
				u_hashrate5m += userstats->hashrate5m;
				u_hashrate1hr += userstats->hashrate1hr;
				if (u_elapsed == -1 || u_elapsed > userstats->elapsed)
					u_elapsed = userstats->elapsed;
				has_uhr = true;
				userstats_workername_root = add_to_ktree(userstats_workername_root,
									 us_item,
									 cmp_userstats_workername);
			}
			us_item = prev_in_ktree(ctx);
			DATA_USERSTATS_NULL(userstats, us_item);
		}
		userstats_workername_root = free_ktree(userstats_workername_root, NULL);
		K_RUNLOCK(userstats_free);
	}

	if (has_uhr) {
		double_to_buf(u_hashrate5m, reply, siz);
		snprintf(tmp, sizeof(tmp), "u_hashrate5m=%s%c", reply, FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);

		double_to_buf(u_hashrate1hr, reply, siz);
		snprintf(tmp, sizeof(tmp), "u_hashrate1hr=%s%c", reply, FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);

		bigint_to_buf(u_elapsed, reply, siz);
		snprintf(tmp, sizeof(tmp), "u_elapsed=%s", reply);
		APPEND_REALLOC(buf, off, len, tmp);
	} else {
		snprintf(tmp, sizeof(tmp), "u_hashrate5m=?%cu_hashrate1hr=?%cu_elapsed=?",
					   FLDSEP, FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);
	}

	LOGDEBUG("%s.ok.home,user=%s", id,
		 i_username ? transfer_data(i_username): "N");
	return buf;
}

/* Return the list of useratts for the given username=value
 * Format is attlist=attname.element,attname.element,...
 * Replies will be attname.element=value
 * The 2 date fields, date and date2, have a secondary element name
 *  dateexp and date2exp
 *  This will return Y or N depending upon if the date has expired as:
 *   attname.dateexp=N (or Y) and attname.date2exp=N (or Y)
 *  Expired means the date is <= now
 */
static char *cmd_getatts(__maybe_unused PGconn *conn, char *cmd, char *id,
			 tv_t *now, __maybe_unused char *by,
			 __maybe_unused char *code, __maybe_unused char *inet,
			 __maybe_unused tv_t *notcd, K_TREE *trf_root)
{
	K_ITEM *i_username, *i_attlist, *u_item, *ua_item;
	char reply[1024] = "";
	size_t siz = sizeof(reply);
	char tmp[1024];
	USERATTS *useratts;
	USERS *users;
	char *reason = NULL;
	char *answer = NULL;
	char *attlist = NULL, *ptr, *comma, *dot;
	size_t len, off;
	bool first;

	LOGDEBUG("%s(): cmd '%s'", __func__, cmd);

	i_username = require_name(trf_root, "username", 3, (char *)userpatt, reply, siz);
	if (!i_username) {
		reason = "Missing username";
		goto nuts;
	}

	K_RLOCK(users_free);
	u_item = find_users(transfer_data(i_username));
	K_RUNLOCK(users_free);

	if (!u_item) {
		reason = "Unknown user";
		goto nuts;
	} else {
		DATA_USERS(users, u_item);
		i_attlist = require_name(trf_root, "attlist", 1, NULL, reply, siz);
		if (!i_attlist) {
			reason = "Missing attlist";
			goto nuts;
		}

		APPEND_REALLOC_INIT(answer, off, len);
		attlist = ptr = strdup(transfer_data(i_attlist));
		first = true;
		while (ptr && *ptr) {
			comma = strchr(ptr, ',');
			if (comma)
				*(comma++) = '\0';
			dot = strchr(ptr, '.');
			if (!dot) {
				reason = "Missing element";
				goto nuts;
			}
			*(dot++) = '\0';
			K_RLOCK(useratts_free);
			ua_item = find_useratts(users->userid, ptr);
			K_RUNLOCK(useratts_free);
			/* web code must check the existance of the attname
			 * in the reply since it will be missing if it doesn't
			 * exist in the DB */
			if (ua_item) {
				char num_buf[BIGINT_BUFSIZ];
				char ctv_buf[CDATE_BUFSIZ];
				char *ans;
				DATA_USERATTS(useratts, ua_item);
				if (strcmp(dot, "str") == 0) {
					ans = useratts->attstr;
				} else if (strcmp(dot, "str2") == 0) {
					ans = useratts->attstr2;
				} else if (strcmp(dot, "num") == 0) {
					bigint_to_buf(useratts->attnum,
						      num_buf,
						      sizeof(num_buf));
					ans = num_buf;
				} else if (strcmp(dot, "num2") == 0) {
					bigint_to_buf(useratts->attnum2,
						      num_buf,
						      sizeof(num_buf));
					ans = num_buf;
				} else if (strcmp(dot, "date") == 0) {
					ctv_to_buf(&(useratts->attdate),
						   ctv_buf,
						   sizeof(num_buf));
					ans = ctv_buf;
				} else if (strcmp(dot, "dateexp") == 0) {
					// Y/N if date is <= now (expired)
					if (tv_newer(&(useratts->attdate), now))
						ans = TRUE_STR;
					else
						ans = FALSE_STR;
				} else if (strcmp(dot, "date2") == 0) {
					ctv_to_buf(&(useratts->attdate2),
						   ctv_buf,
						   sizeof(num_buf));
					ans = ctv_buf;
				} else if (strcmp(dot, "date2exp") == 0) {
					// Y/N if date2 is <= now (expired)
					if (tv_newer(&(useratts->attdate2), now))
						ans = TRUE_STR;
					else
						ans = FALSE_STR;
				} else {
					reason = "Unknown element";
					goto nuts;
				}
				snprintf(tmp, sizeof(tmp), "%s%s.%s=%s",
					 first ? EMPTY : FLDSEPSTR,
					 ptr, dot, ans);
				APPEND_REALLOC(answer, off, len, tmp);
				first = false;
			}
			ptr = comma;
		}
	}
nuts:
	if (attlist)
		free(attlist);

	if (reason) {
		if (answer)
			free(answer);
		snprintf(reply, siz, "ERR.%s", reason);
		LOGERR("%s.%s.%s", cmd, id, reply);
		return strdup(reply);
	}
	snprintf(reply, siz, "ok.%s", answer);
	LOGDEBUG("%s.%s", id, answer);
	free(answer);
	return strdup(reply);
}

static void att_to_date(tv_t *date, char *data, tv_t *now)
{
	int add;

	if (strncasecmp(data, "now+", 4) == 0) {
		add = atoi(data+4);
		copy_tv(date, now);
		date->tv_sec += add;
	} else if (strcasecmp(data, "now") == 0) {
		copy_tv(date, now);
	} else {
		txt_to_ctv("date", data, date, sizeof(*date));
	}
}

/* Store useratts in the DB for the given username=value
 * Format is 1 or more: ua_attname.element=value
 *  i.e. each starts with the constant "ua_"
 * attname cannot contain Tab . or =
 * element is per the coded list below, which also cannot contain Tab . or =
 * Any matching useratts attnames found currently in the DB are expired
 * Transfer will sort them so that any of the same attname
 *  will be next to each other
 *  thus will combine multiple elements for the same attname
 *  into one single useratts record (as is mandatory)
 * The 2 date fields date and date2 require either epoch values sec,usec
 *  (usec is optional and defaults to 0) or one of: now or now+NNN
 *  now is the current epoch value and now+NNN is the epoch + NNN seconds
 *  See att_to_date() above
 *  */
static char *cmd_setatts(PGconn *conn, char *cmd, char *id,
			 tv_t *now, char *by, char *code, char *inet,
			 __maybe_unused tv_t *notcd, K_TREE *trf_root)
{
	ExecStatusType rescode;
	PGresult *res;
	bool conned = false;
	K_ITEM *i_username, *t_item, *u_item, *ua_item = NULL;
	K_TREE_CTX ctx[1];
	char reply[1024] = "";
	size_t siz = sizeof(reply);
	TRANSFER *transfer;
	USERATTS *useratts = NULL;
	USERS *users;
	char attname[sizeof(useratts->attname)*2];
	char *reason = NULL;
	char *dot, *data;
	bool begun = false;
	int set = 0, db = 0;

	LOGDEBUG("%s(): cmd '%s'", __func__, cmd);

	i_username = require_name(trf_root, "username", 3, (char *)userpatt, reply, siz);
	if (!i_username) {
		reason = "Missing user";
		goto bats;
	}

	K_RLOCK(users_free);
	u_item = find_users(transfer_data(i_username));
	K_RUNLOCK(users_free);

	if (!u_item) {
		reason = "Unknown user";
		goto bats;
	} else {
		DATA_USERS(users, u_item);
		t_item = first_in_ktree(trf_root, ctx);
		while (t_item) {
			DATA_TRANSFER(transfer, t_item);
			if (strncmp(transfer->name, "ua_", 3) == 0) {
				data = transfer_data(t_item);
				STRNCPY(attname, transfer->name + 3);
				dot = strchr(attname, '.');
				if (!dot) {
					reason = "Missing element";
					goto bats;
				}
				*(dot++) = '\0';
				// If we already had a different one, save it to the DB
				if (ua_item && strcmp(useratts->attname, attname) != 0) {
					if (conn == NULL) {
						conn = dbconnect();
						conned = true;
					}
					if (!begun) {
						// Beginning of a write txn
						res = PQexec(conn, "Begin", CKPQ_WRITE);
						rescode = PQresultStatus(res);
						PQclear(res);
						if (!PGOK(rescode)) {
							PGLOGERR("Begin", rescode, conn);
							reason = "DBERR";
							goto bats;
						}
						begun = true;
					}
					if (useratts_item_add(conn, ua_item, now, begun)) {
						ua_item = NULL;
						db++;
					} else {
						reason = "DBERR";
						goto rollback;
					}
				}
				if (!ua_item) {
					K_RLOCK(useratts_free);
					ua_item = k_unlink_head(useratts_free);
					K_RUNLOCK(useratts_free);
					DATA_USERATTS(useratts, ua_item);
					bzero(useratts, sizeof(*useratts));
					useratts->userid = users->userid;
					STRNCPY(useratts->attname, attname);
					HISTORYDATEINIT(useratts, now, by, code, inet);
					HISTORYDATETRANSFER(trf_root, useratts);
				}
				// List of valid element names for storage
				if (strcmp(dot, "str") == 0) {
					STRNCPY(useratts->attstr, data);
					set++;
				} else if (strcmp(dot, "str2") == 0) {
					STRNCPY(useratts->attstr2, data);
					set++;
				} else if (strcmp(dot, "num") == 0) {
					TXT_TO_BIGINT("num", data, useratts->attnum);
					set++;
				} else if (strcmp(dot, "num2") == 0) {
					TXT_TO_BIGINT("num2", data, useratts->attnum2);
					set++;
				} else if (strcmp(dot, "date") == 0) {
					att_to_date(&(useratts->attdate), data, now);
					set++;
				} else if (strcmp(dot, "date2") == 0) {
					att_to_date(&(useratts->attdate2), data, now);
					set++;
				} else {
					reason = "Unknown element";
					goto bats;
				}
			}
			t_item = next_in_ktree(ctx);
		}
		if (ua_item) {
			if (conn == NULL) {
				conn = dbconnect();
				conned = true;
			}
			if (!begun) {
				// Beginning of a write txn
				res = PQexec(conn, "Begin", CKPQ_WRITE);
				rescode = PQresultStatus(res);
				PQclear(res);
				if (!PGOK(rescode)) {
					PGLOGERR("Begin", rescode, conn);
					reason = "DBERR";
					goto bats;
				}
				begun = true;
			}
			if (!useratts_item_add(conn, ua_item, now, begun)) {
				reason = "DBERR";
				goto rollback;
			}
			db++;
		}
	}
rollback:
	if (!reason)
		res = PQexec(conn, "Commit", CKPQ_WRITE);
	else
		res = PQexec(conn, "Rollback", CKPQ_WRITE);

	PQclear(res);
bats:
	if (conned)
		PQfinish(conn);
	if (reason) {
		if (ua_item) {
			K_WLOCK(useratts_free);
			k_add_head(useratts_free, ua_item);
			K_WUNLOCK(useratts_free);
		}
		snprintf(reply, siz, "ERR.%s", reason);
		LOGERR("%s.%s.%s", cmd, id, reply);
		return strdup(reply);
	}
	snprintf(reply, siz, "ok.set %d,%d", db, set);
	LOGDEBUG("%s.%s", id, reply);
	return strdup(reply);
}

/* Expire the list of useratts for the given username=value
 * Format is attlist=attname,attname,...
 * Each matching DB attname record will have it's expirydate set to now
 *  thus an attempt to access it with getatts will not find it and
 *  return nothing for that attname
 */
static char *cmd_expatts(__maybe_unused PGconn *conn, char *cmd, char *id,
			 tv_t *now, __maybe_unused char *by,
			 __maybe_unused char *code, __maybe_unused char *inet,
			 __maybe_unused tv_t *notcd, K_TREE *trf_root)
{
	K_ITEM *i_username, *i_attlist, *u_item, *ua_item;
	char reply[1024] = "";
	size_t siz = sizeof(reply);
	USERATTS *useratts;
	USERS *users;
	char *reason = NULL;
	char *attlist, *ptr, *comma;
	int db = 0, mis = 0;

	LOGDEBUG("%s(): cmd '%s'", __func__, cmd);

	i_username = require_name(trf_root, "username", 3, (char *)userpatt, reply, siz);
	if (!i_username) {
		reason = "Missing username";
		goto rats;
	}

	K_RLOCK(users_free);
	u_item = find_users(transfer_data(i_username));
	K_RUNLOCK(users_free);

	if (!u_item) {
		reason = "Unknown user";
		goto rats;
	} else {
		DATA_USERS(users, u_item);
		i_attlist = require_name(trf_root, "attlist", 1, NULL, reply, siz);
		if (!i_attlist) {
			reason = "Missing attlist";
			goto rats;
		}

		attlist = ptr = strdup(transfer_data(i_attlist));
		while (ptr && *ptr) {
			comma = strchr(ptr, ',');
			if (comma)
				*(comma++) = '\0';
			K_RLOCK(useratts_free);
			ua_item = find_useratts(users->userid, ptr);
			K_RUNLOCK(useratts_free);
			if (!ua_item)
				mis++;
			else {
				DATA_USERATTS(useratts, ua_item);
				HISTORYDATEINIT(useratts, now, by, code, inet);
				HISTORYDATETRANSFER(trf_root, useratts);
				/* Since we are expiring records, don't bother
				 *  with combining them all into a single
				 *  transaction and don't abort on error
				 * Thus if an error is returned, retry would be
				 *  necessary, but some may also have been
				 *  expired successfully */
				if (!useratts_item_expire(conn, ua_item, now))
					reason = "DBERR";
				else
					db++;
			}
			ptr = comma;
		}
		free(attlist);
	}
rats:
	if (reason) {
		snprintf(reply, siz, "ERR.%s", reason);
		LOGERR("%s.%s.%s", cmd, id, reply);
		return strdup(reply);
	}
	snprintf(reply, siz, "ok.exp %d,%d", db, mis);
	LOGDEBUG("%s.%s.%s", cmd, id, reply);
	return strdup(reply);
}

/* Return the list of optioncontrols
 * Format is optlist=optionname,optionname,optionname,...
 * Replies will be optionname=value
 * Any optionnames not in the DB or not yet active will be missing
 */
static char *cmd_getopts(__maybe_unused PGconn *conn, char *cmd, char *id,
			 tv_t *now, __maybe_unused char *by,
			 __maybe_unused char *code, __maybe_unused char *inet,
			 __maybe_unused tv_t *notcd, K_TREE *trf_root)
{
	K_ITEM *i_optlist, *oc_item;
	char reply[1024] = "";
	size_t siz = sizeof(reply);
	char tmp[1024];
	OPTIONCONTROL *optioncontrol;
	char *reason = NULL;
	char *answer = NULL;
	char *optlist = NULL, *ptr, *comma;
	size_t len, off;
	bool first;

	LOGDEBUG("%s(): cmd '%s'", __func__, cmd);

	i_optlist = require_name(trf_root, "optlist", 1, NULL, reply, siz);
	if (!i_optlist) {
		reason = "Missing optlist";
		goto ruts;
	}

	APPEND_REALLOC_INIT(answer, off, len);
	optlist = ptr = strdup(transfer_data(i_optlist));
	first = true;
	while (ptr && *ptr) {
		comma = strchr(ptr, ',');
		if (comma)
			*(comma++) = '\0';
		K_RLOCK(optioncontrol_free);
		oc_item = find_optioncontrol(ptr, now);
		K_RUNLOCK(optioncontrol_free);
		/* web code must check the existance of the optionname
		 * in the reply since it will be missing if it doesn't
		 * exist in the DB */
		if (oc_item) {
			DATA_OPTIONCONTROL(optioncontrol, oc_item);
			snprintf(tmp, sizeof(tmp), "%s%s=%s",
				 first ? EMPTY : FLDSEPSTR,
				 optioncontrol->optionname,
				 optioncontrol->optionvalue);
			APPEND_REALLOC(answer, off, len, tmp);
			first = false;
		}
		ptr = comma;
	}
ruts:
	if (optlist)
		free(optlist);

	if (reason) {
		if (answer)
			free(answer);
		snprintf(reply, siz, "ERR.%s", reason);
		LOGERR("%s.%s.%s", cmd, id, reply);
		return strdup(reply);
	}
	snprintf(reply, siz, "ok.%s", answer);
	LOGDEBUG("%s.%s", id, answer);
	free(answer);
	return strdup(reply);
}

// This is the same as att_set_date() for now
#define opt_set_date(_date, _data, _now) att_set_date(_date, _data, _now)

/* Store optioncontrols in the DB
 * Format is 1 or more: oc_optionname.fld=value
 *  i.e. each starts with the constant "oc_"
 * optionname cannot contain Tab . or =
 * fld is one of the 3: value, date, height
 * value must exist
 * None, one or both of date and height can exist
 * If a matching optioncontrol (same name, date and height) exists,
 *  it will have it's expiry date set to now and be replaced with the new value
 * The date field requires either an epoch sec,usec
 *  (usec is optional and defaults to 0) or one of: now or now+NNN
 *  now is the current epoch value and now+NNN is the epoch + NNN seconds
 *  See opt_set_date() above */
static char *cmd_setopts(PGconn *conn, char *cmd, char *id,
			 tv_t *now, char *by, char *code, char *inet,
			 __maybe_unused tv_t *notcd, K_TREE *trf_root)
{
	ExecStatusType rescode;
	PGresult *res;
	bool conned = false;
	K_ITEM *t_item, *oc_item = NULL;
	K_TREE_CTX ctx[1];
	char reply[1024] = "";
	size_t siz = sizeof(reply);
	TRANSFER *transfer;
	OPTIONCONTROL *optioncontrol;
	char optionname[sizeof(optioncontrol->optionname)*2];
	char *reason = NULL;
	char *dot, *data;
	bool begun = false, gotvalue = false;
	int db = 0;

	LOGDEBUG("%s(): cmd '%s'", __func__, cmd);

	t_item = first_in_ktree(trf_root, ctx);
	while (t_item) {
		DATA_TRANSFER(transfer, t_item);
		if (strncmp(transfer->name, "oc_", 3) == 0) {
			data = transfer_data(t_item);
			STRNCPY(optionname, transfer->name + 3);
			dot = strchr(optionname, '.');
			if (!dot) {
				reason = "Missing field";
				goto rollback;
			}
			*(dot++) = '\0';
			// If we already had a different one, save it to the DB
			if (oc_item && strcmp(optioncontrol->optionname, optionname) != 0) {
				if (!gotvalue) {
					reason = "Missing value";
					goto rollback;
				}
				if (conn == NULL) {
					conn = dbconnect();
					conned = true;
				}
				if (!begun) {
					// Beginning of a write txn
					res = PQexec(conn, "Begin", CKPQ_WRITE);
					rescode = PQresultStatus(res);
					PQclear(res);
					if (!PGOK(rescode)) {
						PGLOGERR("Begin", rescode, conn);
						reason = "DBERR";
						goto rollback;
					}
					begun = true;
				}
				if (optioncontrol_item_add(conn, oc_item, now, begun)) {
					oc_item = NULL;
					db++;
				} else {
					reason = "DBERR";
					goto rollback;
				}
			}
			if (!oc_item) {
				K_RLOCK(optioncontrol_free);
				oc_item = k_unlink_head(optioncontrol_free);
				K_RUNLOCK(optioncontrol_free);
				DATA_OPTIONCONTROL(optioncontrol, oc_item);
				bzero(optioncontrol, sizeof(*optioncontrol));
				STRNCPY(optioncontrol->optionname, optionname);
				optioncontrol->activationheight = OPTIONCONTROL_HEIGHT;
				HISTORYDATEINIT(optioncontrol, now, by, code, inet);
				HISTORYDATETRANSFER(trf_root, optioncontrol);
				gotvalue = false;
			}
			if (strcmp(dot, "value") == 0) {
				optioncontrol->optionvalue = strdup(data);
				if (!(optioncontrol->optionvalue))
					quithere(1, "malloc (%d) OOM", (int)strlen(data));
				gotvalue = true;
			} else if (strcmp(dot, "date") == 0) {
				att_to_date(&(optioncontrol->activationdate), data, now);
			} else if (strcmp(dot, "height") == 0) {
				TXT_TO_INT("height", data, optioncontrol->activationheight);
			} else {
				reason = "Unknown field";
				goto rollback;
			}
		}
		t_item = next_in_ktree(ctx);
	}
	if (oc_item) {
		if (!gotvalue) {
			reason = "Missing value";
			goto rollback;
		}
		if (conn == NULL) {
			conn = dbconnect();
			conned = true;
		}
		if (!begun) {
			// Beginning of a write txn
			res = PQexec(conn, "Begin", CKPQ_WRITE);
			rescode = PQresultStatus(res);
			PQclear(res);
			if (!PGOK(rescode)) {
				PGLOGERR("Begin", rescode, conn);
				reason = "DBERR";
				goto rollback;
			}
			begun = true;
		}
		if (!optioncontrol_item_add(conn, oc_item, now, begun)) {
			reason = "DBERR";
			goto rollback;
		}
		db++;
	}
rollback:
	if (begun) {
		if (reason)
			res = PQexec(conn, "Rollback", CKPQ_WRITE);
		else
			res = PQexec(conn, "Commit", CKPQ_WRITE);

		PQclear(res);
	}

	if (conned)
		PQfinish(conn);
	if (reason) {
		if (oc_item) {
			if (optioncontrol->optionvalue)
				free(optioncontrol->optionvalue);
			K_WLOCK(optioncontrol_free);
			k_add_head(optioncontrol_free, oc_item);
			K_WUNLOCK(optioncontrol_free);
		}
		snprintf(reply, siz, "ERR.%s", reason);
		LOGERR("%s.%s.%s", cmd, id, reply);
		return strdup(reply);
	}
	snprintf(reply, siz, "ok.set %d", db);
	LOGDEBUG("%s.%s", id, reply);
	return strdup(reply);
}

// order by userid asc
static cmp_t cmp_mu(K_ITEM *a, K_ITEM *b)
{
	MININGPAYOUTS *ma, *mb;
	DATA_MININGPAYOUTS(ma, a);
	DATA_MININGPAYOUTS(mb, b);
	return CMP_BIGINT(ma->userid, mb->userid);
}

static K_TREE *upd_add_mu(K_TREE *mu_root, K_STORE *mu_store, int64_t userid, int64_t diffacc)
{
	MININGPAYOUTS lookminingpayouts, *miningpayouts;
	K_ITEM look, *mu_item;
	K_TREE_CTX ctx[1];

	lookminingpayouts.userid = userid;
	INIT_MININGPAYOUTS(&look);
	look.data = (void *)(&lookminingpayouts);
	mu_item = find_in_ktree(mu_root, &look, cmp_mu, ctx);
	if (mu_item) {
		DATA_MININGPAYOUTS(miningpayouts, mu_item);
		miningpayouts->amount += diffacc;
	} else {
		K_WLOCK(mu_store);
		mu_item = k_unlink_head(miningpayouts_free);
		DATA_MININGPAYOUTS(miningpayouts, mu_item);
		miningpayouts->userid = userid;
		miningpayouts->amount = diffacc;
		mu_root = add_to_ktree(mu_root, mu_item, cmp_mu);
		k_add_head(mu_store, mu_item);
		K_WUNLOCK(mu_store);
	}

	return mu_root;
}

/* Find the block_workinfoid of the block requested
    then add all it's diffacc shares
    then keep stepping back shares until diffacc_total matches or exceeds
     the number required (diff_want) - this is begin_workinfoid
     (also summarising diffacc per user)
    then keep stepping back until we complete the current begin_workinfoid
     (also summarising diffacc per user)
   This will give us the total number of diff1 shares (diffacc_total)
    to use for the payment calculations
   The value of diff_want defaults to the block's network difficulty
    (block_ndiff) but can be changed with diff_times and diff_add to:
	block_ndiff * diff_times + diff_add
    N.B. diff_times and diff_add can be zero, positive or negative
   The pplns_elapsed time of the shares is from the createdate of the
    begin_workinfoid that has shares accounted to the total,
    up to the createdate of the last share
   The user average hashrate would be:
	diffacc_user * 2^32 / pplns_elapsed
   PPLNS fraction of the block would be:
	diffacc_user / diffacc_total
*/

static char *cmd_pplns(__maybe_unused PGconn *conn, char *cmd, char *id,
			  __maybe_unused tv_t *now, __maybe_unused char *by,
			  __maybe_unused char *code, __maybe_unused char *inet,
			  __maybe_unused tv_t *notcd, K_TREE *trf_root)
{
	char reply[1024], tmp[1024], *buf;
	size_t siz = sizeof(reply);
	K_ITEM *i_height, *i_difftimes, *i_diffadd, *i_allowaged;
	K_ITEM b_look, ss_look, *b_item, *w_item, *ss_item;
	K_ITEM *mu_item, *wb_item, *u_item;
	SHARESUMMARY looksharesummary, *sharesummary;
	MININGPAYOUTS *miningpayouts;
	WORKINFO *workinfo;
	TRANSFER *transfer;
	BLOCKS lookblocks, *blocks;
	K_TREE *mu_root;
	K_STORE *mu_store;
	USERS *users;
	int32_t height;
	int64_t workinfoid, end_workinfoid;
	int64_t begin_workinfoid;
	int64_t share_count;
	char tv_buf[DATE_BUFSIZ];
	tv_t cd, begin_tv, block_tv, end_tv;
	K_TREE_CTX ctx[1];
	double ndiff, total, elapsed;
	double diff_times = 1.0;
	double diff_add = 0.0;
	double diff_want;
	bool allow_aged = false;
	char ndiffbin[TXT_SML+1];
	size_t len, off;
	int rows;

	LOGDEBUG("%s(): cmd '%s'", __func__, cmd);

	i_height = require_name(trf_root, "height", 1, NULL, reply, siz);
	if (!i_height)
		return strdup(reply);
	TXT_TO_INT("height", transfer_data(i_height), height);

	i_difftimes = optional_name(trf_root, "diff_times", 1, NULL, reply, siz);
	if (i_difftimes)
		TXT_TO_DOUBLE("diff_times", transfer_data(i_difftimes), diff_times);

	i_diffadd = optional_name(trf_root, "diff_add", 1, NULL, reply, siz);
	if (i_diffadd)
		TXT_TO_DOUBLE("diff_add", transfer_data(i_diffadd), diff_add);

	i_allowaged = optional_name(trf_root, "allow_aged", 1, NULL, reply, siz);
	if (i_allowaged) {
		DATA_TRANSFER(transfer, i_allowaged);
		if (toupper(transfer->mvalue[0]) == TRUE_STR[0])
			allow_aged = true;
	}

	cd.tv_sec = cd.tv_usec = 0L;
	lookblocks.height = height + 1;
	lookblocks.blockhash[0] = '\0';
	INIT_BLOCKS(&b_look);
	b_look.data = (void *)(&lookblocks);
	K_RLOCK(blocks_free);
	b_item = find_before_in_ktree(blocks_root, &b_look, cmp_blocks, ctx);
	if (!b_item) {
		K_RUNLOCK(blocks_free);
		snprintf(reply, siz, "ERR.no block height %d", height);
		return strdup(reply);
	}
	DATA_BLOCKS_NULL(blocks, b_item);
	while (b_item && blocks->height == height) {
		if (blocks->confirmed[0] == BLOCKS_CONFIRM)
			break;
		b_item = prev_in_ktree(ctx);
		DATA_BLOCKS_NULL(blocks, b_item);
	}
	K_RUNLOCK(blocks_free);
	if (!b_item || blocks->height != height) {
		snprintf(reply, siz, "ERR.unconfirmed block %d", height);
		return strdup(reply);
	}
	workinfoid = blocks->workinfoid;
	copy_tv(&block_tv, &(blocks->createdate));
	copy_tv(&end_tv, &(blocks->createdate));

	w_item = find_workinfo(workinfoid);
	if (!w_item) {
		snprintf(reply, siz, "ERR.missing workinfo %"PRId64, workinfoid);
		return strdup(reply);
	}
	DATA_WORKINFO(workinfo, w_item);

	hex2bin(ndiffbin, workinfo->bits, 4);
	ndiff = diff_from_nbits(ndiffbin);
	diff_want = ndiff * diff_times + diff_add;
	if (diff_want < 1.0) {
		snprintf(reply, siz,
			 "ERR.invalid diff_want result %f",
			 diff_want);
		return strdup(reply);
	}

	begin_workinfoid = 0;
	share_count = 0;
	total = 0;

	looksharesummary.workinfoid = workinfoid;
	looksharesummary.userid = MAXID;
	looksharesummary.workername[0] = '\0';
	INIT_SHARESUMMARY(&ss_look);
	ss_look.data = (void *)(&looksharesummary);
	K_RLOCK(sharesummary_free);
	ss_item = find_before_in_ktree(sharesummary_workinfoid_root, &ss_look,
					cmp_sharesummary_workinfoid, ctx);
	if (!ss_item) {
		K_RUNLOCK(sharesummary_free);
		snprintf(reply, siz,
			 "ERR.no shares found with or before "
			 "workinfo %"PRId64,
			 workinfoid);
		return strdup(reply);
	}
	DATA_SHARESUMMARY(sharesummary, ss_item);

	mu_store = k_new_store(miningpayouts_free);
	mu_root = new_ktree();
	end_workinfoid = sharesummary->workinfoid;
	/* add up all sharesummaries until >= diff_want
	 * also record the latest lastshare - that will be the end pplns time
	 *  which will be >= block_tv */
	while (ss_item && total < diff_want) {
		switch (sharesummary->complete[0]) {
			case SUMMARY_CONFIRM:
				break;
			case SUMMARY_COMPLETE:
				if (allow_aged)
					break;
			default:
				K_RUNLOCK(sharesummary_free);
				snprintf(reply, siz,
					 "ERR.sharesummary1 not ready in "
					 "workinfo %"PRId64,
					 sharesummary->workinfoid);
				goto shazbot;
		}
		share_count++;
		total += (int64_t)(sharesummary->diffacc);
		begin_workinfoid = sharesummary->workinfoid;
		if (tv_newer(&end_tv, &(sharesummary->lastshare)))
			copy_tv(&end_tv, &(sharesummary->lastshare));
		mu_root = upd_add_mu(mu_root, mu_store,
				     sharesummary->userid,
				     (int64_t)(sharesummary->diffacc));
		ss_item = prev_in_ktree(ctx);
		DATA_SHARESUMMARY_NULL(sharesummary, ss_item);
	}

	// include all the rest of the sharesummaries with begin_workinfoid
	while (ss_item && sharesummary->workinfoid == begin_workinfoid) {
		switch (sharesummary->complete[0]) {
			case SUMMARY_CONFIRM:
				break;
			case SUMMARY_COMPLETE:
				if (allow_aged)
					break;
			default:
				K_RUNLOCK(sharesummary_free);
				snprintf(reply, siz,
					 "ERR.sharesummary2 not ready in "
					 "workinfo %"PRId64,
					 sharesummary->workinfoid);
				goto shazbot;
		}
		share_count++;
		total += (int64_t)(sharesummary->diffacc);
		mu_root = upd_add_mu(mu_root, mu_store,
				     sharesummary->userid,
				     (int64_t)(sharesummary->diffacc));
		ss_item = prev_in_ktree(ctx);
		DATA_SHARESUMMARY_NULL(sharesummary, ss_item);
	}
	K_RUNLOCK(sharesummary_free);

	if (total == 0.0) {
		snprintf(reply, siz,
			 "ERR.total share diff 0 before workinfo %"PRId64,
			 workinfoid);
		goto shazbot;
	}

	wb_item = find_workinfo(begin_workinfoid);
	if (!wb_item) {
		snprintf(reply, siz, "ERR.missing begin workinfo record! %"PRId64, workinfoid);
		goto shazbot;
	}
	DATA_WORKINFO(workinfo, wb_item);

	copy_tv(&begin_tv, &(workinfo->createdate));
	/* Elapsed is from the start of the first workinfoid used,
	 *  to the time of the last share counted -
	 *  which can be after the block, but must have the same workinfoid as
	 *  the block, if it is after the block
	 * All shares accepted in all workinfoids after the block's workinfoid
	 *  will not be creditied to this block no matter what the height
	 *  of their workinfoid is - but will be candidates for the next block */
	elapsed = tvdiff(&end_tv, &begin_tv);

	APPEND_REALLOC_INIT(buf, off, len);
	APPEND_REALLOC(buf, off, len, "ok.");
	snprintf(tmp, sizeof(tmp), "block=%d%c", height, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "block_hash=%s%c", blocks->blockhash, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "block_reward=%"PRId64"%c", blocks->reward, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "workername=%s%c", blocks->workername, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "nonce=%s%c", blocks->nonce, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "begin_workinfoid=%"PRId64"%c", begin_workinfoid, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "block_workinfoid=%"PRId64"%c", workinfoid, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "end_workinfoid=%"PRId64"%c", end_workinfoid, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "diffacc_total=%.0f%c", total, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "pplns_elapsed=%f%c", elapsed, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);

	rows = 0;
	mu_item = first_in_ktree(mu_root, ctx);
	while (mu_item) {
		DATA_MININGPAYOUTS(miningpayouts, mu_item);

		K_RLOCK(users_free);
		u_item = find_userid(miningpayouts->userid);
		K_RUNLOCK(users_free);
		if (u_item) {
			K_ITEM *pa_item;
			PAYMENTADDRESSES *pa;
			char *payaddress;

			pa_item = find_paymentaddresses(miningpayouts->userid);
			if (pa_item) {
				DATA_PAYMENTADDRESSES(pa, pa_item);
				payaddress = pa->payaddress;
			} else
				payaddress = "none";

			DATA_USERS(users, u_item);
			snprintf(tmp, sizeof(tmp),
				 "user:%d=%s%cpayaddress:%d=%s%c",
				 rows, users->username, FLDSEP,
				 rows, payaddress, FLDSEP);

		} else {
			snprintf(tmp, sizeof(tmp),
				 "user:%d=%"PRId64"%cpayaddress:%d=none%c",
				 rows, miningpayouts->userid, FLDSEP,
				 rows, FLDSEP);
		}
		APPEND_REALLOC(buf, off, len, tmp);

		snprintf(tmp, sizeof(tmp),
				 "diffacc_user:%d=%"PRId64"%c",
				 rows,
				 miningpayouts->amount,
				 FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);

		mu_item = next_in_ktree(ctx);
		rows++;
	}
	snprintf(tmp, sizeof(tmp),
		 "rows=%d%cflds=%s%c",
		 rows, FLDSEP,
		 "user,diffacc_user,payaddress", FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);

	snprintf(tmp, sizeof(tmp), "arn=%s%carp=%s%c",
				   "Users", FLDSEP, "", FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);

	tv_to_buf(&begin_tv, tv_buf, sizeof(tv_buf));
	snprintf(tmp, sizeof(tmp), "begin_stamp=%s%c", tv_buf, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "begin_epoch=%ld%c", begin_tv.tv_sec, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	tv_to_buf(&block_tv, tv_buf, sizeof(tv_buf));
	snprintf(tmp, sizeof(tmp), "block_stamp=%s%c", tv_buf, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "block_epoch=%ld%c", block_tv.tv_sec, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	tv_to_buf(&end_tv, tv_buf, sizeof(tv_buf));
	snprintf(tmp, sizeof(tmp), "end_stamp=%s%c", tv_buf, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "end_epoch=%ld%c", end_tv.tv_sec, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);

	snprintf(tmp, sizeof(tmp), "block_ndiff=%f%c", ndiff, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "diff_times=%f%c", diff_times, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "diff_add=%f%c", diff_add, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "diff_want=%f%c", diff_want, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "share_count=%"PRId64, share_count);
	APPEND_REALLOC(buf, off, len, tmp);

	mu_root = free_ktree(mu_root, NULL);
	K_WLOCK(mu_store);
	k_list_transfer_to_head(mu_store, miningpayouts_free);
	K_WUNLOCK(mu_store);
	mu_store = k_free_store(mu_store);

	LOGDEBUG("%s.ok.pplns.%s", id, buf);
	return buf;

shazbot:
	mu_root = free_ktree(mu_root, NULL);
	K_WLOCK(mu_store);
	k_list_transfer_to_head(mu_store, miningpayouts_free);
	K_WUNLOCK(mu_store);
	mu_store = k_free_store(mu_store);

	return strdup(reply);
}

static char *cmd_dsp(__maybe_unused PGconn *conn, __maybe_unused char *cmd,
		     char *id, __maybe_unused tv_t *now,
		     __maybe_unused char *by, __maybe_unused char *code,
		     __maybe_unused char *inet, __maybe_unused tv_t *notcd,
		     __maybe_unused K_TREE *trf_root)
{
	__maybe_unused K_ITEM *i_file;
	__maybe_unused char reply[1024] = "";
	__maybe_unused size_t siz = sizeof(reply);

	LOGDEBUG("%s(): cmd '%s'", __func__, cmd);

	// WARNING: This is a gaping security hole - only use in development
	LOGDEBUG("%s.disabled.dsp", id);
	return strdup("disabled.dsp");
/*
	i_file = require_name(trf_root, "file", 1, NULL, reply, siz);
	if (!i_file)
		return strdup(reply);

	dsp_ktree(blocks_free, blocks_root, transfer_data(i_file), NULL);

	dsp_ktree(transfer_free, trf_root, transfer_data(i_file), NULL);

	dsp_ktree(paymentaddresses_free, paymentaddresses_root,
		  transfer_data(i_file), NULL);

	dsp_ktree(sharesummary_free, sharesummary_root,
		  transfer_data(i_file), NULL);

	dsp_ktree(userstats_free, userstats_root, transfer_data(i_file), NULL);

	LOGDEBUG("%s.ok.dsp.file='%s'", id, transfer_data(i_file));
	return strdup("ok.dsp");
*/
}

static char *cmd_stats(__maybe_unused PGconn *conn, char *cmd, char *id,
			__maybe_unused tv_t *now, __maybe_unused char *by,
			__maybe_unused char *code, __maybe_unused char *inet,
			__maybe_unused tv_t *notcd, __maybe_unused K_TREE *trf_root)
{
	char tmp[1024], *buf;
	size_t len, off;
	uint64_t ram, ram2, tot = 0;
	K_LIST *klist;
	int rows = 0;

	LOGDEBUG("%s(): cmd '%s'", __func__, cmd);

	APPEND_REALLOC_INIT(buf, off, len);
	APPEND_REALLOC(buf, off, len, "ok.");

// Doesn't include blob memory
// - average transactiontree length of ~119k I have is ~28k (>3.3GB)
#define USEINFO(_obj, _stores, _trees) \
	klist = _obj ## _free; \
	ram = sizeof(K_LIST) + _stores * sizeof(K_STORE) + \
		klist->allocate * klist->item_mem_count * klist->siz + \
		sizeof(K_TREE) * (klist->total - klist->count) * _trees; \
	ram2 = klist->ram; \
	snprintf(tmp, sizeof(tmp), \
		 "name:%d=" #_obj "%cinitial:%d=%d%callocated:%d=%d%c" \
		 "store:%d=%d%ctrees:%d=%d%cram:%d=%"PRIu64"%c" \
		 "ram2:%d=%"PRIu64"%ccull:%d=%d%c", \
		 rows, FLDSEP, \
		 rows, klist->allocate, FLDSEP, \
		 rows, klist->total, FLDSEP, \
		 rows, klist->total - klist->count, FLDSEP, \
		 rows, _trees, FLDSEP, \
		 rows, ram, FLDSEP, \
		 rows, ram2, FLDSEP, \
		 rows, klist->cull_count, FLDSEP); \
	APPEND_REALLOC(buf, off, len, tmp); \
	tot += ram + ram2; \
	rows++;

	USEINFO(users, 1, 2);
	USEINFO(useratts, 1, 1);
	USEINFO(workers, 1, 1);
	USEINFO(paymentaddresses, 1, 1);
	USEINFO(payments, 1, 1);
	USEINFO(idcontrol, 1, 0);
	USEINFO(optioncontrol, 1, 1);
	USEINFO(workinfo, 1, 1);
	USEINFO(shares, 1, 1);
	USEINFO(shareerrors, 1, 1);
	USEINFO(sharesummary, 1, 2);
	USEINFO(blocks, 1, 1);
	USEINFO(miningpayouts, 1, 1);
	USEINFO(auths, 1, 1);
	USEINFO(poolstats, 1, 1);
	USEINFO(userstats, 4, 2);
	USEINFO(workerstatus, 1, 1);
	USEINFO(workqueue, 1, 0);
	USEINFO(transfer, 0, 0);
	USEINFO(heartbeatqueue, 1, 0);
	USEINFO(logqueue, 1, 0);

	snprintf(tmp, sizeof(tmp), "totalram=%"PRIu64"%c", tot, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);

	snprintf(tmp, sizeof(tmp),
		 "rows=%d%cflds=%s%c",
		 rows, FLDSEP,
		 "name,initial,allocated,store,trees,ram,cull", FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);

	snprintf(tmp, sizeof(tmp), "arn=%s%carp=%s", "Stats", FLDSEP, "");
	APPEND_REALLOC(buf, off, len, tmp);

	LOGDEBUG("%s.ok.%s...", id, cmd);
	return buf;
}

// TODO: limit access by having seperate sockets for each
#define ACCESS_POOL	"p"
#define ACCESS_SYSTEM	"s"
#define ACCESS_WEB	"w"
#define ACCESS_PROXY	"x"
#define ACCESS_CKDB	"c"

/* The socket command format is as follows:
 *  Basic structure:
 *    cmd.ID.fld1=value1 FLDSEP fld2=value2 FLDSEP fld3=...
 *   cmd is the cmd_str from the table below
 *   ID is a string of anything but '.' - preferably just digits and/or letters
 *   FLDSEP is a single character macro - defined in the code near the top
 *    no spaces around FLDSEP - they are added above for readability
 *     i.e. it's really: cmd.ID.fld1=value1FLDSEPfld2...
 *   fldN names cannot contain '=' or FLDSEP
 *   valueN values cannot contain FLDSEP except for the json field (see below)
 *
 *  The reply will be ID.timestamp.status.information...
 *  Status 'ok' means it succeeded
 *  Some cmds you can optionally send as just 'cmd' if 'noid' below is true
 *   then the reply will be .timestamp.status.information
 *   i.e. a zero length 'ID' at the start of the reply
 *
 *  Data from ckpool starts with a fld1: json={...} of field data
 *  This is assumed to be the only field data sent and any other fields after
 *   it will cause a json error
 *  Any fields before it will circumvent the json interpretation of {...} and
 *   the full json in {...} will be stored as text in TRANSFER under the name
 *   'json' - which will (usually) mean the command will fail if it requires
 *   actual field data
 *
 *  Examples of the commands not from ckpool with an example reply
 *  STAMP is the unix timestamp in seconds
 *   With no ID:
 *	ping
 *	.STAMP.ok.pong
 *
 *	shutdown
 *	.STAMP.ok.exiting
 *
 *   With an ID
 *   In each case the ID in these examples, also returned, is 'ID' which can
 *   of course be most any string, as stated above
 *   For commands with multiple fld=value the space between them must be typed
 *   as a TAB
 *	ping.ID
 *	ID.STAMP.ok.pong
 *
 *	newid.ID.idname=fooid idvalue=1234
 *	ID.STAMP.ok.added fooid 1234
 *
 *  loglevel is a special case to make it quick and easy to use:
 *	loglevel.ID
 *  sets the loglevel to atoi(ID)
 *  Without an ID, it just reports the current value
 *
 *  createdate = true
 *   means that the data sent must contain a fld or json fld called createdate
 *
 * The reply format for authorise, addrauth and heartbeat includes json:
 *   ID.STAMP.ok.cmd={json}
 *  where cmd is auth, addrauth, or heartbeat
 * For the heartbeat pulse reply it has no '={}'
 */

//	  cmd_val	cmd_str		noid	createdate func		access
struct CMDS ckdb_cmds[] = {
	{ CMD_SHUTDOWN,	"shutdown",	true,	false,	NULL,		ACCESS_SYSTEM },
	{ CMD_PING,	"ping",		true,	false,	NULL,		ACCESS_SYSTEM ACCESS_POOL ACCESS_WEB },
	{ CMD_VERSION,	"version",	true,	false,	NULL,		ACCESS_SYSTEM ACCESS_POOL ACCESS_WEB },
	{ CMD_LOGLEVEL,	"loglevel",	true,	false,	NULL,		ACCESS_SYSTEM },
	{ CMD_SHARELOG,	STR_WORKINFO,	false,	true,	cmd_sharelog,	ACCESS_POOL },
	{ CMD_SHARELOG,	STR_SHARES,	false,	true,	cmd_sharelog,	ACCESS_POOL },
	{ CMD_SHARELOG,	STR_SHAREERRORS, false,	true,	cmd_sharelog,	ACCESS_POOL },
	{ CMD_SHARELOG,	STR_AGEWORKINFO, false,	true,	cmd_sharelog,	ACCESS_POOL },
	{ CMD_AUTH,	"authorise",	false,	true,	cmd_auth,	ACCESS_POOL },
	{ CMD_ADDRAUTH,	"addrauth",	false,	true,	cmd_addrauth,	ACCESS_POOL },
	{ CMD_HEARTBEAT,"heartbeat",	false,	true,	cmd_heartbeat,	ACCESS_POOL },
	{ CMD_ADDUSER,	"adduser",	false,	false,	cmd_adduser,	ACCESS_WEB },
	{ CMD_NEWPASS,	"newpass",	false,	false,	cmd_newpass,	ACCESS_WEB },
	{ CMD_CHKPASS,	"chkpass",	false,	false,	cmd_chkpass,	ACCESS_WEB },
	{ CMD_USERSET,	"usersettings",	false,	false,	cmd_userset,	ACCESS_WEB },
	{ CMD_WORKERSET,"workerset",	false,	false,	cmd_workerset,	ACCESS_WEB },
	{ CMD_POOLSTAT,	"poolstats",	false,	true,	cmd_poolstats,	ACCESS_POOL },
	{ CMD_USERSTAT,	"userstats",	false,	true,	cmd_userstats,	ACCESS_POOL },
	{ CMD_BLOCK,	"block",	false,	true,	cmd_blocks,	ACCESS_POOL },
	{ CMD_BLOCKLIST,"blocklist",	false,	false,	cmd_blocklist,	ACCESS_WEB },
	{ CMD_BLOCKSTATUS,"blockstatus",false,	false,	cmd_blockstatus,ACCESS_WEB },
	{ CMD_NEWID,	"newid",	false,	false,	cmd_newid,	ACCESS_SYSTEM },
	{ CMD_PAYMENTS,	"payments",	false,	false,	cmd_payments,	ACCESS_WEB },
	{ CMD_WORKERS,	"workers",	false,	false,	cmd_workers,	ACCESS_WEB },
	{ CMD_ALLUSERS,	"allusers",	false,	false,	cmd_allusers,	ACCESS_WEB },
	{ CMD_HOMEPAGE,	"homepage",	false,	false,	cmd_homepage,	ACCESS_WEB },
	{ CMD_GETATTS,	"getatts",	false,	false,	cmd_getatts,	ACCESS_WEB },
	{ CMD_SETATTS,	"setatts",	false,	false,	cmd_setatts,	ACCESS_WEB },
	{ CMD_EXPATTS,	"expatts",	false,	false,	cmd_expatts,	ACCESS_WEB },
	{ CMD_GETOPTS,	"getopts",	false,	false,	cmd_getopts,	ACCESS_WEB },
	{ CMD_SETOPTS,	"setopts",	false,	false,	cmd_setopts,	ACCESS_WEB },
	{ CMD_DSP,	"dsp",		false,	false,	cmd_dsp,	ACCESS_SYSTEM },
	{ CMD_STATS,	"stats",	true,	false,	cmd_stats,	ACCESS_SYSTEM },
	{ CMD_PPLNS,	"pplns",	false,	false,	cmd_pplns,	ACCESS_SYSTEM },
	{ CMD_END,	NULL,		false,	false,	NULL,		NULL }
};
