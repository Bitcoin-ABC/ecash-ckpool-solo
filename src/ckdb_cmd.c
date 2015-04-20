/*
 * Copyright 1995-2015 Andrew Smith
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#include "ckdb.h"

/*
 * Allow overriding the username however the username must still be present
 * This should ONLY be used for web reporting cmds i.e. read only
 * Current PHP allows this for a hard coded user
 */
static K_ITEM *adminuser(K_TREE *trf_root, char *reply, size_t siz)
{
	K_ITEM *i_username, *i_admin;
	char reply2[1024] = "";

	i_username = require_name(trf_root, "username", 3, (char *)userpatt,
				  reply, siz);
	if (!i_username)
		return NULL;

	i_admin = optional_name(trf_root, "admin", 3, (char *)userpatt,
				reply2, sizeof(reply2));
	if (i_admin)
		return i_admin;

	return i_username;
}

static char *cmd_adduser(PGconn *conn, char *cmd, char *id, tv_t *now, char *by,
			 char *code, char *inet, __maybe_unused tv_t *notcd,
			 K_TREE *trf_root)
{
	char reply[1024] = "";
	size_t siz = sizeof(reply);
	K_ITEM *i_username, *i_emailaddress, *i_passwordhash, *u_item = NULL;

	LOGDEBUG("%s(): cmd '%s'", __func__, cmd);

	i_username = require_name(trf_root, "username", 3, (char *)userpatt, reply, siz);
	if (!i_username)
		return strdup(reply);

	/* If a username added from the web site looks like an address
	 *  then disallow it - a false positive is not an issue
	 * Allowing it will create a security issue - someone could create
	 *  an account with someone else's, as yet unused, payout address
	 *  and redirect the payout to another payout address.
	 *  ... and the person who owns the payout address can't check that
	 *  in advance, they'll just find out with their first payout not
	 *  arriving at their payout address */
	if (!like_address(transfer_data(i_username))) {
		i_emailaddress = require_name(trf_root, "emailaddress", 7,
					      (char *)mailpatt, reply, siz);
		if (!i_emailaddress)
			return strdup(reply);

		i_passwordhash = require_name(trf_root, "passwordhash", 64,
					      (char *)hashpatt, reply, siz);
		if (!i_passwordhash)
			return strdup(reply);

		u_item = users_add(conn, transfer_data(i_username),
					 transfer_data(i_emailaddress),
					 transfer_data(i_passwordhash),
					 by, code, inet, now, trf_root);
	}

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
			ok = users_update(NULL, u_item,
						oldhash,
						transfer_data(i_newhash),
						NULL,
						by, code, inet, now,
						trf_root,
						NULL);
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
	K_ITEM *i_username, *i_passwordhash, *i_rows, *i_address, *i_ratio;
	K_ITEM *i_email, *u_item, *pa_item, *old_pa_item;
	char *email, *address;
	char reply[1024] = "";
	size_t siz = sizeof(reply);
	char tmp[1024];
	PAYMENTADDRESSES *row, *pa;
	K_STORE *pa_store = NULL;
	K_TREE_CTX ctx[1];
	USERS *users;
	char *reason = NULL;
	char *answer = NULL;
	char *ret = NULL;
	size_t len, off;
	int32_t ratio;
	int rows, i;
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
			pa_item = find_paymentaddresses(users->userid, ctx);
			rows = 0;
			if (pa_item) {
				DATA_PAYMENTADDRESSES(row, pa_item);
				while (pa_item && CURRENT(&(row->expirydate)) &&
				       row->userid == users->userid) {
					snprintf(tmp, sizeof(tmp), "addr:%d=%s%c",
						 rows, row->payaddress, FLDSEP);
					APPEND_REALLOC(answer, off, len, tmp);
					snprintf(tmp, sizeof(tmp), "ratio:%d=%d%c",
						 rows, row->payratio, FLDSEP);
					APPEND_REALLOC(answer, off, len, tmp);
					rows++;

					pa_item = prev_in_ktree(ctx);
					DATA_PAYMENTADDRESSES_NULL(row, pa_item);
				}
			}
			K_RUNLOCK(paymentaddresses_free);

			snprintf(tmp, sizeof(tmp), "rows=%d%cflds=%s%c",
				 rows, FLDSEP,
				 "addr,ratio", FLDSEP);
			APPEND_REALLOC(answer, off, len, tmp);
			snprintf(tmp, sizeof(tmp), "arn=%s%carp=%s",
				 "PaymentAddresses", FLDSEP, "");
			APPEND_REALLOC(answer, off, len, tmp);
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

			// address rows
			i_rows = optional_name(trf_root, "rows",
					       1, (char *)intpatt,
					       reply, siz);
			if (!i_rows && *reply) {
				// Exists, but invalid
				reason = "System error";
				goto struckout;
			}
			if (i_rows) {
				rows = atoi(transfer_data(i_rows));
				if (rows < 0)  {
					reason = "System error";
					goto struckout;
				}
				if (rows > 0) {
					pa_store = k_new_store(paymentaddresses_free);
					K_WLOCK(paymentaddresses_free);
					for (i = 0; i < rows; i++) {
						snprintf(tmp, sizeof(tmp), "ratio:%d", i);
						i_ratio = optional_name(trf_root, tmp,
									1, (char *)intpatt,
									reply, siz);
						if (*reply) {
							K_WUNLOCK(paymentaddresses_free);
							reason = "Invalid ratio";
							goto struckout;
						}
						if (i_ratio)
							ratio = atoi(transfer_data(i_ratio));
						else
							ratio = PAYRATIODEF;

						/* 0 = expire/remove the address
						 * intpatt means it will be >= 0 */
						if (ratio == 0)
							continue;

						snprintf(tmp, sizeof(tmp), "address:%d", i);
						i_address = require_name(trf_root, tmp,
									 ADDR_MIN_LEN,
									 (char *)addrpatt,
									 reply, siz);
						if (!i_address) {
							K_WUNLOCK(paymentaddresses_free);
							reason = "Invalid address";
							goto struckout;
						}
						address = transfer_data(i_address);
						pa_item = pa_store->head;
						while (pa_item) {
							DATA_PAYMENTADDRESSES(row, pa_item);
							if (strcmp(row->payaddress, address) == 0) {
								K_WUNLOCK(paymentaddresses_free);
								reason = "Duplicate address";
								goto struckout;
							}
							pa_item = pa_item->next;
						}
						pa_item = k_unlink_head(paymentaddresses_free);
						DATA_PAYMENTADDRESSES(row, pa_item);
						bzero(row, sizeof(*row));
						STRNCPY(row->payaddress, address);
						row->payratio = ratio;
						k_add_head(pa_store, pa_item);
					}
					K_WUNLOCK(paymentaddresses_free);
				}
			}
			/* If all addresses have a ratio of zero
			 * pa_store->count will be 0 */
			if ((email == NULL || *email == '\0') &&
			    (pa_store == NULL || pa_store->count == 0)) {
				reason = "Missing/Invalid value";
				goto struckout;
			}

			if (pa_store && pa_store->count > 0) {
				pa_item = pa_store->head;
				while (pa_item) {
					DATA_PAYMENTADDRESSES(row, pa_item);
					// Only EVER validate addresses once ... for now
					old_pa_item = find_any_payaddress(row->payaddress);
					if (old_pa_item) {
						/* This test effectively means that
						 * two users can never add the same
						 * payout address */
						DATA_PAYMENTADDRESSES(pa, old_pa_item);
						if (pa->userid != users->userid) {
							reason = "Unavailable BTC address";
							goto struckout;
						}
					} else if (!btc_valid_address(row->payaddress)) {
						reason = "Invalid BTC address";
						goto struckout;
					}
					pa_item = pa_item->next;
				}
			}

			if (email && *email) {
				ok = users_update(conn, u_item,
							NULL, NULL,
							email,
							by, code, inet, now,
							trf_root,
							NULL);
				if (!ok) {
					reason = "email error";
					goto struckout;
				}
			}

			if (pa_store && pa_store->count > 0) {
				ok = paymentaddresses_set(conn, users->userid,
								pa_store, by,
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
	if (pa_store) {
		if (pa_store->count) {
			K_WLOCK(paymentaddresses_free);
			k_list_transfer_to_head(pa_store, paymentaddresses_free);
			K_WUNLOCK(paymentaddresses_free);
		}
		k_free_store(pa_store);
		pa_store = NULL;
	}
	if (reason) {
		snprintf(reply, siz, "ERR.%s", reason);
		LOGERR("%s.%s.%s", cmd, id, reply);
		return strdup(reply);
	}
	APPEND_REALLOC_INIT(ret, off, len);
	APPEND_REALLOC(ret, off, len, "ok.");
	APPEND_REALLOC(ret, off, len, answer);
	free(answer);
	LOGDEBUG("%s.%s", id, ret);
	return ret;
}

static char *cmd_workerset(PGconn *conn, char *cmd, char *id, tv_t *now,
			   char *by, char *code, char *inet, tv_t *cd,
			   K_TREE *trf_root)
{
	K_ITEM *i_username, *i_workername, *i_diffdef, *i_oldworkers;
	K_ITEM *u_item, *ua_item, *w_item;
	HEARTBEATQUEUE *heartbeatqueue;
	K_ITEM *hq_item;
	char workername_buf[32]; // 'workername:' + digits
	char diffdef_buf[32]; // 'difficultydefault:' + digits
	char reply[1024] = "";
	size_t siz = sizeof(reply);
	USERATTS *useratts;
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

		i_oldworkers = optional_name(trf_root, "oldworkers",
					     1, NULL, reply, siz);
		if (i_oldworkers) {
			bool update = false;
			int64_t new_ow = atol(transfer_data(i_oldworkers));

			K_RLOCK(useratts_free);
			ua_item = find_useratts(users->userid, USER_OLD_WORKERS);
			K_RUNLOCK(useratts_free);
			if (!ua_item) {
				if (new_ow != USER_OLD_WORKERS_DEFAULT)
					update = true;
			} else {
				DATA_USERATTS(useratts, ua_item);
				if (new_ow != useratts->attnum)
					update = true;
			}
			if (update) {
				ua_item = useratts_add(conn, users->username,
							USER_OLD_WORKERS, EMPTY,
							EMPTY, EMPTY,
							transfer_data(i_oldworkers),
							EMPTY, EMPTY, EMPTY,
							by, code, inet, cd,
							trf_root, false);
				if (!ua_item)
					reason = "Invalid";
			}
			goto kazuki;
		}

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

kazuki:
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

static char *cmd_workerstats(__maybe_unused PGconn *conn, char *cmd, char *id,
			     __maybe_unused tv_t *notnow, char *by, char *code,
			     char *inet, tv_t *cd, K_TREE *trf_root)
{
	char reply[1024] = "";
	size_t siz = sizeof(reply);

	// log to logfile

	K_ITEM *i_poolinstance, *i_elapsed, *i_username, *i_workername;
	K_ITEM *i_hashrate, *i_hashrate5m, *i_hashrate1hr, *i_hashrate24hr;
	K_ITEM *i_idle;
	bool ok = false, idle;

	LOGDEBUG("%s(): cmd '%s'", __func__, cmd);

	i_poolinstance = require_name(trf_root, "poolinstance", 1, NULL, reply, siz);
	if (!i_poolinstance)
		return strdup(reply);

	i_elapsed = require_name(trf_root, "elapsed", 1, NULL, reply, siz);
	if (!i_elapsed)
		return strdup(reply);

	i_username = require_name(trf_root, "username", 1, NULL, reply, siz);
	if (!i_username)
		return strdup(reply);

	i_workername = require_name(trf_root, "workername", 1, NULL, reply, siz);
	if (!i_workername)
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

	i_idle = require_name(trf_root, "idle", 1, NULL, reply, siz);
	if (!i_idle)
		return strdup(reply);

	idle = (strcasecmp(transfer_data(i_idle), TRUE_STR) == 0);

	ok = workerstats_add(transfer_data(i_poolinstance),
			     transfer_data(i_elapsed),
			     transfer_data(i_username),
			     transfer_data(i_workername),
			     transfer_data(i_hashrate),
			     transfer_data(i_hashrate5m),
			     transfer_data(i_hashrate1hr),
			     transfer_data(i_hashrate24hr),
			     idle, by, code, inet, cd, trf_root);

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
	K_ITEM *b_item;
	BLOCKS *blocks;
	char reply[1024] = "";
	char tmp[1024];
	char *buf, *desc, desc_buf[64];
	size_t len, off;
	int32_t height = -1;
	tv_t first_cd = {0,0}, stats_tv = {0,0}, stats_tv2 = {0,0};
	int rows, srows, tot, seq;
	bool has_stats;

	LOGDEBUG("%s(): cmd '%s'", __func__, cmd);

	APPEND_REALLOC_INIT(buf, off, len);
	APPEND_REALLOC(buf, off, len, "ok.");

redo:
	K_WLOCK(blocks_free);
	has_stats = check_update_blocks_stats(&stats_tv);
	K_WUNLOCK(blocks_free);

	srows = rows = 0;
	K_RLOCK(blocks_free);
	b_item = first_in_ktree(blocks_root, ctx);
	tot = 0;
	while (b_item) {
		DATA_BLOCKS(blocks, b_item);
		if (CURRENT(&(blocks->expirydate))) {
			if (blocks->confirmed[0] != BLOCKS_ORPHAN)
				tot++;
		}
		b_item = next_in_ktree(ctx);
	}
	seq = tot;
	b_item = last_in_ktree(blocks_root, ctx);
	while (b_item && rows < 42) {
		DATA_BLOCKS(blocks, b_item);
		/* For each block remember the initial createdate
		 * Reverse sort order the oldest expirydate is first
		 *  which should be the 'n' record */
		if (height != blocks->height) {
			height = blocks->height;
			copy_tv(&first_cd, &(blocks->createdate));
		}
		if (CURRENT(&(blocks->expirydate))) {
			if (blocks->confirmed[0] == BLOCKS_ORPHAN) {
				snprintf(tmp, sizeof(tmp),
					 "seq:%d=o%c",
					 rows, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);
			} else {
				snprintf(tmp, sizeof(tmp),
					 "seq:%d=%d%c",
					 rows, seq--, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);
			}
			int_to_buf(blocks->height, reply, sizeof(reply));
			snprintf(tmp, sizeof(tmp), "height:%d=%s%c", rows, reply, FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);

			dbhash2btchash(blocks->blockhash, reply, sizeof(reply));
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

			snprintf(tmp, sizeof(tmp),
				 "statsconf:%d=%s%c", rows,
				 blocks->statsconfirmed, FLDSEP);
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

			if (has_stats) {
				snprintf(tmp, sizeof(tmp),
					 "netdiff:%d=%.8f%cdiffratio:%d=%.8f%c"
					 "cdf:%d=%.8f%cluck:%d=%.8f%c",
					 rows, blocks->netdiff, FLDSEP,
					 rows, blocks->blockdiffratio, FLDSEP,
					 rows, blocks->blockcdf, FLDSEP,
					 rows, blocks->blockluck, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);
			} else {
				snprintf(tmp, sizeof(tmp),
					 "netdiff:%d=?%cdiffratio:%d=?%c"
					 "cdf:%d=?%cluck:%d=?%c",
					 rows, FLDSEP, rows, FLDSEP,
					 rows, FLDSEP, rows, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);
			}

			rows++;
		}
		b_item = prev_in_ktree(ctx);
	}
	if (has_stats) {
		seq = tot;
		b_item = last_in_ktree(blocks_root, ctx);
		while (b_item) {
			DATA_BLOCKS(blocks, b_item);
			if (CURRENT(&(blocks->expirydate)) &&
			    blocks->confirmed[0] != BLOCKS_ORPHAN) {
				desc = NULL;
				if (seq == 1) {
					snprintf(desc_buf, sizeof(desc_buf),
						 "All - Last %d", tot);
					desc = desc_buf;
				} else if (seq == tot - 4) {
					desc = "Last 5";
				} else if (seq == tot - 9) {
					desc = "Last 10";
				} else if (seq == tot - 24) {
					desc = "Last 25";
				} else if (seq == tot - 49) {
					desc = "Last 50";
				} else if (seq == tot - 99) {
					desc = "Last 100";
				}
				if (desc) {
					snprintf(tmp, sizeof(tmp),
						 "s_seq:%d=%d%c"
						 "s_desc:%d=%s%c"
						 "s_diffratio:%d=%.8f%c"
						 "s_diffmean:%d=%.8f%c"
						 "s_cdferl:%d=%.8f%c"
						 "s_luck:%d=%.8f%c",
						 srows, seq, FLDSEP,
						 srows, desc, FLDSEP,
						 srows, blocks->diffratio, FLDSEP,
						 srows, blocks->diffmean, FLDSEP,
						 srows, blocks->cdferl, FLDSEP,
						 srows, blocks->luck, FLDSEP);
					APPEND_REALLOC(buf, off, len, tmp);
					srows++;
				}
				seq--;
			}
			b_item = prev_in_ktree(ctx);
		}
		copy_tv(&stats_tv2, &blocks_stats_time);
	}
	K_RUNLOCK(blocks_free);

	// Only check for a redo if we used the stats values
	if (has_stats) {
		/* If the stats changed then redo with the new corrected values
		 * This isn't likely at all, but it guarantees the blocks
		 *  page shows correct information since any code that wants
		 *  to modify the blocks table must have it under write lock
		 *  then flag the stats as needing to be recalculated */
		if (!tv_equal(&stats_tv, &stats_tv2)) {
			APPEND_REALLOC_RESET(buf, off);
			goto redo;
		}
	}

	snprintf(tmp, sizeof(tmp),
		 "s_rows=%d%cs_flds=%s%c",
		 srows, FLDSEP,
		 "s_seq,s_desc,s_diffratio,s_diffmean,s_cdferl,s_luck",
		 FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);

	snprintf(tmp, sizeof(tmp),
		 "rows=%d%cflds=%s%c",
		 rows, FLDSEP,
		 "seq,height,blockhash,nonce,reward,workername,firstcreatedate,"
		 "createdate,status,statsconf,diffacc,diffinv,shareacc,"
		 "shareinv,elapsed,netdiff,diffratio,cdf,luck", FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);

	snprintf(tmp, sizeof(tmp), "arn=%s%carp=%s", "Blocks,BlockStats", FLDSEP, ",s");
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
	b_item = find_blocks(height, transfer_data(i_blockhash), NULL);
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
	K_ITEM *i_username, *u_item, *p_item, *p2_item, *po_item;
	K_TREE_CTX ctx[1];
	K_STORE *pay_store;
	PAYMENTS *payments, *last_payments = NULL;
	PAYOUTS *payouts;
	USERS *users;
	char reply[1024] = "";
	char tmp[1024];
	size_t siz = sizeof(reply);
	char *buf;
	size_t len, off;
	int rows;
	bool pok;

	LOGDEBUG("%s(): cmd '%s'", __func__, cmd);

	i_username = adminuser(trf_root, reply, siz);
	if (!i_username)
		return strdup(reply);

	K_RLOCK(users_free);
	u_item = find_users(transfer_data(i_username));
	K_RUNLOCK(users_free);
	if (!u_item)
		return strdup("bad");
	DATA_USERS(users, u_item);

	APPEND_REALLOC_INIT(buf, off, len);
	APPEND_REALLOC(buf, off, len, "ok.");
	rows = 0;
	pay_store = k_new_store(payments_free);
	K_WLOCK(payments_free);
	p_item = find_first_payments(users->userid, ctx);
	DATA_PAYMENTS_NULL(payments, p_item);
	/* TODO: allow to see details of a single payoutid
	 *	 if it has multiple items (percent payout user) */
	while (p_item && payments->userid == users->userid) {
		if (CURRENT(&(payments->expirydate))) {
			if (!last_payments || payments->payoutid != last_payments->payoutid) {
				p2_item = k_unlink_head(payments_free);
				DATA_PAYMENTS_NULL(last_payments, p2_item);
				memcpy(last_payments, payments, sizeof(*last_payments));
				k_add_tail(pay_store, p2_item);
			} else {
				STRNCPY(last_payments->payaddress, "*Multiple");
				last_payments->amount += payments->amount;
			}
		}
		p_item = next_in_ktree(ctx);
		DATA_PAYMENTS_NULL(payments, p_item);
	}
	K_WUNLOCK(payments_free);

	p_item = pay_store->head;
	while (p_item) {
		DATA_PAYMENTS(payments, p_item);
		pok = false;
		K_RLOCK(payouts_free);
		po_item = find_payoutid(payments->payoutid);
		DATA_PAYOUTS_NULL(payouts, po_item);
		if (p_item && PAYGENERATED(payouts->status))
			pok = true;
		K_RUNLOCK(payouts_free);
		if (pok) {
			bigint_to_buf(payouts->payoutid, reply, sizeof(reply));
			snprintf(tmp, sizeof(tmp), "payoutid:%d=%s%c", rows, reply, FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);

			int_to_buf(payouts->height, reply, sizeof(reply));
			snprintf(tmp, sizeof(tmp), "height:%d=%s%c", rows, reply, FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);

			str_to_buf(payments->payaddress, reply, sizeof(reply));
			snprintf(tmp, sizeof(tmp), "payaddress:%d=%s%c", rows, reply, FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);

			bigint_to_buf(payments->amount, reply, sizeof(reply));
			snprintf(tmp, sizeof(tmp), "amount:%d=%s%c", rows, reply, FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);

			tv_to_buf(&(payments->paydate), reply, sizeof(reply));
			snprintf(tmp, sizeof(tmp), "paydate:%d=%s%c", rows, reply, FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);

			rows++;
		}
		p_item = p_item->next;
	}

	snprintf(tmp, sizeof(tmp), "rows=%d%cflds=%s%c",
		 rows, FLDSEP,
		 "payoutid,height,payaddress,amount,paydate", FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);

	snprintf(tmp, sizeof(tmp), "arn=%s%carp=%s", "Payments", FLDSEP, "");
	APPEND_REALLOC(buf, off, len, tmp);

	LOGDEBUG("%s.ok.%s", id, transfer_data(i_username));
	return buf;
}

static char *cmd_percent(char *cmd, char *id, tv_t *now, USERS *users)
{
	K_ITEM w_look, *w_item, us_look, *us_item, *ws_item;
	K_TREE_CTX w_ctx[1], pay_ctx[1];
	WORKERS lookworkers, *workers;
	WORKERSTATUS *workerstatus;
	USERSTATS *userstats;
	char tmp[1024];
	char *buf;
	size_t len, off;
	int rows;

	double t_hashrate5m = 0, t_hashrate1hr = 0;
	double t_hashrate24hr = 0;
	double t_diffacc = 0, t_diffinv = 0;
	double t_diffsta = 0, t_diffdup = 0;
	double t_diffhi = 0, t_diffrej = 0;
	double t_shareacc = 0, t_shareinv = 0;
	double t_sharesta = 0, t_sharedup = 0;
	double t_sharehi = 0, t_sharerej = 0;

	K_ITEM *pa_item;
	PAYMENTADDRESSES *pa;
	int64_t paytotal;
	double ratio;

	LOGDEBUG("%s(): cmd '%s'", __func__, cmd);

	APPEND_REALLOC_INIT(buf, off, len);
	APPEND_REALLOC(buf, off, len, "ok.");
	snprintf(tmp, sizeof(tmp), "blockacc=%.1f%c",
				   pool.diffacc, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "blockreward=%"PRId64"%c",
				   pool.reward, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);

	INIT_WORKERS(&w_look);
	INIT_USERSTATS(&us_look);

	// Add up all user's worker stats to be divided into payout percentages
	lookworkers.userid = users->userid;
	lookworkers.workername[0] = '\0';
	lookworkers.expirydate.tv_sec = 0;
	lookworkers.expirydate.tv_usec = 0;
	w_look.data = (void *)(&lookworkers);
	w_item = find_after_in_ktree(workers_root, &w_look, cmp_workers, w_ctx);
	DATA_WORKERS_NULL(workers, w_item);
	while (w_item && workers->userid == users->userid) {
		if (CURRENT(&(workers->expirydate))) {
			ws_item = get_workerstatus(users->userid, workers->workername);
			if (ws_item) {
				DATA_WORKERSTATUS(workerstatus, ws_item);
				t_diffacc += workerstatus->diffacc;
				t_diffinv += workerstatus->diffinv;
				t_diffsta += workerstatus->diffsta;
				t_diffdup += workerstatus->diffdup;
				t_diffhi  += workerstatus->diffhi;
				t_diffrej += workerstatus->diffrej;
				t_shareacc += workerstatus->shareacc;
				t_shareinv += workerstatus->shareinv;
				t_sharesta += workerstatus->sharesta;
				t_sharedup += workerstatus->sharedup;
				t_sharehi += workerstatus->sharehi;
				t_sharerej += workerstatus->sharerej;
			}

			/* TODO: workers_root userid+worker is ordered
			 *  so no 'find' should be needed -
			 *  just cmp to last 'unused us_item' userid+worker
			 *  then step it forward to be the next ready 'unused' */
			K_RLOCK(userstats_free);
			us_item = find_userstats(users->userid, workers->workername);
			if (us_item) {
				DATA_USERSTATS(userstats, us_item);
				if (tvdiff(now, &(userstats->statsdate)) < USERSTATS_PER_S) {
					t_hashrate5m += userstats->hashrate5m;
					t_hashrate1hr += userstats->hashrate1hr;
					t_hashrate24hr += userstats->hashrate24hr;
				}
			}
			K_RUNLOCK(userstats_free);
		}
		w_item = next_in_ktree(w_ctx);
		DATA_WORKERS_NULL(workers, w_item);
	}

	// Calculate total payratio
	paytotal = 0;
	K_RLOCK(paymentaddresses_free);
	pa_item = find_paymentaddresses(users->userid, pay_ctx);
	DATA_PAYMENTADDRESSES(pa, pa_item);
	while (pa_item && CURRENT(&(pa->expirydate)) &&
	       pa->userid == users->userid) {
		paytotal += pa->payratio;
		pa_item = prev_in_ktree(pay_ctx);
		DATA_PAYMENTADDRESSES_NULL(pa, pa_item);
	}
	if (paytotal == 0)
		paytotal = 1;

	// Divide totals into payout percentages
	rows = 0;
	pa_item = find_paymentaddresses(users->userid, pay_ctx);
	DATA_PAYMENTADDRESSES_NULL(pa, pa_item);
	while (pa_item && CURRENT(&(pa->expirydate)) &&
	       pa->userid == users->userid) {
		ratio = (double)(pa->payratio) / (double)paytotal;

		snprintf(tmp, sizeof(tmp), "payaddress:%d=%s%c",
					   rows, pa->payaddress, FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);

		snprintf(tmp, sizeof(tmp), "payratio:%d=%"PRId32"%c",
					   rows, pa->payratio, FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);

		snprintf(tmp, sizeof(tmp), "paypercent:%d=%.6f%c",
					   rows, ratio * 100.0, FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);

		snprintf(tmp, sizeof(tmp), "p_hashrate5m:%d=%.1f%c", rows,
					   (double)t_hashrate5m * ratio,
					   FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);

		snprintf(tmp, sizeof(tmp), "p_hashrate1hr:%d=%.1f%c", rows,
					   (double)t_hashrate1hr * ratio,
					   FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);

		snprintf(tmp, sizeof(tmp), "p_hashrate24hr:%d=%.1f%c", rows,
					   (double)t_hashrate24hr * ratio,
					   FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);

		snprintf(tmp, sizeof(tmp), "p_diffacc:%d=%.1f%c", rows,
					   (double)t_diffacc * ratio,
					   FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);

		snprintf(tmp, sizeof(tmp), "p_diffinv:%d=%.1f%c", rows,
					   (double)t_diffinv * ratio,
					   FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);

		snprintf(tmp, sizeof(tmp), "p_diffsta:%d=%.1f%c", rows,
					   (double)t_diffsta * ratio,
					   FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);

		snprintf(tmp, sizeof(tmp), "p_diffdup:%d=%.1f%c", rows,
					   (double)t_diffdup * ratio,
					   FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);

		snprintf(tmp, sizeof(tmp), "p_diffhi:%d=%.1f%c", rows,
					   (double)t_diffhi * ratio,
					   FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);

		snprintf(tmp, sizeof(tmp), "p_diffrej:%d=%.1f%c", rows,
					   (double)t_diffrej * ratio,
					   FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);

		snprintf(tmp, sizeof(tmp), "p_shareacc:%d=%.1f%c", rows,
					   (double)t_shareacc * ratio,
					   FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);

		snprintf(tmp, sizeof(tmp), "p_shareinv:%d=%.1f%c", rows,
					   (double)t_shareinv * ratio,
					   FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);

		snprintf(tmp, sizeof(tmp), "p_sharesta:%d=%.1f%c", rows,
					   (double)t_sharesta * ratio,
					   FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);

		snprintf(tmp, sizeof(tmp), "p_sharedup:%d=%.1f%c", rows,
					   (double)t_sharedup * ratio,
					   FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);

		snprintf(tmp, sizeof(tmp), "p_sharehi:%d=%.1f%c", rows,
					   (double)t_sharehi * ratio,
					   FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);

		snprintf(tmp, sizeof(tmp), "p_sharerej:%d=%.1f%c", rows,
					   (double)t_sharerej * ratio,
					   FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);

		rows++;

		pa_item = prev_in_ktree(pay_ctx);
		DATA_PAYMENTADDRESSES_NULL(pa, pa_item);
	}
	K_RUNLOCK(paymentaddresses_free);

	snprintf(tmp, sizeof(tmp),
		 "rows=%d%cflds=%s%c",
		 rows, FLDSEP,
		 "payaddress,payratio,paypercent,"
		 "p_hashrate5m,p_hashrate1hr,p_hashrate24hr,"
		 "p_diffacc,p_diffinv,"
		 "p_diffsta,p_diffdup,p_diffhi,p_diffrej,"
		 "p_shareacc,p_shareinv,"
		 "p_sharesta,p_sharedup,p_sharehi,p_sharerej",
		 FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);

	snprintf(tmp, sizeof(tmp), "arn=%s%carp=%s", "Percents", FLDSEP, "");
	APPEND_REALLOC(buf, off, len, tmp);

	LOGDEBUG("%s.ok.%s", id, users->username);
	return buf;
}

static char *cmd_workers(__maybe_unused PGconn *conn, char *cmd, char *id,
			 tv_t *now, __maybe_unused char *by,
			 __maybe_unused char *code, __maybe_unused char *inet,
			 __maybe_unused tv_t *notcd, K_TREE *trf_root)
{
	K_ITEM *i_username, *i_stats, *i_percent, w_look, *u_item, *w_item;
	K_ITEM *ua_item, *us_item, *ws_item;
	K_TREE_CTX w_ctx[1];
	WORKERS lookworkers, *workers;
	WORKERSTATUS *workerstatus;
	USERSTATS *userstats;
	USERATTS *useratts;
	USERS *users;
	char reply[1024] = "";
	char tmp[1024];
	int64_t oldworkers = USER_OLD_WORKERS_DEFAULT;
	size_t siz = sizeof(reply);
	tv_t last_share;
	char *buf;
	size_t len, off;
	bool stats, percent;
	int rows;

	LOGDEBUG("%s(): cmd '%s'", __func__, cmd);

	i_username = adminuser(trf_root, reply, siz);
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

	percent = false;
	K_RLOCK(useratts_free);
	ua_item = find_useratts(users->userid, USER_MULTI_PAYOUT);
	K_RUNLOCK(useratts_free);
	if (ua_item) {
		i_percent = optional_name(trf_root, "percent", 1, NULL, reply, siz);
		if (i_percent)
			percent = (strcasecmp(transfer_data(i_stats), TRUE_STR) == 0);
	}

	if (percent)
		return cmd_percent(cmd, id, now, users);

	K_RLOCK(useratts_free);
	ua_item = find_useratts(users->userid, USER_OLD_WORKERS);
	K_RUNLOCK(useratts_free);
	if (ua_item) {
		DATA_USERATTS(useratts, ua_item);
		oldworkers = useratts->attnum;
	}

	APPEND_REALLOC_INIT(buf, off, len);
	APPEND_REALLOC(buf, off, len, "ok.");
	snprintf(tmp, sizeof(tmp), "blockacc=%.1f%c",
				   pool.diffacc, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "blockreward=%"PRId64"%c",
				   pool.reward, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "oldworkers=%"PRId64"%c",
				   oldworkers, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	if (oldworkers > 0)
		oldworkers *= 24L * 60L * 60L;
	else
		oldworkers = now->tv_sec + 1;

	INIT_WORKERS(&w_look);

	lookworkers.userid = users->userid;
	lookworkers.workername[0] = '\0';
	lookworkers.expirydate.tv_sec = 0;
	lookworkers.expirydate.tv_usec = 0;
	w_look.data = (void *)(&lookworkers);
	w_item = find_after_in_ktree(workers_root, &w_look, cmp_workers, w_ctx);
	DATA_WORKERS_NULL(workers, w_item);
	rows = 0;
	while (w_item && workers->userid == users->userid) {
		if (CURRENT(&(workers->expirydate))) {
			ws_item = get_workerstatus(users->userid, workers->workername);
			if (ws_item) {
				DATA_WORKERSTATUS(workerstatus, ws_item);
				K_RLOCK(workerstatus_free);
				copy_tv(&last_share, &(workerstatus->last_share));
				K_RUNLOCK(workerstatus_free);
			} else
				last_share.tv_sec = last_share.tv_usec = 0L;

			if (tvdiff(now, &last_share) < oldworkers) {
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

					if (!ws_item) {
						w_lastshare.tv_sec = 0;
						w_lastdiff = w_diffacc = w_diffinv =
						w_diffsta = w_diffdup =
						w_diffhi = w_diffrej =
						w_shareacc = w_shareinv =
						w_sharesta = w_sharedup =
						w_sharehi = w_sharerej = 0;
					} else {
						DATA_WORKERSTATUS(workerstatus, ws_item);
						// It's bad to read possibly changing data
						K_RLOCK(workerstatus_free);
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
						K_RUNLOCK(workerstatus_free);
					}

					/* TODO: workers_root userid+worker is ordered
					 *  so no 'find' should be needed -
					 *  just cmp to last 'unused us_item' userid+worker
					 *  then step it forward to be the next ready 'unused' */
					K_RLOCK(userstats_free);
					us_item = find_userstats(users->userid, workers->workername);
					if (us_item) {
						DATA_USERSTATS(userstats, us_item);
						if (tvdiff(now, &(userstats->statsdate)) < USERSTATS_PER_S) {
							w_hashrate5m += userstats->hashrate5m;
							w_hashrate1hr += userstats->hashrate1hr;
							w_hashrate24hr += userstats->hashrate24hr;
							if (w_elapsed == -1 || w_elapsed > userstats->elapsed)
								w_elapsed = userstats->elapsed;
						}
					}
					K_RUNLOCK(userstats_free);

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
				}
				rows++;
			}
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
	K_STORE *usu_store = k_new_store(userstats_free);
	K_ITEM *us_item, *usu_item, *u_item;
	K_TREE_CTX us_ctx[1];
	USERSTATS *userstats, *userstats_u = NULL;
	USERS *users;
	char reply[1024] = "";
	char tmp[1024];
	char *buf;
	size_t len, off;
	int rows;

	LOGDEBUG("%s(): cmd '%s'", __func__, cmd);

	/* Sum up all recent userstats without workername
	 * i.e. userstasts per username */
	K_WLOCK(userstats_free);
	us_item = first_in_ktree(userstats_root, us_ctx);
	while (us_item) {
		DATA_USERSTATS(userstats, us_item);
		if (tvdiff(now, &(userstats->statsdate)) < ALLUSERS_LIMIT_S) {
			if (!userstats_u || userstats->userid != userstats_u->userid) {
				usu_item = k_unlink_head(userstats_free);
				DATA_USERSTATS(userstats_u, usu_item);

				userstats_u->userid = userstats->userid;
				/* Remember the first workername for if we ever
				 *  get the missing user LOGERR message below */
				STRNCPY(userstats_u->workername, userstats->workername);
				userstats_u->hashrate5m = userstats->hashrate5m;
				userstats_u->hashrate1hr = userstats->hashrate1hr;

				k_add_head(usu_store, usu_item);
			} else {
				userstats_u->hashrate5m += userstats->hashrate5m;
				userstats_u->hashrate1hr += userstats->hashrate1hr;
			}
		}
		us_item = next_in_ktree(us_ctx);
	}
	K_WUNLOCK(userstats_free);

	APPEND_REALLOC_INIT(buf, off, len);
	APPEND_REALLOC(buf, off, len, "ok.");
	rows = 0;
	usu_item = usu_store->head;
	while (usu_item) {
		DATA_USERSTATS(userstats_u, usu_item);
		K_RLOCK(users_free);
		u_item = find_userid(userstats_u->userid);
		K_RUNLOCK(users_free);
		if (!u_item) {
			LOGERR("%s() userstats, but not users, "
			       "ignored %"PRId64"/%s",
			       __func__, userstats_u->userid,
			       userstats_u->workername);
		} else {
			DATA_USERS(users, u_item);
			str_to_buf(users->username, reply, sizeof(reply));
			snprintf(tmp, sizeof(tmp), "username:%d=%s%c", rows, reply, FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);

			bigint_to_buf(users->userid, reply, sizeof(reply));
			snprintf(tmp, sizeof(tmp), "userid:%d=%s%c", rows, reply, FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);

			double_to_buf(userstats_u->hashrate5m, reply, sizeof(reply));
			snprintf(tmp, sizeof(tmp), "u_hashrate5m:%d=%s%c", rows, reply, FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);

			double_to_buf(userstats_u->hashrate1hr, reply, sizeof(reply));
			snprintf(tmp, sizeof(tmp), "u_hashrate1hr:%d=%s%c", rows, reply, FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);

			rows++;
		}
		usu_item = usu_item->next;
	}

	K_WLOCK(userstats_free);
	k_list_transfer_to_head(usu_store, userstats_free);
	K_WUNLOCK(userstats_free);
	k_free_store(usu_store);

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
		} else {
			// Only flag a successful workinfo
			ck_wlock(&last_lock);
			setnow(&last_workinfo);
			ck_wunlock(&last_lock);
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
		} else {
			// Only flag a successful share
			int32_t errn;
			TXT_TO_INT("errn", transfer_data(i_errn), errn);
			ck_wlock(&last_lock);
			if (errn == SE_NONE)
				setnow(&last_share);
			else
				setnow(&last_share_inv);
			ck_wunlock(&last_lock);
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
			 * N.B. this means if you abort/terminate the reload,
			 * next restart will again go back to the oldest
			 * unaged sharesummary due to a pool terminate */
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

	LOGERR("%s.bad.cmd %s", id, cmd);
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
				char *code, char *inet, tv_t *cd,
				K_TREE *trf_root)
{
	K_TREE_CTX ctx[1];
	char reply[1024] = "";
	size_t siz = sizeof(reply);
	K_ITEM *i_poolinstance, *i_username, *i_workername, *i_clientid;
	K_ITEM *i_enonce1, *i_useragent, *i_preauth, *u_item, *oc_item, *w_item;
	USERS *users = NULL;
	char *username;
	WORKERS *workers = NULL;
	OPTIONCONTROL *optioncontrol;
	size_t len, off;
	char *buf;
	bool ok, first;

	LOGDEBUG("%s(): cmd '%s'", __func__, cmd);

	i_poolinstance = optional_name(trf_root, "poolinstance", 1, NULL,
					reply, siz);
	if (!i_poolinstance)
		i_poolinstance = &auth_poolinstance;

	i_username = require_name(trf_root, "username", 1, NULL, reply, siz);
	if (!i_username)
		return strdup(reply);
	username = transfer_data(i_username);

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

	K_RLOCK(optioncontrol_free);
	oc_item = find_optioncontrol(OPTIONCONTROL_AUTOADDUSER, cd, pool.height);
	K_RUNLOCK(optioncontrol_free);
	if (oc_item) {
		K_RLOCK(users_free);
		u_item = find_users(username);
		K_RUNLOCK(users_free);
		if (!u_item) {
			DATA_OPTIONCONTROL(optioncontrol, oc_item);
			u_item = users_add(conn, username, EMPTY,
					   optioncontrol->optionvalue,
					   by, code, inet, cd, trf_root);
		}
	}

	ok = auths_add(conn, transfer_data(i_poolinstance),
			     username,
			     transfer_data(i_workername),
			     transfer_data(i_clientid),
			     transfer_data(i_enonce1),
			     transfer_data(i_useragent),
			     transfer_data(i_preauth),
			     by, code, inet, cd, trf_root, false,
			     &users, &workers);

	if (!ok) {
		LOGDEBUG("%s() %s.failed.DBE", __func__, id);
		return strdup("failed.DBE");
	}

	// Only flag a successful auth
	ck_wlock(&last_lock);
	setnow(&last_auth);
	ck_wunlock(&last_lock);

	if (switch_state < SWITCH_STATE_AUTHWORKERS) {
		snprintf(reply, siz,
			 "ok.authorise={\"secondaryuserid\":\"%s\","
			 "\"difficultydefault\":%d}",
			 users->secondaryuserid, workers->difficultydefault);
		LOGDEBUG("%s.%s", id, reply);
		return strdup(reply);
	}

	APPEND_REALLOC_INIT(buf, off, len);
	snprintf(reply, siz,
		 "ok.authorise={\"secondaryuserid\":\"%s\","
		 "\"workers\":[",
		 users->secondaryuserid);
	APPEND_REALLOC(buf, off, len, reply);
	first = true;
	K_RLOCK(workers_free);
	w_item = first_workers(users->userid, ctx);
	DATA_WORKERS_NULL(workers, w_item);
	while (w_item && workers->userid == users->userid) {
		if (CURRENT(&(workers->expirydate))) {
			snprintf(reply, siz,
				 "%s{\"workername\":\"%s\","
				 "\"difficultydefault\":%"PRId32"}",
				 first ? EMPTY : ",",
				 workers->workername,
				 workers->difficultydefault);
			APPEND_REALLOC(buf, off, len, reply);
			first = false;
		}
		w_item = next_in_ktree(ctx);
		DATA_WORKERS_NULL(workers, w_item);
	}
	K_RUNLOCK(workers_free);
	APPEND_REALLOC(buf, off, len, "]}");

	LOGDEBUG("%s.%s", id, buf);
	return buf;
}

static char *cmd_auth(PGconn *conn, char *cmd, char *id,
			__maybe_unused tv_t *now, char *by,
			char *code, char *inet, tv_t *cd,
			K_TREE *trf_root)
{
	return cmd_auth_do(conn, cmd, id, by, code, inet, cd, trf_root);
}

static char *cmd_addrauth_do(PGconn *conn, char *cmd, char *id, char *by,
				char *code, char *inet, tv_t *cd,
				K_TREE *trf_root)
{
	K_TREE_CTX ctx[1];
	char reply[1024] = "";
	size_t siz = sizeof(reply);
	K_ITEM *i_poolinstance, *i_username, *i_workername, *i_clientid;
	K_ITEM *i_enonce1, *i_useragent, *i_preauth, *w_item;
	USERS *users = NULL;
	WORKERS *workers = NULL;
	size_t len, off;
	char *buf;
	bool ok, first;

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
			     by, code, inet, cd, trf_root, true,
			     &users, &workers);

	if (!ok) {
		LOGDEBUG("%s() %s.failed.DBE", __func__, id);
		return strdup("failed.DBE");
	}

	// Only flag a successful auth
	ck_wlock(&last_lock);
	setnow(&last_auth);
	ck_wunlock(&last_lock);

	if (switch_state < SWITCH_STATE_AUTHWORKERS) {
		snprintf(reply, siz,
			 "ok.addrauth={\"secondaryuserid\":\"%s\","
			 "\"difficultydefault\":%d}",
			 users->secondaryuserid, workers->difficultydefault);
		LOGDEBUG("%s.%s", id, reply);
		return strdup(reply);
	}

	APPEND_REALLOC_INIT(buf, off, len);
	snprintf(reply, siz,
		 "ok.addrauth={\"secondaryuserid\":\"%s\","
		 "\"workers\":[",
		 users->secondaryuserid);
	APPEND_REALLOC(buf, off, len, reply);
	first = true;
	K_RLOCK(workers_free);
	w_item = first_workers(users->userid, ctx);
	DATA_WORKERS_NULL(workers, w_item);
	while (w_item && workers->userid == users->userid) {
		if (CURRENT(&(workers->expirydate))) {
			snprintf(reply, siz,
				 "%s{\"workername\":\"%s\","
				 "\"difficultydefault\":%"PRId32"}",
				 first ? EMPTY : ",",
				 workers->workername,
				 workers->difficultydefault);
			APPEND_REALLOC(buf, off, len, reply);
			first = false;
		}
		w_item = next_in_ktree(ctx);
		DATA_WORKERS_NULL(workers, w_item);
	}
	K_RUNLOCK(workers_free);
	APPEND_REALLOC(buf, off, len, "]}");

	LOGDEBUG("%s.%s", id, buf);
	return buf;
}

static char *cmd_addrauth(PGconn *conn, char *cmd, char *id,
			__maybe_unused tv_t *now, char *by,
			char *code, char *inet, tv_t *cd,
			K_TREE *trf_root)
{
	return cmd_addrauth_do(conn, cmd, id, by, code, inet, cd, trf_root);
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

	ck_wlock(&last_lock);
	setnow(&last_heartbeat);
	ck_wunlock(&last_lock);

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
			  tv_t *now, __maybe_unused char *by,
			  __maybe_unused char *code, __maybe_unused char *inet,
			  __maybe_unused tv_t *notcd, K_TREE *trf_root)
{
	K_ITEM *i_username, *u_item, *b_item, *p_item, *us_item, look;
	K_ITEM *ua_item, *pa_item;
	double u_hashrate5m, u_hashrate1hr;
	char reply[1024], tmp[1024], *buf;
	size_t siz = sizeof(reply);
	USERSTATS lookuserstats, *userstats;
	POOLSTATS *poolstats;
	BLOCKS *blocks;
	USERS *users;
	int64_t u_elapsed;
	K_TREE_CTX ctx[1];
	size_t len, off;
	bool has_uhr;

	LOGDEBUG("%s(): cmd '%s'", __func__, cmd);

	i_username = optional_name(trf_root, "username", 1, NULL, reply, siz);

	APPEND_REALLOC_INIT(buf, off, len);
	APPEND_REALLOC(buf, off, len, "ok.");

	// N.B. cmd_homepage isn't called until startup_complete
	ftv_to_buf(now, reply, siz);
	snprintf(tmp, sizeof(tmp), "now=%s%c", reply, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	ck_wlock(&last_lock);
	ftv_to_buf(&last_heartbeat, reply, siz);
	snprintf(tmp, sizeof(tmp), "lasthb=%s%c", reply, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	ftv_to_buf(&last_workinfo, reply, siz);
	snprintf(tmp, sizeof(tmp), "lastwi=%s%c", reply, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	ftv_to_buf(&last_share, reply, siz);
	snprintf(tmp, sizeof(tmp), "lastsh=%s%c", reply, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	ftv_to_buf(&last_share_inv, reply, siz);
	snprintf(tmp, sizeof(tmp), "lastshinv=%s%c", reply, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	ftv_to_buf(&last_auth, reply, siz);
	ck_wunlock(&last_lock);
	snprintf(tmp, sizeof(tmp), "lastau=%s%c", reply, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);

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

	// Don't bother with locking - it's just an FYI web stat
	snprintf(tmp, sizeof(tmp), "sync=%d%c", workqueue_store->count, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);

	u_item = NULL;
	if (i_username) {
		K_RLOCK(users_free);
		u_item = find_users(transfer_data(i_username));
		K_RUNLOCK(users_free);
	}

	// User info to add to or affect the web site display
	if (u_item) {
		DATA_USERS(users, u_item);
		K_RLOCK(useratts_free);
		ua_item = find_useratts(users->userid, USER_MULTI_PAYOUT);
		K_RUNLOCK(useratts_free);
		if (ua_item) {
			snprintf(tmp, sizeof(tmp),
				 "u_multiaddr=1%c", FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);
		}
		if (!(*(users->emailaddress))) {
			snprintf(tmp, sizeof(tmp),
				 "u_noemail=1%c", FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);
		}
		K_RLOCK(paymentaddresses_free);
		pa_item = find_paymentaddresses(users->userid, ctx);
		K_RUNLOCK(paymentaddresses_free);
		if (!pa_item) {
			snprintf(tmp, sizeof(tmp),
				 "u_nopayaddr=1%c", FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);
		}
	}

	has_uhr = false;
	if (p_item && u_item) {
		u_hashrate5m = u_hashrate1hr = 0.0;
		u_elapsed = -1;
		/* find last matching userid record - before userid+1
		 * Use 'before' in case there is (unexpectedly) a userstats
		 *  with an empty workername */
		lookuserstats.userid = users->userid+1;
		STRNCPY(lookuserstats.workername, EMPTY);
		INIT_USERSTATS(&look);
		look.data = (void *)(&lookuserstats);
		K_RLOCK(userstats_free);
		us_item = find_before_in_ktree(userstats_root, &look, cmp_userstats, ctx);
		DATA_USERSTATS_NULL(userstats, us_item);
		while (us_item && userstats->userid == users->userid) {
			if (tvdiff(now, &(userstats->statsdate)) < USERSTATS_PER_S) {
				u_hashrate5m += userstats->hashrate5m;
				u_hashrate1hr += userstats->hashrate1hr;
				if (u_elapsed == -1 || u_elapsed > userstats->elapsed)
					u_elapsed = userstats->elapsed;
				has_uhr = true;
			}
			us_item = prev_in_ktree(ctx);
			DATA_USERSTATS_NULL(userstats, us_item);
		}
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
		oc_item = find_optioncontrol(ptr, now, pool.height);
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
	K_ITEM *t_item, *oc_item = NULL, *ok = NULL;
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
				ok = optioncontrol_item_add(conn, oc_item, now, begun);
				oc_item = NULL;
				if (ok)
					db++;
				else {
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
		ok = optioncontrol_item_add(conn, oc_item, now, begun);
		oc_item = NULL;
		if (ok)
			db++;
		else {
			reason = "DBERR";
			goto rollback;
		}
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
		snprintf(reply, siz, "ERR.%s", reason);
		LOGERR("%s.%s.%s", cmd, id, reply);
		return strdup(reply);
	}
	snprintf(reply, siz, "ok.set %d", db);
	LOGDEBUG("%s.%s", id, reply);
	return strdup(reply);
}

/* Kept for reference/comparison to cmd_pplns2()
 * This will get different results due to the fact that it uses the current
 *  contents of the payoutaddresses table
 * However, the only differences should be the addresses,
 *  and the breakdown for percent address users,
 *  the totals per user and per payout should still be the same */
static char *cmd_pplns(__maybe_unused PGconn *conn, char *cmd, char *id,
			  __maybe_unused tv_t *now, __maybe_unused char *by,
			  __maybe_unused char *code, __maybe_unused char *inet,
			  __maybe_unused tv_t *notcd, K_TREE *trf_root)
{
	char reply[1024], tmp[1024], *buf;
	char *block_extra, *share_status = EMPTY, *marks_status = EMPTY;
	size_t siz = sizeof(reply);
	K_ITEM *i_height, *i_difftimes, *i_diffadd, *i_allowaged;
	K_ITEM b_look, ss_look, *b_item, *w_item, *ss_item;
	K_ITEM wm_look, *wm_item, ms_look, *ms_item;
	K_ITEM *mu_item, *wb_item, *u_item;
	SHARESUMMARY looksharesummary, *sharesummary;
	WORKMARKERS lookworkmarkers, *workmarkers;
	MARKERSUMMARY lookmarkersummary, *markersummary;
	MININGPAYOUTS *miningpayouts;
	WORKINFO *workinfo;
	TRANSFER *transfer;
	BLOCKS lookblocks, *blocks;
	K_TREE *mu_root;
	K_STORE *mu_store;
	USERS *users;
	int32_t height;
	int64_t block_workinfoid, end_workinfoid;
	int64_t begin_workinfoid;
	int64_t total_share_count, acc_share_count;
	int64_t ss_count, wm_count, ms_count;
	char tv_buf[DATE_BUFSIZ];
	tv_t cd, begin_tv, block_tv, end_tv;
	K_TREE_CTX ctx[1], wm_ctx[1], ms_ctx[1], pay_ctx[1];
	double ndiff, total_diff, elapsed;
	double diff_times = 1.0;
	double diff_add = 0.0;
	double diff_want;
	bool allow_aged = false, countbacklimit;
	char ndiffbin[TXT_SML+1];
	size_t len, off;
	int rows;

	LOGDEBUG("%s(): cmd '%s'", __func__, cmd);

	if (sharesummary_marks_limit)
		marks_status = "ckdb -w load value means pplns may be incorrect";

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

	LOGDEBUG("%s(): height %"PRId32, __func__, height);

	block_tv.tv_sec = block_tv.tv_usec = 0L;
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
		if (blocks->confirmed[0] == BLOCKS_NEW) {
			copy_tv(&block_tv, &(blocks->createdate));
			copy_tv(&end_tv, &(blocks->createdate));
		}
		// Allow any state, but report it
		if (CURRENT(&(blocks->expirydate)))
			break;
		b_item = prev_in_ktree(ctx);
		DATA_BLOCKS_NULL(blocks, b_item);
	}
	K_RUNLOCK(blocks_free);
	if (!b_item || blocks->height != height) {
		snprintf(reply, siz, "ERR.no CURRENT block %d", height);
		return strdup(reply);
	}
	if (block_tv.tv_sec == 0) {
		snprintf(reply, siz, "ERR.block %d missing '%s' record",
				     height,
				     blocks_confirmed(BLOCKS_NEW_STR));
		return strdup(reply);
	}
	LOGDEBUG("%s(): block %"PRId32"/%"PRId64"/%s/%s/%"PRId64,
		 __func__, blocks->height, blocks->workinfoid,
		 blocks->workername, blocks->confirmed, blocks->reward);
	switch (blocks->confirmed[0]) {
		case BLOCKS_NEW:
			block_extra = "Can't be paid out yet";
			break;
		case BLOCKS_ORPHAN:
			block_extra = "Can't be paid out";
			break;
		default:
			block_extra = EMPTY;
			break;
	}
	block_workinfoid = blocks->workinfoid;
	w_item = find_workinfo(block_workinfoid, NULL);
	if (!w_item) {
		snprintf(reply, siz, "ERR.missing workinfo %"PRId64, block_workinfoid);
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

	if (blocks->height > FIVExSTT)
		countbacklimit = true;
	else
		countbacklimit = false;
	LOGDEBUG("%s(): ndiff %.0f limit=%s",
		 __func__, ndiff,
		 countbacklimit ? "true" : "false");
	begin_workinfoid = end_workinfoid = 0;
	total_share_count = acc_share_count = 0;
	total_diff = 0;
	ss_count = wm_count = ms_count = 0;

	mu_store = k_new_store(miningpayouts_free);
	mu_root = new_ktree();

	looksharesummary.workinfoid = block_workinfoid;
	looksharesummary.userid = MAXID;
	looksharesummary.workername = EMPTY;
	INIT_SHARESUMMARY(&ss_look);
	ss_look.data = (void *)(&looksharesummary);
	K_RLOCK(sharesummary_free);
	K_RLOCK(workmarkers_free);
	K_RLOCK(markersummary_free);
	ss_item = find_before_in_ktree(sharesummary_workinfoid_root, &ss_look,
					cmp_sharesummary_workinfoid, ctx);
	DATA_SHARESUMMARY_NULL(sharesummary, ss_item);
	if (ss_item)
		end_workinfoid = sharesummary->workinfoid;
	/* add up all sharesummaries until >= diff_want
	 * also record the latest lastshare - that will be the end pplns time
	 *  which will be >= block_tv */
	while (total_diff < diff_want && ss_item) {
		switch (sharesummary->complete[0]) {
			case SUMMARY_CONFIRM:
				break;
			case SUMMARY_COMPLETE:
				if (allow_aged)
					break;
			default:
				share_status = "Not ready1";
		}

		// Stop before FIVExWID if necessary
		if (countbacklimit && sharesummary->workinfoid <= FIVExWID)
			break;

		ss_count++;
		total_share_count += sharesummary->sharecount;
		acc_share_count += sharesummary->shareacc;
		total_diff += (int64_t)(sharesummary->diffacc);
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
				if (share_status == EMPTY)
					share_status = "Not ready2";
				else
					share_status = "Not ready1+2";
		}
		ss_count++;
		total_share_count += sharesummary->sharecount;
		acc_share_count += sharesummary->shareacc;
		total_diff += (int64_t)(sharesummary->diffacc);
		mu_root = upd_add_mu(mu_root, mu_store,
				     sharesummary->userid,
				     (int64_t)(sharesummary->diffacc));
		ss_item = prev_in_ktree(ctx);
		DATA_SHARESUMMARY_NULL(sharesummary, ss_item);
	}
	LOGDEBUG("%s(): ss %"PRId64" total %.0f want %.0f",
		 __func__, ss_count, total_diff, diff_want);
	/* If we haven't met or exceeded the required N,
	 * move on to the markersummaries */
	if (total_diff < diff_want) {
		lookworkmarkers.expirydate.tv_sec = default_expiry.tv_sec;
		lookworkmarkers.expirydate.tv_usec = default_expiry.tv_usec;
		if (begin_workinfoid != 0)
			lookworkmarkers.workinfoidend = begin_workinfoid;
		else
			lookworkmarkers.workinfoidend = block_workinfoid + 1;
		INIT_WORKMARKERS(&wm_look);
		wm_look.data = (void *)(&lookworkmarkers);
		wm_item = find_before_in_ktree(workmarkers_workinfoid_root, &wm_look,
					       cmp_workmarkers_workinfoid, wm_ctx);
		DATA_WORKMARKERS_NULL(workmarkers, wm_item);
		LOGDEBUG("%s(): workmarkers < %"PRId64, __func__, lookworkmarkers.workinfoidend);
		while (total_diff < diff_want && wm_item && CURRENT(&(workmarkers->expirydate))) {
			if (WMPROCESSED(workmarkers->status)) {
				// Stop before FIVExWID if necessary
				if (countbacklimit && workmarkers->workinfoidstart <= FIVExWID)
					break;

				wm_count++;
				lookmarkersummary.markerid = workmarkers->markerid;
				lookmarkersummary.userid = MAXID;
				lookmarkersummary.workername = EMPTY;
				INIT_MARKERSUMMARY(&ms_look);
				ms_look.data = (void *)(&lookmarkersummary);
				ms_item = find_before_in_ktree(markersummary_root, &ms_look,
							       cmp_markersummary, ms_ctx);
				DATA_MARKERSUMMARY_NULL(markersummary, ms_item);
				// add the whole markerid
				while (ms_item && markersummary->markerid == workmarkers->markerid) {
					if (end_workinfoid == 0)
						end_workinfoid = workmarkers->workinfoidend;
					ms_count++;
					total_share_count += markersummary->sharecount;
					acc_share_count += markersummary->shareacc;
					total_diff += (int64_t)(markersummary->diffacc);
					begin_workinfoid = workmarkers->workinfoidstart;
					if (tv_newer(&end_tv, &(markersummary->lastshare)))
						copy_tv(&end_tv, &(markersummary->lastshare));
					mu_root = upd_add_mu(mu_root, mu_store,
							     markersummary->userid,
							     (int64_t)(markersummary->diffacc));
					ms_item = prev_in_ktree(ms_ctx);
					DATA_MARKERSUMMARY_NULL(markersummary, ms_item);
				}
			}
			wm_item = prev_in_ktree(wm_ctx);
			DATA_WORKMARKERS_NULL(workmarkers, wm_item);
		}
		LOGDEBUG("%s(): wm %"PRId64" ms %"PRId64" total %.0f want %.0f",
			 __func__, wm_count, ms_count, total_diff, diff_want);
	}
	K_RUNLOCK(markersummary_free);
	K_RUNLOCK(workmarkers_free);
	K_RUNLOCK(sharesummary_free);

	LOGDEBUG("%s(): total %.0f want %.0f", __func__, total_diff, diff_want);
	if (total_diff == 0.0) {
		snprintf(reply, siz,
			 "ERR.total share diff 0 before workinfo %"PRId64,
			 block_workinfoid);
		goto shazbot;
	}

	wb_item = find_workinfo(begin_workinfoid, NULL);
	if (!wb_item) {
		snprintf(reply, siz, "ERR.missing begin workinfo record! %"PRId64, block_workinfoid);
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
	snprintf(tmp, sizeof(tmp), "block_status=%s%c",
				   blocks_confirmed(blocks->confirmed), FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "block_extra=%s%c", block_extra, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "share_status=%s%c", share_status, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "marks_status=%s%c", marks_status, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "workername=%s%c", blocks->workername, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "nonce=%s%c", blocks->nonce, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "begin_workinfoid=%"PRId64"%c", begin_workinfoid, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "block_workinfoid=%"PRId64"%c", block_workinfoid, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "end_workinfoid=%"PRId64"%c", end_workinfoid, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "diffacc_total=%.0f%c", total_diff, FLDSEP);
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
		if (!u_item) {
			snprintf(reply, siz,
				 "ERR.unknown userid %"PRId64,
				 miningpayouts->userid);
			goto shazbot;
		}

		DATA_USERS(users, u_item);

		K_ITEM *pa_item;
		PAYMENTADDRESSES *pa;
		int64_t paytotal;
		double amount;
		int count;

		K_RLOCK(paymentaddresses_free);
		pa_item = find_paymentaddresses(miningpayouts->userid, pay_ctx);
		if (pa_item) {
			paytotal = 0;
			DATA_PAYMENTADDRESSES(pa, pa_item);
			while (pa_item && CURRENT(&(pa->expirydate)) &&
			       pa->userid == miningpayouts->userid) {
				paytotal += pa->payratio;
				pa_item = prev_in_ktree(pay_ctx);
				DATA_PAYMENTADDRESSES_NULL(pa, pa_item);
			}
			count = 0;
			pa_item = find_paymentaddresses(miningpayouts->userid, pay_ctx);
			DATA_PAYMENTADDRESSES_NULL(pa, pa_item);
			while (pa_item && CURRENT(&(pa->expirydate)) &&
			       pa->userid == miningpayouts->userid) {
				amount = (double)(miningpayouts->amount) *
					 (double)pa->payratio / (double)paytotal;

				snprintf(tmp, sizeof(tmp),
					 "user:%d=%s.%d%cpayaddress:%d=%s%c",
					 rows, users->username, ++count, FLDSEP,
					 rows, pa->payaddress, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);
				snprintf(tmp, sizeof(tmp),
					 "diffacc_user:%d=%.1f%c",
					 rows, amount, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);
				rows++;

				pa_item = prev_in_ktree(pay_ctx);
				DATA_PAYMENTADDRESSES_NULL(pa, pa_item);
			}
			K_RUNLOCK(paymentaddresses_free);
		} else {
			K_RUNLOCK(paymentaddresses_free);
			snprintf(tmp, sizeof(tmp),
				 "user:%d=%s.0%cpayaddress:%d=%s%c",
				 rows, users->username, FLDSEP,
				 rows, "none", FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);
			snprintf(tmp, sizeof(tmp),
				 "diffacc_user:%d=%"PRId64"%c",
				 rows,
				 miningpayouts->amount,
				 FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);
			rows++;
		}
		mu_item = next_in_ktree(ctx);
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
	snprintf(tmp, sizeof(tmp), "acc_share_count=%"PRId64"%c",
				   acc_share_count, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "total_share_count=%"PRId64"%c",
				   total_share_count, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "ss_count=%"PRId64"%c", ss_count, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "wm_count=%"PRId64"%c", wm_count, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "ms_count=%"PRId64"%c", ms_count, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	// So web can always verify it received all data
	APPEND_REALLOC(buf, off, len, "pplns_last=1");

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

// Generated from the payouts, miningpayouts and payments data
static char *cmd_pplns2(__maybe_unused PGconn *conn, char *cmd, char *id,
			  __maybe_unused tv_t *now, __maybe_unused char *by,
			  __maybe_unused char *code, __maybe_unused char *inet,
			  __maybe_unused tv_t *notcd, K_TREE *trf_root)
{
	char reply[1024], tmp[1024], *buf;
	char *block_extra, *marks_status = EMPTY;
	size_t siz = sizeof(reply);
	K_ITEM *i_height;
	K_ITEM b_look, *b_item, *p_item, *mp_item, *pay_item, *u_item;
	K_ITEM *w_item;
	MININGPAYOUTS *miningpayouts;
	PAYMENTS *payments;
	PAYOUTS *payouts;
	BLOCKS lookblocks, *blocks;
	tv_t block_tv = { 0L, 0L };
	WORKINFO *bworkinfo, *workinfo;
	char ndiffbin[TXT_SML+1];
	double ndiff;
	USERS *users;
	int32_t height;
	K_TREE_CTX b_ctx[1], mp_ctx[1], pay_ctx[1];
	char tv_buf[DATE_BUFSIZ];
	size_t len, off;
	int rows;
	bool pok;

	LOGDEBUG("%s(): cmd '%s'", __func__, cmd);

	if (sharesummary_marks_limit)
		marks_status = "ckdb -w load value means pplns may be incorrect";

	i_height = require_name(trf_root, "height", 1, NULL, reply, siz);
	if (!i_height)
		return strdup(reply);
	TXT_TO_INT("height", transfer_data(i_height), height);

	LOGDEBUG("%s(): height %"PRId32, __func__, height);

	lookblocks.height = height + 1;
	lookblocks.blockhash[0] = '\0';
	INIT_BLOCKS(&b_look);
	b_look.data = (void *)(&lookblocks);
	K_RLOCK(blocks_free);
	b_item = find_before_in_ktree(blocks_root, &b_look, cmp_blocks, b_ctx);
	if (!b_item) {
		K_RUNLOCK(blocks_free);
		snprintf(reply, siz, "ERR.no block height %"PRId32, height);
		return strdup(reply);
	}
	DATA_BLOCKS(blocks, b_item);
	while (b_item && blocks->height == height) {
		if (blocks->confirmed[0] == BLOCKS_NEW)
			copy_tv(&block_tv, &(blocks->createdate));
		// Allow any state, but report it
		if (CURRENT(&(blocks->expirydate)))
			break;
		b_item = prev_in_ktree(b_ctx);
		DATA_BLOCKS_NULL(blocks, b_item);
	}
	K_RUNLOCK(blocks_free);
	if (!b_item || blocks->height != height) {
		snprintf(reply, siz, "ERR.no block height %"PRId32, height);
		return strdup(reply);
	}
	if (block_tv.tv_sec == 0) {
		snprintf(reply, siz, "ERR.block %"PRId32" missing '%s' record",
				     height,
				     blocks_confirmed(BLOCKS_NEW_STR));
		return strdup(reply);
	}
	if (!CURRENT(&(blocks->expirydate))) {
		snprintf(reply, siz, "ERR.no CURRENT block %d"PRId32, height);
		return strdup(reply);
	}
	LOGDEBUG("%s(): block %"PRId32"/%"PRId64"/%s/%s/%"PRId64,
		 __func__, blocks->height, blocks->workinfoid,
		 blocks->workername, blocks->confirmed, blocks->reward);
	switch (blocks->confirmed[0]) {
		case BLOCKS_NEW:
			block_extra = "Can't be paid out yet";
			break;
		case BLOCKS_ORPHAN:
			block_extra = "Can't be paid out";
			break;
		default:
			block_extra = EMPTY;
			break;
	}

	w_item = find_workinfo(blocks->workinfoid, NULL);
	if (!w_item) {
		snprintf(reply, siz, "ERR.missing block workinfo record!"
			 " %"PRId64,
			 blocks->workinfoid);
		return strdup(reply);
	}
	DATA_WORKINFO(bworkinfo, w_item);

	pok = false;
	K_RLOCK(payouts_free);
	p_item = find_payouts(height, blocks->blockhash);
	DATA_PAYOUTS_NULL(payouts, p_item);
	if (p_item && PAYGENERATED(payouts->status))
		pok = true;
	K_RUNLOCK(payouts_free);
	if (!p_item) {
		snprintf(reply, siz, "ERR.no payout for %"PRId32"/%s",
			 height, blocks->blockhash);
		return strdup(reply);
	}
	if (!pok) {
		snprintf(reply, siz, "ERR.payout %"PRId64" status=%s "
			 "for %"PRId32"/%s",
			 payouts->payoutid, payouts->status, height,
			 blocks->blockhash);
		return strdup(reply);
	}

	LOGDEBUG("%s(): total %.1f want %.1f",
		 __func__, payouts->diffused, payouts->diffwanted);

	w_item = find_workinfo(payouts->workinfoidstart, NULL);
	if (!w_item) {
		snprintf(reply, siz, "ERR.missing begin workinfo record!"
			 " %"PRId64,
			 payouts->workinfoidstart);
		return strdup(reply);
	}
	DATA_WORKINFO(workinfo, w_item);

	APPEND_REALLOC_INIT(buf, off, len);
	APPEND_REALLOC(buf, off, len, "ok.");
	snprintf(tmp, sizeof(tmp), "block=%d%c", height, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "block_hash=%s%c", blocks->blockhash, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "block_reward=%"PRId64"%c", blocks->reward, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "miner_reward=%"PRId64"%c", payouts->minerreward, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "block_status=%s%c",
				   blocks_confirmed(blocks->confirmed), FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "block_extra=%s%c", block_extra, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "marks_status=%s%c", marks_status, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "workername=%s%c", blocks->workername, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "nonce=%s%c", blocks->nonce, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "begin_workinfoid=%"PRId64"%c", payouts->workinfoidstart, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "block_workinfoid=%"PRId64"%c", blocks->workinfoid, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "end_workinfoid=%"PRId64"%c", payouts->workinfoidend, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "diffacc_total=%.1f%c", payouts->diffused, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "pplns_elapsed=%"PRId64"%c", payouts->elapsed, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);

	rows = 0;
	K_RLOCK(miningpayouts_free);
	mp_item = first_miningpayouts(payouts->payoutid, mp_ctx);
	K_RUNLOCK(miningpayouts_free);
	DATA_MININGPAYOUTS_NULL(miningpayouts, mp_item);
	while (mp_item && miningpayouts->payoutid == payouts->payoutid) {
		if (CURRENT(&(miningpayouts->expirydate))) {
			int out = 0;
			K_RLOCK(users_free);
			u_item = find_userid(miningpayouts->userid);
			K_RUNLOCK(users_free);
			if (!u_item) {
				snprintf(reply, siz,
					 "ERR.unknown userid %"PRId64,
					 miningpayouts->userid);
				goto shazbot;
			}
			DATA_USERS(users, u_item);

			K_RLOCK(payments_free);
			pay_item = find_first_paypayid(miningpayouts->userid,
							payouts->payoutid,
							pay_ctx);
			DATA_PAYMENTS_NULL(payments, pay_item);
			while (pay_item &&
			       payments->userid == miningpayouts->userid &&
			       payments->payoutid == payouts->payoutid) {
				if (CURRENT(&(payments->expirydate))) {
					snprintf(tmp, sizeof(tmp),
						 "user:%d=%s%c"
						 "payaddress:%d=%s%c"
						 "amount:%d=%"PRId64"%c"
						 "diffacc:%d=%.1f%c",
						 rows, payments->subname, FLDSEP,
						 rows, payments->payaddress, FLDSEP,
						 rows, payments->amount, FLDSEP,
						 rows, payments->diffacc, FLDSEP);
					APPEND_REALLOC(buf, off, len, tmp);
					rows++;
					out++;
				}
				pay_item = next_in_ktree(pay_ctx);
				DATA_PAYMENTS_NULL(payments, pay_item);
			}
			K_RUNLOCK(payments_free);
			if (out == 0) {
				snprintf(tmp, sizeof(tmp),
					 "user:%d=%s.0%c"
					 "payaddress:%d=%s%c"
					 "amount:%d=%"PRId64"%c"
					 "diffacc:%d=%.1f%c",
					 rows, users->username, FLDSEP,
					 rows, "none", FLDSEP,
					 rows, miningpayouts->amount, FLDSEP,
					 rows, miningpayouts->diffacc, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);
				rows++;
			}
		}
		K_RLOCK(miningpayouts_free);
		mp_item = next_in_ktree(mp_ctx);
		K_RUNLOCK(miningpayouts_free);
		DATA_MININGPAYOUTS_NULL(miningpayouts, mp_item);
	}

	snprintf(tmp, sizeof(tmp),
		 "rows=%d%cflds=%s%c",
		 rows, FLDSEP,
		 "user,payaddress,amount,diffacc", FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);

	snprintf(tmp, sizeof(tmp), "arn=%s%carp=%s%c",
				   "Users", FLDSEP, "", FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);

	tv_to_buf(&(workinfo->createdate), tv_buf, sizeof(tv_buf));
	snprintf(tmp, sizeof(tmp), "begin_stamp=%s%c", tv_buf, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "begin_epoch=%ld%c",
				   workinfo->createdate.tv_sec, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	tv_to_buf(&block_tv, tv_buf, sizeof(tv_buf));
	snprintf(tmp, sizeof(tmp), "block_stamp=%s%c", tv_buf, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "block_epoch=%ld%c", block_tv.tv_sec, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	tv_to_buf(&(payouts->lastshareacc), tv_buf, sizeof(tv_buf));
	snprintf(tmp, sizeof(tmp), "end_stamp=%s%c", tv_buf, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "end_epoch=%ld%c",
				   payouts->lastshareacc.tv_sec, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "%s%c", payouts->stats, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	hex2bin(ndiffbin, bworkinfo->bits, 4);
	ndiff = diff_from_nbits(ndiffbin);
	snprintf(tmp, sizeof(tmp), "block_ndiff=%f%c", ndiff, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "diff_want=%.1f%c",
				   payouts->diffwanted, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "acc_share_count=%.0f%c",
				   payouts->shareacc, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	// So web can always verify it received all data
	APPEND_REALLOC(buf, off, len, "pplns_last=1");

	LOGDEBUG("%s.ok.pplns.%s", id, buf);
	return buf;

shazbot:
	return strdup(reply);
}

static char *cmd_payouts(PGconn *conn, char *cmd, char *id, tv_t *now,
			 char *by, char *code, char *inet,
			 __maybe_unused tv_t *cd, K_TREE *trf_root)
{
	char reply[1024] = "";
	size_t siz = sizeof(reply);
	char msg[1024] = "";
	K_ITEM *i_action, *i_payoutid, *i_height, *i_blockhash, *i_addrdate;
	K_ITEM *p_item, *p2_item, *old_p2_item;
	PAYOUTS *payouts, *payouts2, *old_payouts2;
	char *action;
	int64_t payoutid = -1;
	int32_t height = 0;
	char blockhash[TXT_BIG+1];
	tv_t addrdate;
	bool ok = true;

	LOGDEBUG("%s(): cmd '%s'", __func__, cmd);

	i_action = require_name(trf_root, "action", 1, NULL, reply, siz);
	if (!i_action)
		return strdup(reply);
	action = transfer_data(i_action);

	if (strcasecmp(action, "generated") == 0) {
		/* Change the status of a processing payout to generated
		 * Require payoutid
		 * Use this if the payout process completed but the end txn,
		 *  that only updates the payout to generated, failed */
		i_payoutid = require_name(trf_root, "payoutid", 1,
					  (char *)intpatt, reply, siz);
		if (!i_payoutid)
			return strdup(reply);
		TXT_TO_BIGINT("payoutid", transfer_data(i_payoutid), payoutid);

		K_WLOCK(payouts_free);
		p_item = find_payoutid(payoutid);
		if (!p_item) {
			K_WUNLOCK(payouts_free);
			snprintf(reply, siz,
				 "no payout with id %"PRId64, payoutid);
			return strdup(reply);
		}
		DATA_PAYOUTS(payouts, p_item);
		if (!PAYPROCESSING(payouts->status)) {
			K_WUNLOCK(payouts_free);
			snprintf(reply, siz,
				 "status !processing (%s) for payout %"PRId64,
				 payouts->status, payoutid);
			return strdup(reply);
		}
		p2_item = k_unlink_head(payouts_free);
		K_WUNLOCK(payouts_free);

		/* There is a risk of the p_item changing while it's unlocked,
		 *  but since this is a manual interface it's not really likely
		 *  and there'll be an error if something goes wrong
		 * It reports the old and new status */
		DATA_PAYOUTS(payouts2, p2_item);
		bzero(payouts2, sizeof(*payouts2));
		payouts2->payoutid = payouts->payoutid;
		payouts2->height = payouts->height;
		STRNCPY(payouts2->blockhash, payouts->blockhash);
		payouts2->minerreward = payouts->minerreward;
		payouts2->workinfoidstart = payouts->workinfoidstart;
		payouts2->workinfoidend = payouts->workinfoidend;
		payouts2->elapsed = payouts->elapsed;
		STRNCPY(payouts2->status, PAYOUTS_GENERATED_STR);
		payouts2->diffwanted = payouts->diffwanted;
		payouts2->diffused = payouts->diffused;
		payouts2->shareacc = payouts->shareacc;
		copy_tv(&(payouts2->lastshareacc), &(payouts->lastshareacc));
		payouts2->stats = strdup(payouts->stats);

		ok = payouts_add(conn, true, p2_item, &old_p2_item,
				 by, code, inet, now, NULL, false);
		if (!ok) {
			snprintf(reply, siz, "failed payout %"PRId64, payoutid);
			return strdup(reply);
		}
		DATA_PAYOUTS(payouts2, p2_item);
		DATA_PAYOUTS(old_payouts2, old_p2_item);
		snprintf(msg, sizeof(msg),
			 "payout %"PRId64" changed from '%s' to '%s' for "
			 "%"PRId32"/%s",
			 payoutid, old_payouts2->status, payouts2->status,
			 payouts2->height, payouts2->blockhash);
	} else if (strcasecmp(action, "orphan") == 0) {
		/* Change the status of a generated payout to orphaned
		 * Require payoutid
		 * Use this if the orphan process didn't automatically
		 *  update a generated payout to orphaned
		 * TODO: get orphaned blocks to automatically do this */
		i_payoutid = require_name(trf_root, "payoutid", 1,
					  (char *)intpatt, reply, siz);
		if (!i_payoutid)
			return strdup(reply);
		TXT_TO_BIGINT("payoutid", transfer_data(i_payoutid), payoutid);

		K_WLOCK(payouts_free);
		p_item = find_payoutid(payoutid);
		if (!p_item) {
			K_WUNLOCK(payouts_free);
			snprintf(reply, siz,
				 "no payout with id %"PRId64, payoutid);
			return strdup(reply);
		}
		DATA_PAYOUTS(payouts, p_item);
		if (!PAYGENERATED(payouts->status)) {
			K_WUNLOCK(payouts_free);
			snprintf(reply, siz,
				 "status !generated (%s) for payout %"PRId64,
				 payouts->status, payoutid);
			return strdup(reply);
		}
		p2_item = k_unlink_head(payouts_free);
		K_WUNLOCK(payouts_free);

		/* There is a risk of the p_item changing while it's unlocked,
		 *  but since this is a manual interface it's not really likely
		 *  and there'll be an error if something goes wrong
		 * It reports the old and new status */
		DATA_PAYOUTS(payouts2, p2_item);
		bzero(payouts2, sizeof(*payouts2));
		payouts2->payoutid = payouts->payoutid;
		payouts2->height = payouts->height;
		STRNCPY(payouts2->blockhash, payouts->blockhash);
		payouts2->minerreward = payouts->minerreward;
		payouts2->workinfoidstart = payouts->workinfoidstart;
		payouts2->workinfoidend = payouts->workinfoidend;
		payouts2->elapsed = payouts->elapsed;
		STRNCPY(payouts2->status, PAYOUTS_ORPHAN_STR);
		payouts2->diffwanted = payouts->diffwanted;
		payouts2->diffused = payouts->diffused;
		payouts2->shareacc = payouts->shareacc;
		copy_tv(&(payouts2->lastshareacc), &(payouts->lastshareacc));
		payouts2->stats = strdup(payouts->stats);

		ok = payouts_add(conn, true, p2_item, &old_p2_item,
				 by, code, inet, now, NULL, false);
		if (!ok) {
			snprintf(reply, siz, "failed payout %"PRId64, payoutid);
			return strdup(reply);
		}
		DATA_PAYOUTS(payouts2, p2_item);
		DATA_PAYOUTS(old_payouts2, old_p2_item);
		snprintf(msg, sizeof(msg),
			 "payout %"PRId64" changed from '%s' to '%s' for "
			 "%"PRId32"/%s",
			 payoutid, old_payouts2->status, payouts2->status,
			 payouts2->height, payouts2->blockhash);
/*
	} else if (strcasecmp(action, "expire") == 0) {
		/ TODO: Expire the payout - effectively deletes it
		 * Require payoutid
		 * If any payments are paid then don't allow it /
		i_payoutid = require_name(trf_root, "payoutid", 1,
					  (char *)intpatt, reply, siz);
		if (!i_payoutid)
			return strdup(reply);
		TXT_TO_BIGINT("payoutid", transfer_data(i_payoutid), payoutid);

		K_WLOCK(payouts_free);
		p_item = find_payoutid(payoutid);
		if (!p_item) {
			K_WUNLOCK(payouts_free);
			snprintf(reply, siz,
				 "no payout with id %"PRId64, payoutid);
			return strdup(reply);
		}
		p2_item = k_unlink_head(payouts_free);
		K_WUNLOCK(payouts_free);

		DATA_PAYOUTS(payouts2, p2_item);
		bzero(payouts2, sizeof(*payouts2));
		payouts2->payoutid = payouts->payoutid;

		...
*/
	} else if (strcasecmp(action, "process") == 0) {
		/* Generate a payout
		 * Require height, blockhash and addrdate
		 *  addrdate is an epoch integer
		 *   and 0 means uses the default = block NEW createdate
		 *   this is the date to use to determine payoutaddresses
		 * Check the console for processing messages */
		i_height = require_name(trf_root, "height", 6,
					(char *)intpatt, reply, siz);
		if (!i_height)
			return strdup(reply);
		TXT_TO_INT("height", transfer_data(i_height), height);

		i_blockhash = require_name(trf_root, "blockhash", 64,
					   (char *)hashpatt, reply, siz);
		if (!i_blockhash)
			return strdup(reply);
		TXT_TO_STR("blockhash", transfer_data(i_blockhash), blockhash);

		i_addrdate = require_name(trf_root, "addrdate", 1,
					 (char *)intpatt, reply, siz);
		if (!i_addrdate)
			return strdup(reply);
		TXT_TO_CTV("addrdate", transfer_data(i_addrdate), addrdate);

		if (addrdate.tv_sec == 0)
			ok = process_pplns(height, blockhash, NULL);
		else
			ok = process_pplns(height, blockhash, &addrdate);

	} else {
		snprintf(reply, siz, "unknown action '%s'", action);
		LOGERR("%s.%s", id, reply);
		return strdup(reply);
	}

	snprintf(reply, siz, "%s.%s%s%s",
			     ok ? "ok" : "ERR",
			     action,
			     msg[0] ? " " : EMPTY,
			     msg[0] ? msg : EMPTY);
	LOGWARNING("%s.%s", id, reply);
	return strdup(reply);
}

static char *cmd_mpayouts(__maybe_unused PGconn *conn, char *cmd, char *id,
			  __maybe_unused tv_t *now, __maybe_unused char *by,
			  __maybe_unused char *code, __maybe_unused char *inet,
			  __maybe_unused tv_t *notcd,
			  __maybe_unused K_TREE *trf_root)
{
	K_ITEM *i_username, *u_item, *mp_item, *po_item;
	K_TREE_CTX ctx[1];
	MININGPAYOUTS *mp;
	PAYOUTS *payouts;
	USERS *users;
	char reply[1024] = "";
	char tmp[1024];
	size_t siz = sizeof(reply);
	char *buf;
	size_t len, off;
	int rows;

	LOGDEBUG("%s(): cmd '%s'", __func__, cmd);

	i_username = adminuser(trf_root, reply, siz);
	if (!i_username)
		return strdup(reply);

	K_RLOCK(users_free);
	u_item = find_users(transfer_data(i_username));
	K_RUNLOCK(users_free);
	if (!u_item)
		return strdup("bad");
	DATA_USERS(users, u_item);

	APPEND_REALLOC_INIT(buf, off, len);
	APPEND_REALLOC(buf, off, len, "ok.");
	rows = 0;
	K_RLOCK(payouts_free);
	po_item = last_in_ktree(payouts_root, ctx);
	DATA_PAYOUTS_NULL(payouts, po_item);
	/* TODO: allow to see details of a single payoutid
	 *	 if it has multiple items (percent payout user) */
	while (po_item) {
		if (CURRENT(&(payouts->expirydate)) &&
		    PAYGENERATED(payouts->status)) {
			// Not locked ... for now
			mp_item = find_miningpayouts(payouts->payoutid,
						     users->userid);
			if (mp_item) {
				DATA_MININGPAYOUTS(mp, mp_item);

				bigint_to_buf(payouts->payoutid, reply,
					      sizeof(reply));
				snprintf(tmp, sizeof(tmp), "payoutid:%d=%s%c",
							   rows, reply, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);

				int_to_buf(payouts->height, reply,
					   sizeof(reply));
				snprintf(tmp, sizeof(tmp), "height:%d=%s%c",
							   rows, reply, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);

				bigint_to_buf(payouts->elapsed, reply,
					      sizeof(reply));
				snprintf(tmp, sizeof(tmp), "elapsed:%d=%s%c",
							   rows, reply, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);

				bigint_to_buf(mp->amount, reply, sizeof(reply));
				snprintf(tmp, sizeof(tmp), "amount:%d=%s%c",
							   rows, reply, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);

				double_to_buf(mp->diffacc, reply, sizeof(reply));
				snprintf(tmp, sizeof(tmp), "diffacc:%d=%s%c",
							   rows, reply, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);

				bigint_to_buf(payouts->minerreward, reply,
					      sizeof(reply));
				snprintf(tmp, sizeof(tmp), "minerreward:%d=%s%c",
							   rows, reply, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);

				double_to_buf(payouts->diffused, reply,
					      sizeof(reply));
				snprintf(tmp, sizeof(tmp), "diffused:%d=%s%c",
							   rows, reply, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);

				str_to_buf(payouts->status, reply,
					   sizeof(reply));
				snprintf(tmp, sizeof(tmp), "status:%d=%s%c",
							   rows, reply, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);

				rows++;
			}
		}
		po_item = prev_in_ktree(ctx);
		DATA_PAYOUTS_NULL(payouts, po_item);
	}
	K_RUNLOCK(payouts_free);

	snprintf(tmp, sizeof(tmp), "rows=%d%cflds=%s%c",
		 rows, FLDSEP,
		 "payoutid,height,elapsed,amount,diffacc,minerreward,diffused,status",
		 FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);

	snprintf(tmp, sizeof(tmp), "arn=%s%carp=%s", "MiningPayouts", FLDSEP, "");
	APPEND_REALLOC(buf, off, len, tmp);

	LOGDEBUG("%s.ok.%s", id, transfer_data(i_username));
	return buf;
}

/* Find the offset, in list, of the workername
 * -1 means NULL list, empty list or not found */
static int worker_offset(char **list, char *workername)
{
	char *c1, *c2;
	int i;

	if (!list || !(*list))
		return -1;

	/* Find the start of the workername including the SEP */
	c1 = strchr(workername, WORKSEP1);
	c2 = strchr(workername, WORKSEP2);
	if (c1 || c2) {
		if (!c1 || (c1 && c2 && (c2 < c1)))
			c1 = c2;
	}
	// No workername after the username
	if (!c1)
		c1 = WORKERS_EMPTY;
	for (i = 0; list[i]; i++) {
		if (strcmp(c1, list[i]) == 0)
			return i;
	}
	return -1;
}

/* Some arbitrarily large limit, increase it if needed
    (doesn't need to be very large) */
#define SELECT_LIMIT 63

/* select is a string of workernames separated by WORKERS_SEL_SEP
 * Return an array of strings of select broken up
 * The array is terminated by NULL
 *  and will have 0 elements if select is NULL/empty
 * The count of the first occurrence of WORKERS_ALL is returned in *all_count,
 *  or -1 if WORKERS_ALL isn't found */
static char **select_list(char *select, int *all_count)
{
	size_t len, offset, siz;
	char **list = NULL;
	int count;
	char *end;

	*all_count = -1;

	siz = sizeof(char *) * (SELECT_LIMIT + 1);
	list = malloc(siz);
	if (!list)
		quithere(1, "malloc (%d) OOM", (int)siz);
	list[0] = NULL;

	if (select == NULL || *select == '\0')
		return list;

	len = strlen(select);
	count = 0;
	offset = 0;
	while (offset < len) {
		if (select[offset] == WORKERS_SEL_SEP)
			offset++;
		else {
			list[count] = select + offset;
			list[count+1] = NULL;
			end = strchr(list[count], WORKERS_SEL_SEP);
			if (end != NULL) {
				offset = 1 + end - select;
				*end = '\0';
			}

			if (*all_count == -1 &&
			    strcasecmp(list[count], WORKERS_ALL) == 0) {
				*all_count = count;
			}

			if (end == NULL || ++count > SELECT_LIMIT)
				break;
		}
	}
	return list;
}

static char *cmd_shifts(__maybe_unused PGconn *conn, char *cmd, char *id,
			  tv_t *now, __maybe_unused char *by,
			  __maybe_unused char *code, __maybe_unused char *inet,
			  __maybe_unused tv_t *notcd, K_TREE *trf_root)
{
	K_ITEM *i_username, *i_select;
	K_ITEM *u_item, *p_item, *m_item, ms_look, *wm_item, *ms_item, *wi_item;
	K_TREE_CTX wm_ctx[1], ms_ctx[1];
	WORKMARKERS *wm;
	WORKINFO *wi;
	MARKERSUMMARY markersummary, *ms, ms_add;
	PAYOUTS *payouts;
	USERS *users;
	MARKS *marks = NULL;
	char reply[1024] = "";
	char tmp[1024];
	size_t siz = sizeof(reply);
	char *select = NULL;
	char **selects = NULL;
	bool used[SELECT_LIMIT];
	char *buf;
	size_t len, off;
	tv_t marker_end = { 0L, 0L };
	int rows, want, i, where_all;
	int64_t maxrows;
	double wm_count;

	LOGDEBUG("%s(): cmd '%s'", __func__, cmd);

	i_username = adminuser(trf_root, reply, siz);
	if (!i_username)
		return strdup(reply);

	K_RLOCK(users_free);
	u_item = find_users(transfer_data(i_username));
	K_RUNLOCK(users_free);
	if (!u_item)
		return strdup("bad");
	DATA_USERS(users, u_item);

	maxrows = user_sys_setting(users->userid, SHIFTS_SETTING_NAME,
				   SHIFTS_DEFAULT, now);

	K_RLOCK(payouts_free);
	p_item = find_last_payouts();
	K_RUNLOCK(payouts_free);
	if (p_item) {
		DATA_PAYOUTS(payouts, p_item);
		wm_count = payout_stats(payouts, "wm_count");
		wm_count *= 1.42;
		if (maxrows < wm_count)
			maxrows = wm_count;
	}

	i_select = optional_name(trf_root, "select", 1, NULL, reply, siz);
	if (i_select)
		select = strdup(transfer_data(i_select));

	selects = select_list(select, &where_all);
	// Nothing selected = all
	if (*selects == NULL) {
		where_all = 0;
		selects[0] = WORKERS_ALL;
		selects[1] = NULL;
	}

	bzero(used, sizeof(used));
	if (where_all >= 0)
		used[where_all] = true;

	APPEND_REALLOC_INIT(buf, off, len);
	APPEND_REALLOC(buf, off, len, "ok.");
	INIT_MARKERSUMMARY(&ms_look);
	ms_look.data = (void *)(&markersummary);
	rows = 0;
	K_RLOCK(workmarkers_free);
	wm_item = last_in_ktree(workmarkers_workinfoid_root, wm_ctx);
	DATA_WORKMARKERS_NULL(wm, wm_item);
	/* TODO: allow to see details of a single payoutid
	 *	 if it has multiple items (percent payout user) */
	while (rows < (maxrows - 1) && wm_item) {
		if (CURRENT(&(wm->expirydate)) && WMPROCESSED(wm->status)) {
			K_RUNLOCK(workmarkers_free);

			K_RLOCK(marks_free);
			m_item = find_marks(wm->workinfoidend);
			K_RUNLOCK(marks_free);
			DATA_MARKS_NULL(marks, m_item);
			if (m_item == NULL) {
				// Log it but keep going
				LOGERR("%s() missing mark for markerid "
					"%"PRId64"/%s widend %"PRId64,
					__func__, wm->markerid,
					wm->description,
					wm->workinfoidend);
			}

			bzero(&ms_add, sizeof(ms_add));

			markersummary.markerid = wm->markerid;
			markersummary.userid = users->userid;
			markersummary.workername = EMPTY;
			K_RLOCK(markersummary_free);
			ms_item = find_after_in_ktree(markersummary_root, &ms_look,
						      cmp_markersummary, ms_ctx);
			DATA_MARKERSUMMARY_NULL(ms, ms_item);
			while (ms_item && ms->markerid == wm->markerid &&
			       ms->userid == users->userid) {
				ms_add.diffacc += ms->diffacc;
				ms_add.diffrej += ms->diffrej;
				ms_add.shareacc += ms->shareacc;
				ms_add.sharerej += ms->sharerej;

				want = worker_offset(selects, ms->workername);
				if (want >= 0) {
					used[want] = true;
					double_to_buf(ms->diffacc, reply, sizeof(reply));
					snprintf(tmp, sizeof(tmp), "%d_diffacc:%d=%s%c",
								   want, rows, reply, FLDSEP);
					APPEND_REALLOC(buf, off, len, tmp);

					double_to_buf(ms->diffrej, reply, sizeof(reply));
					snprintf(tmp, sizeof(tmp), "%d_diffrej:%d=%s%c",
								   want, rows, reply, FLDSEP);
					APPEND_REALLOC(buf, off, len, tmp);

					double_to_buf(ms->shareacc, reply, sizeof(reply));
					snprintf(tmp, sizeof(tmp), "%d_shareacc:%d=%s%c",
								   want, rows, reply, FLDSEP);
					APPEND_REALLOC(buf, off, len, tmp);

					double_to_buf(ms->sharerej, reply, sizeof(reply));
					snprintf(tmp, sizeof(tmp), "%d_sharerej:%d=%s%c",
								   want, rows, reply, FLDSEP);
					APPEND_REALLOC(buf, off, len, tmp);
				}

				ms_item = next_in_ktree(ms_ctx);
				DATA_MARKERSUMMARY_NULL(ms, ms_item);
			}
			K_RUNLOCK(markersummary_free);

			if (marker_end.tv_sec == 0L) {
				wi_item = next_workinfo(wm->workinfoidend, NULL);
				if (!wi_item) {
					/* There's no workinfo after this shift
					 * Unexpected ... estimate last wid+30s */
					wi_item = find_workinfo(wm->workinfoidend, NULL);
					if (!wi_item) {
						// Nothing is currently locked
						LOGERR("%s() workmarker %"PRId64"/%s."
							" missing widend %"PRId64,
							__func__, wm->markerid,
							wm->description,
							wm->workinfoidend);
						snprintf(reply, siz, "data error 1");
						free(buf);
						free(selects);
						return(strdup(reply));
					}
					DATA_WORKINFO(wi, wi_item);
					copy_tv(&marker_end, &(wi->createdate));
					marker_end.tv_sec += 30;
				} else {
					DATA_WORKINFO(wi, wi_item);
					copy_tv(&marker_end, &(wi->createdate));
				}
			}

			wi_item = find_workinfo(wm->workinfoidstart, NULL);
			if (!wi_item) {
				// Nothing is currently locked
				LOGERR("%s() workmarker %"PRId64"/%s. missing "
					"widstart %"PRId64,
					__func__, wm->markerid, wm->description,
					wm->workinfoidstart);
				snprintf(reply, siz, "data error 2");
				free(buf);
				free(selects);
				return(strdup(reply));
			}
			DATA_WORKINFO(wi, wi_item);

			bigint_to_buf(wm->markerid, reply, sizeof(reply));
			snprintf(tmp, sizeof(tmp), "markerid:%d=%s%c",
					   rows, reply, FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);

			str_to_buf(wm->description, reply, sizeof(reply));
			snprintf(tmp, sizeof(tmp), "shift:%d=%s%c",
						   rows, reply, FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);

			snprintf(tmp, sizeof(tmp), "endmarkextra:%d=%s%c",
						   rows,
						   m_item ? marks->extra : EMPTY,
						   FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);

			ftv_to_buf(&(wi->createdate), reply, sizeof(reply));
			snprintf(tmp, sizeof(tmp), "start:%d=%s%c",
						   rows, reply, FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);

			ftv_to_buf(&marker_end, reply, sizeof(reply));
			snprintf(tmp, sizeof(tmp), "end:%d=%s%c",
						   rows, reply, FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);

			if (where_all >= 0) {
				double_to_buf(ms_add.diffacc, reply, sizeof(reply));
				snprintf(tmp, sizeof(tmp), "%d_diffacc:%d=%s%c",
							   where_all, rows,
							   reply, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);

				double_to_buf(ms_add.diffrej, reply, sizeof(reply));
				snprintf(tmp, sizeof(tmp), "%d_diffrej:%d=%s%c",
							   where_all, rows,
							   reply, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);

				double_to_buf(ms_add.shareacc, reply, sizeof(reply));
				snprintf(tmp, sizeof(tmp), "%d_shareacc:%d=%s%c",
							   where_all, rows,
							   reply, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);

				double_to_buf(ms_add.sharerej, reply, sizeof(reply));
				snprintf(tmp, sizeof(tmp), "%d_sharerej:%d=%s%c",
							   where_all, rows,
							   reply, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);
			}
			rows++;

			// Setup for next shift
			copy_tv(&marker_end, &(wi->createdate));

			K_RLOCK(workmarkers_free);
		}
		wm_item = prev_in_ktree(wm_ctx);
		DATA_WORKMARKERS_NULL(wm, wm_item);
	}
	K_RUNLOCK(workmarkers_free);

	for (i = 0; selects[i]; i++) {
		if (used[i]) {
			snprintf(tmp, sizeof(tmp),
				 "%d_worker=%s%c",
				 i, selects[i], FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);
			snprintf(tmp, sizeof(tmp),
				 "%d_flds=%s%c", i,
				 "diffacc,diffrej,shareacc,sharerej", FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);
		}
	}

	// Missing if all isn't selected
	if (where_all >= 0) {
		snprintf(tmp, sizeof(tmp), "prefix_all=%d_%c",
					   where_all, FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);
	}

	/* rows is an upper limit of rows in each worker
	 * 'all' starts at 0 and finishes at rows-1
	 * other workers start >= 0 and finish <= rows-1 */
	snprintf(tmp, sizeof(tmp), "rows=%d%cflds=%s%c",
				   rows, FLDSEP,
				   "markerid,shift,start,end", FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);

	snprintf(tmp, sizeof(tmp), "arn=%s", "Shifts");
	APPEND_REALLOC(buf, off, len, tmp);
	for (i = 0; selects[i]; i++) {
		if (used[i]) {
			snprintf(tmp, sizeof(tmp), ",Worker_%d", i);
			APPEND_REALLOC(buf, off, len, tmp);
		}
	}

	snprintf(tmp, sizeof(tmp), "%carp=", FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	for (i = 0; selects[i]; i++) {
		if (used[i]) {
			snprintf(tmp, sizeof(tmp), ",%d_", i);
			APPEND_REALLOC(buf, off, len, tmp);
		}
	}

	LOGDEBUG("%s.ok.%s", id, transfer_data(i_username));
	free(selects);
	return(buf);
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

	dsp_ktree(paymentaddresses_create_free, paymentaddresses_root,
		  transfer_data(i_file), NULL);

	dsp_ktree(sharesummary_free, sharesummary_root,
		  transfer_data(i_file), NULL);

	dsp_ktree(userstats_free, userstats_root,
		  transfer_data(i_file), NULL);

	dsp_ktree(markersummary_free, markersummary_root,
		  transfer_data(i_file), NULL);

	dsp_ktree(workmarkers_free, workmarkers_root,
		  transfer_data(i_file), NULL);

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
	USEINFO(paymentaddresses, 1, 2);
	USEINFO(payments, 1, 1);
	USEINFO(accountbalance, 1, 1);
	USEINFO(idcontrol, 1, 0);
	USEINFO(optioncontrol, 1, 1);
	USEINFO(workinfo, 1, 1);
	// Trees don't share items so count as 1 tree
	USEINFO(shares, 2, 1);
	// Trees don't share items so count as 1 tree
	USEINFO(shareerrors, 2, 1);
	// _pool doesn't share items so is included
	USEINFO(sharesummary, 1, 2);
	USEINFO(workmarkers, 1, 2);
	// _pool doesn't share items so is included
	USEINFO(markersummary, 1, 2);
	USEINFO(marks, 1, 1);
	USEINFO(blocks, 1, 1);
	USEINFO(miningpayouts, 1, 1);
	USEINFO(payouts, 1, 2);
	USEINFO(auths, 1, 1);
	USEINFO(poolstats, 1, 1);
	USEINFO(userstats, 2, 1);
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

// TODO: add to heartbeat to disable the miner if active and status != ""
static char *cmd_userstatus(PGconn *conn, char *cmd, char *id, tv_t *now, char *by,
			    char *code, char *inet, __maybe_unused tv_t *cd,
			    K_TREE *trf_root)
{
	char reply[1024] = "";
	size_t siz = sizeof(reply);
	K_ITEM *i_username, *i_userid, *i_status, *u_item;
	int64_t userid;
	char *status;
	USERS *users;
	bool ok;

	LOGDEBUG("%s(): cmd '%s'", __func__, cmd);

	i_username = optional_name(trf_root, "username", 3, (char *)userpatt, reply, siz);
	i_userid = optional_name(trf_root, "userid", 1, (char *)intpatt, reply, siz);
	// Either username or userid
	if (!i_username && !i_userid) {
		snprintf(reply, siz, "failed.invalid/missing userinfo");
		LOGERR("%s.%s", id, reply);
		return strdup(reply);
	}

	// A zero length status re-enables it
	i_status = require_name(trf_root, "status", 0, NULL, reply, siz);
	if (!i_status)
		return strdup(reply);
	status = transfer_data(i_status);

	K_RLOCK(users_free);
	if (i_username)
		u_item = find_users(transfer_data(i_username));
	else {
		TXT_TO_BIGINT("userid", transfer_data(i_userid), userid);
		u_item = find_userid(userid);
	}
	K_RUNLOCK(users_free);

	if (!u_item)
		ok = false;
	else {
		ok = users_update(conn, u_item,
					NULL, NULL,
					NULL,
					by, code, inet, now,
					trf_root,
					status);
	}

	if (!ok) {
		LOGERR("%s() %s.failed.DBE", __func__, id);
		return strdup("failed.DBE");
	}
	DATA_USERS(users, u_item);
	snprintf(reply, siz, "ok.updated %"PRId64" %s status %s",
			     users->userid,
			     users->username,
			     status[0] ? "disabled" : "enabled");
	LOGWARNING("%s.%s", id, reply);
	return strdup(reply);
}

/* Socket interface to the functions that will be used later to automatically
 * create marks, workmarkers and process the workmarkers and sharesummaries
 * to generate markersummaries */
static char *cmd_marks(PGconn *conn, char *cmd, char *id,
			__maybe_unused tv_t *now, char *by,
			char *code, char *inet, tv_t *cd,
			K_TREE *trf_root)
{
	char reply[1024] = "";
	size_t siz = sizeof(reply);
	char tmp[1024] = "";
	char msg[1024] = "";
	K_ITEM *i_action, *i_workinfoid, *i_marktype, *i_description;
	K_ITEM *i_height, *i_status, *i_extra, *m_item, *b_item, *w_item;
	K_ITEM *wm_item, *wm_item_prev, *i_markerid;
	WORKMARKERS *workmarkers;
	K_TREE_CTX ctx[1];
	BLOCKS *blocks;
	MARKS *marks;
	char *action;
	int64_t workinfoid = -1, markerid = -1;
	char *marktype;
	int32_t height = 0;
	char description[TXT_BIG+1] = { '\0' };
	char extra[TXT_BIG+1] = { '\0' };
	char status[TXT_FLAG+1] = { MARK_READY, '\0' };
	bool ok;

	LOGDEBUG("%s(): cmd '%s'", __func__, cmd);

	i_action = require_name(trf_root, "action", 1, NULL, reply, siz);
	if (!i_action)
		return strdup(reply);
	action = transfer_data(i_action);

	if (strcasecmp(action, "add") == 0) {
		/* Add a mark
		 * Require marktype
		 * Require workinfoid for all but 'b'
		 * If marktype is 'b' or 'p' then require height/block (number)
		 * If marktype is 'o' or 'f' then require description
		 * Status optional - default READY */
		i_marktype = require_name(trf_root, "marktype",
					  1, NULL,
					  reply, siz);
		if (!i_marktype)
			return strdup(reply);
		marktype = transfer_data(i_marktype);

		if (marktype[0] != MARKTYPE_BLOCK) {
			i_workinfoid = require_name(trf_root, "workinfoid",
						    1, (char *)intpatt,
						    reply, siz);
			if (!i_workinfoid)
				return strdup(reply);
			TXT_TO_BIGINT("workinfoid",
				      transfer_data(i_workinfoid),
				      workinfoid);
		}

		switch (marktype[0]) {
			case MARKTYPE_BLOCK:
			case MARKTYPE_PPLNS:
				i_height = require_name(trf_root,
							"height",
							1, (char *)intpatt,
							reply, siz);
				if (!i_height)
					return strdup(reply);
				TXT_TO_INT("height", transfer_data(i_height),
					   height);
				K_RLOCK(blocks_free);
				b_item = find_prev_blocks(height+1);
				K_RUNLOCK(blocks_free);
				if (b_item) {
					DATA_BLOCKS(blocks, b_item);
					if (blocks->height != height)
						b_item = NULL;
				}
				if (!b_item) {
					snprintf(reply, siz,
						 "no blocks with height %"PRId32, height);
					return strdup(reply);
				}
				if (marktype[0] == MARKTYPE_BLOCK)
					workinfoid = blocks->workinfoid;

				if (!marks_description(description, sizeof(description),
							marktype, height, NULL, NULL))
					goto dame;
				break;
			case MARKTYPE_SHIFT_BEGIN:
			case MARKTYPE_SHIFT_END:
				snprintf(reply, siz,
					 "marktype %s not yet handled",
					 marks_marktype(marktype));
				return strdup(reply);
			case MARKTYPE_OTHER_BEGIN:
			case MARKTYPE_OTHER_FINISH:
				i_description = require_name(trf_root,
							     "description",
							     1, NULL,
							     reply, siz);
				if (!i_description)
					return strdup(reply);
				if (!marks_description(description, sizeof(description),
							marktype, height, NULL,
							transfer_data(i_description)))
					goto dame;
				break;
			default:
				snprintf(reply, siz,
					 "unknown marktype '%s'", marktype);
				return strdup(reply);
		}
		i_status = optional_name(trf_root, "status", 1, NULL, reply, siz);
		if (i_status) {
			STRNCPY(status, transfer_data(i_status));
			switch(status[0]) {
				case MARK_READY:
				case MARK_USED:
				case '\0':
					break;
				default:
					snprintf(reply, siz,
						 "unknown mark status '%s'", status);
					return strdup(reply);
			}
		}
		if (workinfoid == -1) {
			snprintf(reply, siz, "workinfoid not found");
			return strdup(reply);
		}
		w_item = find_workinfo(workinfoid, NULL);
		if (!w_item) {
			snprintf(reply, siz, "invalid workinfoid %"PRId64,
				 workinfoid);
			return strdup(reply);
		}
		ok = marks_process(conn, true, EMPTY, workinfoid, description,
				   extra, marktype, status, by, code, inet, cd,
				   trf_root);
	} else if (strcasecmp(action, "expire") == 0) {
		/* Expire the mark - effectively deletes it
		 * Require workinfoid */
		i_workinfoid = require_name(trf_root, "workinfoid", 1, (char *)intpatt, reply, siz);
		if (!i_workinfoid)
			return strdup(reply);
		TXT_TO_BIGINT("workinfoid", transfer_data(i_workinfoid), workinfoid);
		K_RLOCK(marks_free);
		m_item = find_marks(workinfoid);
		K_RUNLOCK(marks_free);
		if (!m_item) {
			snprintf(reply, siz,
				 "unknown current mark with workinfoid %"PRId64, workinfoid);
			return strdup(reply);
		}
		ok = marks_process(conn, false, EMPTY, workinfoid, NULL,
				   NULL, NULL, NULL, by, code, inet, cd,
				   trf_root);
	} else if (strcasecmp(action, "status") == 0) {
		/* Change the status on a mark
		 * Require workinfoid and status
		 * N.B. you can cause generate errors if you change the status of a USED marks */
		i_workinfoid = require_name(trf_root, "workinfoid", 1, (char *)intpatt, reply, siz);
		if (!i_workinfoid)
			return strdup(reply);
		TXT_TO_BIGINT("workinfoid", transfer_data(i_workinfoid), workinfoid);
		K_RLOCK(marks_free);
		m_item = find_marks(workinfoid);
		K_RUNLOCK(marks_free);
		if (!m_item) {
			snprintf(reply, siz,
				 "unknown current mark with workinfoid %"PRId64, workinfoid);
			return strdup(reply);
		}
		DATA_MARKS(marks, m_item);
		i_status = require_name(trf_root, "status", 0, NULL, reply, siz);
		if (!i_status)
			return strdup(reply);
		STRNCPY(status, transfer_data(i_status));
		switch(status[0]) {
			case MARK_READY:
			case MARK_USED:
			case '\0':
				break;
			default:
				snprintf(reply, siz,
					 "unknown mark status '%s'", status);
				return strdup(reply);
		}
		// Unchanged
		if (strcmp(status, marks->status) == 0) {
			action = "status-unchanged";
			ok = true;
		} else {
			ok = marks_process(conn, true, marks->poolinstance,
					   workinfoid, marks->description,
					   marks->extra, marks->marktype,
					   status, by, code, inet, cd,
					   trf_root);
		}
	} else if (strcasecmp(action, "extra") == 0) {
		/* Change the 'extra' description
		 * Require workinfoid and extra
		 * If a mark is actually multiple marks with the same
		 *  workinfoid, then we can record the extra info here
		 * This would be true of each block, once shifts are
		 *  implemented, since the current shift ends when a
		 *  block is found
		 * This could also be true, very rarely, if the beginning
		 *  of a pplns payout range matched any other mark,
		 *  since the beginning can be any workinfoid */
		i_workinfoid = require_name(trf_root, "workinfoid", 1, (char *)intpatt, reply, siz);
		if (!i_workinfoid)
			return strdup(reply);
		TXT_TO_BIGINT("workinfoid", transfer_data(i_workinfoid), workinfoid);
		K_RLOCK(marks_free);
		m_item = find_marks(workinfoid);
		K_RUNLOCK(marks_free);
		if (!m_item) {
			snprintf(reply, siz,
				 "unknown current mark with workinfoid %"PRId64, workinfoid);
			return strdup(reply);
		}
		DATA_MARKS(marks, m_item);
		i_extra = require_name(trf_root, "extra", 0, NULL, reply, siz);
		if (!i_extra)
			return strdup(reply);
		STRNCPY(extra, transfer_data(i_extra));
		// Unchanged
		if (strcmp(extra, marks->extra) == 0) {
			action = "extra-unchanged";
			ok = true;
		} else {
			ok = marks_process(conn, true, marks->poolinstance,
					   workinfoid, marks->description,
					   extra, marks->marktype,
					   status, by, code, inet, cd,
					   trf_root);
		}
	} else if (strcasecmp(action, "generate") == 0) {
		/* Generate workmarkers
		 * No parameters */
		tmp[0] = '\0';
		ok = workmarkers_generate(conn, tmp, sizeof(tmp),
					  by, code, inet, cd, trf_root, true);
		if (!ok) {
			snprintf(reply, siz, "%s error: %s", action, tmp);
			LOGERR("%s.%s", id, reply);
			return strdup(reply);
		}
		if (*tmp) {
			snprintf(reply, siz, "%s: %s", action, tmp);
			LOGWARNING("%s.%s", id, reply);
		}
	} else if (strcasecmp(action, "expunge") == 0) {
		/* Expire all generated workmarkers that aren't PROCESSED
		 * No parameters
		 * This exists so we can fix all workmarkers that haven't
		 *  been PROCESSED yet,
		 *  if there was a problem with the marks
		 * Simply expunge all the workmarkers, correct the marks,
		 *  then generate the workmarkers again
		 * WARNING - using psql to do the worksummary generation
		 *  will not update the workmarkers status inside ckdb
		 *  so this will expunge those worksummary records also
		 *  You'll need to restart ckdb after using psql */
		int count = 0;
		ok = true;
		wm_item_prev = NULL;
		K_RLOCK(workmarkers_free);
		wm_item = last_in_ktree(workmarkers_root, ctx);
		K_RUNLOCK(workmarkers_free);
		while (wm_item) {
			K_RLOCK(workmarkers_free);
			wm_item_prev = prev_in_ktree(ctx);
			K_RUNLOCK(workmarkers_free);
			DATA_WORKMARKERS(workmarkers, wm_item);
			if (CURRENT(&(workmarkers->expirydate)) &&
			    !WMPROCESSED(workmarkers->status)) {
				ok = workmarkers_process(conn, false, false,
							 workmarkers->markerid,
							 NULL, 0, 0, NULL, NULL, by,
							 code, inet, cd, trf_root);
				if (!ok)
					break;
				count++;
			}
			wm_item = wm_item_prev;
		}
		if (ok) {
			if (count == 0) {
				snprintf(msg, sizeof(msg),
					 "no unprocessed current workmarkers");
			} else {
				snprintf(msg, sizeof(msg),
					 "%d workmarkers expunged", count);
			}
		}
	} else if (strcasecmp(action, "sum") == 0) {
		/* For the last available workmarker,
		 *  summarise it's sharesummaries into markersummaries
		 * No parameters */
		ok = make_markersummaries(true, by, code, inet, cd, trf_root);
		if (!ok) {
			snprintf(reply, siz, "%s failed", action);
			LOGERR("%s.%s", id, reply);
			return strdup(reply);
		}
	} else if (strcasecmp(action, "processed") == 0) {
		/* Mark a workmarker as processed
		 * Requires markerid */
		i_markerid = require_name(trf_root, "markerid", 1, (char *)intpatt, reply, siz);
		if (!i_markerid)
			return strdup(reply);
		TXT_TO_BIGINT("markerid", transfer_data(i_markerid), markerid);
		K_RLOCK(workmarkers_free);
		wm_item = find_workmarkerid(markerid, true, '\0');
		K_RUNLOCK(workmarkers_free);
		if (!wm_item) {
			snprintf(reply, siz,
				 "unknown workmarkers with markerid %"PRId64, markerid);
			return strdup(reply);
		}
		DATA_WORKMARKERS(workmarkers, wm_item);
		if (WMPROCESSED(workmarkers->status)) {
			snprintf(reply, siz,
				 "already processed markerid %"PRId64, markerid);
			return strdup(reply);
		}
		ok = workmarkers_process(NULL, false, true, markerid,
					 workmarkers->poolinstance,
					 workmarkers->workinfoidend,
					 workmarkers->workinfoidstart,
					 workmarkers->description,
					 MARKER_PROCESSED_STR,
					 by, code, inet, cd, trf_root);
		if (!ok) {
			snprintf(reply, siz, "%s failed", action);
			LOGERR("%s.%s", id, reply);
			return strdup(reply);
		}
	} else {
		snprintf(reply, siz, "unknown action '%s'", action);
		LOGERR("%s.%s", id, reply);
		return strdup(reply);
	}

	if (!ok) {
dame:
		LOGERR("%s() %s.failed.DBE", __func__, id);
		return strdup("failed.DBE");
	}
	if (msg[0])
		snprintf(reply, siz, "ok.%s %s", action, msg);
	else
		snprintf(reply, siz, "ok.%s", action);
	LOGWARNING("%s.%s", id, reply);
	return strdup(reply);
}

// Layout the reply like cmd_shifts so the php/js code is similar
static char *cmd_pshift(__maybe_unused PGconn *conn, char *cmd, char *id,
			  tv_t *now, __maybe_unused char *by,
			  __maybe_unused char *code, __maybe_unused char *inet,
			  __maybe_unused tv_t *notcd, K_TREE *trf_root)
{
	K_ITEM *i_username;
	K_ITEM *u_item, *p_item, *m_item, *wm_item, *ms_item, *wi_item;
	K_TREE_CTX wm_ctx[1];
	WORKMARKERS *wm;
	WORKINFO *wi;
	MARKERSUMMARY *ms;
	PAYOUTS *payouts;
	USERS *users;
	MARKS *marks = NULL;
	char reply[1024] = "";
	char tmp[1024];
	size_t siz = sizeof(reply);
	char *buf;
	size_t len, off;
	tv_t marker_end = { 0L, 0L };
	int rows;
	int64_t maxrows;
	double wm_count;

	LOGDEBUG("%s(): cmd '%s'", __func__, cmd);

	i_username = adminuser(trf_root, reply, siz);
	if (!i_username)
		return strdup(reply);

	K_RLOCK(users_free);
	u_item = find_users(transfer_data(i_username));
	K_RUNLOCK(users_free);
	if (!u_item)
		return strdup("bad");
	DATA_USERS(users, u_item);

	maxrows = user_sys_setting(users->userid, SHIFTS_SETTING_NAME,
				   SHIFTS_DEFAULT, now);

	K_RLOCK(payouts_free);
	p_item = find_last_payouts();
	K_RUNLOCK(payouts_free);
	if (p_item) {
		DATA_PAYOUTS(payouts, p_item);
		wm_count = payout_stats(payouts, "wm_count");
		wm_count *= 1.42;
		if (maxrows < wm_count)
			maxrows = wm_count;
	}

	APPEND_REALLOC_INIT(buf, off, len);
	APPEND_REALLOC(buf, off, len, "ok.");
	rows = 0;
	K_RLOCK(workmarkers_free);
	wm_item = last_in_ktree(workmarkers_workinfoid_root, wm_ctx);
	DATA_WORKMARKERS_NULL(wm, wm_item);
	while (rows < (maxrows - 1) && wm_item) {
		if (CURRENT(&(wm->expirydate)) && WMPROCESSED(wm->status)) {
			K_RUNLOCK(workmarkers_free);

			K_RLOCK(marks_free);
			m_item = find_marks(wm->workinfoidend);
			K_RUNLOCK(marks_free);
			DATA_MARKS_NULL(marks, m_item);
			if (m_item == NULL) {
				// Log it but keep going
				LOGERR("%s() missing mark for markerid "
					"%"PRId64"/%s widend %"PRId64,
					__func__, wm->markerid,
					wm->description,
					wm->workinfoidend);
			}

			K_RLOCK(markersummary_free);
			ms_item = find_markersummary_p(wm->markerid);
			K_RUNLOCK(markersummary_free);
			if (ms_item) {
				DATA_MARKERSUMMARY(ms, ms_item);
				double_to_buf(ms->diffacc, reply, sizeof(reply));
				snprintf(tmp, sizeof(tmp), "%d_diffacc:%d=%s%c",
							   0, rows, reply, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);

				double_to_buf(ms->diffrej, reply, sizeof(reply));
				snprintf(tmp, sizeof(tmp), "%d_diffrej:%d=%s%c",
							   0, rows, reply, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);

				double_to_buf(ms->shareacc, reply, sizeof(reply));
				snprintf(tmp, sizeof(tmp), "%d_shareacc:%d=%s%c",
							   0, rows, reply, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);

				double_to_buf(ms->sharerej, reply, sizeof(reply));
				snprintf(tmp, sizeof(tmp), "%d_sharerej:%d=%s%c",
							   0, rows, reply, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);
			}

			if (marker_end.tv_sec == 0L) {
				wi_item = next_workinfo(wm->workinfoidend, NULL);
				if (!wi_item) {
					/* There's no workinfo after this shift
					 * Unexpected ... estimate last wid+30s */
					wi_item = find_workinfo(wm->workinfoidend, NULL);
					if (!wi_item) {
						// Nothing is currently locked
						LOGERR("%s() workmarker %"PRId64"/%s."
							" missing widend %"PRId64,
							__func__, wm->markerid,
							wm->description,
							wm->workinfoidend);
						snprintf(reply, siz, "data error 1");
						free(buf);
						return(strdup(reply));
					}
					DATA_WORKINFO(wi, wi_item);
					copy_tv(&marker_end, &(wi->createdate));
					marker_end.tv_sec += 30;
				} else {
					DATA_WORKINFO(wi, wi_item);
					copy_tv(&marker_end, &(wi->createdate));
				}
			}

			wi_item = find_workinfo(wm->workinfoidstart, NULL);
			if (!wi_item) {
				// Nothing is currently locked
				LOGERR("%s() workmarker %"PRId64"/%s. missing "
					"widstart %"PRId64,
					__func__, wm->markerid, wm->description,
					wm->workinfoidstart);
				snprintf(reply, siz, "data error 2");
				free(buf);
				return(strdup(reply));
			}
			DATA_WORKINFO(wi, wi_item);

			bigint_to_buf(wm->markerid, reply, sizeof(reply));
			snprintf(tmp, sizeof(tmp), "markerid:%d=%s%c",
					   rows, reply, FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);

			str_to_buf(wm->description, reply, sizeof(reply));
			snprintf(tmp, sizeof(tmp), "shift:%d=%s%c",
						   rows, reply, FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);

			snprintf(tmp, sizeof(tmp), "endmarkextra:%d=%s%c",
						   rows,
						   m_item ? marks->extra : EMPTY,
						   FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);

			ftv_to_buf(&(wi->createdate), reply, sizeof(reply));
			snprintf(tmp, sizeof(tmp), "start:%d=%s%c",
						   rows, reply, FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);

			ftv_to_buf(&marker_end, reply, sizeof(reply));
			snprintf(tmp, sizeof(tmp), "end:%d=%s%c",
						   rows, reply, FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);

			rows++;

			// Setup for next shift
			copy_tv(&marker_end, &(wi->createdate));

			K_RLOCK(workmarkers_free);
		}
		wm_item = prev_in_ktree(wm_ctx);
		DATA_WORKMARKERS_NULL(wm, wm_item);
	}
	K_RUNLOCK(workmarkers_free);

	snprintf(tmp, sizeof(tmp), "%d_pool=%s%c", 0, "all", FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "%d_flds=%s%c",
		 0, "diffacc,diffrej,shareacc,sharerej", FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "prefix_all=%d_%c", 0, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "rows=%d%cflds=%s%c",
				   rows, FLDSEP,
				   "markerid,shift,start,end", FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "arn=%s", "Pool Shifts");
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), ",Pool_%d", 0);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "%carp=", FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), ",%d_", 0);
	APPEND_REALLOC(buf, off, len, tmp);

	LOGDEBUG("%s.ok.%s", id, transfer_data(i_username));
	return(buf);
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
 *	terminate
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
	{ CMD_TERMINATE, "terminate",	true,	false,	NULL,		ACCESS_SYSTEM },
	{ CMD_PING,	"ping",		true,	false,	NULL,		ACCESS_SYSTEM ACCESS_POOL ACCESS_WEB },
	{ CMD_VERSION,	"version",	true,	false,	NULL,		ACCESS_SYSTEM ACCESS_POOL ACCESS_WEB },
	{ CMD_LOGLEVEL,	"loglevel",	true,	false,	NULL,		ACCESS_SYSTEM },
	{ CMD_FLUSH,	"flush",	true,	false,	NULL,		ACCESS_SYSTEM },
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
	{ CMD_WORKERSTAT,"workerstats",	false,	true,	cmd_workerstats,ACCESS_POOL },
	{ CMD_BLOCK,	"block",	false,	true,	cmd_blocks,	ACCESS_POOL },
	{ CMD_BLOCKLIST,"blocklist",	false,	false,	cmd_blocklist,	ACCESS_WEB },
	{ CMD_BLOCKSTATUS,"blockstatus",false,	false,	cmd_blockstatus,ACCESS_SYSTEM },
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
	{ CMD_STATS,	"stats",	true,	false,	cmd_stats,	ACCESS_SYSTEM ACCESS_WEB },
	{ CMD_PPLNS,	"pplns",	false,	false,	cmd_pplns,	ACCESS_SYSTEM ACCESS_WEB },
	{ CMD_PPLNS2,	"pplns2",	false,	false,	cmd_pplns2,	ACCESS_SYSTEM ACCESS_WEB },
	{ CMD_PAYOUTS,	"payouts",	false,	false,	cmd_payouts,	ACCESS_SYSTEM },
	{ CMD_MPAYOUTS,	"mpayouts",	false,	false,	cmd_mpayouts,	ACCESS_SYSTEM ACCESS_WEB },
	{ CMD_SHIFTS,	"shifts",	false,	false,	cmd_shifts,	ACCESS_SYSTEM ACCESS_WEB },
	{ CMD_USERSTATUS,"userstatus",	false,	false,	cmd_userstatus,	ACCESS_SYSTEM ACCESS_WEB },
	{ CMD_MARKS,	"marks",	false,	false,	cmd_marks,	ACCESS_SYSTEM },
	{ CMD_PSHIFT,	"pshift",	false,	false,	cmd_pshift,	ACCESS_SYSTEM ACCESS_WEB },
	{ CMD_END,	NULL,		false,	false,	NULL,		NULL }
};
