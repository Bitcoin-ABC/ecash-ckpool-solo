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
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <dirent.h>
#include <fcntl.h>
#include <math.h>
#include <string.h>
#include <unistd.h>

#include "ckpool.h"
#include "libckpool.h"
#include "bitcoin.h"
#include "sha2.h"
#include "stratifier.h"
#include "uthash.h"
#include "utlist.h"

/* Consistent across all pool instances */
static const char *workpadding = "000000800000000000000000000000000000000000000000000000000000000000000000000000000000000080020000";
static const char *scriptsig_header = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff";
static uchar scriptsig_header_bin[41];

/* Add unaccounted shares when they arrive, remove them with each update of
 * rolling stats. */
struct pool_stats {
	tv_t start_time;
	ts_t last_update;

	int workers;
	int users;
	int disconnected;
	int dead;

	/* Absolute shares stats */
	int64_t unaccounted_shares;
	int64_t accounted_shares;

	/* Cycle of 24 to determine which users to dump stats on */
	uint8_t userstats_cycle;

	/* Shares per second for 1/5/15/60 minute rolling averages */
	double sps1;
	double sps5;
	double sps15;
	double sps60;

	/* Diff shares stats */
	int64_t unaccounted_diff_shares;
	int64_t accounted_diff_shares;
	int64_t unaccounted_rejects;
	int64_t accounted_rejects;

	/* Diff shares per second for 1/5/15... minute rolling averages */
	double dsps1;
	double dsps5;
	double dsps15;
	double dsps60;
	double dsps360;
	double dsps1440;
	double dsps10080;
};

typedef struct pool_stats pool_stats_t;

struct workbase {
	/* Hash table data */
	UT_hash_handle hh;
	int64_t id;
	char idstring[20];

	ts_t gentime;

	/* GBT/shared variables */
	char target[68];
	double diff;
	double network_diff;
	uint32_t version;
	uint32_t curtime;
	char prevhash[68];
	char ntime[12];
	uint32_t ntime32;
	char bbversion[12];
	char nbit[12];
	uint64_t coinbasevalue;
	int height;
	char *flags;
	int transactions;
	char *txn_data;
	char *txn_hashes;
	int merkles;
	char merklehash[16][68];
	char merklebin[16][32];
	json_t *merkle_array;

	/* Template variables, lengths are binary lengths! */
	char *coinb1; // coinbase1
	uchar *coinb1bin;
	int coinb1len; // length of above

	char enonce1const[32]; // extranonce1 section that is constant
	uchar enonce1constbin[16];
	int enonce1constlen; // length of above - usually zero unless proxying
	int enonce1varlen; // length of unique extranonce1 string for each worker - usually 8

	int enonce2varlen; // length of space left for extranonce2 - usually 8 unless proxying

	char *coinb2; // coinbase2
	uchar *coinb2bin;
	int coinb2len; // length of above
	int genoffset; // Offset into coinbase2 where the generation txn is

	/* Cached header binary */
	char headerbin[112];

	char *logdir;

	ckpool_t *ckp;
	bool proxy;
};

typedef struct workbase workbase_t;

struct json_params {
	json_t *method;
	json_t *params;
	json_t *id_val;
	int64_t client_id;
	char address[INET6_ADDRSTRLEN];
};

typedef struct json_params json_params_t;

/* Stratum json messages with their associated client id */
struct smsg {
	json_t *json_msg;
	int64_t client_id;
	char address[INET6_ADDRSTRLEN];
};

typedef struct smsg smsg_t;

struct userwb {
	UT_hash_handle hh;
	int64_t id;

	workbase_t *wb; // Master workbase
	uchar *coinb2bin; // Coinb2 cointaining this user's address for generation
	char *coinb2;
};

struct user_instance;
struct worker_instance;
struct stratum_instance;

typedef struct user_instance user_instance_t;
typedef struct worker_instance worker_instance_t;
typedef struct stratum_instance stratum_instance_t;

struct user_instance {
	UT_hash_handle hh;
	char username[128];
	int64_t id;
	char *secondaryuserid;
	bool btcaddress;

	/* A linked list of all connected instances of this user */
	stratum_instance_t *instances;

	/* A linked list of all connected workers of this user */
	worker_instance_t *worker_instances;

	int workers;
	char txnbin[25];
	struct userwb *userwbs;

	double best_diff; /* Best share found by this user */

	double dsps1; /* Diff shares per second, 1 minute rolling average */
	double dsps5; /* ... 5 minute ... */
	double dsps60;/* etc */
	double dsps1440;
	double dsps10080;
	tv_t last_share;

	bool authorised; /* Has this username ever been authorised? */
	time_t auth_time;
};

/* Combined data from workers with the same workername */
struct worker_instance {
	user_instance_t *instance;
	char *workername;

	worker_instance_t *next;
	worker_instance_t *prev;

	double dsps1;
	double dsps5;
	double dsps60;
	double dsps1440;
	tv_t last_share;
	time_t start_time;

	double best_diff; /* Best share found by this worker */
	int mindiff; /* User chosen mindiff */

	bool idle;
	bool notified_idle;
};

/* Per client stratum instance == workers */
struct stratum_instance {
	UT_hash_handle hh;
	int64_t id;

	stratum_instance_t *next;
	stratum_instance_t *prev;

	/* Reference count for when this instance is used outside of the
	 * instance_lock */
	int ref;

	char enonce1[32];
	uchar enonce1bin[16];
	char enonce1var[12];
	uint64_t enonce1_64;

	int64_t diff; /* Current diff */
	int64_t old_diff; /* Previous diff */
	int64_t diff_change_job_id; /* Last job_id we changed diff */
	double dsps1; /* Diff shares per second, 1 minute rolling average */
	double dsps5; /* ... 5 minute ... */
	double dsps60;/* etc */
	double dsps1440;
	double dsps10080;
	tv_t ldc; /* Last diff change */
	int ssdc; /* Shares since diff change */
	tv_t first_share;
	tv_t last_share;
	time_t first_invalid; /* Time of first invalid in run of non stale rejects */
	time_t start_time;

	char address[INET6_ADDRSTRLEN];
	bool subscribed;
	bool authorised;
	bool dropped;
	bool idle;
	int reject;	/* Indicator that this client is having a run of rejects
			 * or other problem and should be dropped lazily if
			 * this is set to 2 */

	user_instance_t *user_instance;
	worker_instance_t *worker_instance;

	char *useragent;
	char *workername;
	int64_t user_id;
	int server; /* Which server is this instance bound to */

	ckpool_t *ckp;

	time_t last_txns; /* Last time this worker requested txn hashes */
	time_t disconnected_time; /* Time this instance disconnected */

	int64_t suggest_diff; /* Stratum client suggested diff */
	double best_diff; /* Best share found by this instance */
};

struct share {
	UT_hash_handle hh;
	uchar hash[32];
	int64_t workbase_id;
};

typedef struct share share_t;

struct stratifier_data {
	char pubkeytxnbin[25];
	char donkeytxnbin[25];

	pool_stats_t stats;
	/* Protects changes to pool stats */
	pthread_mutex_t stats_lock;

	/* Serialises sends/receives to ckdb if possible */
	pthread_mutex_t ckdb_lock;

	bool ckdb_offline;

	/* Variable length enonce1 always refers back to a u64 */
	union {
		uint64_t u64;
		uint32_t u32;
		uint16_t u16;
		uint8_t u8;
	} enonce1u;

	/* For protecting the hashtable data */
	cklock_t workbase_lock;

	/* For the hashtable of all workbases */
	workbase_t *workbases;
	workbase_t *current_workbase;
	int workbases_generated;

	int64_t workbase_id;
	int64_t blockchange_id;
	char lasthash[68];
	char lastswaphash[68];

	ckmsgq_t *ssends;	// Stratum sends
	ckmsgq_t *srecvs;	// Stratum receives
	ckmsgq_t *ckdbq;	// ckdb
	ckmsgq_t *sshareq;	// Stratum share sends
	ckmsgq_t *sauthq;	// Stratum authorisations
	ckmsgq_t *stxnq;	// Transaction requests

	int64_t user_instance_id;

	/* Stratum_instances hashlist is stored by id, whereas disconnected_instances
	 * is sorted by enonce1_64. */
	stratum_instance_t *stratum_instances;
	stratum_instance_t *disconnected_instances;
	stratum_instance_t *dead_instances;

	int stratum_generated;
	int disconnected_generated;
	int dead_generated;

	user_instance_t *user_instances;

	/* Protects both stratum and user instances */
	cklock_t instance_lock;

	share_t *shares;
	cklock_t share_lock;

	int64_t shares_generated;

	/* Linked list of block solves, added to during submission, removed on
	 * accept/reject. It is likely we only ever have one solve on here but
	 * you never know... */
	pthread_mutex_t block_lock;
	ckmsg_t *block_solves;

	/* Generator message priority */
	int gen_priority;

	struct {
		double diff;

		char enonce1[32];
		uchar enonce1bin[16];
		int enonce1constlen;
		int enonce1varlen;

		int nonce2len;
		int enonce2varlen;

		bool subscribed;
	} proxy_base;
};

typedef struct stratifier_data sdata_t;

/* Priority levels for generator messages */
#define GEN_LAX 0
#define GEN_NORMAL 1
#define GEN_PRIORITY 2

#define ID_AUTH 0
#define ID_WORKINFO 1
#define ID_AGEWORKINFO 2
#define ID_SHARES 3
#define ID_SHAREERR 4
#define ID_POOLSTATS 5
#define ID_WORKERSTATS 6
#define ID_BLOCK 7
#define ID_ADDRAUTH 8
#define ID_HEARTBEAT 9

static const char *ckdb_ids[] = {
	"authorise",
	"workinfo",
	"ageworkinfo",
	"shares",
	"shareerror",
	"poolstats",
	"workerstats",
	"block",
	"addrauth",
	"heartbeat"
};

static void generate_coinbase(ckpool_t *ckp, workbase_t *wb)
{
	uint64_t *u64, g64, d64 = 0;
	sdata_t *sdata = ckp->data;
	char header[228];
	int len, ofs = 0;
	ts_t now;

	/* Set fixed length coinb1 arrays to be more than enough */
	wb->coinb1 = ckzalloc(256);
	wb->coinb1bin = ckzalloc(128);

	/* Strings in wb should have been zero memset prior. Generate binary
	 * templates first, then convert to hex */
	memcpy(wb->coinb1bin, scriptsig_header_bin, 41);
	ofs += 41; // Fixed header length;

	ofs++; // Script length is filled in at the end @wb->coinb1bin[41];

	/* Put block height at start of template */
	len = ser_number(wb->coinb1bin + ofs, wb->height);
	ofs += len;

	/* Followed by flag */
	len = strlen(wb->flags) / 2;
	wb->coinb1bin[ofs++] = len;
	hex2bin(wb->coinb1bin + ofs, wb->flags, len);
	ofs += len;

	/* Followed by timestamp */
	ts_realtime(&now);
	len = ser_number(wb->coinb1bin + ofs, now.tv_sec);
	ofs += len;

	/* Followed by our unique randomiser based on the nsec timestamp */
	len = ser_number(wb->coinb1bin + ofs, now.tv_nsec);
	ofs += len;

	wb->enonce1varlen = ckp->nonce1length;
	wb->enonce2varlen = ckp->nonce2length;
	wb->coinb1bin[ofs++] = wb->enonce1varlen + wb->enonce2varlen;

	wb->coinb1len = ofs;

	len = wb->coinb1len - 41;

	len += wb->enonce1varlen;
	len += wb->enonce2varlen;

	wb->coinb2bin = ckzalloc(256);
	memcpy(wb->coinb2bin, "\x0a\x63\x6b\x70\x6f\x6f\x6c", 7);
	wb->coinb2len = 7;
	if (ckp->btcsig) {
		int siglen = strlen(ckp->btcsig);

		LOGDEBUG("Len %d sig %s", siglen, ckp->btcsig);
		if (siglen) {
			wb->coinb2bin[wb->coinb2len++] = siglen;
			memcpy(wb->coinb2bin + wb->coinb2len, ckp->btcsig, siglen);
			wb->coinb2len += siglen;
		}
	}
	len += wb->coinb2len;

	wb->coinb1bin[41] = len - 1; /* Set the length now */
	__bin2hex(wb->coinb1, wb->coinb1bin, wb->coinb1len);
	LOGDEBUG("Coinb1: %s", wb->coinb1);
	/* Coinbase 1 complete */

	memcpy(wb->coinb2bin + wb->coinb2len, "\xff\xff\xff\xff", 4);
	wb->coinb2len += 4;

	// Generation value
	g64 = wb->coinbasevalue;
	if (ckp->donvalid) {
		d64 = g64 / 200; // 0.5% donation
		g64 -= d64; // To guarantee integers add up to the original coinbasevalue
		wb->coinb2bin[wb->coinb2len++] = 2; // 2 transactions
	} else
		wb->coinb2bin[wb->coinb2len++] = 1; // 2 transactions

	u64 = (uint64_t *)&wb->coinb2bin[wb->coinb2len];
	*u64 = htole64(g64);
	wb->coinb2len += 8;

	wb->coinb2bin[wb->coinb2len++] = 25;
	wb->genoffset = wb->coinb2len; // This is where the generation txn is
	memcpy(wb->coinb2bin + wb->coinb2len, sdata->pubkeytxnbin, 25);
	wb->coinb2len += 25;

	if (ckp->donvalid) {
		u64 = (uint64_t *)&wb->coinb2bin[wb->coinb2len];
		*u64 = htole64(d64);
		wb->coinb2len += 8;

		wb->coinb2bin[wb->coinb2len++] = 25;
		memcpy(wb->coinb2bin + wb->coinb2len, sdata->donkeytxnbin, 25);
		wb->coinb2len += 25;
	}

	wb->coinb2len += 4; // Blank lock

	wb->coinb2 = bin2hex(wb->coinb2bin, wb->coinb2len);
	LOGDEBUG("Coinb2: %s", wb->coinb2);
	/* Coinbase 2 complete */

	snprintf(header, 225, "%s%s%s%s%s%s%s",
		 wb->bbversion, wb->prevhash,
		 "0000000000000000000000000000000000000000000000000000000000000000",
		 wb->ntime, wb->nbit,
		 "00000000", /* nonce */
		 workpadding);
	LOGDEBUG("Header: %s", header);
	hex2bin(wb->headerbin, header, 112);
}

static void stratum_broadcast_update(sdata_t *sdata, bool clean);
static void stratum_broadcast_updates(sdata_t *sdata, bool clean);

static void clear_userwb(sdata_t *sdata, int64_t id)
{
	user_instance_t *instance, *tmp;

	ck_wlock(&sdata->instance_lock);
	HASH_ITER(hh, sdata->user_instances, instance, tmp) {
		struct userwb *userwb;

		HASH_FIND_I64(instance->userwbs, &id, userwb);
		if (!userwb)
			continue;
		HASH_DEL(instance->userwbs, userwb);
		free(userwb->coinb2bin);
		free(userwb->coinb2);
		free(userwb);
	}
	ck_wunlock(&sdata->instance_lock);
}

static void clear_workbase(ckpool_t *ckp, workbase_t *wb)
{
	if (ckp->btcsolo)
		clear_userwb(ckp->data, wb->id);
	free(wb->flags);
	free(wb->txn_data);
	free(wb->txn_hashes);
	free(wb->logdir);
	free(wb->coinb1bin);
	free(wb->coinb1);
	free(wb->coinb2bin);
	free(wb->coinb2);
	json_decref(wb->merkle_array);
	free(wb);
}

/* Remove all shares with a workbase id less than wb_id for block changes */
static void purge_share_hashtable(sdata_t *sdata, int64_t wb_id)
{
	share_t *share, *tmp;
	int purged = 0;

	ck_wlock(&sdata->share_lock);
	HASH_ITER(hh, sdata->shares, share, tmp) {
		if (share->workbase_id < wb_id) {
			HASH_DEL(sdata->shares, share);
			dealloc(share);
			purged++;
		}
	}
	ck_wunlock(&sdata->share_lock);

	if (purged)
		LOGINFO("Cleared %d shares from share hashtable", purged);
}

/* Remove all shares with a workbase id == wb_id being discarded */
static void age_share_hashtable(sdata_t *sdata, int64_t wb_id)
{
	share_t *share, *tmp;
	int aged = 0;

	ck_wlock(&sdata->share_lock);
	HASH_ITER(hh, sdata->shares, share, tmp) {
		if (share->workbase_id == wb_id) {
			HASH_DEL(sdata->shares, share);
			dealloc(share);
			aged++;
		}
	}
	ck_wunlock(&sdata->share_lock);

	if (aged)
		LOGINFO("Aged %d shares from share hashtable", aged);
}

static char *status_chars = "|/-\\";

/* Absorbs the json and generates a ckdb json message, logs it to the ckdb
 * log and returns the malloced message. */
static char *ckdb_msg(ckpool_t *ckp, json_t *val, const int idtype)
{
	char *json_msg = json_dumps(val, JSON_COMPACT);
	char logname[512];
	char *ret = NULL;

	if (unlikely(!json_msg))
		goto out;
	ASPRINTF(&ret, "%s.id.json=%s", ckdb_ids[idtype], json_msg);
	free(json_msg);
out:
	json_decref(val);
	snprintf(logname, 511, "%s%s", ckp->logdir, ckp->ckdb_name);
	rotating_log(logname, ret);
	return ret;
}

static void _ckdbq_add(ckpool_t *ckp, const int idtype, json_t *val, const char *file,
		       const char *func, const int line)
{
	static time_t time_counter;
	sdata_t *sdata = ckp->data;
	static int counter = 0;
	char *json_msg;
	time_t now_t;
	char ch;

	if (unlikely(!val)) {
		LOGWARNING("Invalid json sent to ckdbq_add from %s %s:%d", file, func, line);
		return;
	}

	now_t = time(NULL);
	if (now_t != time_counter) {
		/* Rate limit to 1 update per second */
		time_counter = now_t;
		ch = status_chars[(counter++) & 0x3];
		fprintf(stdout, "%c\r", ch);
		fflush(stdout);
	}

	if (CKP_STANDALONE(ckp))
		return json_decref(val);

	json_msg = ckdb_msg(ckp, val, idtype);
	if (unlikely(!json_msg)) {
		LOGWARNING("Failed to dump json from %s %s:%d", file, func, line);
		return;
	}

	ckmsgq_add(sdata->ckdbq, json_msg);
}

#define ckdbq_add(ckp, idtype, val) _ckdbq_add(ckp, idtype, val, __FILE__, __func__, __LINE__)

static void send_workinfo(ckpool_t *ckp, workbase_t *wb)
{
	char cdfield[64];
	json_t *val;

	sprintf(cdfield, "%lu,%lu", wb->gentime.tv_sec, wb->gentime.tv_nsec);

	JSON_CPACK(val, "{sI,ss,ss,ss,ss,ss,ss,ss,ss,sI,so,ss,ss,ss,ss}",
			"workinfoid", wb->id,
			"poolinstance", ckp->name,
			"transactiontree", wb->txn_hashes,
			"prevhash", wb->prevhash,
			"coinbase1", wb->coinb1,
			"coinbase2", wb->coinb2,
			"version", wb->bbversion,
			"ntime", wb->ntime,
			"bits", wb->nbit,
			"reward", wb->coinbasevalue,
			"merklehash", json_deep_copy(wb->merkle_array),
			"createdate", cdfield,
			"createby", "code",
			"createcode", __func__,
			"createinet", ckp->serverurl[0]);
	ckdbq_add(ckp, ID_WORKINFO, val);
}

static void send_ageworkinfo(ckpool_t *ckp, int64_t id)
{
	char cdfield[64];
	ts_t ts_now;
	json_t *val;

	ts_realtime(&ts_now);
	sprintf(cdfield, "%lu,%lu", ts_now.tv_sec, ts_now.tv_nsec);

	JSON_CPACK(val, "{sI,ss,ss,ss,ss,ss}",
			"workinfoid", id,
			"poolinstance", ckp->name,
			"createdate", cdfield,
			"createby", "code",
			"createcode", __func__,
			"createinet", ckp->serverurl[0]);
	ckdbq_add(ckp, ID_AGEWORKINFO, val);
}

static void __generate_userwb(workbase_t *wb, user_instance_t *instance)
{
	struct userwb *userwb;

	userwb = ckzalloc(sizeof(struct userwb));
	userwb->wb = wb;
	userwb->id = wb->id;
	userwb->coinb2bin = ckalloc(wb->coinb2len);
	memcpy(userwb->coinb2bin, wb->coinb2bin, wb->coinb2len);
	memcpy(userwb->coinb2bin + wb->genoffset, instance->txnbin, 25);
	userwb->coinb2 = bin2hex(userwb->coinb2bin, wb->coinb2len);
	HASH_ADD_I64(instance->userwbs, id, userwb);
}

static void generate_userwbs(sdata_t *sdata, workbase_t *wb)
{
	user_instance_t *instance, *tmp;

	ck_rlock(&sdata->instance_lock);
	HASH_ITER(hh, sdata->user_instances, instance, tmp) {
		if (!instance->btcaddress)
			continue;
		__generate_userwb(wb, instance);
	}
	ck_runlock(&sdata->instance_lock);
}

static void add_base(ckpool_t *ckp, workbase_t *wb, bool *new_block)
{
	workbase_t *tmp, *tmpa, *aged = NULL;
	sdata_t *sdata = ckp->data;
	int len, ret;

	ts_realtime(&wb->gentime);
	wb->network_diff = diff_from_nbits(wb->headerbin + 72);

	len = strlen(ckp->logdir) + 8 + 1 + 16 + 1;
	wb->logdir = ckzalloc(len);

	/* In proxy mode, the wb->id is received in the notify update and
	 * we set workbase_id from it. In server mode the stratifier is
	 * setting the workbase_id */
	ck_wlock(&sdata->workbase_lock);
	sdata->workbases_generated++;
	if (!ckp->proxy)
		wb->id = sdata->workbase_id++;
	else
		sdata->workbase_id = wb->id;
	if (strncmp(wb->prevhash, sdata->lasthash, 64)) {
		char bin[32], swap[32];

		*new_block = true;
		memcpy(sdata->lasthash, wb->prevhash, 65);
		hex2bin(bin, sdata->lasthash, 32);
		swap_256(swap, bin);
		__bin2hex(sdata->lastswaphash, swap, 32);
		LOGNOTICE("Block hash changed to %s", sdata->lastswaphash);
		sdata->blockchange_id = wb->id;
	}
	if (*new_block && ckp->logshares) {
		sprintf(wb->logdir, "%s%08x/", ckp->logdir, wb->height);
		ret = mkdir(wb->logdir, 0750);
		if (unlikely(ret && errno != EEXIST))
			LOGERR("Failed to create log directory %s", wb->logdir);
	}
	sprintf(wb->idstring, "%016lx", wb->id);
	if (ckp->logshares)
		sprintf(wb->logdir, "%s%08x/%s", ckp->logdir, wb->height, wb->idstring);

	HASH_ITER(hh, sdata->workbases, tmp, tmpa) {
		if (HASH_COUNT(sdata->workbases) < 3)
			break;
		/*  Age old workbases older than 10 minutes old */
		if (tmp->gentime.tv_sec < wb->gentime.tv_sec - 600) {
			HASH_DEL(sdata->workbases, tmp);
			aged = tmp;
			break;
		}
	}
	HASH_ADD_I64(sdata->workbases, id, wb);
	sdata->current_workbase = wb;
	ck_wunlock(&sdata->workbase_lock);

	if (ckp->btcsolo)
		generate_userwbs(sdata, wb);

	if (*new_block)
		purge_share_hashtable(sdata, wb->id);

	send_workinfo(ckp, wb);

	/* Send the aged work message to ckdb once we have dropped the workbase lock
	 * to prevent taking recursive locks */
	if (aged) {
		send_ageworkinfo(ckp, aged->id);
		age_share_hashtable(sdata, aged->id);
		clear_workbase(ckp, aged);
	}
}

/* Mandatory send_recv to the generator which sets the message priority if this
 * message is higher priority. Races galore on gen_priority mean this might
 * read the wrong priority but occasional wrong values are harmless. */
static char *__send_recv_generator(ckpool_t *ckp, const char *msg, int prio)
{
	sdata_t *sdata = ckp->data;
	char *buf = NULL;
	bool set;

	if (prio > sdata->gen_priority) {
		sdata->gen_priority = prio;
		set = true;
	} else
		set = false;
	buf = send_recv_proc(ckp->generator, msg);
	if (unlikely(!buf))
		buf = strdup("failed");
	if (set)
		sdata->gen_priority = 0;

	return buf;
}

/* Conditionally send_recv a message only if it's equal or higher priority than
 * any currently being serviced. NULL is returned if the request is not
 * processed for priority reasons, "failed" for an actual failure. */
static char *send_recv_generator(ckpool_t *ckp, const char *msg, int prio)
{
	sdata_t *sdata = ckp->data;
	char *buf = NULL;

	if (prio >= sdata->gen_priority)
		buf = __send_recv_generator(ckp, msg, prio);
	return buf;
}

static void send_generator(ckpool_t *ckp, const char *msg, int prio)
{
	sdata_t *sdata = ckp->data;
	bool set;

	if (prio > sdata->gen_priority) {
		sdata->gen_priority = prio;
		set = true;
	} else
		set = false;
	send_proc(ckp->generator, msg);
	if (set)
		sdata->gen_priority = 0;
}

struct update_req {
	pthread_t *pth;
	ckpool_t *ckp;
	int prio;
};

static void broadcast_ping(sdata_t *sdata);

/* This function assumes it will only receive a valid json gbt base template
 * since checking should have been done earlier, and creates the base template
 * for generating work templates. */
static void *do_update(void *arg)
{
	struct update_req *ur = (struct update_req *)arg;
	ckpool_t *ckp = ur->ckp;
	sdata_t *sdata = ckp->data;
	bool new_block = false;
	int prio = ur->prio;
	bool ret = false;
	workbase_t *wb;
	json_t *val;
	char *buf;

	pthread_detach(pthread_self());
	rename_proc("updater");

	buf = send_recv_generator(ckp, "getbase", prio);
	if (unlikely(!buf)) {
		LOGNOTICE("Get base in update_base delayed due to higher priority request");
		goto out;
	}
	if (unlikely(cmdmatch(buf, "failed"))) {
		LOGWARNING("Generator returned failure in update_base");
		goto out;
	}

	wb = ckzalloc(sizeof(workbase_t));
	wb->ckp = ckp;
	val = json_loads(buf, 0, NULL);

	json_strcpy(wb->target, val, "target");
	json_dblcpy(&wb->diff, val, "diff");
	json_uintcpy(&wb->version, val, "version");
	json_uintcpy(&wb->curtime, val, "curtime");
	json_strcpy(wb->prevhash, val, "prevhash");
	json_strcpy(wb->ntime, val, "ntime");
	sscanf(wb->ntime, "%x", &wb->ntime32);
	json_strcpy(wb->bbversion, val, "bbversion");
	json_strcpy(wb->nbit, val, "nbit");
	json_uint64cpy(&wb->coinbasevalue, val, "coinbasevalue");
	json_intcpy(&wb->height, val, "height");
	json_strdup(&wb->flags, val, "flags");
	json_intcpy(&wb->transactions, val, "transactions");
	if (wb->transactions) {
		json_strdup(&wb->txn_data, val, "txn_data");
		json_strdup(&wb->txn_hashes, val, "txn_hashes");
	} else
		wb->txn_hashes = ckzalloc(1);
	json_intcpy(&wb->merkles, val, "merkles");
	wb->merkle_array = json_array();
	if (wb->merkles) {
		json_t *arr;
		int i;

		arr = json_object_get(val, "merklehash");
		for (i = 0; i < wb->merkles; i++) {
			strcpy(&wb->merklehash[i][0], json_string_value(json_array_get(arr, i)));
			hex2bin(&wb->merklebin[i][0], &wb->merklehash[i][0], 32);
			json_array_append_new(wb->merkle_array, json_string(&wb->merklehash[i][0]));
		}
	}
	json_decref(val);
	generate_coinbase(ckp, wb);

	add_base(ckp, wb, &new_block);

	if (ckp->btcsolo)
		stratum_broadcast_updates(sdata, new_block);
	else
		stratum_broadcast_update(sdata, new_block);
	ret = true;
	LOGINFO("Broadcast updated stratum base");
out:
	/* Send a ping to miners if we fail to get a base to keep them
	 * connected while bitcoind recovers(?) */
	if (unlikely(!ret)) {
		LOGINFO("Broadcast ping due to failed stratum base update");
		broadcast_ping(sdata);
	}
	dealloc(buf);
	free(ur->pth);
	free(ur);
	return NULL;
}

static void update_base(ckpool_t *ckp, int prio)
{
	struct update_req *ur = ckalloc(sizeof(struct update_req));
	pthread_t *pth = ckalloc(sizeof(pthread_t));

	ur->pth = pth;
	ur->ckp = ckp;
	ur->prio = prio;
	create_pthread(pth, do_update, ur);
}

static void __add_dead(sdata_t *sdata, stratum_instance_t *client)
{
	LOGDEBUG("Adding dead instance %ld", client->id);
	DL_APPEND(sdata->dead_instances, client);
	sdata->stats.dead++;
	sdata->dead_generated++;
}

static void __del_dead(sdata_t *sdata, stratum_instance_t *client)
{
	LOGDEBUG("Deleting dead instance %ld", client->id);
	DL_DELETE_INIT(sdata->dead_instances, client);
	sdata->stats.dead--;
}

static void __del_disconnected(sdata_t *sdata, stratum_instance_t *client)
{
	LOGDEBUG("Deleting disconnected instance %ld", client->id);
	HASH_DEL(sdata->disconnected_instances, client);
	sdata->stats.disconnected--;
	__add_dead(sdata, client);
}

static void drop_allclients(ckpool_t *ckp)
{
	stratum_instance_t *client, *tmp;
	sdata_t *sdata = ckp->data;
	char buf[128];

	ck_wlock(&sdata->instance_lock);
	HASH_ITER(hh, sdata->stratum_instances, client, tmp) {
		HASH_DEL(sdata->stratum_instances, client);
		__add_dead(sdata, client);
		sprintf(buf, "dropclient=%ld", client->id);
		send_proc(ckp->connector, buf);
	}
	HASH_ITER(hh, sdata->disconnected_instances, client, tmp) {
		__del_disconnected(sdata, client);
	}
	sdata->stats.users = sdata->stats.workers = 0;
	ck_wunlock(&sdata->instance_lock);
}

static void update_subscribe(ckpool_t *ckp)
{
	sdata_t *sdata = ckp->data;
	json_t *val;
	char *buf;

	buf = send_recv_proc(ckp->generator, "getsubscribe");
	if (unlikely(!buf)) {
		LOGWARNING("Failed to get subscribe from generator in update_notify");
		drop_allclients(ckp);
		return;
	}
	LOGDEBUG("Update subscribe: %s", buf);
	val = json_loads(buf, 0, NULL);
	free(buf);

	ck_wlock(&sdata->workbase_lock);
	sdata->proxy_base.subscribed = true;
	sdata->proxy_base.diff = ckp->startdiff;
	/* Length is checked by generator */
	strcpy(sdata->proxy_base.enonce1, json_string_value(json_object_get(val, "enonce1")));
	sdata->proxy_base.enonce1constlen = strlen(sdata->proxy_base.enonce1) / 2;
	hex2bin(sdata->proxy_base.enonce1bin, sdata->proxy_base.enonce1, sdata->proxy_base.enonce1constlen);
	sdata->proxy_base.nonce2len = json_integer_value(json_object_get(val, "nonce2len"));
	if (sdata->proxy_base.nonce2len > 7)
		sdata->proxy_base.enonce1varlen = 4;
	else if (sdata->proxy_base.nonce2len > 5)
		sdata->proxy_base.enonce1varlen = 2;
	else
		sdata->proxy_base.enonce1varlen = 1;
	sdata->proxy_base.enonce2varlen = sdata->proxy_base.nonce2len - sdata->proxy_base.enonce1varlen;
	ck_wunlock(&sdata->workbase_lock);

	json_decref(val);
	drop_allclients(ckp);
}

static void update_diff(ckpool_t *ckp);

static void update_notify(ckpool_t *ckp)
{
	bool new_block = false, clean;
	sdata_t *sdata = ckp->data;
	char header[228];
	workbase_t *wb;
	json_t *val;
	char *buf;
	int i;

	buf = send_recv_proc(ckp->generator, "getnotify");
	if (unlikely(!buf)) {
		LOGWARNING("Failed to get notify from generator in update_notify");
		return;
	}

	if (unlikely(!sdata->proxy_base.subscribed)) {
		LOGINFO("No valid proxy subscription to update notify yet");
		return;
	}

	LOGDEBUG("Update notify: %s", buf);
	wb = ckzalloc(sizeof(workbase_t));
	val = json_loads(buf, 0, NULL);
	dealloc(buf);
	wb->ckp = ckp;
	wb->proxy = true;

	json_int64cpy(&wb->id, val, "jobid");
	json_strcpy(wb->prevhash, val, "prevhash");
	json_intcpy(&wb->coinb1len, val, "coinb1len");
	wb->coinb1bin = ckalloc(wb->coinb1len);
	wb->coinb1 = ckalloc(wb->coinb1len * 2 + 1);
	json_strcpy(wb->coinb1, val, "coinbase1");
	hex2bin(wb->coinb1bin, wb->coinb1, wb->coinb1len);
	wb->height = get_sernumber(wb->coinb1bin + 42);
	json_strdup(&wb->coinb2, val, "coinbase2");
	wb->coinb2len = strlen(wb->coinb2) / 2;
	wb->coinb2bin = ckalloc(wb->coinb2len);
	hex2bin(wb->coinb2bin, wb->coinb2, wb->coinb2len);
	wb->merkle_array = json_object_dup(val, "merklehash");
	wb->merkles = json_array_size(wb->merkle_array);
	for (i = 0; i < wb->merkles; i++) {
		strcpy(&wb->merklehash[i][0], json_string_value(json_array_get(wb->merkle_array, i)));
		hex2bin(&wb->merklebin[i][0], &wb->merklehash[i][0], 32);
	}
	json_strcpy(wb->bbversion, val, "bbversion");
	json_strcpy(wb->nbit, val, "nbit");
	json_strcpy(wb->ntime, val, "ntime");
	sscanf(wb->ntime, "%x", &wb->ntime32);
	clean = json_is_true(json_object_get(val, "clean"));
	json_decref(val);
	ts_realtime(&wb->gentime);
	snprintf(header, 225, "%s%s%s%s%s%s%s",
		 wb->bbversion, wb->prevhash,
		 "0000000000000000000000000000000000000000000000000000000000000000",
		 wb->ntime, wb->nbit,
		 "00000000", /* nonce */
		 workpadding);
	LOGDEBUG("Header: %s", header);
	hex2bin(wb->headerbin, header, 112);
	wb->txn_hashes = ckzalloc(1);

	/* Check diff on each notify */
	update_diff(ckp);

	ck_rlock(&sdata->workbase_lock);
	strcpy(wb->enonce1const, sdata->proxy_base.enonce1);
	wb->enonce1constlen = sdata->proxy_base.enonce1constlen;
	memcpy(wb->enonce1constbin, sdata->proxy_base.enonce1bin, wb->enonce1constlen);
	wb->enonce1varlen = sdata->proxy_base.enonce1varlen;
	wb->enonce2varlen = sdata->proxy_base.enonce2varlen;
	wb->diff = sdata->proxy_base.diff;
	ck_runlock(&sdata->workbase_lock);

	add_base(ckp, wb, &new_block);

	stratum_broadcast_update(sdata, new_block | clean);
}

static void stratum_send_diff(sdata_t *sdata, stratum_instance_t *client);

static void update_diff(ckpool_t *ckp)
{
	stratum_instance_t *client;
	sdata_t *sdata = ckp->data;
	double old_diff, diff;
	json_t *val;
	char *buf;

	if (unlikely(!sdata->current_workbase)) {
		LOGINFO("No current workbase to update diff yet");
		return;
	}

	buf = send_recv_proc(ckp->generator, "getdiff");
	if (unlikely(!buf)) {
		LOGWARNING("Failed to get diff from generator in update_diff");
		return;
	}

	LOGDEBUG("Update diff: %s", buf);
	val = json_loads(buf, 0, NULL);
	dealloc(buf);
	json_dblcpy(&diff, val, "diff");
	json_decref(val);

	/* We only really care about integer diffs so clamp the lower limit to
	 * 1 or it will round down to zero. */
	if (unlikely(diff < 1))
		diff = 1;

	ck_wlock(&sdata->workbase_lock);
	old_diff = sdata->proxy_base.diff;
	sdata->current_workbase->diff = sdata->proxy_base.diff = diff;
	ck_wunlock(&sdata->workbase_lock);

	if (old_diff < diff)
		return;

	/* If the diff has dropped, iterate over all the clients and check
	 * they're at or below the new diff, and update it if not. */
	ck_rlock(&sdata->instance_lock);
	for (client = sdata->stratum_instances; client != NULL; client = client->hh.next) {
		if (client->diff > diff) {
			client->diff = diff;
			stratum_send_diff(sdata, client);
		}
	}
	ck_runlock(&sdata->instance_lock);
}

/* Enter with instance_lock held */
static stratum_instance_t *__instance_by_id(sdata_t *sdata, int64_t id)
{
	stratum_instance_t *instance;

	HASH_FIND_I64(sdata->stratum_instances, &id, instance);
	return instance;
}

/* Increase the reference count of instance */
static void __inc_instance_ref(stratum_instance_t *instance)
{
	instance->ref++;
}

/* Find an __instance_by_id and increase its reference count allowing us to
 * use this instance outside of instance_lock without fear of it being
 * dereferenced. */
static stratum_instance_t *ref_instance_by_id(sdata_t *sdata, int64_t id)
{
	stratum_instance_t *instance;

	ck_wlock(&sdata->instance_lock);
	instance = __instance_by_id(sdata, id);
	if (instance)
		__inc_instance_ref(instance);
	ck_wunlock(&sdata->instance_lock);

	return instance;
}

static void __drop_client(sdata_t *sdata, stratum_instance_t *client, user_instance_t *instance,
			  int64_t id)
{
	stratum_instance_t *old_client = NULL;

	HASH_DEL(sdata->stratum_instances, client);
	if (instance)
		DL_DELETE_INIT(instance->instances, client);
	HASH_FIND(hh, sdata->disconnected_instances, &client->enonce1_64, sizeof(uint64_t), old_client);
	/* Only keep around one copy of the old client in server mode */
	if (!client->ckp->proxy && !old_client && client->enonce1_64 && client->authorised) {
		LOGNOTICE("Client %ld %s disconnected %s", id, client->workername,
			  client->dropped ? "lazily" : "");
		HASH_ADD(hh, sdata->disconnected_instances, enonce1_64, sizeof(uint64_t), client);
		sdata->stats.disconnected++;
		sdata->disconnected_generated++;
		client->disconnected_time = time(NULL);
	} else {
		if (client->workername) {
			LOGNOTICE("Client %ld %s dropped %s", id, client->workername,
				  client->dropped ? "lazily" : "");
		} else
			LOGINFO("Workerless client %ld dropped %s", id, client->dropped ? "lazily" : "");
		__add_dead(sdata, client);
	}
}

/* Decrease the reference count of instance. */
static void _dec_instance_ref(sdata_t *sdata, stratum_instance_t *instance, const char *file,
			      const char *func, const int line)
{
	ck_wlock(&sdata->instance_lock);
	if (unlikely(--instance->ref < 0)) {
		LOGERR("Instance ref count dropped below zero from %s %s:%d", file, func, line);
		instance->ref = 0;
	}
	/* See if there are any instances that were dropped that could not be
	 * moved due to holding a reference and drop them now. */
	if (unlikely(instance->dropped && !instance->ref))
		__drop_client(sdata, instance, instance->user_instance, instance->id);
	ck_wunlock(&sdata->instance_lock);
}

#define dec_instance_ref(sdata, instance) _dec_instance_ref(sdata, instance, __FILE__, __func__, __LINE__)

/* Enter with write instance_lock held */
static stratum_instance_t *__stratum_add_instance(ckpool_t *ckp, int64_t id, int server)
{
	stratum_instance_t *instance = ckzalloc(sizeof(stratum_instance_t));
	sdata_t *sdata = ckp->data;

	sdata->stratum_generated++;
	instance->id = id;
	instance->server = server;
	instance->diff = instance->old_diff = ckp->startdiff;
	instance->ckp = ckp;
	tv_time(&instance->ldc);
	LOGINFO("Stratifier added instance %ld server %d", id, server);
	HASH_ADD_I64(sdata->stratum_instances, id, instance);
	return instance;
}

static uint64_t disconnected_sessionid_exists(sdata_t *sdata, const char *sessionid, int64_t id)
{
	stratum_instance_t *instance, *tmp;
	uint64_t enonce1_64 = 0, ret = 0;
	int slen;

	if (!sessionid)
		goto out;
	slen = strlen(sessionid) / 2;
	if (slen < 1 || slen > 8)
		goto out;

	if (!validhex(sessionid))
		goto out;

	/* Number is in BE but we don't swap either of them */
	hex2bin(&enonce1_64, sessionid, slen);

	ck_wlock(&sdata->instance_lock);
	HASH_ITER(hh, sdata->stratum_instances, instance, tmp) {
		if (instance->id == id)
			continue;
		if (instance->enonce1_64 == enonce1_64) {
			/* Only allow one connected instance per enonce1 */
			goto out_unlock;
		}
	}
	instance = NULL;
	HASH_FIND(hh, sdata->disconnected_instances, &enonce1_64, sizeof(uint64_t), instance);
	if (instance) {
		/* Delete the entry once we are going to use it since there
		 * will be a new instance with the enonce1_64 */
		__del_disconnected(sdata, instance);
		ret = enonce1_64;
	}
out_unlock:
	ck_wunlock(&sdata->instance_lock);
out:
	return ret;
}

/* For creating a list of sends without locking that can then be concatenated
 * to the stratum_sends list. Minimises locking and avoids taking recursive
 * locks. */
static void stratum_broadcast(sdata_t *sdata, json_t *val)
{
	stratum_instance_t *instance, *tmp;
	ckmsg_t *bulk_send = NULL;

	if (unlikely(!val)) {
		LOGERR("Sent null json to stratum_broadcast");
		return;
	}

	ck_rlock(&sdata->instance_lock);
	HASH_ITER(hh, sdata->stratum_instances, instance, tmp) {
		ckmsg_t *client_msg;
		smsg_t *msg;

		if (!instance->authorised)
			continue;
		client_msg = ckalloc(sizeof(ckmsg_t));
		msg = ckzalloc(sizeof(smsg_t));
		msg->json_msg = json_deep_copy(val);
		msg->client_id = instance->id;
		client_msg->data = msg;
		DL_APPEND(bulk_send, client_msg);
	}
	ck_runlock(&sdata->instance_lock);

	json_decref(val);

	if (!bulk_send)
		return;

	mutex_lock(sdata->ssends->lock);
	if (sdata->ssends->msgs)
		DL_CONCAT(sdata->ssends->msgs, bulk_send);
	else
		sdata->ssends->msgs = bulk_send;
	pthread_cond_signal(sdata->ssends->cond);
	mutex_unlock(sdata->ssends->lock);
}

static void stratum_add_send(sdata_t *sdata, json_t *val, int64_t client_id)
{
	smsg_t *msg;

	msg = ckzalloc(sizeof(smsg_t));
	msg->json_msg = val;
	msg->client_id = client_id;
	ckmsgq_add(sdata->ssends, msg);
}

static void inc_worker(ckpool_t *ckp, user_instance_t *instance)
{
	sdata_t *sdata = ckp->data;

	mutex_lock(&sdata->stats_lock);
	sdata->stats.workers++;
	if (!instance->workers++)
		sdata->stats.users++;
	mutex_unlock(&sdata->stats_lock);
}

static void dec_worker(ckpool_t *ckp, user_instance_t *instance)
{
	sdata_t *sdata = ckp->data;

	mutex_lock(&sdata->stats_lock);
	sdata->stats.workers--;
	if (!--instance->workers)
		sdata->stats.users--;
	mutex_unlock(&sdata->stats_lock);
}

static void drop_client(sdata_t *sdata, int64_t id)
{
	stratum_instance_t *client, *tmp;
	user_instance_t *instance = NULL;
	time_t now_t = time(NULL);
	ckpool_t *ckp = NULL;
	bool dec = false;

	LOGINFO("Stratifier asked to drop client %ld", id);

	ck_wlock(&sdata->instance_lock);
	client = __instance_by_id(sdata, id);
	if (client) {
		instance = client->user_instance;
		if (client->authorised) {
			dec = true;
			ckp = client->ckp;
		}
		/* If the client is still holding a reference, don't drop them
		 * now but wait till the reference is dropped */
		if (likely(!client->ref))
			__drop_client(sdata, client, instance, id);
		else
			client->dropped = true;
	}

	/* Old disconnected instances will not have any valid shares so remove
	 * them from the disconnected instances list if they've been dead for
	 * more than 10 minutes */
	HASH_ITER(hh, sdata->disconnected_instances, client, tmp) {
		if (now_t - client->disconnected_time < 600)
			continue;
		if (unlikely(client->ref))
			continue;
		LOGINFO("Ageing disconnected instance %ld to dead", client->id);
		__del_disconnected(sdata, client);
	}

	/* Cull old unused clients lazily when there are no more reference
	 * counts for them. */
	DL_FOREACH_SAFE(sdata->dead_instances, client, tmp) {
		if (!client->ref) {
			LOGINFO("Stratifier discarding dead instance %ld", client->id);
			__del_dead(sdata, client);
			dealloc(client->workername);
			dealloc(client->useragent);
			dealloc(client);
		}
	}
	ck_wunlock(&sdata->instance_lock);

	/* Decrease worker count outside of instance_lock to avoid recursive
	 * locking */
	if (dec)
		dec_worker(ckp, instance);
}

static void stratum_broadcast_message(sdata_t *sdata, const char *msg)
{
	json_t *json_msg;

	JSON_CPACK(json_msg, "{sosss[s]}", "id", json_null(), "method", "client.show_message",
			     "params", msg);
	stratum_broadcast(sdata, json_msg);
}

/* Send a generic reconnect to all clients without parameters to make them
 * reconnect to the same server. */
static void reconnect_clients(sdata_t *sdata, const char *cmd)
{
	char *port = strdupa(cmd), *url = NULL;
	json_t *json_msg;

	strsep(&port, ":");
	if (port)
		url = strsep(&port, ",");
	if (url && port) {
		int port_no;

		port_no = strtol(port, NULL, 10);
		JSON_CPACK(json_msg, "{sosss[sii]}", "id", json_null(), "method", "client.reconnect",
			"params", url, port_no, 0);
	} else
		JSON_CPACK(json_msg, "{sosss[]}", "id", json_null(), "method", "client.reconnect",
		   "params");
	stratum_broadcast(sdata, json_msg);
}

static void reset_bestshares(sdata_t *sdata)
{
	user_instance_t *instance, *tmpuser;
	stratum_instance_t *client, *tmp;

	ck_rlock(&sdata->instance_lock);
	HASH_ITER(hh, sdata->stratum_instances, client, tmp) {
		client->best_diff = 0;
	}
	HASH_ITER(hh, sdata->user_instances, instance, tmpuser) {
		worker_instance_t *worker;

		instance->best_diff = 0;
		DL_FOREACH(instance->worker_instances, worker) {
			worker->best_diff = 0;
		}
	}
	ck_runlock(&sdata->instance_lock);
}

/* Ram from blocks is NOT freed at all for now, only their entry is removed
 * from the linked list, leaving a very small leak here and reject. */
static void block_solve(ckpool_t *ckp, const char *blockhash)
{
	ckmsg_t *block, *tmp, *found = NULL;
	sdata_t *sdata = ckp->data;
	char cdfield[64];
	int height = 0;
	ts_t ts_now;
	json_t *val;
	char *msg;

	update_base(ckp, GEN_PRIORITY);

	ts_realtime(&ts_now);
	sprintf(cdfield, "%lu,%lu", ts_now.tv_sec, ts_now.tv_nsec);

	mutex_lock(&sdata->block_lock);
	DL_FOREACH_SAFE(sdata->block_solves, block, tmp) {
		val = block->data;
		char *solvehash;

		json_get_string(&solvehash, val, "blockhash");
		if (unlikely(!solvehash)) {
			LOGERR("Failed to find blockhash in block_solve json!");
			continue;
		}
		if (!strcmp(solvehash, blockhash)) {
			dealloc(solvehash);
			found = block;
			DL_DELETE_INIT(sdata->block_solves, block);
			break;
		}
		dealloc(solvehash);
	}
	mutex_unlock(&sdata->block_lock);

	if (unlikely(!found)) {
		LOGERR("Failed to find blockhash %s in block_solve!", blockhash);
		return;
	}

	val = found->data;
	json_set_string(val, "confirmed", "1");
	json_set_string(val, "createdate", cdfield);
	json_set_string(val, "createcode", __func__);
	json_get_int(&height, val, "height");
	ckdbq_add(ckp, ID_BLOCK, val);
	free(found);

	ASPRINTF(&msg, "Block %d solved by %s!", height, ckp->name);
	stratum_broadcast_message(sdata, msg);
	free(msg);

	LOGWARNING("Solved and confirmed block %d", height);
	reset_bestshares(sdata);
}

static void block_reject(sdata_t *sdata, const char *blockhash)
{
	ckmsg_t *block, *tmp, *found = NULL;
	int height = 0;
	json_t *val;

	mutex_lock(&sdata->block_lock);
	DL_FOREACH_SAFE(sdata->block_solves, block, tmp) {
		val = block->data;
		char *solvehash;

		json_get_string(&solvehash, val, "blockhash");
		if (unlikely(!solvehash)) {
			LOGERR("Failed to find blockhash in block_reject json!");
			continue;
		}
		if (!strcmp(solvehash, blockhash)) {
			dealloc(solvehash);
			found = block;
			DL_DELETE_INIT(sdata->block_solves, block);
			break;
		}
		dealloc(solvehash);
	}
	mutex_unlock(&sdata->block_lock);

	if (unlikely(!found)) {
		LOGERR("Failed to find blockhash %s in block_reject!", blockhash);
		return;
	}
	val = found->data;
	json_get_int(&height, val, "height");
	json_decref(val);
	free(found);

	LOGWARNING("Submitted, but rejected block %d", height);
}

/* Some upstream pools (like p2pool) don't update stratum often enough and
 * miners disconnect if they don't receive regular communication so send them
 * a ping at regular intervals */
static void broadcast_ping(sdata_t *sdata)
{
	json_t *json_msg;

	JSON_CPACK(json_msg, "{s:[],s:i,s:s}",
		   "params",
		   "id", 42,
		   "method", "mining.ping");

	stratum_broadcast(sdata, json_msg);
}

static void ckmsgq_stats(ckmsgq_t *ckmsgq, int size, json_t **val)
{
	int objects, generated;
	int64_t memsize;
	ckmsg_t *msg;

	mutex_lock(ckmsgq->lock);
	DL_COUNT(ckmsgq->msgs, msg, objects);
	generated = ckmsgq->messages;
	mutex_unlock(ckmsgq->lock);

	memsize = (sizeof(ckmsg_t) + size) * objects;
	JSON_CPACK(*val, "{si,si,si}", "count", objects, "memory", memsize, "generated", generated);
}

static char *stratifier_stats(sdata_t *sdata)
{
	json_t *val = json_object(), *subval;
	int objects, generated;
	int64_t memsize;
	char *buf;

	ck_rlock(&sdata->workbase_lock);
	objects = HASH_COUNT(sdata->workbases);
	memsize = SAFE_HASH_OVERHEAD(sdata->workbases) + sizeof(workbase_t) * objects;
	generated = sdata->workbases_generated;
	ck_runlock(&sdata->workbase_lock);

	JSON_CPACK(subval, "{si,si,si}", "count", objects, "memory", memsize, "generated", generated);
	json_set_object(val, "workbases", subval);

	ck_rlock(&sdata->instance_lock);
	objects = HASH_COUNT(sdata->user_instances);
	memsize = SAFE_HASH_OVERHEAD(sdata->user_instances) + sizeof(stratum_instance_t) * objects;
	JSON_CPACK(subval, "{si,si}", "count", objects, "memory", memsize);
	json_set_object(val, "users", subval);

	objects = HASH_COUNT(sdata->stratum_instances);
	memsize = SAFE_HASH_OVERHEAD(sdata->stratum_instances);
	generated = sdata->stratum_generated;
	JSON_CPACK(subval, "{si,si,si}", "count", objects, "memory", memsize, "generated", generated);
	json_set_object(val, "clients", subval);

	objects = sdata->stats.disconnected;
	generated = sdata->disconnected_generated;
	memsize = sizeof(stratum_instance_t) * sdata->stats.disconnected;
	JSON_CPACK(subval, "{si,si,si}", "count", objects, "memory", memsize, "generated", generated);
	json_set_object(val, "disconnected", subval);

	objects = sdata->stats.dead;
	generated = sdata->dead_generated;
	memsize = sizeof(stratum_instance_t) * sdata->stats.dead;
	ck_runlock(&sdata->instance_lock);

	JSON_CPACK(subval, "{si,si,si}", "count", objects, "memory", memsize, "generated", generated);
	json_set_object(val, "dead", subval);

	ck_rlock(&sdata->share_lock);
	generated = sdata->shares_generated;
	objects = HASH_COUNT(sdata->shares);
	memsize = SAFE_HASH_OVERHEAD(sdata->shares) + sizeof(share_t) * objects;
	ck_runlock(&sdata->share_lock);

	JSON_CPACK(subval, "{si,si,si}", "count", objects, "memory", memsize, "generated", generated);
	json_set_object(val, "shares", subval);

	ckmsgq_stats(sdata->ssends, sizeof(smsg_t), &subval);
	json_set_object(val, "ssends", subval);
	/* Don't know exactly how big the string is so just count the pointer for now */
	ckmsgq_stats(sdata->srecvs, sizeof(char *), &subval);
	json_set_object(val, "srecvs", subval);
	ckmsgq_stats(sdata->ckdbq, sizeof(char *), &subval);
	json_set_object(val, "ckdbq", subval);
	ckmsgq_stats(sdata->stxnq, sizeof(json_params_t), &subval);
	json_set_object(val, "stxnq", subval);

	buf = json_dumps(val, JSON_NO_UTF8 | JSON_PRESERVE_ORDER);
	json_decref(val);
	LOGNOTICE("Stratifier stats: %s", buf);
	return buf;
}

static int stratum_loop(ckpool_t *ckp, proc_instance_t *pi)
{
	int sockd, ret = 0, selret = 0;
	sdata_t *sdata = ckp->data;
	unixsock_t *us = &pi->us;
	tv_t start_tv = {0, 0};
	char *buf = NULL;

retry:
	do {
		double tdiff;
		tv_t end_tv;

		tv_time(&end_tv);
		tdiff = tvdiff(&end_tv, &start_tv);
		if (tdiff > ckp->update_interval) {
			copy_tv(&start_tv, &end_tv);
			if (!ckp->proxy) {
				LOGDEBUG("%ds elapsed in strat_loop, updating gbt base",
					 ckp->update_interval);
				update_base(ckp, GEN_NORMAL);
			} else {
				LOGDEBUG("%ds elapsed in strat_loop, pinging miners",
					 ckp->update_interval);
				broadcast_ping(sdata);
			}
			continue;
		}
		selret = wait_read_select(us->sockd, 5);
		if (!selret && !ping_main(ckp)) {
			LOGEMERG("Generator failed to ping main process, exiting");
			ret = 1;
			goto out;
		}
	} while (selret < 1);

	sockd = accept(us->sockd, NULL, NULL);
	if (sockd < 0) {
		LOGERR("Failed to accept on stratifier socket, exiting");
		ret = 1;
		goto out;
	}

	dealloc(buf);
	buf = recv_unix_msg(sockd);
	if (unlikely(!buf)) {
		Close(sockd);
		LOGWARNING("Failed to get message in stratum_loop");
		goto retry;
	}
	if (likely(buf[0] == '{')) {
		/* The bulk of the messages will be received json from the
		 * connector so look for this first. The srecv_process frees
		 * the buf heap ram */
		ckmsgq_add(sdata->srecvs, buf);
		Close(sockd);
		buf = NULL;
		goto retry;
	}
	if (cmdmatch(buf, "ping")) {
		LOGDEBUG("Stratifier received ping request");
		send_unix_msg(sockd, "pong");
		Close(sockd);
		goto retry;
	}
	if (cmdmatch(buf, "stats")) {
		char *msg;

		LOGDEBUG("Stratifier received stats request");
		msg = stratifier_stats(sdata);
		send_unix_msg(sockd, msg);
		Close(sockd);
		goto retry;
	}

	Close(sockd);
	LOGDEBUG("Stratifier received request: %s", buf);
	if (cmdmatch(buf, "shutdown")) {
		ret = 0;
		goto out;
	} else if (cmdmatch(buf, "update")) {
		update_base(ckp, GEN_PRIORITY);
	} else if (cmdmatch(buf, "subscribe")) {
		/* Proxifier has a new subscription */
		update_subscribe(ckp);
	} else if (cmdmatch(buf, "notify")) {
		/* Proxifier has a new notify ready */
		update_notify(ckp);
	} else if (cmdmatch(buf, "diff")) {
		update_diff(ckp);
	} else if (cmdmatch(buf, "dropclient")) {
		int64_t client_id;

		ret = sscanf(buf, "dropclient=%ld", &client_id);
		if (ret < 0)
			LOGDEBUG("Stratifier failed to parse dropclient command: %s", buf);
		else
			drop_client(sdata, client_id);
	} else if (cmdmatch(buf, "dropall")) {
		drop_allclients(ckp);
	} else if (cmdmatch(buf, "block")) {
		block_solve(ckp, buf + 6);
	} else if (cmdmatch(buf, "noblock")) {
		block_reject(sdata, buf + 8);
	} else if (cmdmatch(buf, "reconnect")) {
		reconnect_clients(sdata, buf);
	} else if (cmdmatch(buf, "loglevel")) {
		sscanf(buf, "loglevel=%d", &ckp->loglevel);
	} else
		LOGWARNING("Unhandled stratifier message: %s", buf);
	goto retry;

out:
	dealloc(buf);
	return ret;
}

static void *blockupdate(void *arg)
{
	ckpool_t *ckp = (ckpool_t *)arg;
	sdata_t *sdata = ckp->data;
	char *buf = NULL;
	char request[8];

	pthread_detach(pthread_self());
	rename_proc("blockupdate");
	buf = send_recv_proc(ckp->generator, "getbest");
	if (!cmdmatch(buf, "failed"))
		sprintf(request, "getbest");
	else
		sprintf(request, "getlast");

	while (42) {
		dealloc(buf);
		buf = send_recv_generator(ckp, request, GEN_LAX);
		if (buf && cmdmatch(buf, "notify"))
			cksleep_ms(5000);
		else if (buf && strcmp(buf, sdata->lastswaphash) && !cmdmatch(buf, "failed"))
			update_base(ckp, GEN_PRIORITY);
		else
			cksleep_ms(ckp->blockpoll);
	}
	return NULL;
}

static inline bool enonce1_free(sdata_t *sdata, uint64_t enonce1)
{
	stratum_instance_t *client, *tmp;
	bool ret = true;

	if (unlikely(!enonce1)) {
		ret = false;
		goto out;
	}

	ck_rlock(&sdata->instance_lock);
	HASH_ITER(hh, sdata->stratum_instances, client, tmp) {
		if (client->enonce1_64 == enonce1) {
			ret = false;
			break;
		}
	}
	ck_runlock(&sdata->instance_lock);
out:
	return ret;
}

/* Enter holding workbase_lock */
static void __fill_enonce1data(workbase_t *wb, stratum_instance_t *client)
{
	if (wb->enonce1constlen)
		memcpy(client->enonce1bin, wb->enonce1constbin, wb->enonce1constlen);
	memcpy(client->enonce1bin + wb->enonce1constlen, &client->enonce1_64, wb->enonce1varlen);
	__bin2hex(client->enonce1var, &client->enonce1_64, wb->enonce1varlen);
	__bin2hex(client->enonce1, client->enonce1bin, wb->enonce1constlen + wb->enonce1varlen);
}

/* Create a new enonce1 from the 64 bit enonce1_64 value, using only the number
 * of bytes we have to work with when we are proxying with a split nonce2.
 * When the proxy space is less than 32 bits to work with, we look for an
 * unused enonce1 value and reject clients instead if there is no space left.
 * Needs to be entered with client holding a ref count. */
static bool new_enonce1(stratum_instance_t *client)
{
	sdata_t *sdata = client->ckp->data;
	bool ret = false;
	workbase_t *wb;
	int i;

	ck_wlock(&sdata->workbase_lock);
	wb = sdata->current_workbase;
	switch(wb->enonce1varlen) {
		case 8:
			sdata->enonce1u.u64++;
			ret = true;
			break;
		case 7:
		case 6:
		case 5:
		case 4:
			sdata->enonce1u.u32++;
			ret = true;
			break;
		case 3:
		case 2:
			for (i = 0; i < 65536; i++) {
				sdata->enonce1u.u16++;
				ret = enonce1_free(sdata, sdata->enonce1u.u64);
				if (ret)
					break;
			}
			break;
		case 1:
			for (i = 0; i < 256; i++) {
				sdata->enonce1u.u8++;
				ret = enonce1_free(sdata, sdata->enonce1u.u64);
				if (ret)
					break;
			}
			break;
		default:
			quit(0, "Invalid enonce1varlen %d", wb->enonce1varlen);
	}
	if (ret)
		client->enonce1_64 = sdata->enonce1u.u64;
	__fill_enonce1data(wb, client);
	ck_wunlock(&sdata->workbase_lock);

	if (unlikely(!ret))
		LOGWARNING("Enonce1 space exhausted! Proxy rejecting clients");

	return ret;
}

static void stratum_send_message(sdata_t *sdata, stratum_instance_t *client, const char *msg);

/* Extranonce1 must be set here. Needs to be entered with client holding a ref
 * count. */
static json_t *parse_subscribe(stratum_instance_t *client, int64_t client_id, json_t *params_val)
{
	sdata_t *sdata = client->ckp->data;
	bool old_match = false;
	int arr_size;
	json_t *ret;
	int n2len;

	if (unlikely(!json_is_array(params_val))) {
		stratum_send_message(sdata, client, "Invalid json: params not an array");
		return json_string("params not an array");
	}

	if (unlikely(!sdata->current_workbase)) {
		stratum_send_message(sdata, client, "Pool Initialising");
		return json_string("Initialising");
	}

	arr_size = json_array_size(params_val);
	if (arr_size > 0) {
		const char *buf;

		buf = json_string_value(json_array_get(params_val, 0));
		if (buf && strlen(buf))
			client->useragent = strdup(buf);
		else
			client->useragent = ckzalloc(1); // Set to ""
		if (arr_size > 1) {
			/* This would be the session id for reconnect, it will
			 * not work for clients on a proxied connection. */
			buf = json_string_value(json_array_get(params_val, 1));
			LOGDEBUG("Found old session id %s", buf);
			/* Add matching here */
			if ((client->enonce1_64 = disconnected_sessionid_exists(sdata, buf, client_id))) {
				sprintf(client->enonce1, "%016lx", client->enonce1_64);
				old_match = true;

				ck_rlock(&sdata->workbase_lock);
				__fill_enonce1data(sdata->current_workbase, client);
				ck_runlock(&sdata->workbase_lock);
			}
		}
	} else
		client->useragent = ckzalloc(1);
	if (!old_match) {
		/* Create a new extranonce1 based on a uint64_t pointer */
		if (!new_enonce1(client)) {
			stratum_send_message(sdata, client, "Pool full of clients");
			client->reject = 2;
			return json_string("proxy full");
		}
		LOGINFO("Set new subscription %ld to new enonce1 %lx string %s", client->id,
			client->enonce1_64, client->enonce1);
	} else {
		LOGINFO("Set new subscription %ld to old matched enonce1 %lx string %s",
			client->id, client->enonce1_64, client->enonce1);
	}

	ck_rlock(&sdata->workbase_lock);
	if (likely(sdata->workbases))
		n2len = sdata->workbases->enonce2varlen;
	else
		n2len = 8;
	JSON_CPACK(ret, "[[[s,s]],s,i]", "mining.notify", client->enonce1, client->enonce1,
			n2len);
	ck_runlock(&sdata->workbase_lock);

	client->subscribed = true;

	return ret;
}

static bool test_address(ckpool_t *ckp, const char *address)
{
	bool ret = false;
	char *buf, *msg;

	ASPRINTF(&msg, "checkaddr:%s", address);
	/* Must wait for a response here */
	buf = __send_recv_generator(ckp, msg, GEN_LAX);
	dealloc(msg);
	if (!buf)
		return ret;
	ret = cmdmatch(buf, "true");
	dealloc(buf);
	return ret;
}

static const double nonces = 4294967296;

static double dsps_from_key(json_t *val, const char *key)
{
	char *string, *endptr;
	double ret = 0;

	json_get_string(&string, val, key);
	if (!string)
		return ret;
	ret = strtod(string, &endptr) / nonces;
	if (endptr) {
		switch (endptr[0]) {
			case 'E':
				ret *= (double)1000;
			case 'P':
				ret *= (double)1000;
			case 'T':
				ret *= (double)1000;
			case 'G':
				ret *= (double)1000;
			case 'M':
				ret *= (double)1000;
			case 'K':
				ret *= (double)1000;
			default:
				break;
		}
	}
	free(string);
	return ret;
}

static void read_userstats(ckpool_t *ckp, user_instance_t *instance)
{
	char s[512];
	json_t *val;
	FILE *fp;
	int ret;

	snprintf(s, 511, "%s/users/%s", ckp->logdir, instance->username);
	fp = fopen(s, "re");
	if (!fp) {
		LOGINFO("User %s does not have a logfile to read", instance->username);
		return;
	}
	memset(s, 0, 512);
	ret = fread(s, 1, 511, fp);
	fclose(fp);
	if (ret < 1) {
		LOGINFO("Failed to read user %s logfile", instance->username);
		return;
	}
	val = json_loads(s, 0, NULL);
	if (!val) {
		LOGINFO("Failed to json decode user %s logfile: %s", instance->username, s);
		return;
	}

	tv_time(&instance->last_share);
	instance->dsps1 = dsps_from_key(val, "hashrate1m");
	instance->dsps5 = dsps_from_key(val, "hashrate5m");
	instance->dsps60 = dsps_from_key(val, "hashrate1hr");
	instance->dsps1440 = dsps_from_key(val, "hashrate1d");
	instance->dsps10080 = dsps_from_key(val, "hashrate7d");
	json_get_double(&instance->best_diff, val, "bestshare");
	LOGINFO("Successfully read user %s stats %f %f %f %f %f %f", instance->username,
		instance->dsps1, instance->dsps5, instance->dsps60, instance->dsps1440,
		instance->dsps10080, instance->best_diff);
	json_decref(val);
}

static void read_workerstats(ckpool_t *ckp, worker_instance_t *worker)
{
	char s[512];
	json_t *val;
	FILE *fp;
	int ret;

	snprintf(s, 511, "%s/workers/%s", ckp->logdir, worker->workername);
	fp = fopen(s, "re");
	if (!fp) {
		LOGINFO("Worker %s does not have a logfile to read", worker->workername);
		return;
	}
	memset(s, 0, 512);
	ret = fread(s, 1, 511, fp);
	fclose(fp);
	if (ret < 1) {
		LOGINFO("Failed to read worker %s logfile", worker->workername);
		return;
	}
	val = json_loads(s, 0, NULL);
	if (!val) {
		LOGINFO("Failed to json decode worker %s logfile: %s", worker->workername, s);
		return;
	}

	tv_time(&worker->last_share);
	worker->dsps1 = dsps_from_key(val, "hashrate1m");
	worker->dsps5 = dsps_from_key(val, "hashrate5m");
	worker->dsps60 = dsps_from_key(val, "hashrate1d");
	worker->dsps1440 = dsps_from_key(val, "hashrate1d");
	json_get_double(&worker->best_diff, val, "bestshare");
	LOGINFO("Successfully read worker %s stats %f %f %f %f %f", worker->workername,
		worker->dsps1, worker->dsps5, worker->dsps60, worker->dsps1440, worker->best_diff);
	json_decref(val);
}


/* This simply strips off the first part of the workername and matches it to a
 * user or creates a new one. Needs to be entered with client holding a ref
 * count. */
static user_instance_t *generate_user(ckpool_t *ckp, stratum_instance_t *client,
				      const char *workername)
{
	char *base_username = strdupa(workername), *username;
	sdata_t *sdata = ckp->data;
	user_instance_t *instance;
	stratum_instance_t *tmp;
	bool new = false;
	int len;

	username = strsep(&base_username, "._");
	if (!username || !strlen(username))
		username = base_username;
	len = strlen(username);
	if (unlikely(len > 127))
		username[127] = '\0';

	ck_wlock(&sdata->instance_lock);
	HASH_FIND_STR(sdata->user_instances, username, instance);
	if (!instance) {
		/* New user instance. Secondary user id will be NULL */
		instance = ckzalloc(sizeof(user_instance_t));
		strcpy(instance->username, username);
		new = true;

		instance->id = sdata->user_instance_id++;
		HASH_ADD_STR(sdata->user_instances, username, instance);
		if (CKP_STANDALONE(ckp))
			read_userstats(ckp, instance);
	}
	DL_FOREACH(instance->instances, tmp) {
		if (!safecmp(workername, tmp->workername)) {
			client->worker_instance = tmp->worker_instance;
			break;
		}
	}
	/* Create one worker instance for combined data from workers of the
	 * same name */
	if (!client->worker_instance) {
		worker_instance_t *worker = ckzalloc(sizeof(worker_instance_t));

		worker->workername = strdup(workername);
		worker->instance = instance;
		DL_APPEND(instance->worker_instances, worker);
		if (CKP_STANDALONE(ckp))
			read_workerstats(ckp, worker);
		worker->start_time = time(NULL);
		client->worker_instance = worker;
	}
	DL_APPEND(instance->instances, client);
	ck_wunlock(&sdata->instance_lock);

	if (new && !ckp->proxy) {
		/* Is this a btc address based username? */
		if (len > 26 && len < 35) {
			instance->btcaddress = test_address(ckp, username);
			if (instance->btcaddress)
				address_to_pubkeytxn(instance->txnbin, username);
		}
		LOGNOTICE("Added new user %s%s", username, instance->btcaddress ?
			  " as address based registration" : "");
	}

	return instance;
}

/* Send this to the database and parse the response to authorise a user
 * and get SUID parameters back. We don't add these requests to the sdata->ckdbqueue
 * since we have to wait for the response but this is done from the authoriser
 * thread so it won't hold anything up but other authorisations. Needs to be
 * entered with client holding a ref count. */
static int send_recv_auth(stratum_instance_t *client)
{
	user_instance_t *user_instance = client->user_instance;
	ckpool_t *ckp = client->ckp;
	sdata_t *sdata = ckp->data;
	char *buf = NULL, *json_msg;
	char cdfield[64];
	int ret = 1;
	json_t *val;
	ts_t now;

	ts_realtime(&now);
	sprintf(cdfield, "%lu,%lu", now.tv_sec, now.tv_nsec);

	val = json_object();
	json_set_string(val, "username", user_instance->username);
	json_set_string(val, "workername", client->workername);
	json_set_string(val, "poolinstance", ckp->name);
	json_set_string(val, "useragent", client->useragent);
	json_set_int(val, "clientid", client->id);
	json_set_string(val,"enonce1", client->enonce1);
	json_set_bool(val, "preauth", false);
	json_set_string(val, "createdate", cdfield);
	json_set_string(val, "createby", "code");
	json_set_string(val, "createcode", __func__);
	json_set_string(val, "createinet", client->address);
	if (user_instance->btcaddress)
		json_msg = ckdb_msg(ckp, val, ID_ADDRAUTH);
	else
		json_msg = ckdb_msg(ckp, val, ID_AUTH);
	if (unlikely(!json_msg)) {
		LOGWARNING("Failed to dump json in send_recv_auth");
		goto out;
	}

	/* We want responses from ckdb serialised and not interleaved with
	 * other requests. Wait up to 3 seconds for exclusive access to ckdb
	 * and if we don't receive it treat it as a delayed auth if possible */
	if (likely(!mutex_timedlock(&sdata->ckdb_lock, 3))) {
		buf = ckdb_msg_call(ckp, json_msg);
		mutex_unlock(&sdata->ckdb_lock);
	}

	free(json_msg);
	if (likely(buf)) {
		worker_instance_t *worker = client->worker_instance;
		char *cmd = NULL, *secondaryuserid = NULL;
		char response[PAGESIZE] = {};
		json_error_t err_val;
		json_t *val = NULL;

		LOGINFO("Got ckdb response: %s", buf);
		if (unlikely(sscanf(buf, "id.%*d.%s", response) < 1 || strlen(response) < 1 || !strchr(response, '='))) {
			if (cmdmatch(response, "failed"))
				goto out;
			LOGWARNING("Got unparseable ckdb auth response: %s", buf);
			goto out_fail;
		}
		cmd = response;
		strsep(&cmd, "=");
		LOGINFO("User %s Worker %s got auth response: %s  cmd: %s",
			user_instance->username, client->workername,
			response, cmd);
		val = json_loads(cmd, 0, &err_val);
		if (unlikely(!val))
			LOGWARNING("AUTH JSON decode failed(%d): %s", err_val.line, err_val.text);
		else {
			json_get_string(&secondaryuserid, val, "secondaryuserid");
			json_get_int(&worker->mindiff, val, "difficultydefault");
			client->suggest_diff = worker->mindiff;
			if (!user_instance->auth_time)
				user_instance->auth_time = time(NULL);
		}
		if (secondaryuserid && (!safecmp(response, "ok.authorise") ||
					!safecmp(response, "ok.addrauth"))) {
			if (!user_instance->secondaryuserid)
				user_instance->secondaryuserid = secondaryuserid;
			else
				dealloc(secondaryuserid);
			ret = 0;
		}
		if (likely(val))
			json_decref(val);
		goto out;
	}
	LOGWARNING("Got no auth response from ckdb :(");
out_fail:
	ret = -1;
out:
	free(buf);
	return ret;
}

/* For sending auths to ckdb after we've already decided we can authorise
 * these clients while ckdb is offline, based on an existing client of the
 * same username already having been authorised. Needs to be entered with
 * client holding a ref count. */
static void queue_delayed_auth(stratum_instance_t *client)
{
	ckpool_t *ckp = client->ckp;
	char cdfield[64];
	json_t *val;
	ts_t now;

	ts_realtime(&now);
	sprintf(cdfield, "%lu,%lu", now.tv_sec, now.tv_nsec);

	JSON_CPACK(val, "{ss,ss,ss,ss,sI,ss,sb,ss,ss,ss,ss}",
			"username", client->user_instance->username,
			"workername", client->workername,
			"poolinstance", ckp->name,
			"useragent", client->useragent,
			"clientid", client->id,
			"enonce1", client->enonce1,
			"preauth", true,
			"createdate", cdfield,
			"createby", "code",
			"createcode", __func__,
			"createinet", client->address);
	ckdbq_add(ckp, ID_AUTH, val);
}

static json_t *__user_notify(sdata_t *sdata, user_instance_t *user_instance, bool clean);

static void __update_solo_client(sdata_t *sdata, stratum_instance_t *client, user_instance_t *user_instance)
{
	json_t *json_msg;

	json_msg = __user_notify(sdata, user_instance, true);
	stratum_add_send(sdata, json_msg, client->id);
}

/* Needs to be entered with client holding a ref count. */
static json_t *parse_authorise(stratum_instance_t *client, json_t *params_val, json_t **err_val,
			       const char *address, int *errnum)
{
	user_instance_t *user_instance;
	ckpool_t *ckp = client->ckp;
	bool ret = false;
	const char *buf;
	int arr_size;
	ts_t now;

	if (unlikely(!json_is_array(params_val))) {
		*err_val = json_string("params not an array");
		goto out;
	}
	arr_size = json_array_size(params_val);
	if (unlikely(arr_size < 1)) {
		*err_val = json_string("params missing array entries");
		goto out;
	}
	if (unlikely(!client->useragent)) {
		*err_val = json_string("Failed subscription");
		goto out;
	}
	buf = json_string_value(json_array_get(params_val, 0));
	if (!buf) {
		*err_val = json_string("Invalid workername parameter");
		goto out;
	}
	if (!strlen(buf)) {
		*err_val = json_string("Empty workername parameter");
		goto out;
	}
	if (!memcmp(buf, ".", 1) || !memcmp(buf, "_", 1)) {
		*err_val = json_string("Empty username parameter");
		goto out;
	}
	if (strchr(buf, '/')) {
		*err_val = json_string("Invalid character in username");
		goto out;
	}
	user_instance = client->user_instance = generate_user(ckp, client, buf);
	client->user_id = user_instance->id;
	ts_realtime(&now);
	client->start_time = now.tv_sec;
	strcpy(client->address, address);

	client->workername = strdup(buf);
	if (CKP_STANDALONE(ckp)) {
		if (!ckp->btcsolo || client->user_instance->btcaddress)
			ret = true;
	} else {
		/* Preauth workers for the first 10 minutes after the user is
		 * first authorised by ckdb to avoid floods of worker auths.
		 * *errnum is implied zero already so ret will be set true */
		if (user_instance->auth_time && time(NULL) - user_instance->auth_time < 600)
			queue_delayed_auth(client);
		else
			*errnum = send_recv_auth(client);
		if (!*errnum)
			ret = true;
		else if (*errnum < 0 && user_instance->secondaryuserid) {
			/* This user has already been authorised but ckdb is
			 * offline so we assume they already exist but add the
			 * auth request to the queued messages. */
			queue_delayed_auth(client);
			ret = true;
		}
	}
	if (ret) {
		client->authorised = ret;
		user_instance->authorised = ret;
		inc_worker(ckp, user_instance);
		LOGNOTICE("Authorised client %ld worker %s as user %s", client->id, buf,
			  user_instance->username);
	} else {
		LOGNOTICE("Client %ld worker %s failed to authorise as user %s", client->id, buf,
			  user_instance->username);
	}
out:
	if (ckp->btcsolo && ret) {
		sdata_t *sdata = ckp->data;

		ck_rlock(&sdata->workbase_lock);
		__generate_userwb(sdata->current_workbase, user_instance);
		__update_solo_client(sdata, client, user_instance);
		ck_runlock(&sdata->workbase_lock);

		stratum_send_diff(sdata, client);
	}
	return json_boolean(ret);
}

/* Needs to be entered with client holding a ref count. */
static void stratum_send_diff(sdata_t *sdata, stratum_instance_t *client)
{
	json_t *json_msg;

	JSON_CPACK(json_msg, "{s[I]soss}", "params", client->diff, "id", json_null(),
			     "method", "mining.set_difficulty");
	stratum_add_send(sdata, json_msg, client->id);
}

/* Needs to be entered with client holding a ref count. */
static void stratum_send_message(sdata_t *sdata, stratum_instance_t *client, const char *msg)
{
	json_t *json_msg;

	JSON_CPACK(json_msg, "{sosss[s]}", "id", json_null(), "method", "client.show_message",
			     "params", msg);
	stratum_add_send(sdata, json_msg, client->id);
}

static double time_bias(double tdiff, double period)
{
	double dexp = tdiff / period;

	/* Sanity check to prevent silly numbers for double accuracy **/
	if (unlikely(dexp > 36))
		dexp = 36;
	return 1.0 - 1.0 / exp(dexp);
}

/* Sanity check to prevent clock adjustments backwards from screwing up stats */
static double sane_tdiff(tv_t *end, tv_t *start)
{
	double tdiff = tvdiff(end, start);

	if (unlikely(tdiff < 0.001))
		tdiff = 0.001;
	return tdiff;
}

/* Needs to be entered with client holding a ref count. */
static void add_submit(ckpool_t *ckp, stratum_instance_t *client, int diff, bool valid,
		       bool submit)
{
	worker_instance_t *worker = client->worker_instance;
	double tdiff, bdiff, dsps, drr, network_diff, bias;
	user_instance_t *instance = client->user_instance;
	int64_t next_blockid, optimal;
	sdata_t *sdata = ckp->data;
	tv_t now_t;

	mutex_lock(&sdata->stats_lock);
	if (valid) {
		sdata->stats.unaccounted_shares++;
		sdata->stats.unaccounted_diff_shares += diff;
	} else
		sdata->stats.unaccounted_rejects += diff;
	mutex_unlock(&sdata->stats_lock);

	/* Count only accepted and stale rejects in diff calculation. */
	if (!valid && !submit)
		return;

	tv_time(&now_t);

	ck_rlock(&sdata->workbase_lock);
	next_blockid = sdata->workbase_id + 1;
	if (ckp->proxy)
		network_diff = sdata->current_workbase->diff;
	else
		network_diff = sdata->current_workbase->network_diff;
	ck_runlock(&sdata->workbase_lock);

	if (unlikely(!client->first_share.tv_sec)) {
		copy_tv(&client->first_share, &now_t);
		copy_tv(&client->ldc, &now_t);
	}

	tdiff = sane_tdiff(&now_t, &client->last_share);
	decay_time(&client->dsps1, diff, tdiff, 60);
	decay_time(&client->dsps5, diff, tdiff, 300);
	decay_time(&client->dsps60, diff, tdiff, 3600);
	decay_time(&client->dsps1440, diff, tdiff, 86400);
	decay_time(&client->dsps10080, diff, tdiff, 604800);
	copy_tv(&client->last_share, &now_t);

	tdiff = sane_tdiff(&now_t, &worker->last_share);
	decay_time(&worker->dsps1, diff, tdiff, 60);
	decay_time(&worker->dsps5, diff, tdiff, 300);
	decay_time(&worker->dsps60, diff, tdiff, 3600);
	decay_time(&worker->dsps1440, diff, tdiff, 86400);
	copy_tv(&worker->last_share, &now_t);
	worker->idle = false;

	tdiff = sane_tdiff(&now_t, &instance->last_share);
	decay_time(&instance->dsps1, diff, tdiff, 60);
	decay_time(&instance->dsps5, diff, tdiff, 300);
	decay_time(&instance->dsps60, diff, tdiff, 3600);
	decay_time(&instance->dsps1440, diff, tdiff, 86400);
	decay_time(&instance->dsps10080, diff, tdiff, 604800);
	copy_tv(&instance->last_share, &now_t);
	client->idle = false;

	client->ssdc++;
	bdiff = sane_tdiff(&now_t, &client->first_share);
	bias = time_bias(bdiff, 300);
	tdiff = sane_tdiff(&now_t, &client->ldc);

	/* Check the difficulty every 240 seconds or as many shares as we
	 * should have had in that time, whichever comes first. */
	if (client->ssdc < 72 && tdiff < 240)
		return;

	if (diff != client->diff) {
		client->ssdc = 0;
		return;
	}

	/* Diff rate ratio */
	dsps = client->dsps5 / bias;
	drr = dsps / (double)client->diff;

	/* Optimal rate product is 0.3, allow some hysteresis. */
	if (drr > 0.15 && drr < 0.4)
		return;

	/* Allow slightly lower diffs when users choose their own mindiff */
	if (worker->mindiff || client->suggest_diff) {
		if (drr < 0.5)
			return;
		optimal = lround(dsps * 2.4);
	} else
		optimal = lround(dsps * 3.33);

	/* Clamp to mindiff ~ network_diff */
	if (optimal < ckp->mindiff)
		optimal = ckp->mindiff;
	/* Client suggest diff overrides worker mindiff */
	if (client->suggest_diff) {
		if (optimal < client->suggest_diff)
			optimal = client->suggest_diff;
	} else if (optimal < worker->mindiff)
		optimal = worker->mindiff;
	if (ckp->maxdiff && optimal > ckp->maxdiff)
		optimal = ckp->maxdiff;
	if (optimal > network_diff)
		optimal = network_diff;
	if (client->diff == optimal)
		return;

	/* If this is the first share in a change, reset the last diff change
	 * to make sure the client hasn't just fallen back after a leave of
	 * absence */
	if (optimal < client->diff && client->ssdc == 1) {
		copy_tv(&client->ldc, &now_t);
		return;
	}

	client->ssdc = 0;

	LOGINFO("Client %ld biased dsps %.2f dsps %.2f drr %.2f adjust diff from %ld to: %ld ",
		client->id, dsps, client->dsps5, drr, client->diff, optimal);

	copy_tv(&client->ldc, &now_t);
	client->diff_change_job_id = next_blockid;
	client->old_diff = client->diff;
	client->diff = optimal;
	stratum_send_diff(sdata, client);
}

/* We should already be holding the workbase_lock. Needs to be entered with
 * client holding a ref count. */
static void
test_blocksolve(stratum_instance_t *client, workbase_t *wb, const uchar *data, const uchar *hash,
		double diff, const char *coinbase, int cblen, const char *nonce2, const char *nonce)
{
	int transactions = wb->transactions + 1;
	char hexcoinbase[1024], blockhash[68];
	json_t *val = NULL, *val_copy;
	char *gbt_block, varint[12];
	ckpool_t *ckp = wb->ckp;
	sdata_t *sdata = ckp->data;
	ckmsg_t *block_ckmsg;
	char cdfield[64];
	uchar swap[32];
	ts_t ts_now;

	/* Submit anything over 99% of the diff in case of rounding errors */
	if (diff < sdata->current_workbase->network_diff * 0.99)
		return;

	LOGWARNING("Possible block solve diff %f !", diff);
	/* Can't submit a block in proxy mode without the transactions */
	if (wb->proxy && wb->merkles)
		return;

	ts_realtime(&ts_now);
	sprintf(cdfield, "%lu,%lu", ts_now.tv_sec, ts_now.tv_nsec);

	gbt_block = ckalloc(1024);
	flip_32(swap, hash);
	__bin2hex(blockhash, swap, 32);

	/* Message format: "submitblock:hash,data" */
	sprintf(gbt_block, "submitblock:%s,", blockhash);
	__bin2hex(gbt_block + 12 + 64 + 1, data, 80);
	if (transactions < 0xfd) {
		uint8_t val8 = transactions;

		__bin2hex(varint, (const unsigned char *)&val8, 1);
	} else if (transactions <= 0xffff) {
		uint16_t val16 = htole16(transactions);

		strcat(gbt_block, "fd");
		__bin2hex(varint, (const unsigned char *)&val16, 2);
	} else {
		uint32_t val32 = htole32(transactions);

		strcat(gbt_block, "fe");
		__bin2hex(varint, (const unsigned char *)&val32, 4);
	}
	strcat(gbt_block, varint);
	__bin2hex(hexcoinbase, coinbase, cblen);
	strcat(gbt_block, hexcoinbase);
	if (wb->transactions)
		realloc_strcat(&gbt_block, wb->txn_data);
	send_generator(ckp, gbt_block, GEN_PRIORITY);
	free(gbt_block);

	JSON_CPACK(val, "{si,ss,ss,sI,ss,ss,sI,ss,ss,ss,sI,ss,ss,ss,ss}",
			"height", wb->height,
			"blockhash", blockhash,
			"confirmed", "n",
			"workinfoid", wb->id,
			"username", client->user_instance->username,
			"workername", client->workername,
			"clientid", client->id,
			"enonce1", client->enonce1,
			"nonce2", nonce2,
			"nonce", nonce,
			"reward", wb->coinbasevalue,
			"createdate", cdfield,
			"createby", "code",
			"createcode", __func__,
			"createinet", ckp->serverurl[client->server]);
	val_copy = json_deep_copy(val);
	block_ckmsg = ckalloc(sizeof(ckmsg_t));
	block_ckmsg->data = val_copy;

	mutex_lock(&sdata->block_lock);
	DL_APPEND(sdata->block_solves, block_ckmsg);
	mutex_unlock(&sdata->block_lock);

	ckdbq_add(ckp, ID_BLOCK, val);
}

/* Needs to be entered with client holding a ref count. */
static inline uchar *user_coinb2(stratum_instance_t *client, workbase_t *wb)
{
	struct userwb *userwb;
	int64_t id;

	if (!client->ckp->btcsolo)
		return wb->coinb2bin;

	id = wb->id;
	HASH_FIND_I64(client->user_instance->userwbs, &id, userwb);
	if (unlikely(!userwb))
		return wb->coinb2bin;
	return userwb->coinb2bin;
}

/* Needs to be entered with client holding a ref count. */
static double submission_diff(stratum_instance_t *client, workbase_t *wb, const char *nonce2,
			      uint32_t ntime32, const char *nonce, uchar *hash)
{
	unsigned char merkle_root[32], merkle_sha[64];
	uint32_t *data32, *swap32, benonce32;
	char *coinbase, data[80];
	uchar swap[80], hash1[32];
	uchar *coinb2bin;
	int cblen, i;
	double ret;

	coinbase = alloca(wb->coinb1len + wb->enonce1constlen + wb->enonce1varlen + wb->enonce2varlen + wb->coinb2len);
	memcpy(coinbase, wb->coinb1bin, wb->coinb1len);
	cblen = wb->coinb1len;
	memcpy(coinbase + cblen, &client->enonce1bin, wb->enonce1constlen + wb->enonce1varlen);
	cblen += wb->enonce1constlen + wb->enonce1varlen;
	hex2bin(coinbase + cblen, nonce2, wb->enonce2varlen);
	cblen += wb->enonce2varlen;
	coinb2bin = user_coinb2(client, wb);
	memcpy(coinbase + cblen, coinb2bin, wb->coinb2len);
	cblen += wb->coinb2len;

	gen_hash((uchar *)coinbase, merkle_root, cblen);
	memcpy(merkle_sha, merkle_root, 32);
	for (i = 0; i < wb->merkles; i++) {
		memcpy(merkle_sha + 32, &wb->merklebin[i], 32);
		gen_hash(merkle_sha, merkle_root, 64);
		memcpy(merkle_sha, merkle_root, 32);
	}
	data32 = (uint32_t *)merkle_sha;
	swap32 = (uint32_t *)merkle_root;
	flip_32(swap32, data32);

	/* Copy the cached header binary and insert the merkle root */
	memcpy(data, wb->headerbin, 80);
	memcpy(data + 36, merkle_root, 32);

	/* Insert the nonce value into the data */
	hex2bin(&benonce32, nonce, 4);
	data32 = (uint32_t *)(data + 64 + 12);
	*data32 = benonce32;

	/* Insert the ntime value into the data */
	data32 = (uint32_t *)(data + 68);
	*data32 = htobe32(ntime32);

	/* Hash the share */
	data32 = (uint32_t *)data;
	swap32 = (uint32_t *)swap;
	flip_80(swap32, data32);
	sha256(swap, 80, hash1);
	sha256(hash1, 32, hash);

	/* Calculate the diff of the share here */
	ret = diff_from_target(hash);

	/* Test we haven't solved a block regardless of share status */
	test_blocksolve(client, wb, swap, hash, ret, coinbase, cblen, nonce2, nonce);

	return ret;
}

static bool new_share(sdata_t *sdata, const uchar *hash, int64_t  wb_id)
{
	share_t *share, *match = NULL;
	bool ret = false;

	ck_wlock(&sdata->share_lock);
	HASH_FIND(hh, sdata->shares, hash, 32, match);
	if (match)
		goto out_unlock;
	share = ckzalloc(sizeof(share_t));
	memcpy(share->hash, hash, 32);
	share->workbase_id = wb_id;
	sdata->shares_generated++;
	HASH_ADD(hh, sdata->shares, hash, 32, share);
	ret = true;
out_unlock:
	ck_wunlock(&sdata->share_lock);

	return ret;
}

/* Submit a share in proxy mode to the parent pool. workbase_lock is held.
 * Needs to be entered with client holding a ref count. */
static void submit_share(stratum_instance_t *client, int64_t jobid, const char *nonce2,
			 const char *ntime, const char *nonce, int msg_id)
{
	ckpool_t *ckp = client->ckp;
	json_t *json_msg;
	char enonce2[32];
	char *msg;

	sprintf(enonce2, "%s%s", client->enonce1var, nonce2);
	JSON_CPACK(json_msg, "{sisssssssIsi}", "jobid", jobid, "nonce2", enonce2,
			     "ntime", ntime, "nonce", nonce, "client_id", client->id,
			     "msg_id", msg_id);
	msg = json_dumps(json_msg, 0);
	json_decref(json_msg);
	send_generator(ckp, msg, GEN_LAX);
	free(msg);
}

#define JSON_ERR(err) json_string(SHARE_ERR(err))

/* Needs to be entered with client holding a ref count. */
static json_t *parse_submit(stratum_instance_t *client, json_t *json_msg,
			    json_t *params_val, json_t **err_val)
{
	bool share = false, result = false, invalid = true, submit = false;
	user_instance_t *user_instance = client->user_instance;
	double diff = client->diff, wdiff = 0, sdiff = -1;
	char hexhash[68] = {}, sharehash[32], cdfield[64];
	const char *user, *job_id, *ntime, *nonce;
	char *fname = NULL, *s, *nonce2;
	enum share_err err = SE_NONE;
	ckpool_t *ckp = client->ckp;
	sdata_t *sdata = ckp->data;
	char idstring[20] = {};
	workbase_t *wb = NULL;
	uint32_t ntime32;
	uchar hash[32];
	int nlen, len;
	time_t now_t;
	json_t *val;
	int64_t id;
	ts_t now;
	FILE *fp;

	ts_realtime(&now);
	now_t = now.tv_sec;
	sprintf(cdfield, "%lu,%lu", now.tv_sec, now.tv_nsec);

	if (unlikely(!json_is_array(params_val))) {
		err = SE_NOT_ARRAY;
		*err_val = JSON_ERR(err);
		goto out;
	}
	if (unlikely(json_array_size(params_val) != 5)) {
		err = SE_INVALID_SIZE;
		*err_val = JSON_ERR(err);
		goto out;
	}
	user = json_string_value(json_array_get(params_val, 0));
	if (unlikely(!user || !strlen(user))) {
		err = SE_NO_USERNAME;
		*err_val = JSON_ERR(err);
		goto out;
	}
	job_id = json_string_value(json_array_get(params_val, 1));
	if (unlikely(!job_id || !strlen(job_id))) {
		err = SE_NO_JOBID;
		*err_val = JSON_ERR(err);
		goto out;
	}
	nonce2 = (char *)json_string_value(json_array_get(params_val, 2));
	if (unlikely(!nonce2 || !strlen(nonce2))) {
		err = SE_NO_NONCE2;
		*err_val = JSON_ERR(err);
		goto out;
	}
	ntime = json_string_value(json_array_get(params_val, 3));
	if (unlikely(!ntime || !strlen(ntime))) {
		err = SE_NO_NTIME;
		*err_val = JSON_ERR(err);
		goto out;
	}
	nonce = json_string_value(json_array_get(params_val, 4));
	if (unlikely(!nonce || !strlen(nonce))) {
		err = SE_NO_NONCE;
		*err_val = JSON_ERR(err);
		goto out;
	}
	if (safecmp(user, client->workername)) {
		err = SE_WORKER_MISMATCH;
		*err_val = JSON_ERR(err);
		goto out;
	}
	sscanf(job_id, "%lx", &id);
	sscanf(ntime, "%x", &ntime32);

	share = true;

	ck_rlock(&sdata->workbase_lock);
	HASH_FIND_I64(sdata->workbases, &id, wb);
	if (unlikely(!wb)) {
		id = sdata->current_workbase->id;
		err = SE_INVALID_JOBID;
		json_set_string(json_msg, "reject-reason", SHARE_ERR(err));
		strncpy(idstring, job_id, 19);
		ASPRINTF(&fname, "%s.sharelog", sdata->current_workbase->logdir);
		goto out_unlock;
	}
	wdiff = wb->diff;
	strncpy(idstring, wb->idstring, 19);
	ASPRINTF(&fname, "%s.sharelog", wb->logdir);
	/* Fix broken clients sending too many chars. Nonce2 is part of the
	 * read only json so use a temporary variable and modify it. */
	len = wb->enonce2varlen * 2;
	nlen = strlen(nonce2);
	if (nlen > len) {
		nonce2 = strdupa(nonce2);
		nonce2[len] = '\0';
	} else if (nlen < len) {
		char *tmp = nonce2;

		nonce2 = strdupa("0000000000000000");
		memcpy(nonce2, tmp, nlen);
		nonce2[len] = '\0';
	}
	sdiff = submission_diff(client, wb, nonce2, ntime32, nonce, hash);
	if (sdiff > client->best_diff) {
		worker_instance_t *worker = client->worker_instance;

		client->best_diff = sdiff;
		LOGINFO("User %s worker %s client %ld new best diff %lf", user_instance->username,
			worker->workername, client->id, sdiff);
		if (sdiff > worker->best_diff)
			worker->best_diff = sdiff;
		if (sdiff > user_instance->best_diff)
			user_instance->best_diff = sdiff;
	}
	bswap_256(sharehash, hash);
	__bin2hex(hexhash, sharehash, 32);

	if (id < sdata->blockchange_id) {
		err = SE_STALE;
		json_set_string(json_msg, "reject-reason", SHARE_ERR(err));
		goto out_submit;
	}
	/* Ntime cannot be less, but allow forward ntime rolling up to max */
	if (ntime32 < wb->ntime32 || ntime32 > wb->ntime32 + 7000) {
		err = SE_NTIME_INVALID;
		json_set_string(json_msg, "reject-reason", SHARE_ERR(err));
		goto out_unlock;
	}
	invalid = false;
out_submit:
	if (sdiff >= wdiff)
		submit = true;
out_unlock:
	ck_runlock(&sdata->workbase_lock);

	/* Accept the lower of new and old diffs until the next update */
	if (id < client->diff_change_job_id && client->old_diff < client->diff)
		diff = client->old_diff;
	if (!invalid) {
		char wdiffsuffix[16];

		suffix_string(wdiff, wdiffsuffix, 16, 0);
		if (sdiff >= diff) {
			if (new_share(sdata, hash, id)) {
				LOGINFO("Accepted client %ld share diff %.1f/%.0f/%s: %s",
					client->id, sdiff, diff, wdiffsuffix, hexhash);
				result = true;
			} else {
				err = SE_DUPE;
				json_set_string(json_msg, "reject-reason", SHARE_ERR(err));
				LOGINFO("Rejected client %ld dupe diff %.1f/%.0f/%s: %s",
					client->id, sdiff, diff, wdiffsuffix, hexhash);
				submit = false;
			}
		} else {
			err = SE_HIGH_DIFF;
			LOGINFO("Rejected client %ld high diff %.1f/%.0f/%s: %s",
				client->id, sdiff, diff, wdiffsuffix, hexhash);
			json_set_string(json_msg, "reject-reason", SHARE_ERR(err));
			submit = false;
		}
	}  else
		LOGINFO("Rejected client %ld invalid share", client->id);

	/* Submit share to upstream pool in proxy mode. We submit valid and
	 * stale shares and filter out the rest. */
	if (wb && wb->proxy && submit) {
		LOGINFO("Submitting share upstream: %s", hexhash);
		submit_share(client, id, nonce2, ntime, nonce, json_integer_value(json_object_get(json_msg, "id")));
	}

	add_submit(ckp, client, diff, result, submit);

	/* Now write to the pool's sharelog. */
	val = json_object();
	json_set_int(val, "workinfoid", id);
	json_set_int(val, "clientid", client->id);
	json_set_string(val, "enonce1", client->enonce1);
	if (!CKP_STANDALONE(ckp))
		json_set_string(val, "secondaryuserid", user_instance->secondaryuserid);
	json_set_string(val, "nonce2", nonce2);
	json_set_string(val, "nonce", nonce);
	json_set_string(val, "ntime", ntime);
	json_set_double(val, "diff", diff);
	json_set_double(val, "sdiff", sdiff);
	json_set_string(val, "hash", hexhash);
	json_set_bool(val, "result", result);
	json_object_set(val, "reject-reason", json_object_get(json_msg, "reject-reason"));
	json_object_set(val, "error", *err_val);
	json_set_int(val, "errn", err);
	json_set_string(val, "createdate", cdfield);
	json_set_string(val, "createby", "code");
	json_set_string(val, "createcode", __func__);
	json_set_string(val, "createinet", ckp->serverurl[client->server]);
	json_set_string(val, "workername", client->workername);
	json_set_string(val, "username", user_instance->username);

	if (ckp->logshares) {
		fp = fopen(fname, "ae");
		if (likely(fp)) {
			s = json_dumps(val, JSON_EOL);
			len = strlen(s);
			len = fprintf(fp, "%s", s);
			free(s);
			fclose(fp);
			if (unlikely(len < 0))
				LOGERR("Failed to fwrite to %s", fname);
		} else
			LOGERR("Failed to fopen %s", fname);
	}
	ckdbq_add(ckp, ID_SHARES, val);
out:
	if ((!result && !submit) || !share) {
		/* Is this the first in a run of invalids? */
		if (client->first_invalid < client->last_share.tv_sec || !client->first_invalid)
			client->first_invalid = now_t;
		else if (client->first_invalid && client->first_invalid < now_t - 120) {
			LOGNOTICE("Client %ld rejecting for 120s, disconnecting", client->id);
			stratum_send_message(sdata, client, "Disconnecting for continuous invalid shares");
			client->reject = 2;
		} else if (client->first_invalid && client->first_invalid < now_t - 60) {
			if (!client->reject) {
				LOGINFO("Client %ld rejecting for 60s, sending diff", client->id);
				stratum_send_diff(sdata, client);
				client->reject = 1;
			}
		}
	} else {
		client->first_invalid = 0;
		client->reject = 0;
	}

	if (!share) {
		val = json_object();
		json_set_int(val, "clientid", client->id);
		if (!CKP_STANDALONE(ckp))
			json_set_string(val, "secondaryuserid", user_instance->secondaryuserid);
		json_set_string(val, "enonce1", client->enonce1);
		json_set_int(val, "workinfoid", sdata->current_workbase->id);
		json_set_string(val, "workername", client->workername);
		json_set_string(val, "username", user_instance->username);
		json_object_set(val, "error", *err_val);
		json_set_int(val, "errn", err);
		json_set_string(val, "createdate", cdfield);
		json_set_string(val, "createby", "code");
		json_set_string(val, "createcode", __func__);
		json_set_string(val, "createinet", ckp->serverurl[client->server]);
		ckdbq_add(ckp, ID_SHAREERR, val);
		LOGINFO("Invalid share from client %ld: %s", client->id, client->workername);
	}
	free(fname);
	return json_boolean(result);
}

/* Must enter with workbase_lock held */
static json_t *__stratum_notify(sdata_t *sdata, bool clean)
{
	json_t *val;

	JSON_CPACK(val, "{s:[ssssosssb],s:o,s:s}",
			"params",
			sdata->current_workbase->idstring,
			sdata->current_workbase->prevhash,
			sdata->current_workbase->coinb1,
			sdata->current_workbase->coinb2,
			json_deep_copy(sdata->current_workbase->merkle_array),
			sdata->current_workbase->bbversion,
			sdata->current_workbase->nbit,
			sdata->current_workbase->ntime,
			clean,
			"id", json_null(),
			"method", "mining.notify");
	return val;
}

static void stratum_broadcast_update(sdata_t *sdata, bool clean)
{
	json_t *json_msg;

	ck_rlock(&sdata->workbase_lock);
	json_msg = __stratum_notify(sdata, clean);
	ck_runlock(&sdata->workbase_lock);

	stratum_broadcast(sdata, json_msg);
}

/* For sending a single stratum template update */
static void stratum_send_update(sdata_t *sdata, int64_t client_id, bool clean)
{
	json_t *json_msg;

	ck_rlock(&sdata->workbase_lock);
	json_msg = __stratum_notify(sdata, clean);
	ck_runlock(&sdata->workbase_lock);

	stratum_add_send(sdata, json_msg, client_id);
}

static json_t *__user_notify(sdata_t *sdata, user_instance_t *user_instance, bool clean)
{
	int64_t id = sdata->current_workbase->id;
	struct userwb *userwb;
	json_t *val;

	HASH_FIND_I64(user_instance->userwbs, &id, userwb);
	if (unlikely(!userwb)) {
		LOGINFO("Failed to find userwb in __user_notify!");
		return NULL;
	}

	JSON_CPACK(val, "{s:[ssssosssb],s:o,s:s}",
			"params",
			sdata->current_workbase->idstring,
			sdata->current_workbase->prevhash,
			sdata->current_workbase->coinb1,
			userwb->coinb2,
			json_deep_copy(sdata->current_workbase->merkle_array),
			sdata->current_workbase->bbversion,
			sdata->current_workbase->nbit,
			sdata->current_workbase->ntime,
			clean,
			"id", json_null(),
			"method", "mining.notify");
	return val;
}

/* Current workbase can't be pulled out from under us here even without
 * locking since it's serialised with this code. Sends a stratum update with
 * a unique coinb2 for every client. */
static void stratum_broadcast_updates(sdata_t *sdata, bool clean)
{
	stratum_instance_t *client, *tmp;
	json_t *json_msg;

	ck_rlock(&sdata->instance_lock);
	HASH_ITER(hh, sdata->stratum_instances, client, tmp) {
		if (!client->user_instance)
			continue;

		json_msg = __user_notify(sdata, client->user_instance, clean);
		if (likely(json_msg))
			stratum_add_send(sdata, json_msg, client->id);
	}
	ck_runlock(&sdata->instance_lock);
}

static void send_json_err(sdata_t *sdata, int64_t client_id, json_t *id_val, const char *err_msg)
{
	json_t *val;

	JSON_CPACK(val, "{soss}", "id", json_copy(id_val), "error", err_msg);
	stratum_add_send(sdata, val, client_id);
}

/* Needs to be entered with client holding a ref count. */
static void update_client(sdata_t *sdata, stratum_instance_t *client, const int64_t client_id)
{
	stratum_send_update(sdata, client_id, true);
	stratum_send_diff(sdata, client);
}

static json_params_t
*create_json_params(const int64_t client_id, json_t *method, const json_t *params,
		    const json_t *id_val, const char *address)
{
	json_params_t *jp = ckalloc(sizeof(json_params_t));

	jp->method = json_copy(method);
	jp->params = json_deep_copy(params);
	jp->id_val = json_deep_copy(id_val);
	jp->client_id = client_id;
	strcpy(jp->address, address);
	return jp;
}

static void set_worker_mindiff(ckpool_t *ckp, const char *workername, int mindiff)
{
	worker_instance_t *worker = NULL, *tmp;
	char *username = strdupa(workername), *ignore;
	user_instance_t *instance = NULL;
	stratum_instance_t *client;
	sdata_t *sdata = ckp->data;

	ignore = username;
	strsep(&ignore, "._");

	/* Find the user first */
	ck_rlock(&sdata->instance_lock);
	HASH_FIND_STR(sdata->user_instances, username, instance);
	ck_runlock(&sdata->instance_lock);

	/* They may just have not connected yet */
	if (!instance) {
		LOGINFO("Failed to find user %s in set_worker_mindiff", username);
		return;
	}

	/* Then find the matching worker instance */
	ck_rlock(&sdata->instance_lock);
	DL_FOREACH(instance->worker_instances, tmp) {
		if (!safecmp(workername, tmp->workername)) {
			worker = tmp;
			break;
		}
	}
	ck_runlock(&sdata->instance_lock);

	/* They may just not be connected at the moment */
	if (!worker) {
		LOGINFO("Failed to find worker %s in set_worker_mindiff", workername);
		return;
	}

	if (mindiff < 1) {
		LOGINFO("Worker %s requested invalid diff %d", worker->workername, mindiff);
		return;
	}
	if (mindiff < ckp->mindiff)
		mindiff = ckp->mindiff;
	if (mindiff == worker->mindiff)
		return;
	worker->mindiff = mindiff;

	/* Iterate over all the workers from this user to find any with the
	 * matching worker that are currently live and send them a new diff
	 * if we can. Otherwise it will only act as a clamp on next share
	 * submission. */
	ck_rlock(&sdata->instance_lock);
	DL_FOREACH(instance->instances, client) {
		if (client->worker_instance != worker)
			continue;
		/* Per connection suggest diff overrides worker mindiff ugh */
		if (mindiff < client->suggest_diff)
			continue;
		if (mindiff == client->diff)
			continue;
		client->diff = mindiff;
		stratum_send_diff(sdata, client);
	}
	ck_runlock(&sdata->instance_lock);
}

/* Implement support for the diff in the params as well as the originally
 * documented form of placing diff within the method. Needs to be entered with
 * client holding a ref count. */
static void suggest_diff(stratum_instance_t *client, const char *method, json_t *params_val)
{
	json_t *arr_val = json_array_get(params_val, 0);
	sdata_t *sdata = client->ckp->data;
	int64_t sdiff;

	if (unlikely(!client->authorised)) {
		LOGWARNING("Attempted to suggest diff on unauthorised client %ld", client->id);
		return;
	}
	if (arr_val && json_is_integer(arr_val))
		sdiff = json_integer_value(arr_val);
	else if (sscanf(method, "mining.suggest_difficulty(%ld", &sdiff) != 1) {
		LOGINFO("Failed to parse suggest_difficulty for client %"PRId64, client->id);
		return;
	}
	if (sdiff == client->suggest_diff)
		return;
	client->suggest_diff = sdiff;
	if (client->diff == sdiff)
		return;
	if (sdiff < client->ckp->mindiff)
		client->diff = client->ckp->mindiff;
	else
		client->diff = sdiff;
	stratum_send_diff(sdata, client);
}

static void parse_method(sdata_t *sdata, const int64_t client_id, json_t *id_val,
			 json_t *method_val, json_t *params_val, char *address)
{
	stratum_instance_t *client;
	const char *method;
	char buf[256];

	client = ref_instance_by_id(sdata, client_id);
	if (unlikely(!client)) {
		LOGINFO("Failed to find client id %ld in hashtable!", client_id);
		return;
	}

	if (unlikely(client->reject == 2)) {
		LOGINFO("Dropping client %"PRId64" tagged for lazy invalidation", client_id);
		snprintf(buf, 255, "dropclient=%ld", client->id);
		send_proc(client->ckp->connector, buf);
		goto out;
	}

	/* Random broken clients send something not an integer as the id so we copy
	 * the json item for id_val as is for the response. */
	method = json_string_value(method_val);
	if (cmdmatch(method, "mining.subscribe")) {
		json_t *val, *result_val = parse_subscribe(client, client_id, params_val);

		/* Shouldn't happen, sanity check */
		if (unlikely(!result_val)) {
			LOGWARNING("parse_subscribe returned NULL result_val");
			goto out;
		}
		val = json_object();
		json_object_set_new_nocheck(val, "result", result_val);
		json_object_set_nocheck(val, "id", id_val);
		json_object_set_new_nocheck(val, "error", json_null());
		stratum_add_send(sdata, val, client_id);
		if (!client->ckp->btcsolo && likely(client->subscribed))
			update_client(sdata, client, client_id);
		goto out;
	}

	if (unlikely(cmdmatch(method, "mining.passthrough"))) {
		/* We need to inform the connector process that this client
		 * is a passthrough and to manage its messages accordingly.
		 * Remove this instance since the client id may well be
		 * reused */
		ck_wlock(&sdata->instance_lock);
		if (likely(__instance_by_id(sdata, client_id)))
			HASH_DEL(sdata->stratum_instances, client);
		__add_dead(sdata, client);
		ck_wunlock(&sdata->instance_lock);

		LOGNOTICE("Adding passthrough client %ld", client->id);
		snprintf(buf, 255, "passthrough=%ld", client->id);
		send_proc(client->ckp->connector, buf);
		goto out;
	}

	if (cmdmatch(method, "mining.auth") && client->subscribed) {
		json_params_t *jp = create_json_params(client_id, method_val, params_val, id_val, address);

		ckmsgq_add(sdata->sauthq, jp);
		goto out;
	}

	/* We should only accept authorised requests from here on */
	if (!client->authorised) {
		/* Dropping unauthorised clients here also allows the
		 * stratifier process to restart since it will have lost all
		 * the stratum instance data. Clients will just reconnect. */
		LOGINFO("Dropping unauthorised client %ld", client->id);
		snprintf(buf, 255, "dropclient=%ld", client->id);
		send_proc(client->ckp->connector, buf);
		goto out;
	}

	if (cmdmatch(method, "mining.submit")) {
		json_params_t *jp = create_json_params(client_id, method_val, params_val, id_val, address);

		ckmsgq_add(sdata->sshareq, jp);
		goto out;
	}

	if (cmdmatch(method, "mining.suggest")) {
		suggest_diff(client, method, params_val);
		goto out;
	}

	/* Covers both get_transactions and get_txnhashes */
	if (cmdmatch(method, "mining.get")) {
		json_params_t *jp = create_json_params(client_id, method_val, params_val, id_val, address);

		ckmsgq_add(sdata->stxnq, jp);
		goto out;
	}
	/* Unhandled message here */
out:
	dec_instance_ref(sdata, client);
}

static void parse_instance_msg(sdata_t *sdata, smsg_t *msg)
{
	json_t *val = msg->json_msg, *id_val, *method, *params;
	int64_t client_id = msg->client_id;

	/* Return back the same id_val even if it's null or not existent. */
	id_val = json_object_get(val, "id");

	method = json_object_get(val, "method");
	if (unlikely(!method)) {
		json_t *res_val = json_object_get(val, "result");

		/* Is this a spurious result or ping response? */
		if (res_val) {
			const char *result = json_string_value(res_val);

			LOGDEBUG("Received spurious response %s", result ? result : "");
			goto out;
		}
		send_json_err(sdata, client_id, id_val, "-3:method not found");
		goto out;
	}
	if (unlikely(!json_is_string(method))) {
		send_json_err(sdata, client_id, id_val, "-1:method is not string");
		goto out;
	}
	params = json_object_get(val, "params");
	if (unlikely(!params)) {
		send_json_err(sdata, client_id, id_val, "-1:params not found");
		goto out;
	}
	parse_method(sdata, client_id, id_val, method, params, msg->address);
out:
	json_decref(val);
	free(msg);
}

static void srecv_process(ckpool_t *ckp, char *buf)
{
	sdata_t *sdata = ckp->data;
	smsg_t *msg;
	json_t *val;
	int server;

	val = json_loads(buf, 0, NULL);
	if (unlikely(!val)) {
		LOGWARNING("Received unrecognised non-json message: %s", buf);
		goto out;
	}
	msg = ckzalloc(sizeof(smsg_t));
	msg->json_msg = val;
	val = json_object_get(msg->json_msg, "client_id");
	if (unlikely(!val)) {
		LOGWARNING("Failed to extract client_id from connector json smsg %s", buf);
		json_decref(msg->json_msg);
		free(msg);
		goto out;
	}

	msg->client_id = json_integer_value(val);
	json_object_clear(val);

	val = json_object_get(msg->json_msg, "address");
	if (unlikely(!val)) {
		LOGWARNING("Failed to extract address from connector json smsg %s", buf);
		json_decref(msg->json_msg);
		free(msg);
		goto out;
	}
	strcpy(msg->address, json_string_value(val));
	json_object_clear(val);

	val = json_object_get(msg->json_msg, "server");
	if (unlikely(!val)) {
		LOGWARNING("Failed to extract server from connector json smsg %s", buf);
		json_decref(msg->json_msg);
		free(msg);
		goto out;
	}
	server = json_integer_value(val);
	json_object_clear(val);

	/* Parse the message here */
	ck_wlock(&sdata->instance_lock);
	/* client_id instance doesn't exist yet, create one */
	if (!__instance_by_id(sdata, msg->client_id))
		__stratum_add_instance(ckp, msg->client_id, server);
	ck_wunlock(&sdata->instance_lock);

	parse_instance_msg(sdata, msg);
out:
	free(buf);
}

static void discard_stratum_msg(smsg_t **msg)
{
	json_decref((*msg)->json_msg);
	free(*msg);
	*msg = NULL;
}

static void ssend_process(ckpool_t *ckp, smsg_t *msg)
{
	char *s;

	if (unlikely(!msg->json_msg)) {
		LOGERR("Sent null json msg to stratum_sender");
		free(msg);
		return;
	}

	/* Add client_id to the json message and send it to the
	 * connector process to be delivered */
	json_object_set_new_nocheck(msg->json_msg, "client_id", json_integer(msg->client_id));
	s = json_dumps(msg->json_msg, 0);
	send_proc(ckp->connector, s);
	free(s);
	discard_stratum_msg(&msg);
}

static void discard_json_params(json_params_t **jp)
{
	json_decref((*jp)->method);
	json_decref((*jp)->params);
	json_decref((*jp)->id_val);
	free(*jp);
	*jp = NULL;
}

static void sshare_process(ckpool_t *ckp, json_params_t *jp)
{
	json_t *result_val, *json_msg, *err_val = NULL;
	stratum_instance_t *client;
	sdata_t *sdata = ckp->data;
	int64_t client_id;

	client_id = jp->client_id;

	client = ref_instance_by_id(sdata, client_id);
	if (unlikely(!client)) {
		LOGINFO("Share processor failed to find client id %ld in hashtable!", client_id);
		goto out;
	}
	if (unlikely(!client->authorised)) {
		LOGDEBUG("Client %ld no longer authorised to submit shares", client_id);
		goto out_decref;
	}
	json_msg = json_object();
	result_val = parse_submit(client, json_msg, jp->params, &err_val);
	json_object_set_new_nocheck(json_msg, "result", result_val);
	json_object_set_new_nocheck(json_msg, "error", err_val ? err_val : json_null());
	json_object_set_nocheck(json_msg, "id", jp->id_val);
	stratum_add_send(sdata, json_msg, client_id);
out_decref:
	dec_instance_ref(sdata, client);
out:
	discard_json_params(&jp);
}

static void sauth_process(ckpool_t *ckp, json_params_t *jp)
{
	json_t *result_val, *json_msg, *err_val = NULL;
	stratum_instance_t *client;
	sdata_t *sdata = ckp->data;
	int mindiff, errnum = 0;
	int64_t client_id;

	client_id = jp->client_id;

	client = ref_instance_by_id(sdata, client_id);

	if (unlikely(!client)) {
		LOGINFO("Authoriser failed to find client id %ld in hashtable!", client_id);
		goto out;
	}
	result_val = parse_authorise(client, jp->params, &err_val, jp->address, &errnum);
	if (json_is_true(result_val)) {
		char *buf;

		ASPRINTF(&buf, "Authorised, welcome to %s %s!", ckp->name,
			 client->user_instance->username);
		stratum_send_message(sdata, client, buf);
		free(buf);
	} else {
		if (errnum < 0)
			stratum_send_message(sdata, client, "Authorisations temporarily offline :(");
		else
			stratum_send_message(sdata, client, "Failed authorisation :(");
	}
	json_msg = json_object();
	json_object_set_new_nocheck(json_msg, "result", result_val);
	json_object_set_new_nocheck(json_msg, "error", err_val ? err_val : json_null());
	json_object_set_nocheck(json_msg, "id", jp->id_val);
	stratum_add_send(sdata, json_msg, client_id);

	if (!json_is_true(result_val) || !client->suggest_diff)
		goto out;

	/* Update the client now if they have set a valid mindiff different
	 * from the startdiff */
	mindiff = MAX(ckp->mindiff, client->suggest_diff);
	if (mindiff != client->diff) {
		client->diff = mindiff;
		stratum_send_diff(sdata, client);
	}
out:
	if (client)
		dec_instance_ref(sdata, client);
	discard_json_params(&jp);

}

static void parse_ckdb_cmd(ckpool_t __maybe_unused *ckp, const char *cmd)
{
	json_t *val, *res_val, *arr_val;
	json_error_t err_val;
	size_t index;

	val = json_loads(cmd, 0, &err_val);
	if (unlikely(!val)) {
		LOGWARNING("CKDB MSG %s JSON decode failed(%d): %s", cmd, err_val.line, err_val.text);
		return;
	}
	res_val = json_object_get(val, "diffchange");
	json_array_foreach(res_val, index, arr_val) {
		char *workername;
		int mindiff;

		json_get_string(&workername, arr_val, "workername");
		if (!workername)
			continue;
		json_get_int(&mindiff, arr_val, "difficultydefault");
		set_worker_mindiff(ckp, workername, mindiff);
		dealloc(workername);
	}
	json_decref(val);
}

/* Test a value under lock and set it, returning the original value */
static bool test_and_set(bool *val, pthread_mutex_t *lock)
{
	bool ret;

	mutex_lock(lock);
	ret = *val;
	*val = true;
	mutex_unlock(lock);

	return ret;
}

static bool test_and_clear(bool *val, pthread_mutex_t *lock)
{
	bool ret;

	mutex_lock(lock);
	ret = *val;
	*val = false;
	mutex_unlock(lock);

	return ret;
}

static void ckdbq_process(ckpool_t *ckp, char *msg)
{
	sdata_t *sdata = ckp->data;
	char *buf = NULL;

	while (!buf) {
		mutex_lock(&sdata->ckdb_lock);
		buf = ckdb_msg_call(ckp, msg);
		mutex_unlock(&sdata->ckdb_lock);

		if (unlikely(!buf)) {
			if (!test_and_set(&sdata->ckdb_offline, &sdata->ckdb_lock))
				LOGWARNING("Failed to talk to ckdb, queueing messages");
			sleep(5);
		}
	}
	free(msg);
	if (test_and_clear(&sdata->ckdb_offline, &sdata->ckdb_lock))
		LOGWARNING("Successfully resumed talking to ckdb");

	/* TODO: Process any requests from ckdb that are heartbeat responses
	 * with specific requests. */
	if (likely(buf)) {
		char response[PAGESIZE] = {};

		sscanf(buf, "id.%*d.%s", response);
		if (safecmp(response, "ok")) {
			char *cmd;

			cmd = response;
			strsep(&cmd, ".");
			LOGDEBUG("Got ckdb response: %s cmd %s", response, cmd);
			if (cmdmatch(cmd, "heartbeat=")) {
				strsep(&cmd, "=");
				parse_ckdb_cmd(ckp, cmd);
			}
		} else
			LOGWARNING("Got failed ckdb response: %s", buf);
		free(buf);
	}
}

static int transactions_by_jobid(sdata_t *sdata, int64_t id)
{
	workbase_t *wb;
	int ret = -1;

	ck_rlock(&sdata->workbase_lock);
	HASH_FIND_I64(sdata->workbases, &id, wb);
	if (wb)
		ret = wb->transactions;
	ck_runlock(&sdata->workbase_lock);

	return ret;
}

static json_t *txnhashes_by_jobid(sdata_t *sdata, int64_t id)
{
	json_t *ret = NULL;
	workbase_t *wb;

	ck_rlock(&sdata->workbase_lock);
	HASH_FIND_I64(sdata->workbases, &id, wb);
	if (wb)
		ret = json_string(wb->txn_hashes);
	ck_runlock(&sdata->workbase_lock);

	return ret;
}

static void send_transactions(ckpool_t *ckp, json_params_t *jp)
{
	const char *msg = json_string_value(jp->method),
		*params = json_string_value(json_array_get(jp->params, 0));
	stratum_instance_t *client = NULL;
	sdata_t *sdata = ckp->data;
	json_t *val, *hashes;
	int64_t job_id = 0;
	time_t now_t;

	if (unlikely(!msg || !strlen(msg))) {
		LOGWARNING("send_transactions received null method");
		goto out;
	}
	val = json_object();
	json_object_set_nocheck(val, "id", jp->id_val);
	if (cmdmatch(msg, "mining.get_transactions")) {
		int txns;

		/* We don't actually send the transactions as that would use
		 * up huge bandwidth, so we just return the number of
		 * transactions :) . Support both forms of encoding the
		 * request in method name and as a parameter. */
		if (params && strlen(params) > 0)
			sscanf(params, "%lx", &job_id);
		else
			sscanf(msg, "mining.get_transactions(%lx", &job_id);
		txns = transactions_by_jobid(sdata, job_id);
		if (txns != -1) {
			json_set_int(val, "result", txns);
			json_object_set_new_nocheck(val, "error", json_null());
		} else
			json_set_string(val, "error", "Invalid job_id");
		goto out_send;
	}
	if (!cmdmatch(msg, "mining.get_txnhashes")) {
		LOGDEBUG("Unhandled mining get request: %s", msg);
		json_set_string(val, "error", "Unhandled");
		goto out_send;
	}

	client = ref_instance_by_id(sdata, jp->client_id);
	if (unlikely(!client)) {
		LOGINFO("send_transactions failed to find client id %ld in hashtable!",
			jp->client_id);
		goto out;
	}

	now_t = time(NULL);
	if (now_t - client->last_txns < ckp->update_interval) {
		LOGNOTICE("Rate limiting get_txnhashes on client %ld!", jp->client_id);
		json_set_string(val, "error", "Ratelimit");
		goto out_send;
	}
	client->last_txns = now_t;
	if (!params || !strlen(params)) {
		json_set_string(val, "error", "Invalid params");
		goto out_send;
	}
	sscanf(params, "%lx", &job_id);
	hashes = txnhashes_by_jobid(sdata, job_id);
	if (hashes) {
		json_object_set_new_nocheck(val, "result", hashes);
		json_object_set_new_nocheck(val, "error", json_null());
	} else
		json_set_string(val, "error", "Invalid job_id");
out_send:
	stratum_add_send(sdata, val, jp->client_id);
out:
	discard_json_params(&jp);
	if (client)
		dec_instance_ref(sdata, client);
}

/* Called 32 times per min, we send the updated stats to ckdb of those users
 * who have gone 1 minute between updates. This ends up staggering stats to
 * avoid floods of stat data coming at once. */
static void update_workerstats(ckpool_t *ckp, sdata_t *sdata)
{
	user_instance_t *user, *tmp;
	char cdfield[64];
	time_t now_t;
	ts_t ts_now;

	if (sdata->ckdb_offline) {
		LOGDEBUG("Not queueing workerstats due to ckdb offline");
		return;
	}

	if (++sdata->stats.userstats_cycle > 0x1f)
		sdata->stats.userstats_cycle = 0;

	ts_realtime(&ts_now);
	sprintf(cdfield, "%lu,%lu", ts_now.tv_sec, ts_now.tv_nsec);
	now_t = ts_now.tv_sec;

	ck_rlock(&sdata->instance_lock);
	HASH_ITER(hh, sdata->user_instances, user, tmp) {
		worker_instance_t *worker;
		uint8_t cycle_mask;

		if (!user->authorised)
			continue;

		/* Select users using a mask to return each user's stats once
		 * every ~10 minutes */
		cycle_mask = user->id & 0x1f;
		if (cycle_mask != sdata->stats.userstats_cycle)
			continue;
		DL_FOREACH(user->worker_instances, worker) {
			double ghs1, ghs5, ghs60, ghs1440;
			int elapsed;
			json_t *val;

			/* Send one lot of stats once the worker is idle if
			 * they have submitted no shares in the last 10 minutes
			 * with the idle bool set. */
			if (worker->idle && worker->notified_idle)
				continue;
			elapsed = now_t - worker->start_time;
			ghs1 = worker->dsps1 * nonces;
			ghs5 = worker->dsps5 * nonces;
			ghs60 = worker->dsps60 * nonces;
			ghs1440 = worker->dsps1440 * nonces;
			JSON_CPACK(val, "{ss,si,ss,ss,sf,sf,sf,sf,sb,ss,ss,ss,ss}",
					"poolinstance", ckp->name,
					"elapsed", elapsed,
					"username", user->username,
					"workername", worker->workername,
					"hashrate", ghs1,
					"hashrate5m", ghs5,
					"hashrate1hr", ghs60,
					"hashrate24hr", ghs1440,
					"idle", worker->idle,
					"createdate", cdfield,
					"createby", "code",
					"createcode", __func__,
					"createinet", ckp->serverurl[0]);
			worker->notified_idle = worker->idle;
			ckdbq_add(ckp, ID_WORKERSTATS, val);
		}
	}
	ck_runlock(&sdata->instance_lock);
}

static void *statsupdate(void *arg)
{
	ckpool_t *ckp = (ckpool_t *)arg;
	sdata_t *sdata = ckp->data;
	pool_stats_t *stats = &sdata->stats;

	pthread_detach(pthread_self());
	rename_proc("statsupdate");

	tv_time(&stats->start_time);
	cksleep_prepare_r(&stats->last_update);
	sleep(1);

	while (42) {
		double ghs, ghs1, ghs5, ghs15, ghs60, ghs360, ghs1440, ghs10080;
		double bias;
		double tdiff, per_tdiff;
		char suffix1[16], suffix5[16], suffix15[16], suffix60[16], cdfield[64];
		char suffix360[16], suffix1440[16], suffix10080[16];
		user_instance_t *instance, *tmpuser;
		stratum_instance_t *client, *tmp;
		double sps1, sps5, sps15, sps60;
		int idle_workers = 0;
		char fname[512] = {};
		tv_t now, diff;
		ts_t ts_now;
		json_t *val;
		FILE *fp;
		char *s;
		int i;

		tv_time(&now);
		timersub(&now, &stats->start_time, &diff);
		tdiff = diff.tv_sec + (double)diff.tv_usec / 1000000;

		ck_rlock(&sdata->instance_lock);
		HASH_ITER(hh, sdata->stratum_instances, client, tmp) {
			if (!client->authorised)
				continue;

			per_tdiff = tvdiff(&now, &client->last_share);
			/* Decay times per connected instance */
			if (per_tdiff > 60) {
				/* No shares for over a minute, decay to 0 */
				decay_time(&client->dsps1, 0, per_tdiff, 60);
				decay_time(&client->dsps5, 0, per_tdiff, 300);
				decay_time(&client->dsps60, 0, per_tdiff, 3600);
				decay_time(&client->dsps1440, 0, per_tdiff, 86400);
				decay_time(&client->dsps10080, 0, per_tdiff, 604800);
				idle_workers++;
				if (per_tdiff > 600)
					client->idle = true;
				continue;
			}
		}

		HASH_ITER(hh, sdata->user_instances, instance, tmpuser) {
			worker_instance_t *worker;
			bool idle = false;

			if (!instance->authorised)
				continue;

			/* Decay times per worker */
			DL_FOREACH(instance->worker_instances, worker) {
				per_tdiff = tvdiff(&now, &worker->last_share);
				if (per_tdiff > 60) {
					decay_time(&worker->dsps1, 0, per_tdiff, 60);
					decay_time(&worker->dsps5, 0, per_tdiff, 300);
					decay_time(&worker->dsps60, 0, per_tdiff, 3600);
					decay_time(&worker->dsps1440, 0, per_tdiff, 86400);
					worker->idle = true;
				}
				ghs = worker->dsps1 * nonces;
				suffix_string(ghs, suffix1, 16, 0);

				ghs = worker->dsps5 * nonces;
				suffix_string(ghs, suffix5, 16, 0);

				ghs = worker->dsps60 * nonces;
				suffix_string(ghs, suffix60, 16, 0);

				ghs = worker->dsps1440 * nonces;
				suffix_string(ghs, suffix1440, 16, 0);

				JSON_CPACK(val, "{ss,ss,ss,ss,sf}",
						"hashrate1m", suffix1,
						"hashrate5m", suffix5,
						"hashrate1hr", suffix60,
						"hashrate1d", suffix1440,
						"bestshare", worker->best_diff);

				snprintf(fname, 511, "%s/workers/%s", ckp->logdir, worker->workername);
				fp = fopen(fname, "we");
				if (unlikely(!fp)) {
					LOGERR("Failed to fopen %s", fname);
					continue;
				}
				s = json_dumps(val, JSON_NO_UTF8 | JSON_PRESERVE_ORDER | JSON_EOL);
				fprintf(fp, "%s", s);
				dealloc(s);
				json_decref(val);
				fclose(fp);
			}

			/* Decay times per user */
			per_tdiff = tvdiff(&now, &instance->last_share);
			if (per_tdiff > 60) {
				decay_time(&instance->dsps1, 0, per_tdiff, 60);
				decay_time(&instance->dsps5, 0, per_tdiff, 300);
				decay_time(&instance->dsps60, 0, per_tdiff, 3600);
				decay_time(&instance->dsps1440, 0, per_tdiff, 86400);
				decay_time(&instance->dsps10080, 0, per_tdiff, 604800);
				idle = true;
			}
			ghs = instance->dsps1 * nonces;
			suffix_string(ghs, suffix1, 16, 0);

			ghs = instance->dsps5 * nonces;
			suffix_string(ghs, suffix5, 16, 0);

			ghs = instance->dsps60 * nonces;
			suffix_string(ghs, suffix60, 16, 0);

			ghs = instance->dsps1440 * nonces;
			suffix_string(ghs, suffix1440, 16, 0);

			ghs = instance->dsps10080 * nonces;
			suffix_string(ghs, suffix10080, 16, 0);

			JSON_CPACK(val, "{ss,ss,ss,ss,ss,si,sf}",
					"hashrate1m", suffix1,
					"hashrate5m", suffix5,
					"hashrate1hr", suffix60,
					"hashrate1d", suffix1440,
					"hashrate7d", suffix10080,
					"workers", instance->workers,
					"bestshare", instance->best_diff);

			snprintf(fname, 511, "%s/users/%s", ckp->logdir, instance->username);
			fp = fopen(fname, "we");
			if (unlikely(!fp)) {
				LOGERR("Failed to fopen %s", fname);
				continue;
			}
			s = json_dumps(val, JSON_NO_UTF8 | JSON_PRESERVE_ORDER);
			fprintf(fp, "%s\n", s);
			if (!idle)
				LOGNOTICE("User %s:%s", instance->username, s);
			dealloc(s);
			json_decref(val);
			fclose(fp);
		}
		ck_runlock(&sdata->instance_lock);

		ghs1 = stats->dsps1 * nonces;
		suffix_string(ghs1, suffix1, 16, 0);
		sps1 = stats->sps1;

		bias = !CKP_STANDALONE(ckp) ? 1.0 : time_bias(tdiff, 300);
		ghs5 = stats->dsps5 * nonces / bias;
		sps5 = stats->sps5 / bias;
		suffix_string(ghs5, suffix5, 16, 0);

		bias = !CKP_STANDALONE(ckp) ? 1.0 : time_bias(tdiff, 900);
		ghs15 = stats->dsps15 * nonces / bias;
		suffix_string(ghs15, suffix15, 16, 0);
		sps15 = stats->sps15 / bias;

		bias = !CKP_STANDALONE(ckp) ? 1.0 : time_bias(tdiff, 3600);
		ghs60 = stats->dsps60 * nonces / bias;
		sps60 = stats->sps60 / bias;
		suffix_string(ghs60, suffix60, 16, 0);

		bias = !CKP_STANDALONE(ckp) ? 1.0 : time_bias(tdiff, 21600);
		ghs360 = stats->dsps360 * nonces / bias;
		suffix_string(ghs360, suffix360, 16, 0);

		bias = !CKP_STANDALONE(ckp) ? 1.0 : time_bias(tdiff, 86400);
		ghs1440 = stats->dsps1440 * nonces / bias;
		suffix_string(ghs1440, suffix1440, 16, 0);

		bias = !CKP_STANDALONE(ckp) ? 1.0 : time_bias(tdiff, 604800);
		ghs10080 = stats->dsps10080 * nonces / bias;
		suffix_string(ghs10080, suffix10080, 16, 0);

		snprintf(fname, 511, "%s/pool/pool.status", ckp->logdir);
		fp = fopen(fname, "we");
		if (unlikely(!fp))
			LOGERR("Failed to fopen %s", fname);

		JSON_CPACK(val, "{si,si,si,si,si,si}",
				"runtime", diff.tv_sec,
				"Users", stats->users,
				"Workers", stats->workers,
				"Idle", idle_workers,
				"Disconnected", stats->disconnected,
				"Dead", stats->dead);
		s = json_dumps(val, JSON_NO_UTF8 | JSON_PRESERVE_ORDER);
		json_decref(val);
		LOGNOTICE("Pool:%s", s);
		fprintf(fp, "%s\n", s);
		dealloc(s);

		JSON_CPACK(val, "{ss,ss,ss,ss,ss,ss,ss}",
				"hashrate1m", suffix1,
				"hashrate5m", suffix5,
				"hashrate15m", suffix15,
				"hashrate1hr", suffix60,
				"hashrate6hr", suffix360,
				"hashrate1d", suffix1440,
				"hashrate7d", suffix10080);
		s = json_dumps(val, JSON_NO_UTF8 | JSON_PRESERVE_ORDER);
		json_decref(val);
		LOGNOTICE("Pool:%s", s);
		fprintf(fp, "%s\n", s);
		dealloc(s);

		JSON_CPACK(val, "{sf,sf,sf,sf}",
				"SPS1m", sps1,
				"SPS5m", sps5,
				"SPS15m", sps15,
				"SPS1h", sps60);
		s = json_dumps(val, JSON_NO_UTF8 | JSON_PRESERVE_ORDER);
		json_decref(val);
		LOGNOTICE("Pool:%s", s);
		fprintf(fp, "%s\n", s);
		dealloc(s);
		fclose(fp);

		ts_realtime(&ts_now);
		sprintf(cdfield, "%lu,%lu", ts_now.tv_sec, ts_now.tv_nsec);
		JSON_CPACK(val, "{ss,si,si,si,sf,sf,sf,sf,ss,ss,ss,ss}",
				"poolinstance", ckp->name,
				"elapsed", diff.tv_sec,
				"users", stats->users,
				"workers", stats->workers,
				"hashrate", ghs1,
				"hashrate5m", ghs5,
				"hashrate1hr", ghs60,
				"hashrate24hr", ghs1440,
				"createdate", cdfield,
				"createby", "code",
				"createcode", __func__,
				"createinet", ckp->serverurl[0]);
		ckdbq_add(ckp, ID_POOLSTATS, val);

		/* Update stats 32 times per minute to divide up userstats for
		 * ckdb, displaying status every minute. */
		for (i = 0; i < 32; i++) {
			cksleep_ms_r(&stats->last_update, 1875);
			cksleep_prepare_r(&stats->last_update);
			update_workerstats(ckp, sdata);

			mutex_lock(&sdata->stats_lock);
			stats->accounted_shares += stats->unaccounted_shares;
			stats->accounted_diff_shares += stats->unaccounted_diff_shares;
			stats->accounted_rejects += stats->unaccounted_rejects;

			decay_time(&stats->sps1, stats->unaccounted_shares, 1.875, 60);
			decay_time(&stats->sps5, stats->unaccounted_shares, 1.875, 300);
			decay_time(&stats->sps15, stats->unaccounted_shares, 1.875, 900);
			decay_time(&stats->sps60, stats->unaccounted_shares, 1.875, 3600);

			decay_time(&stats->dsps1, stats->unaccounted_diff_shares, 1.875, 60);
			decay_time(&stats->dsps5, stats->unaccounted_diff_shares, 1.875, 300);
			decay_time(&stats->dsps15, stats->unaccounted_diff_shares, 1.875, 900);
			decay_time(&stats->dsps60, stats->unaccounted_diff_shares, 1.875, 3600);
			decay_time(&stats->dsps360, stats->unaccounted_diff_shares, 1.875, 21600);
			decay_time(&stats->dsps1440, stats->unaccounted_diff_shares, 1.875, 86400);
			decay_time(&stats->dsps10080, stats->unaccounted_diff_shares, 1.875, 604800);

			stats->unaccounted_shares =
			stats->unaccounted_diff_shares =
			stats->unaccounted_rejects = 0;
			mutex_unlock(&sdata->stats_lock);
		}
	}

	return NULL;
}

/* Sends a heartbeat to ckdb every second to maintain the relationship of
 * ckpool always initiating a request -> getting a ckdb response, but allows
 * ckdb to provide specific commands to ckpool. */
static void *ckdb_heartbeat(void *arg)
{
	ckpool_t *ckp = (ckpool_t *)arg;
	sdata_t *sdata = ckp->data;

	pthread_detach(pthread_self());
	rename_proc("heartbeat");

	while (42) {
		char cdfield[64];
		ts_t ts_now;
		json_t *val;

		cksleep_ms(1000);
		if (unlikely(!ckmsgq_empty(sdata->ckdbq))) {
			LOGDEBUG("Witholding heartbeat due to ckdb messages being queued");
			continue;
		}
		ts_realtime(&ts_now);
		sprintf(cdfield, "%lu,%lu", ts_now.tv_sec, ts_now.tv_nsec);
		JSON_CPACK(val, "{ss,ss,ss,ss}",
				"createdate", cdfield,
				"createby", "code",
				"createcode", __func__,
				"createinet", ckp->serverurl[0]);
		ckdbq_add(ckp, ID_HEARTBEAT, val);
	}
	return NULL;
}

int stratifier(proc_instance_t *pi)
{
	pthread_t pth_blockupdate, pth_statsupdate, pth_heartbeat;
	ckpool_t *ckp = pi->ckp;
	int ret = 1, threads;
	int64_t randomiser;
	sdata_t *sdata;
	char *buf;

	LOGWARNING("%s stratifier starting", ckp->name);
	sdata = ckzalloc(sizeof(sdata_t));
	ckp->data = sdata;

	/* Wait for the generator to have something for us */
	do {
		if (!ping_main(ckp)) {
			ret = 1;
			goto out;
		}
		buf = send_recv_proc(ckp->generator, "ping");
	} while (!buf);

	if (!ckp->proxy) {
		if (!test_address(ckp, ckp->btcaddress)) {
			LOGEMERG("Fatal: btcaddress invalid according to bitcoind");
			goto out;
		}

		/* Store this for use elsewhere */
		hex2bin(scriptsig_header_bin, scriptsig_header, 41);
		address_to_pubkeytxn(sdata->pubkeytxnbin, ckp->btcaddress);

		if (test_address(ckp, ckp->donaddress)) {
			ckp->donvalid = true;
			address_to_pubkeytxn(sdata->donkeytxnbin, ckp->donaddress);
		}
	}

	randomiser = ((int64_t)time(NULL)) << 32;
	/* Set the initial id to time as high bits so as to not send the same
	 * id on restarts */
	if (!ckp->proxy)
		sdata->blockchange_id = sdata->workbase_id = randomiser;
	sdata->enonce1u.u64 = htobe64(randomiser);

	dealloc(buf);

	if (!ckp->serverurls) {
		ckp->serverurl[0] = "127.0.0.1";
		ckp->serverurls = 1;
	}
	cklock_init(&sdata->instance_lock);

	mutex_init(&sdata->ckdb_lock);
	sdata->ssends = create_ckmsgq(ckp, "ssender", &ssend_process);
	/* Create half as many share processing threads as there are CPUs */
	threads = sysconf(_SC_NPROCESSORS_ONLN) / 2 ? : 1;
	sdata->sshareq = create_ckmsgqs(ckp, "sprocessor", &sshare_process, threads);
	/* Create 1/4 as many stratum processing threads as there are CPUs */
	threads = threads / 2 ? : 1;
	sdata->srecvs = create_ckmsgqs(ckp, "sreceiver", &srecv_process, threads);
	sdata->sauthq = create_ckmsgq(ckp, "authoriser", &sauth_process);
	sdata->ckdbq = create_ckmsgq(ckp, "ckdbqueue", &ckdbq_process);
	sdata->stxnq = create_ckmsgq(ckp, "stxnq", &send_transactions);
	if (!CKP_STANDALONE(ckp))
		create_pthread(&pth_heartbeat, ckdb_heartbeat, ckp);

	cklock_init(&sdata->workbase_lock);
	if (!ckp->proxy)
		create_pthread(&pth_blockupdate, blockupdate, ckp);

	mutex_init(&sdata->stats_lock);
	create_pthread(&pth_statsupdate, statsupdate, ckp);

	cklock_init(&sdata->share_lock);
	mutex_init(&sdata->block_lock);

	LOGWARNING("%s stratifier ready", ckp->name);

	ret = stratum_loop(ckp, pi);
out:
	dealloc(ckp->data);
	return process_exit(ckp, pi, ret);
}
