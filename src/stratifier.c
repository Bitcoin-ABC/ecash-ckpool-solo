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

static const char *workpadding = "000000800000000000000000000000000000000000000000000000000000000000000000000000000000000080020000";

static const char *scriptsig_header = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff";
static uchar scriptsig_header_bin[41];

static char pubkeytxnbin[25];
static char donkeytxnbin[25];

/* Add unaccounted shares when they arrive, remove them with each update of
 * rolling stats. */
struct pool_stats {
	tv_t start_time;
	ts_t last_update;

	int workers;
	int users;

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

static pool_stats_t stats;

/* Protects changes to pool stats */
static pthread_mutex_t stats_lock;

/* Serialises sends/receives to ckdb if possible */
static pthread_mutex_t ckdb_lock;

static union {
	uint64_t u64;
	uint32_t u32;
	uint16_t u16;
	uint8_t u8;
} enonce1u;

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

/* For protecting the hashtable data */
static cklock_t workbase_lock;

/* For the hashtable of all workbases */
static workbase_t *workbases;
static workbase_t *current_workbase;

static struct {
	double diff;

	char enonce1[32];
	uchar enonce1bin[16];
	int enonce1constlen;
	int enonce1varlen;

	int nonce2len;
	int enonce2varlen;

	bool subscribed;
} proxy_base;

static int64_t workbase_id;
static int64_t blockchange_id;
static char lasthash[68], lastswaphash[68];

struct json_params {
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

static ckmsgq_t *ssends;	// Stratum sends
static ckmsgq_t *srecvs;	// Stratum receives
static ckmsgq_t *ckdbq;		// ckdb
static ckmsgq_t *sshareq;	// Stratum share sends
static ckmsgq_t *sauthq;	// Stratum authorisations
static ckmsgq_t *stxnq;		// Transaction requests

struct userwb {
	UT_hash_handle hh;
	int64_t id;

	workbase_t *wb; // Master workbase
	uchar *coinb2bin; // Coinb2 cointaining this user's address for generation
	char *coinb2;
};

static int64_t user_instance_id;

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

	double dsps1; /* Diff shares per second, 1 minute rolling average */
	double dsps5; /* ... 5 minute ... */
	double dsps60;/* etc */
	double dsps1440;
	double dsps10080;
	tv_t last_share;
};

static user_instance_t *user_instances;

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

	int mindiff; /* User chosen mindiff */
};

/* Per client stratum instance == workers */
struct stratum_instance {
	UT_hash_handle hh;
	int64_t id;

	stratum_instance_t *next;
	stratum_instance_t *prev;

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
	bool idle;
	bool notified_idle;
	int reject;	/* Indicator that this client is having a run of rejects
			 * or other problem and should be dropped lazily if
			 * this is set to 2 */

	user_instance_t *user_instance;
	worker_instance_t *worker_instance;

	char *useragent;
	char *workername;
	char *password;
	int64_t user_id;

	ckpool_t *ckp;

	time_t last_txns; /* Last time this worker requested txn hashes */

	int64_t suggest_diff; /* Stratum client suggested diff */
};

/* Stratum_instances hashlist is stored by id, whereas disconnected_instances
 * is sorted by enonce1_64. */
static stratum_instance_t *stratum_instances;
static stratum_instance_t *disconnected_instances;

/* Protects both stratum and user instances */
static cklock_t instance_lock;

struct share {
	UT_hash_handle hh;
	uchar hash[32];
	int64_t workbase_id;
};

typedef struct share share_t;

static share_t *shares;

static cklock_t share_lock;

/* Linked list of block solves, added to during submission, removed on
 * accept/reject. It is likely we only ever have one solve on here but you
 * never know... */
static pthread_mutex_t block_lock;
static ckmsg_t *block_solves;

static int gen_priority;

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
#define ID_USERSTATS 6
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
	"userstats",
	"block",
	"addrauth",
	"heartbeat"
};

static void generate_coinbase(ckpool_t *ckp, workbase_t *wb)
{
	uint64_t *u64, g64, d64 = 0;
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

	/* Leave enonce1/2varlen constant at 8 bytes for bitcoind sources */
	wb->enonce1varlen = 8;
	wb->enonce2varlen = 8;
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
	memcpy(wb->coinb2bin + wb->coinb2len, pubkeytxnbin, 25);
	wb->coinb2len += 25;

	if (ckp->donvalid) {
		u64 = (uint64_t *)&wb->coinb2bin[wb->coinb2len];
		*u64 = htole64(d64);
		wb->coinb2len += 8;

		wb->coinb2bin[wb->coinb2len++] = 25;
		memcpy(wb->coinb2bin + wb->coinb2len, donkeytxnbin, 25);
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

static void stratum_broadcast_update(bool clean);
static void stratum_broadcast_updates(bool clean);

static void clear_userwb(int64_t id)
{
	user_instance_t *instance, *tmp;

	ck_rlock(&instance_lock);
	HASH_ITER(hh, user_instances, instance, tmp) {
		struct userwb *userwb;

		HASH_FIND_I64(instance->userwbs, &id, userwb);
		if (!userwb)
			continue;
		HASH_DEL(instance->userwbs, userwb);
		free(userwb->coinb2bin);
		free(userwb->coinb2);
		free(userwb);
	}
	ck_runlock(&instance_lock);
}

static void clear_workbase(ckpool_t *ckp, workbase_t *wb)
{
	if (ckp->btcsolo)
		clear_userwb(wb->id);
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

static void purge_share_hashtable(int64_t wb_id)
{
	share_t *share, *tmp;
	int purged = 0;

	ck_wlock(&share_lock);
	HASH_ITER(hh, shares, share, tmp) {
		if (share->workbase_id < wb_id) {
			HASH_DEL(shares, share);
			free(share);
			purged++;
		}
	}
	ck_wunlock(&share_lock);

	if (purged)
		LOGINFO("Cleared %d shares from share hashtable", purged);
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

	ckmsgq_add(ckdbq, json_msg);
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
			"createinet", ckp->serverurl);
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
			"createinet", ckp->serverurl);
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

static void generate_userwbs(workbase_t *wb)
{
	user_instance_t *instance, *tmp;

	ck_rlock(&instance_lock);
	HASH_ITER(hh, user_instances, instance, tmp) {
		if (!instance->btcaddress)
			continue;
		__generate_userwb(wb, instance);
	}
	ck_runlock(&instance_lock);
}

static void add_base(ckpool_t *ckp, workbase_t *wb, bool *new_block)
{
	workbase_t *tmp, *tmpa, *aged = NULL;
	int len, ret;

	ts_realtime(&wb->gentime);
	wb->network_diff = diff_from_nbits(wb->headerbin + 72);

	len = strlen(ckp->logdir) + 8 + 1 + 16 + 1;
	wb->logdir = ckalloc(len);

	/* In proxy mode, the wb->id is received in the notify update and
	 * we set workbase_id from it. In server mode the stratifier is
	 * setting the workbase_id */
	ck_wlock(&workbase_lock);
	if (!ckp->proxy)
		wb->id = workbase_id++;
	else
		workbase_id = wb->id;
	if (strncmp(wb->prevhash, lasthash, 64)) {
		char bin[32], swap[32];

		*new_block = true;
		memcpy(lasthash, wb->prevhash, 65);
		hex2bin(bin, lasthash, 32);
		swap_256(swap, bin);
		__bin2hex(lastswaphash, swap, 32);
		LOGNOTICE("Block hash changed to %s", lastswaphash);
		blockchange_id = wb->id;
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

	HASH_ITER(hh, workbases, tmp, tmpa) {
		if (HASH_COUNT(workbases) < 3)
			break;
		/*  Age old workbases older than 10 minutes old */
		if (tmp->gentime.tv_sec < wb->gentime.tv_sec - 600) {
			HASH_DEL(workbases, tmp);
			aged = tmp;
			break;
		}
	}
	HASH_ADD_I64(workbases, id, wb);
	current_workbase = wb;
	ck_wunlock(&workbase_lock);

	if (ckp->btcsolo)
		generate_userwbs(wb);

	if (*new_block)
		purge_share_hashtable(wb->id);

	send_workinfo(ckp, wb);

	/* Send the aged work message to ckdb once we have dropped the workbase lock
	 * to prevent taking recursive locks */
	if (aged) {
		send_ageworkinfo(ckp, aged->id);
		clear_workbase(ckp, aged);
	}
}

/* Mandatory send_recv to the generator which sets the message priority if this
 * message is higher priority. Races galore on gen_priority mean this might
 * read the wrong priority but occasional wrong values are harmless. */
static char *__send_recv_generator(ckpool_t *ckp, const char *msg, int prio)
{
	char *buf = NULL;
	bool set;

	if (prio > gen_priority) {
		gen_priority = prio;
		set = true;
	} else
		set = false;
	buf = send_recv_proc(ckp->generator, msg);
	if (set)
		gen_priority = 0;

	return buf;
}

/* Conditionally send_recv a message only if it's equal or higher priority than
 * any currently being serviced. */
static char *send_recv_generator(ckpool_t *ckp, const char *msg, int prio)
{
	char *buf = NULL;

	if (prio >= gen_priority)
		buf = __send_recv_generator(ckp, msg, prio);
	return buf;
}

static void send_generator(ckpool_t *ckp, const char *msg, int prio)
{
	bool set;

	if (prio > gen_priority) {
		gen_priority = prio;
		set = true;
	} else
		set = false;
	send_proc(ckp->generator, msg);
	if (set)
		gen_priority = 0;
}

/* This function assumes it will only receive a valid json gbt base template
 * since checking should have been done earlier, and creates the base template
 * for generating work templates. */
static void update_base(ckpool_t *ckp, int prio)
{
	bool new_block = false;
	workbase_t *wb;
	json_t *val;
	char *buf;

	buf = send_recv_generator(ckp, "getbase", prio);
	if (unlikely(!buf)) {
		LOGWARNING("Failed to get base from generator in update_base");
		return;
	}
	if (unlikely(cmdmatch(buf, "failed"))) {
		LOGWARNING("Generator returned failure in update_base");
		return;
	}

	wb = ckzalloc(sizeof(workbase_t));
	wb->ckp = ckp;
	val = json_loads(buf, 0, NULL);
	dealloc(buf);

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
		stratum_broadcast_updates(new_block);
	else
		stratum_broadcast_update(new_block);
}

static void drop_allclients(ckpool_t *ckp)
{
	stratum_instance_t *client, *tmp;
	char buf[128];

	ck_wlock(&instance_lock);
	HASH_ITER(hh, stratum_instances, client, tmp) {
		HASH_DEL(stratum_instances, client);
		sprintf(buf, "dropclient=%ld", client->id);
		send_proc(ckp->connector, buf);
	}
	HASH_ITER(hh, disconnected_instances, client, tmp)
		HASH_DEL(disconnected_instances, client);
	stats.users = stats.workers = 0;
	ck_wunlock(&instance_lock);
}

static void update_subscribe(ckpool_t *ckp)
{
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

	ck_wlock(&workbase_lock);
	proxy_base.subscribed = true;
	proxy_base.diff = ckp->startdiff;
	/* Length is checked by generator */
	strcpy(proxy_base.enonce1, json_string_value(json_object_get(val, "enonce1")));
	proxy_base.enonce1constlen = strlen(proxy_base.enonce1) / 2;
	hex2bin(proxy_base.enonce1bin, proxy_base.enonce1, proxy_base.enonce1constlen);
	proxy_base.nonce2len = json_integer_value(json_object_get(val, "nonce2len"));
	if (proxy_base.nonce2len > 7)
		proxy_base.enonce1varlen = 4;
	else if (proxy_base.nonce2len > 5)
		proxy_base.enonce1varlen = 2;
	else
		proxy_base.enonce1varlen = 1;
	proxy_base.enonce2varlen = proxy_base.nonce2len - proxy_base.enonce1varlen;
	ck_wunlock(&workbase_lock);

	json_decref(val);
	drop_allclients(ckp);
}

static void update_diff(ckpool_t *ckp);

static void update_notify(ckpool_t *ckp)
{
	bool new_block = false, clean;
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

	if (unlikely(!proxy_base.subscribed)) {
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

	ck_rlock(&workbase_lock);
	strcpy(wb->enonce1const, proxy_base.enonce1);
	wb->enonce1constlen = proxy_base.enonce1constlen;
	memcpy(wb->enonce1constbin, proxy_base.enonce1bin, wb->enonce1constlen);
	wb->enonce1varlen = proxy_base.enonce1varlen;
	wb->enonce2varlen = proxy_base.enonce2varlen;
	wb->diff = proxy_base.diff;
	ck_runlock(&workbase_lock);

	add_base(ckp, wb, &new_block);

	stratum_broadcast_update(new_block | clean);
}

static void stratum_send_diff(stratum_instance_t *client);

static void update_diff(ckpool_t *ckp)
{
	stratum_instance_t *client;
	double old_diff, diff;
	json_t *val;
	char *buf;

	if (unlikely(!current_workbase)) {
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

	ck_wlock(&workbase_lock);
	old_diff = proxy_base.diff;
	current_workbase->diff = proxy_base.diff = diff;
	ck_wunlock(&workbase_lock);

	if (old_diff < diff)
		return;

	/* If the diff has dropped, iterate over all the clients and check
	 * they're at or below the new diff, and update it if not. */
	ck_rlock(&instance_lock);
	for (client = stratum_instances; client != NULL; client = client->hh.next) {
		if (client->diff > diff) {
			client->diff = diff;
			stratum_send_diff(client);
		}
	}
	ck_runlock(&instance_lock);
}

/* Enter with instance_lock held */
static stratum_instance_t *__instance_by_id(int64_t id)
{
	stratum_instance_t *instance;

	HASH_FIND_I64(stratum_instances, &id, instance);
	return instance;
}

/* Enter with write instance_lock held */
static stratum_instance_t *__stratum_add_instance(ckpool_t *ckp, int64_t id)
{
	stratum_instance_t *instance = ckzalloc(sizeof(stratum_instance_t));

	instance->id = id;
	instance->diff = instance->old_diff = ckp->startdiff;
	instance->ckp = ckp;
	tv_time(&instance->ldc);
	LOGINFO("Added instance %ld", id);
	HASH_ADD_I64(stratum_instances, id, instance);
	return instance;
}

/* Only supports a full ckpool instance sessionid with an 8 byte sessionid */
static bool disconnected_sessionid_exists(const char *sessionid, int64_t id)
{
	stratum_instance_t *instance, *tmp;
	uint64_t session64;
	bool ret = false;

	if (!sessionid)
		goto out;
	if (strlen(sessionid) != 16)
		goto out;
	/* Number is in BE but we don't swap either of them */
	hex2bin(&session64, sessionid, 8);

	ck_rlock(&instance_lock);
	HASH_ITER(hh, stratum_instances, instance, tmp) {
		if (instance->id == id)
			continue;
		if (instance->enonce1_64 == session64) {
			/* Only allow one connected instance per enonce1 */
			goto out_unlock;
		}
	}
	instance = NULL;
	HASH_FIND(hh, disconnected_instances, &session64, sizeof(uint64_t), instance);
	if (instance)
		ret = true;
out_unlock:
	ck_runlock(&instance_lock);
out:
	return ret;
}

static void stratum_add_recvd(json_t *val)
{
	smsg_t *msg;

	msg = ckzalloc(sizeof(smsg_t));
	msg->json_msg = val;
	ckmsgq_add(srecvs, msg);
}

/* For creating a list of sends without locking that can then be concatenated
 * to the stratum_sends list. Minimises locking and avoids taking recursive
 * locks. */
static void stratum_broadcast(json_t *val)
{
	stratum_instance_t *instance, *tmp;
	ckmsg_t *bulk_send = NULL;

	if (unlikely(!val)) {
		LOGERR("Sent null json to stratum_broadcast");
		return;
	}

	ck_rlock(&instance_lock);
	HASH_ITER(hh, stratum_instances, instance, tmp) {
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
	ck_runlock(&instance_lock);

	json_decref(val);

	if (!bulk_send)
		return;

	mutex_lock(&ssends->lock);
	if (ssends->msgs)
		DL_CONCAT(ssends->msgs, bulk_send);
	else
		ssends->msgs = bulk_send;
	pthread_cond_signal(&ssends->cond);
	mutex_unlock(&ssends->lock);
}

static void stratum_add_send(json_t *val, int64_t client_id)
{
	smsg_t *msg;

	msg = ckzalloc(sizeof(smsg_t));
	msg->json_msg = val;
	msg->client_id = client_id;
	ckmsgq_add(ssends, msg);
}

static void inc_worker(user_instance_t *instance)
{
	mutex_lock(&stats_lock);
	stats.workers++;
	if (!instance->workers++)
		stats.users++;
	mutex_unlock(&stats_lock);
}

static void dec_worker(user_instance_t *instance)
{
	mutex_lock(&stats_lock);
	stats.workers--;
	if (!--instance->workers)
		stats.users--;
	mutex_unlock(&stats_lock);
}

static void drop_client(int64_t id)
{
	stratum_instance_t *client = NULL;
	bool dec = false;

	LOGINFO("Stratifier dropping client %ld", id);

	ck_wlock(&instance_lock);
	client = __instance_by_id(id);
	if (client) {
		stratum_instance_t *old_client = NULL;

		if (client->authorised) {
			dec = true;
			client->authorised = false;
		}

		HASH_DEL(stratum_instances, client);
		HASH_FIND(hh, disconnected_instances, &client->enonce1_64, sizeof(uint64_t), old_client);
		/* Only keep around one copy of the old client in server mode */
		if (!client->ckp->proxy && !old_client && client->enonce1_64)
			HASH_ADD(hh, disconnected_instances, enonce1_64, sizeof(uint64_t), client);
	}
	ck_wunlock(&instance_lock);

	if (dec)
		dec_worker(client->user_instance);
}

static void stratum_broadcast_message(const char *msg)
{
	json_t *json_msg;

	JSON_CPACK(json_msg, "{sosss[s]}", "id", json_null(), "method", "client.show_message",
			     "params", msg);
	stratum_broadcast(json_msg);
}

/* Send a generic reconnect to all clients without parameters to make them
 * reconnect to the same server. */
static void reconnect_clients(void)
{
	json_t *json_msg;

	JSON_CPACK(json_msg, "{sosss[]}", "id", json_null(), "method", "client.reconnect",
		   "params");
	stratum_broadcast(json_msg);
}

static void block_solve(ckpool_t *ckp, const char *blockhash)
{
	ckmsg_t *block, *tmp, *found = NULL;
	char cdfield[64];
	int height = 0;
	ts_t ts_now;
	json_t *val;
	char *msg;

	update_base(ckp, GEN_PRIORITY);

	ts_realtime(&ts_now);
	sprintf(cdfield, "%lu,%lu", ts_now.tv_sec, ts_now.tv_nsec);

	mutex_lock(&block_lock);
	DL_FOREACH_SAFE(block_solves, block, tmp) {
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
			DL_DELETE(block_solves, block);
			break;
		}
		dealloc(solvehash);
	}
	mutex_unlock(&block_lock);

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
	stratum_broadcast_message(msg);
	free(msg);

	LOGWARNING("Solved and confirmed block %d", height);
}

static void block_reject(const char *blockhash)
{
	ckmsg_t *block, *tmp, *found = NULL;
	int height = 0;
	json_t *val;

	mutex_lock(&block_lock);
	DL_FOREACH_SAFE(block_solves, block, tmp) {
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
			DL_DELETE(block_solves, block);
			break;
		}
		dealloc(solvehash);
	}
	mutex_unlock(&block_lock);

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
static void broadcast_ping(void)
{
	json_t *json_msg;

	JSON_CPACK(json_msg, "{s:[],s:o,s:s}",
		   "params",
		   "id", json_null(),
		   "method", "mining.ping");

	stratum_broadcast(json_msg);
}

static int stratum_loop(ckpool_t *ckp, proc_instance_t *pi)
{
	int sockd, ret = 0, selret = 0;
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
				broadcast_ping();
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
	if (!buf) {
		Close(sockd);
		LOGWARNING("Failed to get message in stratum_loop");
		goto retry;
	}
	if (cmdmatch(buf, "ping")) {
		LOGDEBUG("Stratifier received ping request");
		send_unix_msg(sockd, "pong");
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
			drop_client(client_id);
	} else if (cmdmatch(buf, "dropall")) {
		drop_allclients(ckp);
	} else if (cmdmatch(buf, "block")) {
		block_solve(ckp, buf + 6);
	} else if (cmdmatch(buf, "noblock")) {
		block_reject(buf + 8);
	} else if (cmdmatch(buf, "reconnect")) {
		reconnect_clients();
	} else if (cmdmatch(buf, "loglevel")) {
		sscanf(buf, "loglevel=%d", &ckp->loglevel);
	} else {
		json_t *val = json_loads(buf, 0, NULL);

		if (!val) {
			LOGWARNING("Received unrecognised message: %s", buf);
		}  else
			stratum_add_recvd(val);
	}
	goto retry;

out:
	dealloc(buf);
	return ret;
}

static void *blockupdate(void *arg)
{
	ckpool_t *ckp = (ckpool_t *)arg;
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
		else if (buf && strcmp(buf, lastswaphash) && !cmdmatch(buf, "failed"))
			update_base(ckp, GEN_PRIORITY);
		else
			cksleep_ms(ckp->blockpoll);
	}
	return NULL;
}

static inline bool enonce1_free(uint64_t enonce1)
{
	stratum_instance_t *client, *tmp;
	bool ret = true;

	if (unlikely(!enonce1)) {
		ret = false;
		goto out;
	}
	HASH_ITER(hh, stratum_instances, client, tmp) {
		if (client->enonce1_64 == enonce1) {
			ret = false;
			break;
		}
	}
out:
	return ret;
}

/* Create a new enonce1 from the 64 bit enonce1_64 value, using only the number
 * of bytes we have to work with when we are proxying with a split nonce2.
 * When the proxy space is less than 32 bits to work with, we look for an
 * unused enonce1 value and reject clients instead if there is no space left */
static bool new_enonce1(stratum_instance_t *client)
{
	bool ret = false;
	workbase_t *wb;
	int i;

	ck_wlock(&workbase_lock);
	wb = current_workbase;
	switch(wb->enonce1varlen) {
		case 8:
			enonce1u.u64++;
			ret = true;
			break;
		case 4:
			enonce1u.u32++;
			ret = true;
			break;
		case 2:
			for (i = 0; i < 65536; i++) {
				enonce1u.u16++;
				ret = enonce1_free(enonce1u.u64);
				if (ret)
					break;
			}
			break;
		case 1:
			for (i = 0; i < 256; i++) {
				enonce1u.u8++;
				ret = enonce1_free(enonce1u.u64);
				if (ret)
					break;
			}
			break;
	}
	if (ret)
		client->enonce1_64 = enonce1u.u64;
	if (wb->enonce1constlen)
		memcpy(client->enonce1bin, wb->enonce1constbin, wb->enonce1constlen);
	memcpy(client->enonce1bin + wb->enonce1constlen, &client->enonce1_64, wb->enonce1varlen);
	__bin2hex(client->enonce1var, &client->enonce1_64, wb->enonce1varlen);
	__bin2hex(client->enonce1, client->enonce1bin, wb->enonce1constlen + wb->enonce1varlen);
	ck_wunlock(&workbase_lock);

	if (unlikely(!ret))
		LOGWARNING("Enonce1 space exhausted! Proxy rejecting clients");

	return ret;
}

static void stratum_send_message(stratum_instance_t *client, const char *msg);

/* Extranonce1 must be set here */
static json_t *parse_subscribe(stratum_instance_t *client, int64_t client_id, json_t *params_val)
{
	bool old_match = false;
	int arr_size;
	json_t *ret;
	int n2len;

	if (unlikely(!json_is_array(params_val))) {
		stratum_send_message(client, "Invalid json: params not an array");
		return json_string("params not an array");
	}

	if (unlikely(!current_workbase)) {
		stratum_send_message(client, "Pool Initialising");
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
			if (disconnected_sessionid_exists(buf, client_id)) {
				sprintf(client->enonce1, "%016lx", client->enonce1_64);
				old_match = true;
			}
		}
	} else
		client->useragent = ckzalloc(1);
	if (!old_match) {
		/* Create a new extranonce1 based on a uint64_t pointer */
		if (!new_enonce1(client)) {
			stratum_send_message(client, "Pool full of clients");
			client->reject = 2;
			return json_string("proxy full");
		}
		LOGINFO("Set new subscription %ld to new enonce1 %s", client->id,
			client->enonce1);
	} else {
		LOGINFO("Set new subscription %ld to old matched enonce1 %s", client->id,
			 client->enonce1);
	}

	ck_rlock(&workbase_lock);
	if (likely(workbases))
		n2len = workbases->enonce2varlen;
	else
		n2len = 8;
	JSON_CPACK(ret, "[[[s,s]],s,i]", "mining.notify", client->enonce1, client->enonce1,
			n2len);
	ck_runlock(&workbase_lock);

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

/* This simply strips off the first part of the workername and matches it to a
 * user or creates a new one. */
static user_instance_t *generate_user(ckpool_t *ckp, stratum_instance_t *client,
				      const char *workername)
{
	char *base_username = strdupa(workername), *username;
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

	ck_wlock(&instance_lock);
	HASH_FIND_STR(user_instances, username, instance);
	if (!instance) {
		/* New user instance. Secondary user id will be NULL */
		instance = ckzalloc(sizeof(user_instance_t));
		strcpy(instance->username, username);
		new = true;

		instance->id = user_instance_id++;
		HASH_ADD_STR(user_instances, username, instance);
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
		client->worker_instance = ckzalloc(sizeof(worker_instance_t));
		client->worker_instance->workername = strdup(workername);
		client->worker_instance->instance = instance;
		DL_APPEND(instance->worker_instances, client->worker_instance);
	}
	DL_APPEND(instance->instances, client);
	ck_wunlock(&instance_lock);

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
 * and get SUID parameters back. We don't add these requests to the ckdbqueue
 * since we have to wait for the response but this is done from the authoriser
 * thread so it won't hold anything up but other authorisations. */
static int send_recv_auth(stratum_instance_t *client)
{
	user_instance_t *user_instance = client->user_instance;
	ckpool_t *ckp = client->ckp;
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
		return ret;
	}

	/* We want responses from ckdb serialised and not interleaved with
	 * other requests. Wait up to 3 seconds for exclusive access to ckdb
	 * and if we don't receive it treat it as a delayed auth if possible */
	if (likely(!mutex_timedlock(&ckdb_lock, 3))) {
		buf = ckdb_msg_call(ckp, json_msg);
		mutex_unlock(&ckdb_lock);
	}

	free(json_msg);
	if (likely(buf)) {
		worker_instance_t *worker = client->worker_instance;
		char *cmd = NULL, *secondaryuserid = NULL;
		char response[PAGESIZE] = {};
		json_error_t err_val;
		json_t *val = NULL;

		LOGINFO("Got ckdb response: %s", buf);
		sscanf(buf, "id.%*d.%s", response);
		cmd = response;
		strsep(&cmd, "=");
		LOGINFO("User %s Worker %s got auth response: %s  cmd: %s",
			user_instance->username, client->workername,
			response, cmd);
		val = json_loads(cmd, 0, &err_val);
		if (unlikely(!val))
			LOGINFO("AUTH JSON decode failed(%d): %s", err_val.line, err_val.text);
		else {
			json_get_string(&secondaryuserid, val, "secondaryuserid");
			json_get_int(&worker->mindiff, val, "difficultydefault");
			client->suggest_diff = worker->mindiff;
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
	} else {
		ret = -1;
		LOGWARNING("Got no auth response from ckdb :(");
	}

	return ret;
}

/* For sending auths to ckdb after we've already decided we can authorise
 * these clients while ckdb is offline, based on an existing client of the
 * same username already having been authorised. */
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

static json_t *__user_notify(user_instance_t *user_instance, bool clean);

static void __update_solo_client(stratum_instance_t *client, user_instance_t *user_instance)
{
	json_t *json_msg;

	json_msg = __user_notify(user_instance, true);
	stratum_add_send(json_msg, client->id);
}

static json_t *parse_authorise(stratum_instance_t *client, json_t *params_val, json_t **err_val,
			       const char *address, int *errnum)
{
	user_instance_t *user_instance;
	ckpool_t *ckp = client->ckp;
	const char *buf, *pw = NULL;
	bool ret = false;
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
	if (arr_size >= 2) {
		pw = json_string_value(json_array_get(params_val, 1));
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
	if (pw && strlen(pw) > 0)
		client->password = strdup(pw);
	LOGNOTICE("Authorised client %ld worker %s as user %s %s", client->id, buf,
		  user_instance->username, pw ? pw : "");
	if (CKP_STANDALONE(client->ckp)) {
		if (!ckp->btcsolo || client->user_instance->btcaddress)
			ret = true;
	} else {
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
	client->authorised = ret;
	if (client->authorised)
		inc_worker(user_instance);
out:
	if (ckp->btcsolo && ret) {
		ck_rlock(&workbase_lock);
		__generate_userwb(current_workbase, user_instance);
		__update_solo_client(client, user_instance);
		ck_runlock(&workbase_lock);

		stratum_send_diff(client);
	}
	return json_boolean(ret);
}

static void stratum_send_diff(stratum_instance_t *client)
{
	json_t *json_msg;

	JSON_CPACK(json_msg, "{s[I]soss}", "params", client->diff, "id", json_null(),
			     "method", "mining.set_difficulty");
	stratum_add_send(json_msg, client->id);
}

static void stratum_send_message(stratum_instance_t *client, const char *msg)
{
	json_t *json_msg;

	JSON_CPACK(json_msg, "{sosss[s]}", "id", json_null(), "method", "client.show_message",
			     "params", msg);
	stratum_add_send(json_msg, client->id);
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

static void add_submit(ckpool_t *ckp, stratum_instance_t *client, int diff, bool valid,
		       bool submit)
{
	worker_instance_t *worker = client->worker_instance;
	double tdiff, bdiff, dsps, drr, network_diff, bias;
	user_instance_t *instance = client->user_instance;
	int64_t next_blockid, optimal;
	tv_t now_t;

	mutex_lock(&stats_lock);
	if (valid) {
		stats.unaccounted_shares++;
		stats.unaccounted_diff_shares += diff;
	} else
		stats.unaccounted_rejects += diff;
	mutex_unlock(&stats_lock);

	/* Count only accepted and stale rejects in diff calculation. */
	if (!valid && !submit)
		return;

	tv_time(&now_t);

	ck_rlock(&workbase_lock);
	next_blockid = workbase_id + 1;
	if (ckp->proxy)
		network_diff = current_workbase->diff;
	else
		network_diff = current_workbase->network_diff;
	ck_runlock(&workbase_lock);

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
	stratum_send_diff(client);
}

/* We should already be holding the workbase_lock */
static void
test_blocksolve(stratum_instance_t *client, workbase_t *wb, const uchar *data, const uchar *hash,
		double diff, const char *coinbase, int cblen, const char *nonce2, const char *nonce)
{
	int transactions = wb->transactions + 1;
	char hexcoinbase[1024], blockhash[68];
	json_t *val = NULL, *val_copy;
	char *gbt_block, varint[12];
	ckmsg_t *block_ckmsg;
	char cdfield[64];
	uchar swap[32];
	ckpool_t *ckp;
	ts_t ts_now;

	/* Submit anything over 99% of the diff in case of rounding errors */
	if (diff < current_workbase->network_diff * 0.99)
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
	ckp = wb->ckp;
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
			"createinet", ckp->serverurl);
	val_copy = json_deep_copy(val);
	block_ckmsg = ckalloc(sizeof(ckmsg_t));
	block_ckmsg->data = val_copy;

	mutex_lock(&block_lock);
	DL_APPEND(block_solves, block_ckmsg);
	mutex_unlock(&block_lock);

	ckdbq_add(ckp, ID_BLOCK, val);
}

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

static bool new_share(const uchar *hash, int64_t  wb_id)
{
	share_t *share, *match = NULL;
	bool ret = false;

	ck_wlock(&share_lock);
	HASH_FIND(hh, shares, hash, 32, match);
	if (match)
		goto out_unlock;
	share = ckzalloc(sizeof(share_t));
	memcpy(share->hash, hash, 32);
	share->workbase_id = wb_id;
	HASH_ADD(hh, shares, hash, 32, share);
	ret = true;
out_unlock:
	ck_wunlock(&share_lock);

	return ret;
}

/* Submit a share in proxy mode to the parent pool. workbase_lock is held */
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
	workbase_t *wb = NULL;
	char idstring[20];
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

	ck_rlock(&workbase_lock);
	HASH_FIND_I64(workbases, &id, wb);
	if (unlikely(!wb)) {
		id = current_workbase->id;
		err = SE_INVALID_JOBID;
		json_set_string(json_msg, "reject-reason", SHARE_ERR(err));
		strcpy(idstring, job_id);
		ASPRINTF(&fname, "%s.sharelog", current_workbase->logdir);
		goto out_unlock;
	}
	wdiff = wb->diff;
	strcpy(idstring, wb->idstring);
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
	bswap_256(sharehash, hash);
	__bin2hex(hexhash, sharehash, 32);

	if (id < blockchange_id) {
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
	ck_runlock(&workbase_lock);

	/* Accept the lower of new and old diffs until the next update */
	if (id < client->diff_change_job_id && client->old_diff < client->diff)
		diff = client->old_diff;
	if (!invalid) {
		char wdiffsuffix[16];

		suffix_string(wdiff, wdiffsuffix, 16, 0);
		if (sdiff >= diff) {
			if (new_share(hash, id)) {
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
	json_object_set(val, "reject-reason", json_object_dup(json_msg, "reject-reason"));
	json_object_set(val, "error", *err_val);
	json_set_int(val, "errn", err);
	json_set_string(val, "createdate", cdfield);
	json_set_string(val, "createby", "code");
	json_set_string(val, "createcode", __func__);
	json_set_string(val, "createinet", ckp->serverurl);
	json_set_string(val, "workername", client->workername);
	json_set_string(val, "username", user_instance->username);

	if (ckp->logshares) {
		fp = fopen(fname, "ae");
		if (likely(fp)) {
			s = json_dumps(val, 0);
			len = strlen(s);
			len = fprintf(fp, "%s\n", s);
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
			LOGNOTICE("Client %d rejecting for 120s, disconnecting", client->id);
			stratum_send_message(client, "Disconnecting for continuous invalid shares");
			client->reject = 2;
		} else if (client->first_invalid && client->first_invalid < now_t - 60) {
			if (!client->reject) {
				LOGINFO("Client %d rejecting for 60s, sending diff", client->id);
				stratum_send_diff(client);
				client->reject = 1;
			}
		}
	} else {
		client->first_invalid = 0;
		client->reject = 0;
	}

	if (!share) {
		JSON_CPACK(val, "{sI,ss,ss,sI,ss,ss,so,si,ss,ss,ss,ss}",
				"clientid", client->id,
				"secondaryuserid", user_instance->secondaryuserid,
				"enonce1", client->enonce1,
				"workinfoid", current_workbase->id,
				"workername", client->workername,
				"username", user_instance->username,
				"error", json_copy(*err_val),
				"errn", err,
				"createdate", cdfield,
				"createby", "code",
				"createcode", __func__,
				"createinet", ckp->serverurl);
		ckdbq_add(ckp, ID_SHAREERR, val);
		LOGINFO("Invalid share from client %ld: %s", client->id, client->workername);
	}
	free(fname);
	return json_boolean(result);
}

/* Must enter with workbase_lock held */
static json_t *__stratum_notify(bool clean)
{
	json_t *val;

	JSON_CPACK(val, "{s:[ssssosssb],s:o,s:s}",
			"params",
			current_workbase->idstring,
			current_workbase->prevhash,
			current_workbase->coinb1,
			current_workbase->coinb2,
			json_deep_copy(current_workbase->merkle_array),
			current_workbase->bbversion,
			current_workbase->nbit,
			current_workbase->ntime,
			clean,
			"id", json_null(),
			"method", "mining.notify");
	return val;
}

static void stratum_broadcast_update(bool clean)
{
	json_t *json_msg;

	ck_rlock(&workbase_lock);
	json_msg = __stratum_notify(clean);
	ck_runlock(&workbase_lock);

	stratum_broadcast(json_msg);
}

/* For sending a single stratum template update */
static void stratum_send_update(int64_t client_id, bool clean)
{
	json_t *json_msg;

	ck_rlock(&workbase_lock);
	json_msg = __stratum_notify(clean);
	ck_runlock(&workbase_lock);

	stratum_add_send(json_msg, client_id);
}

static json_t *__user_notify(user_instance_t *user_instance, bool clean)
{
	int64_t id = current_workbase->id;
	struct userwb *userwb;
	json_t *val;

	HASH_FIND_I64(user_instance->userwbs, &id, userwb);
	if (unlikely(!userwb)) {
		LOGINFO("Failed to find userwb in __user_notify!");
		return NULL;
	}

	JSON_CPACK(val, "{s:[ssssosssb],s:o,s:s}",
			"params",
			current_workbase->idstring,
			current_workbase->prevhash,
			current_workbase->coinb1,
			userwb->coinb2,
			json_deep_copy(current_workbase->merkle_array),
			current_workbase->bbversion,
			current_workbase->nbit,
			current_workbase->ntime,
			clean,
			"id", json_null(),
			"method", "mining.notify");
	return val;
}

/* Current workbase can't be pulled out from under us here even without
 * locking since it's serialised with this code. Sends a stratum update with
 * a unique coinb2 for every client. */
static void stratum_broadcast_updates(bool clean)
{
	stratum_instance_t *client, *tmp;
	json_t *json_msg;

	ck_rlock(&instance_lock);
	HASH_ITER(hh, stratum_instances, client, tmp) {
		if (!client->user_instance)
			continue;

		json_msg = __user_notify(client->user_instance, clean);
		if (likely(json_msg))
			stratum_add_send(json_msg, client->id);
	}
	ck_runlock(&instance_lock);
}

static void send_json_err(int64_t client_id, json_t *id_val, const char *err_msg)
{
	json_t *val;

	JSON_CPACK(val, "{soss}", "id", json_copy(id_val), "error", err_msg);
	stratum_add_send(val, client_id);
}

static void update_client(stratum_instance_t *client, const int64_t client_id)
{
	stratum_send_update(client_id, true);
	stratum_send_diff(client);
}

static json_params_t *create_json_params(const int64_t client_id, const json_t *params, const json_t *id_val, const char *address)
{
	json_params_t *jp = ckalloc(sizeof(json_params_t));

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

	ignore = username;
	strsep(&ignore, "._");

	/* Find the user first */
	ck_rlock(&instance_lock);
	HASH_FIND_STR(user_instances, username, instance);
	ck_runlock(&instance_lock);

	/* They may just have not connected yet */
	if (!instance)
		return LOGINFO("Failed to find user %s in set_worker_mindiff", username);

	/* Then find the matching worker instance */
	ck_rlock(&instance_lock);
	DL_FOREACH(instance->worker_instances, tmp) {
		if (!safecmp(workername, tmp->workername)) {
			worker = tmp;
			break;
		}
	}
	ck_runlock(&instance_lock);

	/* They may just not be connected at the moment */
	if (!worker)
		return LOGINFO("Failed to find worker %s in set_worker_mindiff", workername);

	if (mindiff < 1)
		return LOGINFO("Worker %s requested invalid diff %ld", worker->workername, mindiff);
	if (mindiff < ckp->mindiff)
		mindiff = ckp->mindiff;
	if (mindiff == worker->mindiff)
		return;
	worker->mindiff = mindiff;

	/* Iterate over all the workers from this user to find any with the
	 * matching worker that are currently live and send them a new diff
	 * if we can. Otherwise it will only act as a clamp on next share
	 * submission. */
	ck_rlock(&instance_lock);
	DL_FOREACH(instance->instances, client) {
		if (client->worker_instance != worker)
			continue;
		/* Per connection suggest diff overrides worker mindiff ugh */
		if (mindiff < client->suggest_diff)
			continue;
		if (mindiff == client->diff)
			continue;
		client->diff = mindiff;
		stratum_send_diff(client);
	}
	ck_runlock(&instance_lock);
}

/* Implement support for the diff in the params as well as the originally
 * documented form of placing diff within the method. */
static void suggest_diff(stratum_instance_t *client, const char *method, json_t *params_val)
{
	json_t *arr_val = json_array_get(params_val, 0);
	int64_t sdiff;

	if (unlikely(!client->authorised))
		return LOGWARNING("Attempted to suggest diff on unauthorised client %ld", client->id);
	if (arr_val && json_is_integer(arr_val))
		sdiff = json_integer_value(arr_val);
	else if (sscanf(method, "mining.suggest_difficulty(%ld", &sdiff) != 1)
		return LOGINFO("Failed to parse suggest_difficulty for client %ld", client->id);
	if (sdiff == client->suggest_diff)
		return;
	client->suggest_diff = sdiff;
	if (client->diff == sdiff)
		return;
	if (sdiff < client->diff * 2 / 3)
		client->diff = client->diff * 2 / 3;
	else
		client->diff = sdiff;
	stratum_send_diff(client);
}

static void parse_method(const int64_t client_id, json_t *id_val, json_t *method_val,
			 json_t *params_val, char *address)
{
	stratum_instance_t *client;
	const char *method;
	char buf[256];

	ck_rlock(&instance_lock);
	client = __instance_by_id(client_id);
	ck_runlock(&instance_lock);

	if (unlikely(!client)) {
		LOGINFO("Failed to find client id %ld in hashtable!", client_id);
		return;
	}

	if (unlikely(client->reject == 2)) {
		LOGINFO("Dropping client %d tagged for lazy invalidation", client_id);
		snprintf(buf, 255, "dropclient=%ld", client->id);
		send_proc(client->ckp->connector, buf);
		return;
	}

	/* Random broken clients send something not an integer as the id so we copy
	 * the json item for id_val as is for the response. */
	method = json_string_value(method_val);
	if (cmdmatch(method, "mining.subscribe")) {
		json_t *val, *result_val = parse_subscribe(client, client_id, params_val);

		/* Shouldn't happen, sanity check */
		if (unlikely(!result_val)) {
			LOGWARNING("parse_subscribe returned NULL result_val");
			return;
		}
		val = json_object();
		json_object_set_new_nocheck(val, "result", result_val);
		json_object_set_nocheck(val, "id", id_val);
		json_object_set_new_nocheck(val, "error", json_null());
		stratum_add_send(val, client_id);
		if (!client->ckp->btcsolo && likely(client->subscribed))
			update_client(client, client_id);
		return;
	}

	if (unlikely(cmdmatch(method, "mining.passthrough"))) {
		/* We need to inform the connector process that this client
		 * is a passthrough and to manage its messages accordingly.
		 * Remove this instance since the client id may well be
		 * reused */
		ck_wlock(&instance_lock);
		HASH_DEL(stratum_instances, client);
		ck_wunlock(&instance_lock);

		LOGINFO("Adding passthrough client %ld", client->id);
		snprintf(buf, 255, "passthrough=%ld", client->id);
		send_proc(client->ckp->connector, buf);
		free(client);
		return;
	}

	if (cmdmatch(method, "mining.auth") && client->subscribed) {
		json_params_t *jp = create_json_params(client_id, params_val, id_val, address);

		ckmsgq_add(sauthq, jp);
		return;
	}

	/* We should only accept authorised requests from here on */
	if (!client->authorised) {
		/* Dropping unauthorised clients here also allows the
		 * stratifier process to restart since it will have lost all
		 * the stratum instance data. Clients will just reconnect. */
		LOGINFO("Dropping unauthorised client %ld", client->id);
		snprintf(buf, 255, "dropclient=%ld", client->id);
		send_proc(client->ckp->connector, buf);
		return;
	}

	if (cmdmatch(method, "mining.submit")) {
		json_params_t *jp = create_json_params(client_id, params_val, id_val, address);

		ckmsgq_add(sshareq, jp);
		return;
	}

	if (cmdmatch(method, "mining.suggest")) {
		suggest_diff(client, method, params_val);
		return;
	}

	/* Covers both get_transactions and get_txnhashes */
	if (cmdmatch(method, "mining.get")) {
		json_params_t *jp = create_json_params(client_id, method_val, id_val, address);

		ckmsgq_add(stxnq, jp);
		return;
	}
	/* Unhandled message here */
}

static void parse_instance_msg(smsg_t *msg)
{
	json_t *val = msg->json_msg, *id_val, *method, *params;
	int64_t client_id = msg->client_id;

	/* Return back the same id_val even if it's null or not existent. */
	id_val = json_object_get(val, "id");

	method = json_object_get(val, "method");
	if (unlikely(!method)) {
		send_json_err(client_id, id_val, "-3:method not found");
		goto out;
	}
	if (unlikely(!json_is_string(method))) {
		send_json_err(client_id, id_val, "-1:method is not string");
		goto out;
	}
	params = json_object_get(val, "params");
	if (unlikely(!params)) {
		send_json_err(client_id, id_val, "-1:params not found");
		goto out;
	}
	parse_method(client_id, id_val, method, params, msg->address);
out:
	json_decref(val);
	free(msg);
}

static void srecv_process(ckpool_t *ckp, smsg_t *msg)
{
	stratum_instance_t *instance;
	json_t *val;

	val = json_object_get(msg->json_msg, "client_id");
	if (unlikely(!val)) {
		char *s;

		s = json_dumps(msg->json_msg, 0);
		LOGWARNING("Failed to extract client_id from connector json smsg %s", s);
		free(s);
		json_decref(msg->json_msg);
		free(msg);
		return;
	}

	msg->client_id = json_integer_value(val);
	json_object_clear(val);

	val = json_object_get(msg->json_msg, "address");
	if (unlikely(!val)) {
		char *s;

		s = json_dumps(msg->json_msg, 0);
		LOGWARNING("Failed to extract address from connector json smsg %s", s);
		free(s);
		json_decref(msg->json_msg);
		free(msg);
		return;
	}
	strcpy(msg->address, json_string_value(val));
	json_object_clear(val);

	/* Parse the message here */
	ck_wlock(&instance_lock);
	instance = __instance_by_id(msg->client_id);
	if (!instance) {
		/* client_id instance doesn't exist yet, create one */
		instance = __stratum_add_instance(ckp, msg->client_id);
	}
	ck_wunlock(&instance_lock);

	parse_instance_msg(msg);

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
	json_decref((*jp)->params);
	json_decref((*jp)->id_val);
	free(*jp);
	*jp = NULL;
}

static void sshare_process(ckpool_t __maybe_unused *ckp, json_params_t *jp)
{
	json_t *result_val, *json_msg, *err_val = NULL;
	stratum_instance_t *client;
	int64_t client_id;

	client_id = jp->client_id;

	ck_rlock(&instance_lock);
	client = __instance_by_id(client_id);
	ck_runlock(&instance_lock);

	if (unlikely(!client)) {
		LOGINFO("Share processor failed to find client id %ld in hashtable!", client_id);
		goto out;
	}
	if (unlikely(!client->authorised)) {
		LOGDEBUG("Client %ld no longer authorised to submit shares", client_id);
		goto out;
	}
	json_msg = json_object();
	result_val = parse_submit(client, json_msg, jp->params, &err_val);
	json_object_set_new_nocheck(json_msg, "result", result_val);
	json_object_set_new_nocheck(json_msg, "error", err_val ? err_val : json_null());
	json_object_set_nocheck(json_msg, "id", jp->id_val);
	stratum_add_send(json_msg, client_id);
out:
	discard_json_params(&jp);
}

static void sauth_process(ckpool_t *ckp, json_params_t *jp)
{
	json_t *result_val, *json_msg, *err_val = NULL;
	stratum_instance_t *client;
	int mindiff, errnum = 0;
	int64_t client_id;

	client_id = jp->client_id;

	ck_rlock(&instance_lock);
	client = __instance_by_id(client_id);
	ck_runlock(&instance_lock);

	if (unlikely(!client)) {
		LOGINFO("Authoriser failed to find client id %ld in hashtable!", client_id);
		goto out;
	}
	result_val = parse_authorise(client, jp->params, &err_val, jp->address, &errnum);
	if (json_is_true(result_val)) {
		char *buf;

		ASPRINTF(&buf, "Authorised, welcome to %s %s!", ckp->name,
			 client->user_instance->username);
		stratum_send_message(client, buf);
	} else {
		if (errnum < 0)
			stratum_send_message(client, "Authorisations temporarily offline :(");
		else
			stratum_send_message(client, "Failed authorisation :(");
	}
	json_msg = json_object();
	json_object_set_new_nocheck(json_msg, "result", result_val);
	json_object_set_new_nocheck(json_msg, "error", err_val ? err_val : json_null());
	json_object_set_nocheck(json_msg, "id", jp->id_val);
	stratum_add_send(json_msg, client_id);

	if (!json_is_true(result_val) || !client->suggest_diff)
		goto out;

	/* Update the client now if they have set a valid mindiff different
	 * from the startdiff */
	mindiff = MAX(ckp->mindiff, client->suggest_diff);
	if (mindiff != client->diff) {
		client->diff = mindiff;
		stratum_send_diff(client);
	}
out:
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

static void ckdbq_process(ckpool_t *ckp, char *msg)
{
	static bool failed = false;
	char *buf = NULL;

	while (!buf) {
		mutex_lock(&ckdb_lock);
		buf = ckdb_msg_call(ckp, msg);
		mutex_unlock(&ckdb_lock);

		if (unlikely(!buf)) {
			if (!failed) {
				failed = true;
				LOGWARNING("Failed to talk to ckdb, queueing messages");
			}
			sleep(5);
		}
	}
	free(msg);
	if (failed) {
		failed = false;
		LOGWARNING("Successfully resumed talking to ckdb");
	}
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

static int transactions_by_jobid(int64_t id)
{
	workbase_t *wb;
	int ret = -1;

	ck_rlock(&workbase_lock);
	HASH_FIND_I64(workbases, &id, wb);
	if (wb)
		ret = wb->transactions;
	ck_runlock(&workbase_lock);

	return ret;
}

static json_t *txnhashes_by_jobid(int64_t id)
{
	json_t *ret = NULL;
	workbase_t *wb;

	ck_rlock(&workbase_lock);
	HASH_FIND_I64(workbases, &id, wb);
	if (wb)
		ret = json_string(wb->txn_hashes);
	ck_runlock(&workbase_lock);

	return ret;
}

static void send_transactions(ckpool_t *ckp, json_params_t *jp)
{
	const char *msg = json_string_value(jp->params);
	stratum_instance_t *client;
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
		 * transactions :) */
		sscanf(msg, "mining.get_transactions(%lx", &job_id);
		txns = transactions_by_jobid(job_id);
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

	ck_rlock(&instance_lock);
	client = __instance_by_id(jp->client_id);
	ck_runlock(&instance_lock);

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
	sscanf(msg, "mining.get_txnhashes(%lx", &job_id);
	hashes = txnhashes_by_jobid(job_id);
	if (hashes) {
		json_object_set_new_nocheck(val, "result", hashes);
		json_object_set_new_nocheck(val, "error", json_null());
	} else
		json_set_string(val, "error", "Invalid job_id");
out_send:
	stratum_add_send(val, jp->client_id);
out:
	discard_json_params(&jp);
}

static const double nonces = 4294967296;

/* Called every 20 seconds, we send the updated stats to ckdb of those users
 * who have gone 10 minutes between updates. This ends up staggering stats to
 * avoid floods of stat data coming at once. */
static void update_userstats(ckpool_t *ckp)
{
	stratum_instance_t *client, *tmp;
	json_t *val = NULL;
	char cdfield[64];
	time_t now_t;
	ts_t ts_now;

	if (++stats.userstats_cycle > 0x1f)
		stats.userstats_cycle = 0;

	ts_realtime(&ts_now);
	sprintf(cdfield, "%lu,%lu", ts_now.tv_sec, ts_now.tv_nsec);
	now_t = ts_now.tv_sec;

	ck_rlock(&instance_lock);
	HASH_ITER(hh, stratum_instances, client, tmp) {
		double ghs1, ghs5, ghs60, ghs1440;
		uint8_t cycle_mask;
		int elapsed;

		if (!client->authorised)
			continue;

		/* Send one lot of stats once the client is idle if they have submitted
		 * no shares in the last 10 minutes with the idle bool set. */
		if (client->idle && client->notified_idle)
			continue;
		/* Select clients using a mask to return each user's stats once
		 * every ~10 minutes */
		cycle_mask = client->user_id & 0x1f;
		if (cycle_mask != stats.userstats_cycle)
			continue;

		if (val) {
			json_set_bool(val,"eos", false);
			ckdbq_add(ckp, ID_USERSTATS, val);
			val = NULL;
		}
		elapsed = now_t - client->start_time;
		ghs1 = client->dsps1 * nonces;
		ghs5 = client->dsps5 * nonces;
		ghs60 = client->dsps60 * nonces;
		ghs1440 = client->dsps1440 * nonces;
		JSON_CPACK(val, "{ss,sI,si,ss,ss,sf,sf,sf,sf,sb,ss,ss,ss,ss}",
				"poolinstance", ckp->name,
				"instanceid", client->id,
				"elapsed", elapsed,
				"username", client->user_instance->username,
				"workername", client->workername,
				"hashrate", ghs1,
				"hashrate5m", ghs5,
				"hashrate1hr", ghs60,
				"hashrate24hr", ghs1440,
				"idle", client->idle,
				"createdate", cdfield,
				"createby", "code",
				"createcode", __func__,
				"createinet", ckp->serverurl);
		client->notified_idle = client->idle;
	}
	/* Mark the last userstats sent on this pass of stats with an end of
	 * stats marker. */
	if (val) {
		json_set_bool(val,"eos", true);
		ckdbq_add(ckp, ID_USERSTATS, val);
	}
	ck_runlock(&instance_lock);
}

static void *statsupdate(void *arg)
{
	ckpool_t *ckp = (ckpool_t *)arg;

	pthread_detach(pthread_self());
	rename_proc("statsupdate");

	tv_time(&stats.start_time);
	cksleep_prepare_r(&stats.last_update);
	sleep(1);

	while (42) {
		double ghs, ghs1, ghs5, ghs15, ghs60, ghs360, ghs1440, ghs10080;
		double bias, bias5, bias60, bias1440;
		double tdiff, per_tdiff;
		char suffix1[16], suffix5[16], suffix15[16], suffix60[16], cdfield[64];
		char suffix360[16], suffix1440[16], suffix10080[16];
		user_instance_t *instance, *tmpuser;
		stratum_instance_t *client, *tmp;
		double sps1, sps5, sps15, sps60;
		char fname[512] = {};
		tv_t now, diff;
		ts_t ts_now;
		json_t *val;
		FILE *fp;
		char *s;
		int i;

		tv_time(&now);
		timersub(&now, &stats.start_time, &diff);
		tdiff = diff.tv_sec + (double)diff.tv_usec / 1000000;

		ghs1 = stats.dsps1 * nonces;
		suffix_string(ghs1, suffix1, 16, 0);
		sps1 = stats.sps1;

		bias5 = time_bias(tdiff, 300);
		ghs5 = stats.dsps5 * nonces / bias5;
		suffix_string(ghs5, suffix5, 16, 0);
		sps5 = stats.sps5 / bias5;

		bias = time_bias(tdiff, 900);
		ghs15 = stats.dsps15 * nonces / bias;
		suffix_string(ghs15, suffix15, 16, 0);
		sps15 = stats.sps15 / bias;

		bias60 = time_bias(tdiff, 3600);
		ghs60 = stats.dsps60 * nonces / bias60;
		suffix_string(ghs60, suffix60, 16, 0);
		sps60 = stats.sps60 / bias60;

		bias = time_bias(tdiff, 21600);
		ghs360 = stats.dsps360 * nonces / bias;
		suffix_string(ghs360, suffix360, 16, 0);

		bias1440 = time_bias(tdiff, 86400);
		ghs1440 = stats.dsps1440 * nonces / bias1440;
		suffix_string(ghs1440, suffix1440, 16, 0);

		bias = time_bias(tdiff, 604800);
		ghs10080 = stats.dsps10080 * nonces / bias;
		suffix_string(ghs10080, suffix10080, 16, 0);

		snprintf(fname, 511, "%s/pool/pool.status", ckp->logdir);
		fp = fopen(fname, "we");
		if (unlikely(!fp))
			LOGERR("Failed to fopen %s", fname);

		JSON_CPACK(val, "{si,si,si}",
				"runtime", diff.tv_sec,
				"Users", stats.users,
				"Workers", stats.workers);
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

		ck_rlock(&instance_lock);
		HASH_ITER(hh, stratum_instances, client, tmp) {
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
				if (per_tdiff > 600)
					client->idle = true;
				continue;
			}
		}

		HASH_ITER(hh, user_instances, instance, tmpuser) {
			worker_instance_t *worker;
			bool idle = false;

			/* Decay times per worker */
			DL_FOREACH(instance->worker_instances, worker) {
				per_tdiff = tvdiff(&now, &worker->last_share);
				if (per_tdiff > 60) {
					decay_time(&worker->dsps1, 0, per_tdiff, 60);
					decay_time(&worker->dsps5, 0, per_tdiff, 300);
					decay_time(&worker->dsps60, 0, per_tdiff, 3600);
					decay_time(&worker->dsps1440, 0, per_tdiff, 86400);
				}
				ghs = worker->dsps1 * nonces;
				suffix_string(ghs, suffix1, 16, 0);

				ghs = worker->dsps5 * nonces / bias5;
				suffix_string(ghs, suffix5, 16, 0);

				ghs = worker->dsps60 * nonces / bias60;
				suffix_string(ghs, suffix60, 16, 0);

				ghs = worker->dsps1440 * nonces / bias1440;
				suffix_string(ghs, suffix1440, 16, 0);

				JSON_CPACK(val, "{ss,ss,ss,ss}",
						"hashrate1m", suffix1,
						"hashrate5m", suffix5,
						"hashrate1hr", suffix60,
						"hashrate1d", suffix1440);

				snprintf(fname, 511, "%s/workers/%s", ckp->logdir, worker->workername);
				fp = fopen(fname, "we");
				if (unlikely(!fp)) {
					LOGERR("Failed to fopen %s", fname);
					continue;
				}
				s = json_dumps(val, JSON_NO_UTF8 | JSON_PRESERVE_ORDER);
				fprintf(fp, "%s\n", s);
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

			ghs = instance->dsps5 * nonces / bias5;
			suffix_string(ghs, suffix5, 16, 0);

			ghs = instance->dsps60 * nonces / bias60;
			suffix_string(ghs, suffix60, 16, 0);

			ghs = instance->dsps1440 * nonces / bias1440;
			suffix_string(ghs, suffix1440, 16, 0);
			ghs = instance->dsps10080 * nonces;
			suffix_string(ghs, suffix10080, 16, 0);

			JSON_CPACK(val, "{ss,ss,ss,ss,ss,si}",
					"hashrate1m", suffix1,
					"hashrate5m", suffix5,
					"hashrate1hr", suffix60,
					"hashrate1d", suffix1440,
					"hashrate7d", suffix10080,
					"workers", instance->workers);

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
		ck_runlock(&instance_lock);

		ts_realtime(&ts_now);
		sprintf(cdfield, "%lu,%lu", ts_now.tv_sec, ts_now.tv_nsec);
		JSON_CPACK(val, "{ss,si,si,si,sf,sf,sf,sf,ss,ss,ss,ss}",
				"poolinstance", ckp->name,
				"elapsed", diff.tv_sec,
				"users", stats.users,
				"workers", stats.workers,
				"hashrate", ghs1,
				"hashrate5m", ghs5,
				"hashrate1hr", ghs60,
				"hashrate24hr", ghs1440,
				"createdate", cdfield,
				"createby", "code",
				"createcode", __func__,
				"createinet", ckp->serverurl);
		ckdbq_add(ckp, ID_POOLSTATS, val);

		/* Update stats 3 times per minute for smooth values, displaying
		 * status every minute. */
		for (i = 0; i < 3; i++) {
			cksleep_ms_r(&stats.last_update, 20000);
			cksleep_prepare_r(&stats.last_update);
			update_userstats(ckp);

			mutex_lock(&stats_lock);
			stats.accounted_shares += stats.unaccounted_shares;
			stats.accounted_diff_shares += stats.unaccounted_diff_shares;
			stats.accounted_rejects += stats.unaccounted_rejects;

			decay_time(&stats.sps1, stats.unaccounted_shares, 20, 60);
			decay_time(&stats.sps5, stats.unaccounted_shares, 20, 300);
			decay_time(&stats.sps15, stats.unaccounted_shares, 20, 900);
			decay_time(&stats.sps60, stats.unaccounted_shares, 20, 3600);

			decay_time(&stats.dsps1, stats.unaccounted_diff_shares, 20, 60);
			decay_time(&stats.dsps5, stats.unaccounted_diff_shares, 20, 300);
			decay_time(&stats.dsps15, stats.unaccounted_diff_shares, 20, 900);
			decay_time(&stats.dsps60, stats.unaccounted_diff_shares, 20, 3600);
			decay_time(&stats.dsps360, stats.unaccounted_diff_shares, 20, 21600);
			decay_time(&stats.dsps1440, stats.unaccounted_diff_shares, 20, 86400);
			decay_time(&stats.dsps10080, stats.unaccounted_diff_shares, 20, 604800);

			stats.unaccounted_shares =
			stats.unaccounted_diff_shares =
			stats.unaccounted_rejects = 0;
			mutex_unlock(&stats_lock);
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

	pthread_detach(pthread_self());
	rename_proc("heartbeat");

	while (42) {
		char cdfield[64];
		ts_t ts_now;
		json_t *val;

		cksleep_ms(1000);
		if (unlikely(!ckmsgq_empty(ckdbq))) {
			LOGDEBUG("Witholding heartbeat due to ckdb messages being queued");
			continue;
		}
		ts_realtime(&ts_now);
		sprintf(cdfield, "%lu,%lu", ts_now.tv_sec, ts_now.tv_nsec);
		JSON_CPACK(val, "{ss,ss,ss,ss}",
				"createdate", cdfield,
				"createby", "code",
				"createcode", __func__,
				"createinet", ckp->serverurl);
		ckdbq_add(ckp, ID_HEARTBEAT, val);
	}
	return NULL;
}

int stratifier(proc_instance_t *pi)
{
	pthread_t pth_blockupdate, pth_statsupdate, pth_heartbeat;
	ckpool_t *ckp = pi->ckp;
	int ret = 1;
	char *buf;

	LOGWARNING("%s stratifier starting", ckp->name);

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
		address_to_pubkeytxn(pubkeytxnbin, ckp->btcaddress);

		if (test_address(ckp, ckp->donaddress)) {
			ckp->donvalid = true;
			address_to_pubkeytxn(donkeytxnbin, ckp->donaddress);
		}
	}

	/* Set the initial id to time as high bits so as to not send the same
	 * id on restarts */
	if (!ckp->proxy)
		blockchange_id = workbase_id = ((int64_t)time(NULL)) << 32;

	dealloc(buf);

	if (!ckp->serverurl)
		ckp->serverurl = "127.0.0.1";
	cklock_init(&instance_lock);

	mutex_init(&ckdb_lock);
	ssends = create_ckmsgq(ckp, "ssender", &ssend_process);
	srecvs = create_ckmsgq(ckp, "sreceiver", &srecv_process);
	sshareq = create_ckmsgq(ckp, "sprocessor", &sshare_process);
	sauthq = create_ckmsgq(ckp, "authoriser", &sauth_process);
	ckdbq = create_ckmsgq(ckp, "ckdbqueue", &ckdbq_process);
	stxnq = create_ckmsgq(ckp, "stxnq", &send_transactions);
	if (!CKP_STANDALONE(ckp))
		create_pthread(&pth_heartbeat, ckdb_heartbeat, ckp);

	cklock_init(&workbase_lock);
	if (!ckp->proxy)
		create_pthread(&pth_blockupdate, blockupdate, ckp);

	mutex_init(&stats_lock);
	create_pthread(&pth_statsupdate, statsupdate, ckp);

	cklock_init(&share_lock);
	mutex_init(&block_lock);

	LOGWARNING("%s stratifier ready", ckp->name);

	ret = stratum_loop(ckp, pi);
out:
	return process_exit(ckp, pi, ret);
}
