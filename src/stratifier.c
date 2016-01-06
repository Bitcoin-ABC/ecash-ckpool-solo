/*
 * Copyright 2014-2016 Con Kolivas
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

#define MIN1	60
#define MIN5	300
#define MIN15	900
#define HOUR	3600
#define HOUR6	21600
#define DAY	86400
#define WEEK	604800

/* Consistent across all pool instances */
static const char *workpadding = "000000800000000000000000000000000000000000000000000000000000000000000000000000000000000080020000";
static const char *scriptsig_header = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff";
static uchar scriptsig_header_bin[41];
static const double nonces = 4294967296;

/* Add unaccounted shares when they arrive, remove them with each update of
 * rolling stats. */
struct pool_stats {
	tv_t start_time;
	ts_t last_update;

	int workers;
	int users;
	int disconnected;

	/* Absolute shares stats */
	int64_t unaccounted_shares;
	int64_t accounted_shares;

	/* Cycle of 32 to determine which users to dump stats on */
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

	/* Cached header binary */
	char headerbin[112];

	char *logdir;

	ckpool_t *ckp;
	bool proxy; /* This workbase is proxied work */
};

typedef struct workbase workbase_t;

struct json_params {
	json_t *method;
	json_t *params;
	json_t *id_val;
	int64_t client_id;
};

typedef struct json_params json_params_t;

/* Stratum json messages with their associated client id */
struct smsg {
	json_t *json_msg;
	int64_t client_id;
};

typedef struct smsg smsg_t;

struct user_instance;
struct worker_instance;
struct stratum_instance;

typedef struct user_instance user_instance_t;
typedef struct worker_instance worker_instance_t;
typedef struct stratum_instance stratum_instance_t;

struct user_instance {
	UT_hash_handle hh;
	char username[128];
	int id;
	char *secondaryuserid;
	bool btcaddress;

	/* A linked list of all connected instances of this user */
	stratum_instance_t *clients;

	/* A linked list of all connected workers of this user */
	worker_instance_t *worker_instances;

	int workers;

	double best_diff; /* Best share found by this user */

	int64_t shares;
	double dsps1; /* Diff shares per second, 1 minute rolling average */
	double dsps5; /* ... 5 minute ... */
	double dsps60;/* etc */
	double dsps1440;
	double dsps10080;
	tv_t last_share;
	tv_t last_decay;
	tv_t last_update;

	bool authorised; /* Has this username ever been authorised? */
	time_t auth_time;
	time_t failed_authtime; /* Last time this username failed to authorise */
	int auth_backoff; /* How long to reject any auth attempts since last failure */
	bool throttled; /* Have we begun rejecting auth attempts */
};

/* Combined data from workers with the same workername */
struct worker_instance {
	user_instance_t *user_instance;
	char *workername;

	worker_instance_t *next;
	worker_instance_t *prev;

	int64_t shares;
	double dsps1;
	double dsps5;
	double dsps60;
	double dsps1440;
	double dsps10080;
	tv_t last_share;
	tv_t last_decay;
	tv_t last_update;
	time_t start_time;

	double best_diff; /* Best share found by this worker */
	int mindiff; /* User chosen mindiff */

	bool idle;
	bool notified_idle;
};

typedef struct stratifier_data sdata_t;

typedef struct proxy_base proxy_t;

/* Per client stratum instance == workers */
struct stratum_instance {
	UT_hash_handle hh;
	int64_t id;

	stratum_instance_t *next;
	stratum_instance_t *prev;

	/* Reference count for when this instance is used outside of the
	 * instance_lock */
	int ref;

	char enonce1[36]; /* Fit up to 16 byte binary enonce1 */
	uchar enonce1bin[16];
	char enonce1var[20]; /* Fit up to 8 byte binary enonce1var */
	uint64_t enonce1_64;
	int session_id;

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
	tv_t last_decay;
	time_t first_invalid; /* Time of first invalid in run of non stale rejects */
	time_t upstream_invalid; /* As first_invalid but for upstream responses */
	time_t start_time;

	char address[INET6_ADDRSTRLEN];
	bool node; /* Is this a mining node */
	bool subscribed;
	bool authorising; /* In progress, protected by instance_lock */
	bool authorised;
	bool dropped;
	bool idle;
	int reject;	/* Indicator that this client is having a run of rejects
			 * or other problem and should be dropped lazily if
			 * this is set to 2 */

	bool reconnect; /* This client really needs to reconnect */
	time_t reconnect_request; /* The time we sent a reconnect message */

	user_instance_t *user_instance;
	worker_instance_t *worker_instance;

	char *useragent;
	char *workername;
	char *password;
	int user_id;
	int server; /* Which server is this instance bound to */

	ckpool_t *ckp;

	time_t last_txns; /* Last time this worker requested txn hashes */
	time_t disconnected_time; /* Time this instance disconnected */

	int64_t suggest_diff; /* Stratum client suggested diff */
	double best_diff; /* Best share found by this instance */

	sdata_t *sdata; /* Which sdata this client is bound to */
	proxy_t *proxy; /* Proxy this is bound to in proxy mode */
	int proxyid; /* Which proxy id  */
	int subproxyid; /* Which subproxy */

	bool remote; /* Is this a trusted remote server */
};

struct share {
	UT_hash_handle hh;
	uchar hash[32];
	int64_t workbase_id;
};

typedef struct share share_t;

struct proxy_base {
	UT_hash_handle hh;
	UT_hash_handle sh; /* For subproxy hashlist */
	proxy_t *next; /* For retired subproxies */
	proxy_t *prev;
	int id;
	int subid;

	/* Priority has the user id encoded in the high bits if it's not a
	 * global proxy. */
	int64_t priority;

	bool global; /* Is this a global proxy */
	int userid; /* Userid for non global proxies */

	double diff;

	char url[128];
	char auth[128];
	char pass[128];
	char enonce1[32];
	uchar enonce1bin[16];
	int enonce1constlen;
	int enonce1varlen;

	int nonce2len;
	int enonce2varlen;

	bool subscribed;
	bool notified;

	int64_t clients; /* Incrementing client count */
	int64_t max_clients; /* Maximum number of clients per subproxy */
	int64_t bound_clients; /* Currently actively bound clients */
	int64_t combined_clients; /* Total clients of all subproxies of a parent proxy */
	int64_t headroom; /* Temporary variable when calculating how many more clients can bind */

	int subproxy_count; /* Number of subproxies */
	proxy_t *parent; /* Parent proxy of each subproxy */
	proxy_t *subproxies; /* Hashlist of subproxies sorted by subid */
	sdata_t *sdata; /* Unique stratifer data for each subproxy */
	bool dead;
};

typedef struct session session_t;

struct session {
	UT_hash_handle hh;
	int session_id;
	uint64_t enonce1_64;
	int64_t client_id;
	int userid;
	time_t added;
	char address[INET6_ADDRSTRLEN];
};

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

static const char *ckdb_seq_names[] = {
	"seqauthorise",
	"seqworkinfo",
	"seqageworkinfo",
	"seqshares",
	"seqshareerror",
	"seqpoolstats",
	"seqworkerstats",
	"seqblock",
	"seqaddrauth",
	"seqheartbeat"
};

#define ID_COUNT (sizeof(ckdb_ids)/sizeof(char *))

struct stratifier_data {
	ckpool_t *ckp;

	char pubkeytxnbin[25];
	int pubkeytxnlen;
	char donkeytxnbin[25];
	int donkeytxnlen;

	pool_stats_t stats;
	/* Protects changes to pool stats */
	mutex_t stats_lock;

	/* Serialises sends/receives to ckdb if possible */
	mutex_t ckdb_lock;
	/* Protects sequence numbers */
	mutex_t ckdb_msg_lock;
	/* Incrementing global sequence number */
	uint64_t ckdb_seq;
	/* Incrementing ckdb_ids[] sequence numbers */
	uint64_t ckdb_seq_ids[ID_COUNT];

	bool ckdb_offline;
	bool verbose;

	uint64_t enonce1_64;

	/* For protecting the hashtable data */
	cklock_t workbase_lock;

	/* For the hashtable of all workbases */
	workbase_t *workbases;
	workbase_t *current_workbase;
	int workbases_generated;

	/* Semaphore to serialise calls to add_base */
	sem_t update_sem;
	/* Time we last sent out a stratum update */
	time_t update_time;

	int64_t workbase_id;
	int64_t blockchange_id;
	int session_id;
	char lasthash[68];
	char lastswaphash[68];

	ckmsgq_t *ssends;	// Stratum sends
	ckmsgq_t *srecvs;	// Stratum receives
	ckmsgq_t *ckdbq;	// ckdb
	ckmsgq_t *sshareq;	// Stratum share sends
	ckmsgq_t *sauthq;	// Stratum authorisations
	ckmsgq_t *stxnq;	// Transaction requests

	int user_instance_id;

	stratum_instance_t *stratum_instances;
	stratum_instance_t *recycled_instances;
	stratum_instance_t *node_instances;

	int stratum_generated;
	int disconnected_generated;
	session_t *disconnected_sessions;

	user_instance_t *user_instances;

	/* Protects both stratum and user instances */
	cklock_t instance_lock;

	share_t *shares;
	mutex_t share_lock;

	int64_t shares_generated;

	/* Linked list of block solves, added to during submission, removed on
	 * accept/reject. It is likely we only ever have one solve on here but
	 * you never know... */
	mutex_t block_lock;
	ckmsg_t *block_solves;

	/* Generator message priority */
	int gen_priority;

	int proxy_count; /* Total proxies generated (not necessarily still alive) */
	proxy_t *proxy; /* Current proxy in use */
	proxy_t *proxies; /* Hashlist of all proxies */
	mutex_t proxy_lock; /* Protects all proxy data */
	proxy_t *subproxy; /* Which subproxy this sdata belongs to in proxy mode */
};

typedef struct json_entry json_entry_t;

struct json_entry {
	json_entry_t *next;
	json_entry_t *prev;
	json_t *val;
};

/* Priority levels for generator messages */
#define GEN_LAX 0
#define GEN_NORMAL 1
#define GEN_PRIORITY 2

/* For storing a set of messages within another lock, allowing us to dump them
 * to the log outside of lock */
static void add_msg_entry(char_entry_t **entries, char **buf)
{
	char_entry_t *entry = ckalloc(sizeof(char_entry_t));

	entry->buf = *buf;
	*buf = NULL;
	DL_APPEND(*entries, entry);
}

static void notice_msg_entries(char_entry_t **entries)
{
	char_entry_t *entry, *tmpentry;

	DL_FOREACH_SAFE(*entries, entry, tmpentry) {
		DL_DELETE(*entries, entry);
		LOGNOTICE("%s", entry->buf);
		free(entry->buf);
		free(entry);
	}
}

static void info_msg_entries(char_entry_t **entries)
{
	char_entry_t *entry, *tmpentry;

	DL_FOREACH_SAFE(*entries, entry, tmpentry) {
		DL_DELETE(*entries, entry);
		LOGINFO("%s", entry->buf);
		free(entry->buf);
		free(entry);
	}
}

static void generate_coinbase(const ckpool_t *ckp, workbase_t *wb)
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

	wb->coinb2bin[wb->coinb2len++] = sdata->pubkeytxnlen;
	memcpy(wb->coinb2bin + wb->coinb2len, sdata->pubkeytxnbin, sdata->pubkeytxnlen);
	wb->coinb2len += sdata->pubkeytxnlen;

	if (ckp->donvalid) {
		u64 = (uint64_t *)&wb->coinb2bin[wb->coinb2len];
		*u64 = htole64(d64);
		wb->coinb2len += 8;

		wb->coinb2bin[wb->coinb2len++] = sdata->donkeytxnlen;
		memcpy(wb->coinb2bin + wb->coinb2len, sdata->donkeytxnbin, sdata->donkeytxnlen);
		wb->coinb2len += sdata->donkeytxnlen;
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

static void stratum_broadcast_update(sdata_t *sdata, const workbase_t *wb, bool clean);

static void clear_workbase(workbase_t *wb)
{
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
static void purge_share_hashtable(sdata_t *sdata, const int64_t wb_id)
{
	share_t *share, *tmp;
	int purged = 0;

	mutex_lock(&sdata->share_lock);
	HASH_ITER(hh, sdata->shares, share, tmp) {
		if (share->workbase_id < wb_id) {
			HASH_DEL(sdata->shares, share);
			dealloc(share);
			purged++;
		}
	}
	mutex_unlock(&sdata->share_lock);

	if (purged)
		LOGINFO("Cleared %d shares from share hashtable", purged);
}

/* Remove all shares with a workbase id == wb_id being discarded */
static void age_share_hashtable(sdata_t *sdata, const int64_t wb_id)
{
	share_t *share, *tmp;
	int aged = 0;

	mutex_lock(&sdata->share_lock);
	HASH_ITER(hh, sdata->shares, share, tmp) {
		if (share->workbase_id == wb_id) {
			HASH_DEL(sdata->shares, share);
			dealloc(share);
			aged++;
		}
	}
	mutex_unlock(&sdata->share_lock);

	if (aged)
		LOGINFO("Aged %d shares from share hashtable", aged);
}

static char *status_chars = "|/-\\";

/* Absorbs the json and generates a ckdb json message, logs it to the ckdb
 * log and returns the malloced message. */
static char *ckdb_msg(ckpool_t *ckp, sdata_t *sdata, json_t *val, const int idtype)
{
	char *json_msg;
	char logname[512];
	char *ret = NULL;
	uint64_t seqall;

	json_set_int(val, "seqstart", ckp->starttime);
	json_set_int(val, "seqpid", ckp->startpid);
	/* Set the atomically incrementing sequence numbers */
	mutex_lock(&sdata->ckdb_msg_lock);
	seqall = sdata->ckdb_seq++;
	json_set_int(val, "seqall", seqall);
	json_set_int(val, ckdb_seq_names[idtype], sdata->ckdb_seq_ids[idtype]++);
	mutex_unlock(&sdata->ckdb_msg_lock);

	json_msg = json_dumps(val, JSON_COMPACT);
	if (unlikely(!json_msg))
		goto out;
	ASPRINTF(&ret, "%s.%"PRIu64".json=%s", ckdb_ids[idtype], seqall, json_msg);
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
		pool_stats_t *stats = &sdata->stats;
		char hashrate[16];

		/* Rate limit to 1 update per second */
		time_counter = now_t;
		suffix_string(stats->dsps1 * nonces, hashrate, 16, 3);
		ch = status_chars[(counter++) & 0x3];
		fprintf(stdout, "\33[2K\r%c %sH/s  %.1f SPS  %d users  %d workers",
			ch, hashrate, stats->sps1, stats->users, stats->workers);
		fflush(stdout);
	}

	if (CKP_STANDALONE(ckp))
		return json_decref(val);

	json_msg = ckdb_msg(ckp, sdata, val, idtype);
	if (unlikely(!json_msg)) {
		LOGWARNING("Failed to dump json from %s %s:%d", file, func, line);
		return;
	}

	ckmsgq_add(sdata->ckdbq, json_msg);
}

#define ckdbq_add(ckp, idtype, val) _ckdbq_add(ckp, idtype, val, __FILE__, __func__, __LINE__)

static void stratum_add_send(sdata_t *sdata, json_t *val, const int64_t client_id,
			     const int msg_type);

static void send_node_workinfo(sdata_t *sdata, const workbase_t *wb)
{
	stratum_instance_t *client;
	ckmsg_t *bulk_send = NULL;

	ck_rlock(&sdata->instance_lock);
	if (sdata->node_instances) {
		json_t *wb_val = json_object();

		json_set_int(wb_val, "jobid", wb->id);
		json_set_string(wb_val, "target", wb->target);
		json_set_double(wb_val, "diff", wb->diff);
		json_set_int(wb_val, "version", wb->version);
		json_set_int(wb_val, "curtime", wb->curtime);
		json_set_string(wb_val, "prevhash", wb->prevhash);
		json_set_string(wb_val, "ntime", wb->ntime);
		json_set_string(wb_val, "bbversion", wb->bbversion);
		json_set_string(wb_val, "nbit", wb->nbit);
		json_set_int(wb_val, "coinbasevalue", wb->coinbasevalue);
		json_set_int(wb_val, "height", wb->height);
		json_set_string(wb_val, "flags", wb->flags);
		json_set_int(wb_val, "transactions", wb->transactions);
		if (likely(wb->transactions))
			json_set_string(wb_val, "txn_data", wb->txn_data);
		/* We don't need txn_hashes */
		json_set_int(wb_val, "merkles", wb->merkles);
		json_object_set_new_nocheck(wb_val, "merklehash", json_deep_copy(wb->merkle_array));
		json_set_string(wb_val, "coinb1", wb->coinb1);
		json_set_int(wb_val, "enonce1varlen", wb->enonce1varlen);
		json_set_int(wb_val, "enonce2varlen", wb->enonce2varlen);
		json_set_int(wb_val, "coinb1len", wb->coinb1len);
		json_set_int(wb_val, "coinb2len", wb->coinb2len);
		json_set_string(wb_val, "coinb2", wb->coinb2);

		DL_FOREACH(sdata->node_instances, client) {
			ckmsg_t *client_msg;
			smsg_t *msg;
			json_t *json_msg = json_deep_copy(wb_val);

			json_set_string(json_msg, "node.method", stratum_msgs[SM_WORKINFO]);
			client_msg = ckalloc(sizeof(ckmsg_t));
			msg = ckzalloc(sizeof(smsg_t));
			msg->json_msg = json_msg;
			msg->client_id = client->id;
			client_msg->data = msg;
			DL_APPEND(bulk_send, client_msg);
		}
		json_decref(wb_val);
	}
	ck_runlock(&sdata->instance_lock);

	if (bulk_send) {
		ckmsgq_t *ssends = sdata->ssends;

		LOGINFO("Sending workinfo to mining nodes");

		mutex_lock(ssends->lock);
		DL_CONCAT(ssends->msgs, bulk_send);
		pthread_cond_signal(ssends->cond);
		mutex_unlock(ssends->lock);
	}
}

static void send_workinfo(ckpool_t *ckp, sdata_t *sdata, const workbase_t *wb)
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
	send_node_workinfo(sdata, wb);
}

static void send_ageworkinfo(ckpool_t *ckp, const int64_t id)
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

/* Add a new workbase to the table of workbases. Sdata is the global data in
 * pool mode but unique to each subproxy in proxy mode */
static void add_base(ckpool_t *ckp, sdata_t *sdata, workbase_t *wb, bool *new_block)
{
	workbase_t *tmp, *tmpa, *aged = NULL;
	sdata_t *ckp_sdata = ckp->data;
	int len, ret;

	ts_realtime(&wb->gentime);
	wb->network_diff = diff_from_nbits(wb->headerbin + 72);

	len = strlen(ckp->logdir) + 8 + 1 + 16 + 1;
	wb->logdir = ckzalloc(len);

	/* In proxy mode, the wb->id is received in the notify update and
	 * we set workbase_id from it. In server mode the stratifier is
	 * setting the workbase_id */
	ck_wlock(&sdata->workbase_lock);
	ckp_sdata->workbases_generated++;
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

	/* Is this long enough to ensure we don't dereference a workbase
	 * immediately? Should be unless clock changes 10 minutes so we use
	 * ts_realtime */
	HASH_ITER(hh, sdata->workbases, tmp, tmpa) {
		if (HASH_COUNT(sdata->workbases) < 3)
			break;
		if (wb == tmp)
			continue;
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

	if (*new_block)
		purge_share_hashtable(sdata, wb->id);

	if (!ckp->passthrough)
		send_workinfo(ckp, sdata, wb);

	/* Send the aged work message to ckdb once we have dropped the workbase lock
	 * to prevent taking recursive locks */
	if (aged) {
		send_ageworkinfo(ckp, aged->id);
		age_share_hashtable(sdata, aged->id);
		clear_workbase(aged);
	}
}

/* Mandatory send_recv to the generator which sets the message priority if this
 * message is higher priority. Races galore on gen_priority mean this might
 * read the wrong priority but occasional wrong values are harmless. */
static char *__send_recv_generator(ckpool_t *ckp, const char *msg, const int prio)
{
	sdata_t *sdata = ckp->data;
	char *buf = NULL;
	bool set;

	if (prio > sdata->gen_priority) {
		sdata->gen_priority = prio;
		set = true;
	} else
		set = false;
	buf = _send_recv_proc(ckp->generator, msg, UNIX_WRITE_TIMEOUT, RPC_TIMEOUT, __FILE__, __func__, __LINE__);
	if (unlikely(!buf))
		buf = strdup("failed");
	if (set)
		sdata->gen_priority = 0;

	return buf;
}

/* Conditionally send_recv a message only if it's equal or higher priority than
 * any currently being serviced. NULL is returned if the request is not
 * processed for priority reasons, "failed" for an actual failure. */
static char *send_recv_generator(ckpool_t *ckp, const char *msg, const int prio)
{
	sdata_t *sdata = ckp->data;
	char *buf = NULL;

	if (prio >= sdata->gen_priority)
		buf = __send_recv_generator(ckp, msg, prio);
	return buf;
}

static void send_generator(const ckpool_t *ckp, const char *msg, const int prio)
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
	int prio = ur->prio, retries = 0;
	ckpool_t *ckp = ur->ckp;
	sdata_t *sdata = ckp->data;
	bool new_block = false;
	bool ret = false;
	workbase_t *wb;
	time_t now_t;
	json_t *val;
	char *buf;

	pthread_detach(pthread_self());
	rename_proc("updater");

	/* Serialise access to getbase to avoid out of order new block notifies */
	cksem_wait(&sdata->update_sem);
retry:
	buf = send_recv_generator(ckp, "getbase", prio);
	if (unlikely(!buf)) {
		LOGNOTICE("Get base in update_base delayed due to higher priority request");
		goto out;
	}
	if (unlikely(cmdmatch(buf, "failed"))) {
		if (retries++ < 5 || prio == GEN_PRIORITY) {
			LOGWARNING("Generator returned failure in update_base, retry #%d", retries);
			goto retry;
		}
		LOGWARNING("Generator failed in update_base after retrying");
		goto out;
	}
	if (unlikely(retries))
		LOGWARNING("Generator succeeded in update_base after retrying");

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

	add_base(ckp, sdata, wb, &new_block);
	/* Reset the update time to avoid stacked low priority notifies. Bring
	 * forward the next notify in case of a new block. */
	now_t = time(NULL);
	if (new_block)
		now_t -= ckp->update_interval / 2;
	sdata->update_time = now_t;

	if (new_block)
		LOGNOTICE("Block hash changed to %s", sdata->lastswaphash);
	stratum_broadcast_update(sdata, wb, new_block);
	ret = true;
	LOGINFO("Broadcast updated stratum base");
out:
	cksem_post(&sdata->update_sem);

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

static void add_node_base(ckpool_t *ckp, json_t *val)
{
	workbase_t *wb = ckzalloc(sizeof(workbase_t));
	sdata_t *sdata = ckp->data;
	bool new_block = false;
	char header[228];
	int i;

	wb->ckp = ckp;
	json_int64cpy(&wb->id, val, "jobid");
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
	if (wb->transactions)
		json_strdup(&wb->txn_data, val, "txn_data");
	json_intcpy(&wb->merkles, val, "merkles");
	wb->merkle_array = json_object_dup(val, "merklehash");
	for (i = 0; i < wb->merkles; i++) {
		strcpy(&wb->merklehash[i][0], json_string_value(json_array_get(wb->merkle_array, i)));
		hex2bin(&wb->merklebin[i][0], &wb->merklehash[i][0], 32);
	}
	json_strdup(&wb->coinb1, val, "coinb1");
	json_intcpy(&wb->coinb1len, val, "coinb1len");
	wb->coinb1bin = ckzalloc(wb->coinb1len);
	hex2bin(wb->coinb1bin, wb->coinb1, wb->coinb1len);
	json_strdup(&wb->coinb2, val, "coinb2");
	json_intcpy(&wb->coinb2len, val, "coinb2len");
	wb->coinb2bin = ckzalloc(wb->coinb2len);
	hex2bin(wb->coinb2bin, wb->coinb2, wb->coinb2len);
	json_intcpy(&wb->enonce1varlen, val, "enonce1varlen");
	json_intcpy(&wb->enonce2varlen, val, "enonce2varlen");
	ts_realtime(&wb->gentime);

	snprintf(header, 225, "%s%s%s%s%s%s%s",
		 wb->bbversion, wb->prevhash,
		 "0000000000000000000000000000000000000000000000000000000000000000",
		 wb->ntime, wb->nbit,
		 "00000000", /* nonce */
		 workpadding);
	LOGDEBUG("Header: %s", header);
	hex2bin(wb->headerbin, header, 112);

	add_base(ckp, sdata, wb, &new_block);
	if (new_block)
		LOGNOTICE("Block hash changed to %s", sdata->lastswaphash);
}

static void update_base(ckpool_t *ckp, const int prio)
{
	struct update_req *ur = ckalloc(sizeof(struct update_req));
	pthread_t *pth = ckalloc(sizeof(pthread_t));

	ur->pth = pth;
	ur->ckp = ckp;
	ur->prio = prio;
	create_pthread(pth, do_update, ur);
}

/* Instead of removing the client instance, we add it to a list of recycled
 * clients allowing us to reuse it instead of callocing a new one */
static void __kill_instance(sdata_t *sdata, stratum_instance_t *client)
{
	if (client->proxy) {
		client->proxy->bound_clients--;
		client->proxy->parent->combined_clients--;
	}
	free(client->workername);
	free(client->password);
	free(client->useragent);
	memset(client, 0, sizeof(stratum_instance_t));
	DL_APPEND(sdata->recycled_instances, client);
}

/* Called with instance_lock held. Note stats.users is protected by
 * instance lock to avoid recursive locking. */
static void __inc_worker(sdata_t *sdata, user_instance_t *instance)
{
	sdata->stats.workers++;
	if (!instance->workers++)
		sdata->stats.users++;
}

static void __dec_worker(sdata_t *sdata, user_instance_t *instance)
{
	sdata->stats.workers--;
	if (!--instance->workers)
		sdata->stats.users--;
}

static void __disconnect_session(sdata_t *sdata, const stratum_instance_t *client)
{
	time_t now_t = time(NULL);
	session_t *session, *tmp;

	/* Opportunity to age old sessions */
	HASH_ITER(hh, sdata->disconnected_sessions, session, tmp) {
		if (now_t - session->added > 600) {
			HASH_DEL(sdata->disconnected_sessions, session);
			dealloc(session);
			sdata->stats.disconnected--;
		}
	}

	if (!client->enonce1_64 || !client->user_instance || !client->authorised)
		return;
	HASH_FIND_INT(sdata->disconnected_sessions, &client->session_id, session);
	if (session)
		return;
	session = ckalloc(sizeof(session_t));
	session->enonce1_64 = client->enonce1_64;
	session->session_id = client->session_id;
	session->client_id = client->id;
	session->userid = client->user_id;
	session->added = now_t;
	strcpy(session->address, client->address);
	HASH_ADD_INT(sdata->disconnected_sessions, session_id, session);
	sdata->stats.disconnected++;
	sdata->disconnected_generated++;
}

/* Removes a client instance we know is on the stratum_instances list and from
 * the user client list if it's been placed on it */
static void __del_client(sdata_t *sdata, stratum_instance_t *client)
{
	user_instance_t *user = client->user_instance;

	HASH_DEL(sdata->stratum_instances, client);
	if (user) {
		DL_DELETE(user->clients, client);
		__dec_worker(sdata, user);
	}
}

static void connector_drop_client(ckpool_t *ckp, const int64_t id)
{
	char buf[256];

	LOGDEBUG("Stratifier requesting connector drop client %"PRId64, id);
	snprintf(buf, 255, "dropclient=%"PRId64, id);
	send_proc(ckp->connector, buf);
}

static void drop_allclients(ckpool_t *ckp)
{
	stratum_instance_t *client, *tmp;
	sdata_t *sdata = ckp->data;
	int kills = 0;

	ck_wlock(&sdata->instance_lock);
	HASH_ITER(hh, sdata->stratum_instances, client, tmp) {
		int64_t client_id = client->id;

		if (!client->ref) {
			__del_client(sdata, client);
			__kill_instance(sdata, client);
		} else
			client->dropped = true;
		kills++;
		connector_drop_client(ckp, client_id);
	}
	sdata->stats.users = sdata->stats.workers = 0;
	ck_wunlock(&sdata->instance_lock);

	if (kills)
		LOGNOTICE("Dropped %d instances for dropall request", kills);
}

/* Copy only the relevant parts of the master sdata for each subproxy */
static sdata_t *duplicate_sdata(const sdata_t *sdata)
{
	sdata_t *dsdata = ckzalloc(sizeof(sdata_t));

	dsdata->ckp = sdata->ckp;

	/* Copy the transaction binaries for workbase creation */
	memcpy(dsdata->pubkeytxnbin, sdata->pubkeytxnbin, 25);
	memcpy(dsdata->donkeytxnbin, sdata->donkeytxnbin, 25);

	/* Use the same work queues for all subproxies */
	dsdata->ssends = sdata->ssends;
	dsdata->srecvs = sdata->srecvs;
	dsdata->ckdbq = sdata->ckdbq;
	dsdata->sshareq = sdata->sshareq;
	dsdata->sauthq = sdata->sauthq;
	dsdata->stxnq = sdata->stxnq;

	/* Give the sbuproxy its own workbase list and lock */
	cklock_init(&dsdata->workbase_lock);
	cksem_init(&dsdata->update_sem);
	cksem_post(&dsdata->update_sem);
	return dsdata;
}

static int64_t prio_sort(proxy_t *a, proxy_t *b)
{
	return (a->priority - b->priority);
}

/* Priority values can be sparse, they do not need to be sequential */
static void __set_proxy_prio(sdata_t *sdata, proxy_t *proxy, int64_t priority)
{
	proxy_t *tmpa, *tmpb, *exists = NULL;
	int64_t next_prio = 0;

	/* Encode the userid as the high bits in priority */
	if (!proxy->global) {
		int64_t high_bits = proxy->userid;

		high_bits <<= 32;
		priority |= high_bits;
	}

	/* See if the priority is already in use */
	HASH_ITER(hh, sdata->proxies, tmpa, tmpb) {
		if (tmpa->priority > priority)
			break;
		if (tmpa->priority == priority) {
			exists = tmpa;
			next_prio = exists->priority + 1;
			break;
		}
	}
	/* See if we need to push the priority of everything after exists up */
	HASH_ITER(hh, exists, tmpa, tmpb) {
		if (tmpa->priority > next_prio)
			break;
		tmpa->priority++;
		next_prio++;
	}
	proxy->priority = priority;
	HASH_SORT(sdata->proxies, prio_sort);
}

static proxy_t *__generate_proxy(sdata_t *sdata, const int id)
{
	proxy_t *proxy = ckzalloc(sizeof(proxy_t));

	proxy->parent = proxy;
	proxy->id = id;
	proxy->sdata = duplicate_sdata(sdata);
	proxy->sdata->subproxy = proxy;
	proxy->sdata->verbose = true;
	/* subid == 0 on parent proxy */
	HASH_ADD(sh, proxy->subproxies, subid, sizeof(int), proxy);
	proxy->subproxy_count++;
	HASH_ADD_INT(sdata->proxies, id, proxy);
	/* Set the new proxy priority to its id */
	__set_proxy_prio(sdata, proxy, id);
	sdata->proxy_count++;
	return proxy;
}

static proxy_t *__generate_subproxy(sdata_t *sdata, proxy_t *proxy, const int subid)
{
	proxy_t *subproxy = ckzalloc(sizeof(proxy_t));

	subproxy->parent = proxy;
	subproxy->id = proxy->id;
	subproxy->subid = subid;
	HASH_ADD(sh, proxy->subproxies, subid, sizeof(int), subproxy);
	proxy->subproxy_count++;
	subproxy->sdata = duplicate_sdata(sdata);
	subproxy->sdata->subproxy = subproxy;
	return subproxy;
}

static proxy_t *__existing_proxy(const sdata_t *sdata, const int id)
{
	proxy_t *proxy;

	HASH_FIND_INT(sdata->proxies, &id, proxy);
	return proxy;
}

static proxy_t *existing_proxy(sdata_t *sdata, const int id)
{
	proxy_t *proxy;

	mutex_lock(&sdata->proxy_lock);
	proxy = __existing_proxy(sdata, id);
	mutex_unlock(&sdata->proxy_lock);

	return proxy;
}

/* Find proxy by id number, generate one if none exist yet by that id */
static proxy_t *__proxy_by_id(sdata_t *sdata, const int id)
{
	proxy_t *proxy = __existing_proxy(sdata, id);

	if (unlikely(!proxy)) {
		proxy = __generate_proxy(sdata, id);
		LOGNOTICE("Stratifier added new proxy %d", id);
	}

	return proxy;
}

static proxy_t *__existing_subproxy(proxy_t *proxy, const int subid)
{
	proxy_t *subproxy;

	HASH_FIND(sh, proxy->subproxies, &subid, sizeof(int), subproxy);
	return subproxy;
}

static proxy_t *__subproxy_by_id(sdata_t *sdata, proxy_t *proxy, const int subid)
{
	proxy_t *subproxy = __existing_subproxy(proxy, subid);

	if (!subproxy) {
		subproxy = __generate_subproxy(sdata, proxy, subid);
		LOGINFO("Stratifier added new subproxy %d:%d", proxy->id, subid);
	}
	return subproxy;
}

static proxy_t *subproxy_by_id(sdata_t *sdata, const int id, const int subid)
{
	proxy_t *proxy, *subproxy;

	mutex_lock(&sdata->proxy_lock);
	proxy = __proxy_by_id(sdata, id);
	subproxy = __subproxy_by_id(sdata, proxy, subid);
	mutex_unlock(&sdata->proxy_lock);

	return subproxy;
}

static proxy_t *existing_subproxy(sdata_t *sdata, const int id, const int subid)
{
	proxy_t *proxy, *subproxy = NULL;

	mutex_lock(&sdata->proxy_lock);
	proxy = __existing_proxy(sdata, id);
	if (proxy)
		subproxy = __existing_subproxy(proxy, subid);
	mutex_unlock(&sdata->proxy_lock);

	return subproxy;
}

static void set_proxy_prio(sdata_t *sdata, proxy_t *proxy, const int priority)
{
	mutex_lock(&sdata->proxy_lock);
	__set_proxy_prio(sdata, proxy, priority);
	mutex_unlock(&sdata->proxy_lock);
}

/* Set proxy to the current proxy and calculate how much headroom it has */
static int64_t current_headroom(sdata_t *sdata, proxy_t **proxy)
{
	proxy_t *subproxy, *tmp;
	int64_t headroom = 0;

	mutex_lock(&sdata->proxy_lock);
	*proxy = sdata->proxy;
	if (!*proxy)
		goto out_unlock;
	HASH_ITER(sh, (*proxy)->subproxies, subproxy, tmp) {
		if (subproxy->dead)
			continue;
		headroom += subproxy->max_clients - subproxy->clients;
	}
out_unlock:
	mutex_unlock(&sdata->proxy_lock);

	return headroom;
}

static int64_t proxy_headroom(sdata_t *sdata, const int userid)
{
	proxy_t *proxy, *subproxy, *tmp, *subtmp;
	int64_t headroom = 0;

	mutex_lock(&sdata->proxy_lock);
	HASH_ITER(hh, sdata->proxies, proxy, tmp) {
		if (proxy->userid < userid)
			continue;
		if (proxy->userid > userid)
			break;
		HASH_ITER(sh, proxy->subproxies, subproxy, subtmp) {
			if (subproxy->dead)
				continue;
			headroom += subproxy->max_clients - subproxy->clients;
		}
	}
	mutex_unlock(&sdata->proxy_lock);

	return headroom;
}

static void reconnect_client(sdata_t *sdata, stratum_instance_t *client);

static void generator_recruit(const ckpool_t *ckp, const int proxyid, const int recruits)
{
	char buf[256];

	sprintf(buf, "recruit=%d:%d", proxyid, recruits);
	LOGINFO("Stratifer requesting %d more subproxies of proxy %d from generator",
		recruits, proxyid);
	send_generator(ckp, buf, GEN_PRIORITY);
}

/* Find how much headroom we have and connect up to that many clients that are
 * not currently on this pool, recruiting more slots to switch more clients
 * later on lazily. Only reconnect clients bound to global proxies. */
static void reconnect_clients(sdata_t *sdata)
{
	stratum_instance_t *client, *tmpclient;
	int reconnects = 0;
	int64_t headroom;
	proxy_t *proxy;

	headroom = current_headroom(sdata, &proxy);
	if (!proxy)
		return;

	ck_rlock(&sdata->instance_lock);
	HASH_ITER(hh, sdata->stratum_instances, client, tmpclient) {
		if (client->dropped)
			continue;
		if (!client->authorised)
			continue;
		/* Is this client bound to a dead proxy? */
		if (!client->reconnect) {
			/* This client is bound to a user proxy */
			if (client->proxy->userid)
				continue;
			if (client->proxyid == proxy->id)
				continue;
		}
		if (headroom-- < 1)
			continue;
		reconnects++;
		reconnect_client(sdata, client);
	}
	ck_runlock(&sdata->instance_lock);

	if (reconnects) {
		LOGINFO("%d clients flagged for reconnect to global proxy %d",
			reconnects, proxy->id);
	}
	if (headroom < 0)
		generator_recruit(sdata->ckp, proxy->id, -headroom);
}

static bool __subproxies_alive(proxy_t *proxy)
{
	proxy_t *subproxy, *tmp;
	bool alive = false;

	HASH_ITER(sh, proxy->subproxies, subproxy, tmp) {
		if (!subproxy->dead) {
			alive = true;
			break;
		}
	}
	return alive;
}

/* Iterate over the current global proxy list and see if the current one is
 * the highest priority alive one. Proxies are sorted by priority so the first
 * available will be highest priority. Uses ckp sdata */
static void check_bestproxy(sdata_t *sdata)
{
	proxy_t *proxy, *tmp;
	int changed_id = -1;

	mutex_lock(&sdata->proxy_lock);
	if (sdata->proxy && !__subproxies_alive(sdata->proxy))
		sdata->proxy = NULL;
	HASH_ITER(hh, sdata->proxies, proxy, tmp) {
		if (!__subproxies_alive(proxy))
			continue;
		if (!proxy->global)
			break;
		if (proxy != sdata->proxy) {
			sdata->proxy = proxy;
			changed_id = proxy->id;
		}
		break;
	}
	mutex_unlock(&sdata->proxy_lock);

	if (changed_id != -1)
		LOGNOTICE("Stratifier setting active proxy to %d", changed_id);
}

static void dead_proxyid(sdata_t *sdata, const int id, const int subid, const bool replaced)
{
	stratum_instance_t *client, *tmp;
	int reconnects = 0, proxyid = 0;
	int64_t headroom;
	proxy_t *proxy;

	proxy = existing_subproxy(sdata, id, subid);
	if (proxy) {
		proxy->dead = true;
		if (!replaced && proxy->global)
			check_bestproxy(sdata);
	}
	LOGINFO("Stratifier dropping clients from proxy %d:%d", id, subid);
	headroom = current_headroom(sdata, &proxy);
	if (proxy)
		proxyid = proxy->id;

	ck_rlock(&sdata->instance_lock);
	HASH_ITER(hh, sdata->stratum_instances, client, tmp) {
		if (client->proxyid != id || client->subproxyid != subid)
			continue;
		/* Clients could remain connected to a dead connection here
		 * but should be picked up when we recruit enough slots after
		 * another notify. */
		if (headroom-- < 1) {
			client->reconnect = true;
			continue;
		}
		reconnects++;
		reconnect_client(sdata, client);
	}
	ck_runlock(&sdata->instance_lock);

	if (reconnects) {
		LOGINFO("%d clients flagged to reconnect from dead proxy %d:%d", reconnects,
			id, subid);
	}
	/* When a proxy dies, recruit more of the global proxies for them to
	 * fail over to in case user proxies are unavailable. */
	if (headroom < 0)
		generator_recruit(sdata->ckp, proxyid, -headroom);
}

static void update_subscribe(ckpool_t *ckp, const char *cmd)
{
	sdata_t *sdata = ckp->data, *dsdata;
	int id = 0, subid = 0, userid = 0;
	proxy_t *proxy, *old = NULL;
	const char *buf;
	bool global;
	json_t *val;

	if (unlikely(strlen(cmd) < 11)) {
		LOGWARNING("Received zero length string for subscribe in update_subscribe");
		return;
	}
	buf = cmd + 10;
	LOGDEBUG("Update subscribe: %s", buf);
	val = json_loads(buf, 0, NULL);
	if (unlikely(!val)) {
		LOGWARNING("Failed to json decode subscribe response in update_subscribe %s", buf);
		return;
	}
	if (unlikely(!json_get_int(&id, val, "proxy"))) {
		LOGWARNING("Failed to json decode proxy value in update_subscribe %s", buf);
		return;
	}
	if (unlikely(!json_get_int(&subid, val, "subproxy"))) {
		LOGWARNING("Failed to json decode subproxy value in update_subscribe %s", buf);
		return;
	}
	if (unlikely(!json_get_bool(&global, val, "global"))) {
		LOGWARNING("Failed to json decode global value in update_subscribe %s", buf);
		return;
	}
	if (!global) {
		if (unlikely(!json_get_int(&userid, val, "userid"))) {
			LOGWARNING("Failed to json decode userid value in update_subscribe %s", buf);
			return;
		}
	}

	if (!subid)
		LOGNOTICE("Got updated subscribe for proxy %d", id);
	else
		LOGINFO("Got updated subscribe for proxy %d:%d", id, subid);

	/* Is this a replacement for an existing proxy id? */
	old = existing_subproxy(sdata, id, subid);
	if (old) {
		dead_proxyid(sdata, id, subid, true);
		proxy = old;
		proxy->dead = false;
	} else
		proxy = subproxy_by_id(sdata, id, subid);
	proxy->global = global;
	proxy->userid = userid;
	proxy->subscribed = true;
	proxy->diff = ckp->startdiff;
	memset(proxy->url, 0, 128);
	memset(proxy->auth, 0, 128);
	memset(proxy->pass, 0, 128);
	strncpy(proxy->url, json_string_value(json_object_get(val, "url")), 127);
	strncpy(proxy->auth, json_string_value(json_object_get(val, "auth")), 127);
	strncpy(proxy->pass, json_string_value(json_object_get(val, "pass")), 127);

	dsdata = proxy->sdata;

	ck_wlock(&dsdata->workbase_lock);
	/* Length is checked by generator */
	strcpy(proxy->enonce1, json_string_value(json_object_get(val, "enonce1")));
	proxy->enonce1constlen = strlen(proxy->enonce1) / 2;
	hex2bin(proxy->enonce1bin, proxy->enonce1, proxy->enonce1constlen);
	proxy->nonce2len = json_integer_value(json_object_get(val, "nonce2len"));
	if (proxy->nonce2len > 7)
		proxy->enonce1varlen = 4;
	else if (proxy->nonce2len > 5)
		proxy->enonce1varlen = 2;
	else if (proxy->nonce2len > 3)
		proxy->enonce1varlen = 1;
	else
		proxy->enonce1varlen = 0;
	proxy->enonce2varlen = proxy->nonce2len - proxy->enonce1varlen;
	proxy->max_clients = 1ll << (proxy->enonce1varlen * 8);
	proxy->clients = 0;
	ck_wunlock(&dsdata->workbase_lock);

	if (subid) {
		LOGINFO("Upstream pool %s %d:%d extranonce2 length %d, max proxy clients %"PRId64,
			proxy->url, id, subid, proxy->nonce2len, proxy->max_clients);
	} else {
		LOGNOTICE("Upstream pool %s %d extranonce2 length %d, max proxy clients %"PRId64,
			  proxy->url, id, proxy->nonce2len, proxy->max_clients);
	}
	json_decref(val);
}

/* Find the highest priority alive proxy belonging to userid and recruit extra
 * subproxies. */
static void recruit_best_userproxy(sdata_t *sdata, const int userid, const int recruits)
{
	proxy_t *proxy, *subproxy, *tmp, *subtmp, *best = NULL;

	mutex_lock(&sdata->proxy_lock);
	HASH_ITER(hh, sdata->proxies, proxy, tmp) {
		if (proxy->userid < userid)
			continue;
		if (proxy->userid > userid)
			break;
		HASH_ITER(sh, proxy->subproxies, subproxy, subtmp) {
			if (subproxy->dead)
				continue;
			best = proxy;
		}
	}
	mutex_unlock(&sdata->proxy_lock);

	if (best)
		generator_recruit(sdata->ckp, best->id, recruits);
}

/* Check how much headroom the userid proxies have and reconnect any clients
 * that are not bound to it that should be */
static void check_userproxies(sdata_t *sdata, const int userid)
{
	int64_t headroom = proxy_headroom(sdata, userid);
	stratum_instance_t *client, *tmpclient;
	int reconnects = 0;

	ck_rlock(&sdata->instance_lock);
	HASH_ITER(hh, sdata->stratum_instances, client, tmpclient) {
		if (client->dropped)
			continue;
		if (!client->authorised)
			continue;
		if (client->user_id != userid)
			continue;
		/* Is this client bound to a dead proxy? */
		if (!client->reconnect && client->proxy->userid == userid)
			continue;
		if (headroom-- < 1)
			continue;
		reconnects++;
		reconnect_client(sdata, client);
	}
	ck_runlock(&sdata->instance_lock);

	if (reconnects) {
		LOGINFO("%d clients flagged for reconnect to user %d proxies",
			reconnects, userid);
	}
	if (headroom < 0)
		recruit_best_userproxy(sdata, userid, -headroom);
}

static proxy_t *best_proxy(sdata_t *sdata)
{
	proxy_t *proxy;

	mutex_lock(&sdata->proxy_lock);
	proxy = sdata->proxy;
	mutex_unlock(&sdata->proxy_lock);

	return proxy;
}

static void update_notify(ckpool_t *ckp, const char *cmd)
{
	sdata_t *sdata = ckp->data, *dsdata;
	bool new_block = false, clean;
	int i, id = 0, subid = 0;
	char header[228];
	const char *buf;
	proxy_t *proxy;
	workbase_t *wb;
	json_t *val;

	if (unlikely(strlen(cmd) < 8)) {
		LOGWARNING("Zero length string passed to update_notify");
		return;
	}
	buf = cmd + 7; /* "notify=" */
	LOGDEBUG("Update notify: %s", buf);

	val = json_loads(buf, 0, NULL);
	if (unlikely(!val)) {
		LOGWARNING("Failed to json decode in update_notify");
		return;
	}
	json_get_int(&id, val, "proxy");
	json_get_int(&subid, val, "subproxy");
	proxy = existing_subproxy(sdata, id, subid);
	if (unlikely(!proxy || !proxy->subscribed)) {
		LOGINFO("No valid proxy %d:%d subscription to update notify yet", id, subid);
		goto out;
	}
	LOGINFO("Got updated notify for proxy %d:%d", id, subid);

	wb = ckzalloc(sizeof(workbase_t));
	wb->ckp = ckp;
	wb->proxy = true;

	json_get_int64(&wb->id, val, "jobid");
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

	dsdata = proxy->sdata;

	ck_rlock(&dsdata->workbase_lock);
	strcpy(wb->enonce1const, proxy->enonce1);
	wb->enonce1constlen = proxy->enonce1constlen;
	memcpy(wb->enonce1constbin, proxy->enonce1bin, wb->enonce1constlen);
	wb->enonce1varlen = proxy->enonce1varlen;
	wb->enonce2varlen = proxy->enonce2varlen;
	wb->diff = proxy->diff;
	ck_runlock(&dsdata->workbase_lock);

	add_base(ckp, dsdata, wb, &new_block);
	if (new_block) {
		if (subid)
			LOGINFO("Block hash on proxy %d:%d changed to %s", id, subid, dsdata->lastswaphash);
		else
			LOGNOTICE("Block hash on proxy %d changed to %s", id, dsdata->lastswaphash);
	}

	if (proxy->global) {
		check_bestproxy(sdata);
		if (proxy->parent == best_proxy(sdata)->parent)
			reconnect_clients(sdata);
	} else
		check_userproxies(sdata, proxy->userid);
	clean |= new_block;
	LOGINFO("Proxy %d:%d broadcast updated stratum notify with%s clean", id,
		subid, clean ? "" : "out");
	stratum_broadcast_update(dsdata, wb, clean);
out:
	json_decref(val);
}

static void stratum_send_diff(sdata_t *sdata, const stratum_instance_t *client);

static void update_diff(ckpool_t *ckp, const char *cmd)
{
	sdata_t *sdata = ckp->data, *dsdata;
	stratum_instance_t *client, *tmp;
	double old_diff, diff;
	int id = 0, subid = 0;
	const char *buf;
	proxy_t *proxy;
	json_t *val;

	if (unlikely(strlen(cmd) < 6)) {
		LOGWARNING("Zero length string passed to update_diff");
		return;
	}
	buf = cmd + 5; /* "diff=" */
	LOGDEBUG("Update diff: %s", buf);

	val = json_loads(buf, 0, NULL);
	if (unlikely(!val)) {
		LOGWARNING("Failed to json decode in update_diff");
		return;
	}
	json_get_int(&id, val, "proxy");
	json_get_int(&subid, val, "subproxy");
	json_dblcpy(&diff, val, "diff");
	json_decref(val);

	LOGINFO("Got updated diff for proxy %d:%d", id, subid);
	proxy = existing_subproxy(sdata, id, subid);
	if (!proxy) {
		LOGINFO("No existing subproxy %d:%d to update diff", id, subid);
		return;
	}

	/* We only really care about integer diffs so clamp the lower limit to
	 * 1 or it will round down to zero. */
	if (unlikely(diff < 1))
		diff = 1;

	dsdata = proxy->sdata;

	if (unlikely(!dsdata->current_workbase)) {
		LOGINFO("No current workbase to update diff yet");
		return;
	}

	ck_wlock(&dsdata->workbase_lock);
	old_diff = proxy->diff;
	dsdata->current_workbase->diff = proxy->diff = diff;
	ck_wunlock(&dsdata->workbase_lock);

	if (old_diff < diff)
		return;

	/* If the diff has dropped, iterate over all the clients and check
	 * they're at or below the new diff, and update it if not. */
	ck_rlock(&sdata->instance_lock);
	HASH_ITER(hh, sdata->stratum_instances, client, tmp) {
		if (client->proxyid != id)
			continue;
		if (client->subproxyid != subid)
			continue;
		if (client->diff > diff) {
			client->diff = diff;
			stratum_send_diff(sdata, client);
		}
	}
	ck_runlock(&sdata->instance_lock);
}

#if 0
static void generator_drop_proxy(ckpool_t *ckp, const int64_t id, const int subid)
{
	char msg[256];

	sprintf(msg, "dropproxy=%ld:%d", id, subid);
	send_generator(ckp, msg, GEN_LAX);
}
#endif

static void free_proxy(proxy_t *proxy)
{
	free(proxy->sdata);
	free(proxy);
}

/* Remove subproxies that are flagged dead. Then see if there
 * are any retired proxies that no longer have any other subproxies and reap
 * those. */
static void reap_proxies(ckpool_t *ckp, sdata_t *sdata)
{
	proxy_t *proxy, *proxytmp, *subproxy, *subtmp;
	int dead = 0;

	if (!ckp->proxy)
		return;

	mutex_lock(&sdata->proxy_lock);
	HASH_ITER(hh, sdata->proxies, proxy, proxytmp) {
		HASH_ITER(sh, proxy->subproxies, subproxy, subtmp) {
			if (!subproxy->bound_clients && !subproxy->dead) {
				/* Reset the counter to reuse this proxy */
				subproxy->clients = 0;
				continue;
			}
			if (proxy == subproxy)
				continue;
			if (subproxy->bound_clients)
				continue;
			if (!subproxy->dead)
				continue;
			if (unlikely(!subproxy->subid)) {
				LOGWARNING("Unexepectedly found proxy %d:%d as subproxy of %d:%d",
					   subproxy->id, subproxy->subid, proxy->id, proxy->subid);
				continue;
			}
			if (unlikely(subproxy == sdata->proxy)) {
				LOGWARNING("Unexepectedly found proxy %d:%d as current",
					   subproxy->id, subproxy->subid);
				continue;
			}
			dead++;
			HASH_DELETE(sh, proxy->subproxies, subproxy);
			proxy->subproxy_count--;
			free_proxy(subproxy);
		}
	}
	mutex_unlock(&sdata->proxy_lock);

	if (dead)
		LOGINFO("Stratifier discarded %d dead proxies", dead);
}

/* Enter with instance_lock held */
static stratum_instance_t *__instance_by_id(sdata_t *sdata, const int64_t id)
{
	stratum_instance_t *client;

	HASH_FIND_I64(sdata->stratum_instances, &id, client);
	return client;
}

/* Increase the reference count of instance */
static void __inc_instance_ref(stratum_instance_t *client)
{
	client->ref++;
}

/* Find an __instance_by_id and increase its reference count allowing us to
 * use this instance outside of instance_lock without fear of it being
 * dereferenced. Does not return dropped clients still on the list. */
static stratum_instance_t *ref_instance_by_id(sdata_t *sdata, const int64_t id)
{
	stratum_instance_t *client;

	ck_wlock(&sdata->instance_lock);
	client = __instance_by_id(sdata, id);
	if (client) {
		if (unlikely(client->dropped))
			client = NULL;
		else
			__inc_instance_ref(client);
	}
	ck_wunlock(&sdata->instance_lock);

	return client;
}

static void __drop_client(sdata_t *sdata, stratum_instance_t *client, bool lazily, char **msg)
{
	user_instance_t *user = client->user_instance;

	if (unlikely(client->node))
		DL_DELETE(sdata->node_instances, client);
	if (client->workername) {
		if (user) {
			ASPRINTF(msg, "Dropped client %"PRId64" %s %suser %s worker %s %s",
				 client->id, client->address, user->throttled ? "throttled " : "",
				 user->username, client->workername, lazily ? "lazily" : "");
		} else {
			ASPRINTF(msg, "Dropped client %"PRId64" %s no user worker %s %s",
				 client->id, client->address, client->workername,
				 lazily ? "lazily" : "");
		}
	} else {
		ASPRINTF(msg, "Dropped workerless client %"PRId64" %s %s",
			 client->id, client->address, lazily ? "lazily" : "");
	}
	__del_client(sdata, client);
	__kill_instance(sdata, client);
}

/* Decrease the reference count of instance. */
static void _dec_instance_ref(sdata_t *sdata, stratum_instance_t *client, const char *file,
			      const char *func, const int line)
{
	char_entry_t *entries = NULL;
	bool dropped = false;
	char *msg;
	int ref;

	ck_wlock(&sdata->instance_lock);
	ref = --client->ref;
	/* See if there are any instances that were dropped that could not be
	 * moved due to holding a reference and drop them now. */
	if (unlikely(client->dropped && !ref)) {
		dropped = true;
		__drop_client(sdata, client, true, &msg);
		add_msg_entry(&entries, &msg);
	}
	ck_wunlock(&sdata->instance_lock);

	notice_msg_entries(&entries);
	/* This should never happen */
	if (unlikely(ref < 0))
		LOGERR("Instance ref count dropped below zero from %s %s:%d", file, func, line);

	if (dropped)
		reap_proxies(sdata->ckp, sdata);
}

#define dec_instance_ref(sdata, instance) _dec_instance_ref(sdata, instance, __FILE__, __func__, __LINE__)

/* If we have a no longer used stratum instance in the recycled linked list,
 * use that, otherwise calloc a fresh one. */
static stratum_instance_t *__recruit_stratum_instance(sdata_t *sdata)
{
	stratum_instance_t *client = sdata->recycled_instances;

	if (client)
		DL_DELETE(sdata->recycled_instances, client);
	else {
		client = ckzalloc(sizeof(stratum_instance_t));
		sdata->stratum_generated++;
	}
	return client;
}

/* Enter with write instance_lock held */
static stratum_instance_t *__stratum_add_instance(ckpool_t *ckp, const int64_t id,
						  const char *address, int server)
{
	stratum_instance_t *client;
	sdata_t *sdata = ckp->data;

	client = __recruit_stratum_instance(sdata);
	client->start_time = time(NULL);
	client->id = id;
	client->session_id = ++sdata->session_id;
	strcpy(client->address, address);
	/* Sanity check to not overflow lookup in ckp->serverurl[] */
	if (server >= ckp->serverurls)
		server = 0;
	client->server = server;
	client->diff = client->old_diff = ckp->startdiff;
	client->ckp = ckp;
	tv_time(&client->ldc);
	HASH_ADD_I64(sdata->stratum_instances, id, client);
	/* Points to ckp sdata in ckpool mode, but is changed later in proxy
	 * mode . */
	client->sdata = sdata;
	return client;
}

static uint64_t disconnected_sessionid_exists(sdata_t *sdata, const int session_id,
					      const int64_t id)
{
	session_t *session;
	int64_t old_id = 0;
	uint64_t ret = 0;

	ck_wlock(&sdata->instance_lock);
	HASH_FIND_INT(sdata->disconnected_sessions, &session_id, session);
	if (!session)
		goto out_unlock;
	HASH_DEL(sdata->disconnected_sessions, session);
	sdata->stats.disconnected--;
	ret = session->enonce1_64;
	old_id = session->client_id;
	dealloc(session);
out_unlock:
	ck_wunlock(&sdata->instance_lock);

	if (ret)
		LOGNOTICE("Reconnecting old instance %"PRId64" to instance %"PRId64, old_id, id);
	return ret;
}

static inline bool client_active(stratum_instance_t *client)
{
	return (client->authorised && !client->dropped);
}

/* Ask the connector asynchronously to send us dropclient commands if this
 * client no longer exists. */
static void connector_test_client(ckpool_t *ckp, const int64_t id)
{
	char buf[256];

	LOGDEBUG("Stratifier requesting connector test client %"PRId64, id);
	snprintf(buf, 255, "testclient=%"PRId64, id);
	send_proc(ckp->connector, buf);
}

/* passthrough subclients have client_ids in the high bits */
static inline bool passthrough_subclient(const int64_t client_id)
{
	return (client_id > 0xffffffffll);
}

/* For creating a list of sends without locking that can then be concatenated
 * to the stratum_sends list. Minimises locking and avoids taking recursive
 * locks. Sends only to sdata bound clients (everyone in ckpool) */
static void stratum_broadcast(sdata_t *sdata, json_t *val, const int msg_type)
{
	ckpool_t *ckp = sdata->ckp;
	sdata_t *ckp_sdata = ckp->data;
	stratum_instance_t *client, *tmp;
	ckmsg_t *bulk_send = NULL;
	time_t now_t = time(NULL);
	ckmsgq_t *ssends;

	if (unlikely(!val)) {
		LOGERR("Sent null json to stratum_broadcast");
		return;
	}

	if (ckp->node) {
		json_decref(val);
		return;
	}

	/* Use this locking as an opportunity to test other clients. */
	ck_rlock(&ckp_sdata->instance_lock);
	HASH_ITER(hh, ckp_sdata->stratum_instances, client, tmp) {
		ckmsg_t *client_msg;
		smsg_t *msg;

		if (sdata != ckp_sdata && client->sdata != sdata)
			continue;

		/* Look for clients that may have been dropped which the stratifer has
		* not been informed about and ask the connector of they still exist */
		if (client->dropped) {
			connector_test_client(ckp, client->id);
			continue;
		}

		if (client->node || client->remote)
			continue;

		/* Test for clients that haven't authed in over a minute and drop them */
		if (!client->authorised) {
			if (now_t > client->start_time + 60) {
				client->dropped = true;
				connector_drop_client(ckp, client->id);
			}
			continue;
		}

		if (!client_active(client))
			continue;
		client_msg = ckalloc(sizeof(ckmsg_t));
		msg = ckzalloc(sizeof(smsg_t));
		if (passthrough_subclient(client->id))
			json_set_string(val, "node.method", stratum_msgs[msg_type]);
		msg->json_msg = json_deep_copy(val);
		msg->client_id = client->id;
		client_msg->data = msg;
		DL_APPEND(bulk_send, client_msg);
	}
	ck_runlock(&ckp_sdata->instance_lock);

	json_decref(val);

	if (!bulk_send)
		return;

	ssends = sdata->ssends;

	mutex_lock(ssends->lock);
	if (ssends->msgs)
		DL_CONCAT(ssends->msgs, bulk_send);
	else
		ssends->msgs = bulk_send;
	pthread_cond_signal(ssends->cond);
	mutex_unlock(ssends->lock);
}

static void stratum_add_send(sdata_t *sdata, json_t *val, const int64_t client_id,
			     const int msg_type)
{
	smsg_t *msg;
	ckpool_t *ckp = sdata->ckp;

	if (ckp->node) {
		/* Node shouldn't be sending any messages as it only uses the
		 * stratifier for monitoring activity. */
		json_decref(val);
		return;
	}

	if (passthrough_subclient(client_id))
		json_set_string(val, "node.method", stratum_msgs[msg_type]);
	LOGDEBUG("Sending stratum message %s", stratum_msgs[msg_type]);
	msg = ckzalloc(sizeof(smsg_t));
	msg->json_msg = val;
	msg->client_id = client_id;
	ckmsgq_add(sdata->ssends, msg);
}

static void drop_client(ckpool_t *ckp, sdata_t *sdata, const int64_t id)
{
	char_entry_t *entries = NULL;
	stratum_instance_t *client;
	char *msg;

	LOGINFO("Stratifier asked to drop client %"PRId64, id);

	ck_wlock(&sdata->instance_lock);
	client = __instance_by_id(sdata, id);
	if (client && !client->dropped) {
		__disconnect_session(sdata, client);
		/* If the client is still holding a reference, don't drop them
		 * now but wait till the reference is dropped */
		if (!client->ref) {
			__drop_client(sdata, client, false, &msg);
			add_msg_entry(&entries, &msg);
		} else
			client->dropped = true;
	}
	ck_wunlock(&sdata->instance_lock);

	notice_msg_entries(&entries);
	reap_proxies(ckp, sdata);
}

static void stratum_broadcast_message(sdata_t *sdata, const char *msg)
{
	json_t *json_msg;

	JSON_CPACK(json_msg, "{sosss[s]}", "id", json_null(), "method", "client.show_message",
			     "params", msg);
	stratum_broadcast(sdata, json_msg, SM_MSG);
}

/* Send a generic reconnect to all clients without parameters to make them
 * reconnect to the same server. */
static void request_reconnect(sdata_t *sdata, const char *cmd)
{
	char *port = strdupa(cmd), *url = NULL;
	stratum_instance_t *client, *tmp;
	json_t *json_msg;

	strsep(&port, ":");
	if (port)
		url = strsep(&port, ",");
	if (url && port) {
		JSON_CPACK(json_msg, "{sosss[ssi]}", "id", json_null(), "method", "client.reconnect",
			"params", url, port, 0);
	} else
		JSON_CPACK(json_msg, "{sosss[]}", "id", json_null(), "method", "client.reconnect",
		   "params");
	stratum_broadcast(sdata, json_msg, SM_RECONNECT);

	/* Tag all existing clients as dropped now so they can be removed
	 * lazily */
	ck_wlock(&sdata->instance_lock);
	HASH_ITER(hh, sdata->stratum_instances, client, tmp) {
		client->dropped = true;
	}
	ck_wunlock(&sdata->instance_lock);
}

static void reset_bestshares(sdata_t *sdata)
{
	user_instance_t *user, *tmpuser;
	stratum_instance_t *client, *tmp;

	ck_rlock(&sdata->instance_lock);
	HASH_ITER(hh, sdata->stratum_instances, client, tmp) {
		client->best_diff = 0;
	}
	HASH_ITER(hh, sdata->user_instances, user, tmpuser) {
		worker_instance_t *worker;

		user->best_diff = 0;
		DL_FOREACH(user->worker_instances, worker) {
			worker->best_diff = 0;
		}
	}
	ck_runlock(&sdata->instance_lock);
}

static user_instance_t *get_user(sdata_t *sdata, const char *username);

static user_instance_t *user_by_workername(sdata_t *sdata, const char *workername)
{
	char *username = strdupa(workername), *ignore;
	user_instance_t *user;

	ignore = username;
	strsep(&ignore, "._");

	/* Find the user first */
	user = get_user(sdata, username);
	return user;
}

static worker_instance_t *get_worker(sdata_t *sdata, user_instance_t *user, const char *workername);

static json_t *worker_stats(const worker_instance_t *worker)
{
	char suffix1[16], suffix5[16], suffix60[16], suffix1440[16], suffix10080[16];
	json_t *val;
	double ghs;

	ghs = worker->dsps1 * nonces;
	suffix_string(ghs, suffix1, 16, 0);

	ghs = worker->dsps5 * nonces;
	suffix_string(ghs, suffix5, 16, 0);

	ghs = worker->dsps60 * nonces;
	suffix_string(ghs, suffix60, 16, 0);

	ghs = worker->dsps1440 * nonces;
	suffix_string(ghs, suffix1440, 16, 0);

	ghs = worker->dsps10080 * nonces;
	suffix_string(ghs, suffix10080, 16, 0);

	JSON_CPACK(val, "{ss,ss,ss,ss,ss}",
			"hashrate1m", suffix1,
			"hashrate5m", suffix5,
			"hashrate1hr", suffix60,
			"hashrate1d", suffix1440,
			"hashrate7d", suffix10080);
	return val;
}

static json_t *user_stats(const user_instance_t *user)
{
	char suffix1[16], suffix5[16], suffix60[16], suffix1440[16], suffix10080[16];
	json_t *val;
	double ghs;

	ghs = user->dsps1 * nonces;
	suffix_string(ghs, suffix1, 16, 0);

	ghs = user->dsps5 * nonces;
	suffix_string(ghs, suffix5, 16, 0);

	ghs = user->dsps60 * nonces;
	suffix_string(ghs, suffix60, 16, 0);

	ghs = user->dsps1440 * nonces;
	suffix_string(ghs, suffix1440, 16, 0);

	ghs = user->dsps10080 * nonces;
	suffix_string(ghs, suffix10080, 16, 0);

	JSON_CPACK(val, "{ss,ss,ss,ss,ss}",
			"hashrate1m", suffix1,
			"hashrate5m", suffix5,
			"hashrate1hr", suffix60,
			"hashrate1d", suffix1440,
			"hashrate7d", suffix10080);
	return val;
}

static void block_solve(ckpool_t *ckp, const char *blockhash)
{
	ckmsg_t *block, *tmp, *found = NULL;
	char *msg, *workername = NULL;
	sdata_t *sdata = ckp->data;
	char cdfield[64];
	int height = 0;
	ts_t ts_now;
	json_t *val;

	if (!ckp->node)
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
			json_get_string(&workername, val, "workername");
			found = block;
			DL_DELETE(sdata->block_solves, block);
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

	if (unlikely(!workername)) {
		/* This should be impossible! */
		ASPRINTF(&msg, "Block %d solved by %s!", height, ckp->name);
		LOGWARNING("Solved and confirmed block %d", height);
	} else {
		json_t *user_val, *worker_val;
		worker_instance_t *worker;
		user_instance_t *user;
		char *s;

		ASPRINTF(&msg, "Block %d solved by %s @ %s!", height, workername, ckp->name);
		LOGWARNING("Solved and confirmed block %d by %s", height, workername);
		user = user_by_workername(sdata, workername);
		worker = get_worker(sdata, user, workername);

		ck_rlock(&sdata->instance_lock);
		user_val = user_stats(user);
		worker_val = worker_stats(worker);
		ck_runlock(&sdata->instance_lock);

		s = json_dumps(user_val, JSON_NO_UTF8 | JSON_PRESERVE_ORDER);
		json_decref(user_val);
		LOGWARNING("User %s:%s", user->username, s);
		dealloc(s);
		s = json_dumps(worker_val, JSON_NO_UTF8 | JSON_PRESERVE_ORDER);
		json_decref(worker_val);
		LOGWARNING("Worker %s:%s", workername, s);
		dealloc(s);
	}
	stratum_broadcast_message(sdata, msg);
	free(msg);

	free(workername);

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
			DL_DELETE(sdata->block_solves, block);
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

	stratum_broadcast(sdata, json_msg, SM_PING);
}

static void ckmsgq_stats(ckmsgq_t *ckmsgq, const int size, json_t **val)
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

static char *stratifier_stats(ckpool_t *ckp, sdata_t *sdata)
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
	memsize = SAFE_HASH_OVERHEAD(sdata->disconnected_sessions);
	memsize += sizeof(session_t) * sdata->stats.disconnected;
	JSON_CPACK(subval, "{si,si,si}", "count", objects, "memory", memsize, "generated", generated);
	json_set_object(val, "disconnected", subval);
	ck_runlock(&sdata->instance_lock);

	mutex_lock(&sdata->share_lock);
	generated = sdata->shares_generated;
	objects = HASH_COUNT(sdata->shares);
	memsize = SAFE_HASH_OVERHEAD(sdata->shares) + sizeof(share_t) * objects;
	mutex_unlock(&sdata->share_lock);

	JSON_CPACK(subval, "{si,si,si}", "count", objects, "memory", memsize, "generated", generated);
	json_set_object(val, "shares", subval);

	ckmsgq_stats(sdata->ssends, sizeof(smsg_t), &subval);
	json_set_object(val, "ssends", subval);
	/* Don't know exactly how big the string is so just count the pointer for now */
	ckmsgq_stats(sdata->srecvs, sizeof(char *), &subval);
	json_set_object(val, "srecvs", subval);
	if (!CKP_STANDALONE(ckp)) {
		ckmsgq_stats(sdata->ckdbq, sizeof(char *), &subval);
		json_set_object(val, "ckdbq", subval);
	}
	ckmsgq_stats(sdata->stxnq, sizeof(json_params_t), &subval);
	json_set_object(val, "stxnq", subval);

	buf = json_dumps(val, JSON_NO_UTF8 | JSON_PRESERVE_ORDER);
	json_decref(val);
	LOGNOTICE("Stratifier stats: %s", buf);
	return buf;
}

/* Send a single client a reconnect request, setting the time we sent the
 * request so we can drop the client lazily if it hasn't reconnected on its
 * own more than one minute later if we call reconnect again */
static void reconnect_client(sdata_t *sdata, stratum_instance_t *client)
{
	json_t *json_msg;

	/* Already requested? */
	if (client->reconnect_request) {
		if (time(NULL) - client->reconnect_request >= 60)
			connector_drop_client(sdata->ckp, client->id);
		return;
	}
	client->reconnect_request = time(NULL);
	JSON_CPACK(json_msg, "{sosss[]}", "id", json_null(), "method", "client.reconnect",
		   "params");
	stratum_add_send(sdata, json_msg, client->id, SM_RECONNECT);
}

static void dead_proxy(sdata_t *sdata, const char *buf)
{
	int id = 0, subid = 0;

	sscanf(buf, "deadproxy=%d:%d", &id, &subid);
	dead_proxyid(sdata, id, subid, false);
}

static void reconnect_client_id(sdata_t *sdata, const int64_t client_id)
{
	stratum_instance_t *client;

	client = ref_instance_by_id(sdata, client_id);
	if (!client) {
		LOGINFO("reconnect_client_id failed to find client %"PRId64, client_id);
		return;
	}
	client->reconnect = true;
	reconnect_client(sdata, client);
	dec_instance_ref(sdata, client);
}

/* API commands */

static user_instance_t *get_user(sdata_t *sdata, const char *username);

static json_t *userinfo(const user_instance_t *user)
{
	json_t *val;

	JSON_CPACK(val, "{ss,si,si,sf,sf,sf,sf,sf,sf,si}",
		   "user", user->username, "id", user->id, "workers", user->workers,
	    "bestdiff", user->best_diff, "dsps1", user->dsps1, "dsps5", user->dsps5,
	    "dsps60", user->dsps60, "dsps1440", user->dsps1440, "dsps10080", user->dsps10080,
	    "lastshare", user->last_share.tv_sec);
	return val;
}

static void getuser(sdata_t *sdata, const char *buf, int *sockd)
{
	char *username = NULL;
	user_instance_t *user;
	json_error_t err_val;
	json_t *val = NULL;

	val = json_loads(buf, 0, &err_val);
	if (unlikely(!val)) {
		val = json_encode_errormsg(&err_val);
		goto out;
	}
	if (!json_get_string(&username, val, "user")) {
		val = json_errormsg("Failed to find user key");
		goto out;
	}
	if (!strlen(username)) {
		val = json_errormsg("Zero length user key");
		goto out;
	}
	user = get_user(sdata, username);
	val = userinfo(user);
out:
	free(username);
	send_api_response(val, *sockd);
	_Close(sockd);
}

static void userclients(sdata_t *sdata, const char *buf, int *sockd)
{
	json_t *val = NULL, *client_arr;
	stratum_instance_t *client;
	char *username = NULL;
	user_instance_t *user;
	json_error_t err_val;

	val = json_loads(buf, 0, &err_val);
	if (unlikely(!val)) {
		val = json_encode_errormsg(&err_val);
		goto out;
	}
	if (!json_get_string(&username, val, "user")) {
		val = json_errormsg("Failed to find user key");
		goto out;
	}
	if (!strlen(username)) {
		val = json_errormsg("Zero length user key");
		goto out;
	}
	user = get_user(sdata, username);
	client_arr = json_array();

	ck_rlock(&sdata->instance_lock);
	DL_FOREACH(user->clients, client) {
		json_array_append_new(client_arr, json_integer(client->id));
	}
	ck_runlock(&sdata->instance_lock);

	JSON_CPACK(val, "{ss,so}", "user", username, "clients", client_arr);
out:
	free(username);
	send_api_response(val, *sockd);
	_Close(sockd);
}

static void workerclients(sdata_t *sdata, const char *buf, int *sockd)
{
	char *tmp, *username, *workername = NULL;
	json_t *val = NULL, *client_arr;
	stratum_instance_t *client;
	user_instance_t *user;
	json_error_t err_val;

	val = json_loads(buf, 0, &err_val);
	if (unlikely(!val)) {
		val = json_encode_errormsg(&err_val);
		goto out;
	}
	if (!json_get_string(&workername, val, "worker")) {
		val = json_errormsg("Failed to find worker key");
		goto out;
	}
	if (!strlen(workername)) {
		val = json_errormsg("Zero length worker key");
		goto out;
	}
	tmp = strdupa(workername);
	username = strsep(&tmp, "._");
	user = get_user(sdata, username);
	client_arr = json_array();

	ck_rlock(&sdata->instance_lock);
	DL_FOREACH(user->clients, client) {
		if (strcmp(client->workername, workername))
			continue;
		json_array_append_new(client_arr, json_integer(client->id));
	}
	ck_runlock(&sdata->instance_lock);

	JSON_CPACK(val, "{ss,so}", "worker", workername, "clients", client_arr);
out:
	free(workername);
	send_api_response(val, *sockd);
	_Close(sockd);
}

static worker_instance_t *get_worker(sdata_t *sdata, user_instance_t *user, const char *workername);

static json_t *workerinfo(const user_instance_t *user, const worker_instance_t *worker)
{
	json_t *val;

	JSON_CPACK(val, "{ss,ss,si,sf,sf,sf,sf,si,sf,si,sb}",
		   "user", user->username, "worker", worker->workername, "id", user->id,
	    "dsps1", worker->dsps1, "dsps5", worker->dsps5, "dsps60", worker->dsps60,
	    "dsps1440", worker->dsps1440, "lastshare", worker->last_share.tv_sec,
	    "bestdiff", worker->best_diff, "mindiff", worker->mindiff, "idle", worker->idle);
	return val;
}

static void getworker(sdata_t *sdata, const char *buf, int *sockd)
{
	char *tmp, *username, *workername = NULL;
	worker_instance_t *worker;
	user_instance_t *user;
	json_error_t err_val;
	json_t *val = NULL;

	val = json_loads(buf, 0, &err_val);
	if (unlikely(!val)) {
		val = json_encode_errormsg(&err_val);
		goto out;
	}
	if (!json_get_string(&workername, val, "worker")) {
		val = json_errormsg("Failed to find worker key");
		goto out;
	}
	if (!strlen(workername)) {
		val = json_errormsg("Zero length worker key");
		goto out;
	}
	tmp = strdupa(workername);
	username = strsep(&tmp, "._");
	user = get_user(sdata, username);
	worker = get_worker(sdata, user, workername);
	val = workerinfo(user, worker);
out:
	free(workername);
	send_api_response(val, *sockd);
	_Close(sockd);
}

static void getworkers(sdata_t *sdata, int *sockd)
{
	json_t *val = NULL, *worker_arr;
	worker_instance_t *worker;
	user_instance_t *user;

	worker_arr = json_array();

	ck_rlock(&sdata->instance_lock);
	for (user = sdata->user_instances; user; user = user->hh.next) {
		DL_FOREACH(user->worker_instances, worker) {
			json_array_append_new(worker_arr, workerinfo(user, worker));
		}
	}
	ck_runlock(&sdata->instance_lock);

	JSON_CPACK(val, "{so}", "workers", worker_arr);
	send_api_response(val, *sockd);
	_Close(sockd);
}

static void getusers(sdata_t *sdata, int *sockd)
{
	json_t *val = NULL, *user_array;
	user_instance_t *user;

	user_array = json_array();

	ck_rlock(&sdata->instance_lock);
	for (user = sdata->user_instances; user; user = user->hh.next) {
		json_array_append_new(user_array, userinfo(user));
	}
	ck_runlock(&sdata->instance_lock);

	JSON_CPACK(val, "{so}", "users", user_array);
	send_api_response(val, *sockd);
	_Close(sockd);
}

static json_t *clientinfo(const stratum_instance_t *client)
{
	json_t *val = json_object();

	/* Too many fields for a pack object, do each discretely to keep track */
	json_set_int(val, "id", client->id);
	json_set_string(val, "enonce1", client->enonce1);
	json_set_string(val, "enonce1var", client->enonce1var);
	json_set_int(val, "enonce1_64", client->enonce1_64);
	json_set_double(val, "diff", client->diff);
	json_set_double(val, "dsps1", client->dsps1);
	json_set_double(val, "dsps5", client->dsps5);
	json_set_double(val, "dsps60", client->dsps60);
	json_set_double(val, "dsps1440", client->dsps1440);
	json_set_double(val, "dsps10080", client->dsps10080);
	json_set_int(val, "lastshare", client->last_share.tv_sec);
	json_set_int(val, "starttime", client->start_time);
	json_set_string(val, "address", client->address);
	json_set_bool(val, "subscribed", client->subscribed);
	json_set_bool(val, "authorised", client->authorised);
	json_set_bool(val, "idle", client->idle);
	json_set_string(val, "useragent", client->useragent ? client->useragent : "");
	json_set_string(val, "workername", client->workername ? client->workername : "");
	json_set_int(val, "userid", client->user_id);
	json_set_int(val, "server", client->server);
	json_set_double(val, "bestdiff", client->best_diff);
	json_set_int(val, "proxyid", client->proxyid);
	json_set_int(val, "subproxyid", client->subproxyid);
	return val;
}

static void getclient(sdata_t *sdata, const char *buf, int *sockd)
{
	stratum_instance_t *client;
	json_error_t err_val;
	json_t *val = NULL;
	int64_t client_id;

	val = json_loads(buf, 0, &err_val);
	if (unlikely(!val)) {
		val = json_encode_errormsg(&err_val);
		goto out;
	}
	if (!json_get_int64(&client_id, val, "id")) {
		val = json_errormsg("Failed to find id key");
		goto out;
	}
	client = ref_instance_by_id(sdata, client_id);
	if (!client) {
		val = json_errormsg("Failed to find client %"PRId64, client_id);
		goto out;
	}
	val = clientinfo(client);

	dec_instance_ref(sdata, client);
out:
	send_api_response(val, *sockd);
	_Close(sockd);
}

static void getclients(sdata_t *sdata, int *sockd)
{
	json_t *val = NULL, *client_arr;
	stratum_instance_t *client;

	client_arr = json_array();

	ck_rlock(&sdata->instance_lock);
	for (client = sdata->stratum_instances; client; client = client->hh.next) {
		json_array_append_new(client_arr, clientinfo(client));
	}
	ck_runlock(&sdata->instance_lock);

	JSON_CPACK(val, "{so}", "clients", client_arr);
	send_api_response(val, *sockd);
	_Close(sockd);
}

static void user_clientinfo(sdata_t *sdata, const char *buf, int *sockd)
{
	json_t *val = NULL, *client_arr;
	stratum_instance_t *client;
	char *username = NULL;
	user_instance_t *user;
	json_error_t err_val;

	val = json_loads(buf, 0, &err_val);
	if (unlikely(!val)) {
		val = json_encode_errormsg(&err_val);
		goto out;
	}
	if (!json_get_string(&username, val, "user")) {
		val = json_errormsg("Failed to find user key");
		goto out;
	}
	if (!strlen(username)) {
		val = json_errormsg("Zero length user key");
		goto out;
	}
	user = get_user(sdata, username);
	client_arr = json_array();

	ck_rlock(&sdata->instance_lock);
	DL_FOREACH(user->clients, client) {
		json_array_append_new(client_arr, clientinfo(client));
	}
	ck_runlock(&sdata->instance_lock);

	JSON_CPACK(val, "{ss,so}", "user", username, "clients", client_arr);
out:
	free(username);
	send_api_response(val, *sockd);
	_Close(sockd);
}

static void worker_clientinfo(sdata_t *sdata, const char *buf, int *sockd)
{
	char *tmp, *username, *workername = NULL;
	json_t *val = NULL, *client_arr;
	stratum_instance_t *client;
	user_instance_t *user;
	json_error_t err_val;

	val = json_loads(buf, 0, &err_val);
	if (unlikely(!val)) {
		val = json_encode_errormsg(&err_val);
		goto out;
	}
	if (!json_get_string(&workername, val, "worker")) {
		val = json_errormsg("Failed to find worker key");
		goto out;
	}
	if (!strlen(workername)) {
		val = json_errormsg("Zero length worker key");
		goto out;
	}
	tmp = strdupa(workername);
	username = strsep(&tmp, "._");
	user = get_user(sdata, username);
	client_arr = json_array();

	ck_rlock(&sdata->instance_lock);
	DL_FOREACH(user->clients, client) {
		if (strcmp(client->workername, workername))
			continue;
		json_array_append_new(client_arr, clientinfo(client));
	}
	ck_runlock(&sdata->instance_lock);

	JSON_CPACK(val, "{ss,so}", "worker", workername, "clients", client_arr);
out:
	free(workername);
	send_api_response(val, *sockd);
	_Close(sockd);
}

/* Return the user masked priority value of the proxy */
static int proxy_prio(const proxy_t *proxy)
{
	int prio = proxy->priority & 0x00000000ffffffff;

	return prio;
}

static json_t *json_proxyinfo(const proxy_t *proxy)
{
	const proxy_t *parent = proxy->parent;
	json_t *val;

	JSON_CPACK(val, "{si,si,si,sf,ss,ss,ss,ss,si,si,si,si,sb,sb,sI,sI,sI,sI,si,si,sb,sb,si}",
	    "id", proxy->id, "subid", proxy->subid, "priority", proxy_prio(parent),
	    "diff", proxy->diff, "url", proxy->url, "auth", proxy->auth, "pass", proxy->pass,
	    "enonce1", proxy->enonce1, "enonce1constlen", proxy->enonce1constlen,
	    "enonce1varlen", proxy->enonce1varlen, "nonce2len", proxy->nonce2len,
	    "enonce2varlen", proxy->enonce2varlen, "subscribed", proxy->subscribed,
	    "notified", proxy->notified, "clients", proxy->clients, "maxclients", proxy->max_clients,
	    "bound_clients", proxy->bound_clients, "combined_clients", parent->combined_clients,
	    "headroom", proxy->headroom, "subproxy_count", parent->subproxy_count,
	    "dead", proxy->dead, "global", proxy->global, "userid", proxy->userid);
	return val;
}

static void getproxy(sdata_t *sdata, const char *buf, int *sockd)
{
	json_error_t err_val;
	json_t *val = NULL;
	int id, subid = 0;
	proxy_t *proxy;

	val = json_loads(buf, 0, &err_val);
	if (unlikely(!val)) {
		val = json_encode_errormsg(&err_val);
		goto out;
	}
	if (!json_get_int(&id, val, "id")) {
		val = json_errormsg("Failed to find id key");
		goto out;
	}
	json_get_int(&subid, val, "subid");
	if (!subid)
		proxy = existing_proxy(sdata, id);
	else
		proxy = existing_subproxy(sdata, id, subid);
	if (!proxy) {
		val = json_errormsg("Failed to find proxy %d:%d", id, subid);
		goto out;
	}
	val = json_proxyinfo(proxy);
out:
	send_api_response(val, *sockd);
	_Close(sockd);
}

static void proxyinfo(sdata_t *sdata, const char *buf, int *sockd)
{
	json_t *val = NULL, *arr_val = json_array();
	proxy_t *proxy, *subproxy;
	bool all = true;
	int userid = 0;

	if (buf) {
		/* See if there's a userid specified */
		val = json_loads(buf, 0, NULL);
		if (json_get_int(&userid, val, "userid"))
			all = false;
	}

	mutex_lock(&sdata->proxy_lock);
	for (proxy = sdata->proxies; proxy; proxy = proxy->hh.next) {
		if (!all && proxy->userid != userid)
			continue;
		for (subproxy = proxy->subproxies; subproxy; subproxy = subproxy->sh.next)
			json_array_append_new(arr_val, json_proxyinfo(subproxy));
	}
	mutex_unlock(&sdata->proxy_lock);

	JSON_CPACK(val, "{so}", "proxies", arr_val);
	send_api_response(val, *sockd);
	_Close(sockd);
}

static void setproxy(sdata_t *sdata, const char *buf, int *sockd)
{
	json_error_t err_val;
	json_t *val = NULL;
	int id, priority;
	proxy_t *proxy;

	val = json_loads(buf, 0, &err_val);
	if (unlikely(!val)) {
		val = json_encode_errormsg(&err_val);
		goto out;
	}
	if (!json_get_int(&id, val, "id")) {
		val = json_errormsg("Failed to find id key");
		goto out;
	}
	if (!json_get_int(&priority, val, "priority")) {
		val = json_errormsg("Failed to find priority key");
		goto out;
	}
	proxy = existing_proxy(sdata, id);
	if (!proxy) {
		val = json_errormsg("Failed to find proxy %d", id);
		goto out;
	}
	if (priority != proxy_prio(proxy))
		set_proxy_prio(sdata, proxy, priority);
	val = json_proxyinfo(proxy);
out:
	send_api_response(val, *sockd);
	_Close(sockd);
}

static void get_poolstats(sdata_t *sdata, int *sockd)
{
	pool_stats_t *stats = &sdata->stats;
	json_t *val;

	mutex_lock(&sdata->stats_lock);
	JSON_CPACK(val, "{si,si,si,si,si,sI,sf,sf,sf,sf,sI,sI,sf,sf,sf,sf,sf,sf,sf}",
		   "start", stats->start_time.tv_sec, "update", stats->last_update.tv_sec,
	    "workers", stats->workers, "users", stats->users, "disconnected", stats->disconnected,
	    "shares", stats->accounted_shares, "sps1", stats->sps1, "sps5", stats->sps5,
	    "sps15", stats->sps15, "sps60", stats->sps60, "accepted", stats->accounted_diff_shares,
	    "rejected", stats->accounted_rejects, "dsps1", stats->dsps1, "dsps5", stats->dsps5,
	    "dsps15", stats->dsps15, "dsps60", stats->dsps60, "dsps360", stats->dsps360,
	    "dsps1440", stats->dsps1440, "dsps10080", stats->dsps10080);
	mutex_unlock(&sdata->stats_lock);

	send_api_response(val, *sockd);
	_Close(sockd);
}

static void srecv_process(ckpool_t *ckp, char *buf);

static int stratum_loop(ckpool_t *ckp, proc_instance_t *pi)
{
	sdata_t *sdata = ckp->data;
	unix_msg_t *umsg = NULL;
	int ret = 0;
	char *buf;

retry:
	if (umsg) {
		free(umsg->buf);
		dealloc(umsg);
	}

	do {
		time_t end_t;

		end_t = time(NULL);
		if (end_t - sdata->update_time >= ckp->update_interval) {
			sdata->update_time = end_t;
			if (!ckp->proxy) {
				LOGDEBUG("%ds elapsed in strat_loop, updating gbt base",
					 ckp->update_interval);
				update_base(ckp, GEN_NORMAL);
			} else if (!ckp->passthrough) {
				LOGDEBUG("%ds elapsed in strat_loop, pinging miners",
					 ckp->update_interval);
				broadcast_ping(sdata);
			}
		}

		umsg = get_unix_msg(pi);
		if (unlikely(!umsg &&!ping_main(ckp))) {
			LOGEMERG("Stratifier failed to ping main process, exiting");
			ret = 1;
			goto out;
		}
	} while (!umsg);

	buf = umsg->buf;
	if (likely(buf[0] == '{')) {
		/* The bulk of the messages will be received json from the
		 * connector so look for this first. The srecv_process frees
		 * the buf heap ram */
		Close(umsg->sockd);
		ckmsgq_add(sdata->srecvs, umsg->buf);
		umsg->buf = NULL;
		goto retry;
	}
	if (cmdmatch(buf, "ping")) {
		LOGDEBUG("Stratifier received ping request");
		send_unix_msg(umsg->sockd, "pong");
		Close(umsg->sockd);
		goto retry;
	}
	if (cmdmatch(buf, "stats")) {
		char *msg;

		LOGDEBUG("Stratifier received stats request");
		msg = stratifier_stats(ckp, sdata);
		send_unix_msg(umsg->sockd, msg);
		Close(umsg->sockd);
		goto retry;
	}
	/* Parse API commands here to return a message to sockd */
	if (cmdmatch(buf, "clients")) {
		getclients(sdata, &umsg->sockd);
		goto retry;
	}
	if (cmdmatch(buf, "workers")) {
		getworkers(sdata, &umsg->sockd);
		goto retry;
	}
	if (cmdmatch(buf, "users")) {
		getusers(sdata, &umsg->sockd);
		goto retry;
	}
	if (cmdmatch(buf, "getclient")) {
		getclient(sdata, buf + 10, &umsg->sockd);
		goto retry;
	}
	if (cmdmatch(buf, "getuser")) {
		getuser(sdata, buf + 8, &umsg->sockd);
		goto retry;
	}
	if (cmdmatch(buf, "getworker")) {
		getworker(sdata, buf + 10, &umsg->sockd);
		goto retry;
	}
	if (cmdmatch(buf, "userclients")) {
		userclients(sdata, buf + 12, &umsg->sockd);
		goto retry;
	}
	if (cmdmatch(buf, "workerclients")) {
		workerclients(sdata, buf + 14, &umsg->sockd);
		goto retry;
	}
	if (cmdmatch(buf, "getproxy")) {
		getproxy(sdata, buf + 9, &umsg->sockd);
		goto retry;
	}
	if (cmdmatch(buf, "setproxy")) {
		setproxy(sdata, buf + 9, &umsg->sockd);
		goto retry;
	}
	if (cmdmatch(buf, "poolstats")) {
		get_poolstats(sdata, &umsg->sockd);
		goto retry;
	}
	if (cmdmatch(buf, "proxyinfo")) {
		proxyinfo(sdata, buf + 10, &umsg->sockd);
		goto retry;
	}
	if (cmdmatch(buf, "ucinfo")) {
		user_clientinfo(sdata, buf + 7, &umsg->sockd);
		goto retry;
	}
	if (cmdmatch(buf, "wcinfo")) {
		worker_clientinfo(sdata, buf + 7, &umsg->sockd);
		goto retry;
	}

	Close(umsg->sockd);
	LOGDEBUG("Stratifier received request: %s", buf);
	if (cmdmatch(buf, "shutdown")) {
		ret = 0;
		goto out;
	} else if (cmdmatch(buf, "update")) {
		update_base(ckp, GEN_PRIORITY);
	} else if (cmdmatch(buf, "subscribe")) {
		/* Proxifier has a new subscription */
		update_subscribe(ckp, buf);
	} else if (cmdmatch(buf, "notify")) {
		/* Proxifier has a new notify ready */
		update_notify(ckp, buf);
	} else if (cmdmatch(buf, "diff")) {
		update_diff(ckp, buf);
	} else if (cmdmatch(buf, "dropclient")) {
		int64_t client_id;

		ret = sscanf(buf, "dropclient=%"PRId64, &client_id);
		if (ret < 0)
			LOGDEBUG("Stratifier failed to parse dropclient command: %s", buf);
		else
			drop_client(ckp, sdata, client_id);
	} else if (cmdmatch(buf, "reconnclient")) {
		int64_t client_id;

		ret = sscanf(buf, "reconnclient=%"PRId64, &client_id);
		if (ret < 0)
			LOGWARNING("Stratifier failed to parse reconnclient command: %s", buf);
		else
			reconnect_client_id(sdata, client_id);
	} else if (cmdmatch(buf, "dropall")) {
		drop_allclients(ckp);
	} else if (cmdmatch(buf, "block")) {
		block_solve(ckp, buf + 6);
	} else if (cmdmatch(buf, "noblock")) {
		block_reject(sdata, buf + 8);
	} else if (cmdmatch(buf, "reconnect")) {
		request_reconnect(sdata, buf);
	} else if (cmdmatch(buf, "deadproxy")) {
		dead_proxy(sdata, buf);
	} else if (cmdmatch(buf, "loglevel")) {
		sscanf(buf, "loglevel=%d", &ckp->loglevel);
	} else
		LOGWARNING("Unhandled stratifier message: %s", buf);
	goto retry;

out:
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

/* Enter holding workbase_lock and client a ref count. */
static void __fill_enonce1data(const workbase_t *wb, stratum_instance_t *client)
{
	if (wb->enonce1constlen)
		memcpy(client->enonce1bin, wb->enonce1constbin, wb->enonce1constlen);
	if (wb->enonce1varlen) {
		memcpy(client->enonce1bin + wb->enonce1constlen, &client->enonce1_64, wb->enonce1varlen);
		__bin2hex(client->enonce1var, &client->enonce1_64, wb->enonce1varlen);
	}
	__bin2hex(client->enonce1, client->enonce1bin, wb->enonce1constlen + wb->enonce1varlen);
}

/* Create a new enonce1 from the 64 bit enonce1_64 value, using only the number
 * of bytes we have to work with when we are proxying with a split nonce2.
 * When the proxy space is less than 32 bits to work with, we look for an
 * unused enonce1 value and reject clients instead if there is no space left.
 * Needs to be entered with client holding a ref count. */
static bool new_enonce1(ckpool_t *ckp, sdata_t *ckp_sdata, sdata_t *sdata, stratum_instance_t *client)
{
	proxy_t *proxy = NULL;
	uint64_t enonce1;

	if (ckp->proxy) {
		if (!ckp_sdata->proxy)
			return false;

		mutex_lock(&ckp_sdata->proxy_lock);
		proxy = sdata->subproxy;
		client->proxyid = proxy->id;
		client->subproxyid = proxy->subid;
		mutex_unlock(&ckp_sdata->proxy_lock);

		if (proxy->clients >= proxy->max_clients) {
			LOGWARNING("Proxy reached max clients %"PRId64, proxy->max_clients);
			return false;
		}
	}

	/* instance_lock protects enonce1_64. Incrementing a little endian 64bit
	 * number ensures that no matter how many of the bits we take from the
	 * left depending on nonce2 length, we'll always get a changing value
	 * for every next client.*/
	ck_wlock(&ckp_sdata->instance_lock);
	enonce1 = le64toh(ckp_sdata->enonce1_64);
	enonce1++;
	client->enonce1_64 = ckp_sdata->enonce1_64 = htole64(enonce1);
	if (proxy) {
		client->proxy = proxy;
		proxy->clients++;
		proxy->bound_clients++;
		proxy->parent->combined_clients++;
	}
	ck_wunlock(&ckp_sdata->instance_lock);

	ck_rlock(&sdata->workbase_lock);
	__fill_enonce1data(sdata->current_workbase, client);
	ck_runlock(&sdata->workbase_lock);

	return true;
}

static void stratum_send_message(sdata_t *sdata, const stratum_instance_t *client, const char *msg);

/* Need to hold sdata->proxy_lock */
static proxy_t *__best_subproxy(proxy_t *proxy)
{
	proxy_t *subproxy, *best = NULL, *tmp;
	int64_t max_headroom;

	proxy->headroom = max_headroom = 0;
	HASH_ITER(sh, proxy->subproxies, subproxy, tmp) {
		int64_t subproxy_headroom;

		if (subproxy->dead)
			continue;
		if (!subproxy->sdata->current_workbase)
			continue;
		subproxy_headroom = subproxy->max_clients - subproxy->clients;

		proxy->headroom += subproxy_headroom;
		if (subproxy_headroom > max_headroom) {
			best = subproxy;
			max_headroom = subproxy_headroom;
		}
		if (best)
			break;
	}
	return best;
}

/* Choose the stratifier data for a new client. Use the main ckp_sdata except
 * in proxy mode where we find a subproxy based on the current proxy with room
 * for more clients. Signal the generator to recruit more subproxies if we are
 * running out of room. */
static sdata_t *select_sdata(const ckpool_t *ckp, sdata_t *ckp_sdata, const int userid)
{
	proxy_t *current, *proxy, *tmp, *best = NULL;

	if (!ckp->proxy || ckp->passthrough)
		return ckp_sdata;
	current = ckp_sdata->proxy;
	if (!current) {
		LOGWARNING("No proxy available yet to generate subscribes");
		return NULL;
	}

	/* Proxies are ordered by priority so first available will be the best
	 * priority */
	mutex_lock(&ckp_sdata->proxy_lock);
	HASH_ITER(hh, ckp_sdata->proxies, proxy, tmp) {
		if (proxy->userid < userid)
			continue;
		if (proxy->userid > userid)
			break;
		best = __best_subproxy(proxy);
		if (best)
			break;
	}
	mutex_unlock(&ckp_sdata->proxy_lock);

	if (!best) {
		if (!userid)
			LOGWARNING("Temporarily insufficient subproxies to accept more clients");
		return NULL;
	}
	if (!userid) {
		if (best->id != current->id || current_headroom(ckp_sdata, &proxy) < 2)
			generator_recruit(ckp, current->id, 1);
	} else {
		if (proxy_headroom(ckp_sdata, userid) < 2)
			generator_recruit(ckp, best->id, 1);
	}
	return best->sdata;
}

static int int_from_sessionid(const char *sessionid)
{
	int ret = 0, slen;

	if (!sessionid)
		goto out;
	slen = strlen(sessionid) / 2;
	if (slen < 1 || slen > 4)
		goto out;

	if (!validhex(sessionid))
		goto out;

	sscanf(sessionid, "%x", &ret);
out:
	return ret;
}

static int userid_from_sessionid(sdata_t *sdata, const int session_id)
{
	session_t *session;
	int ret = -1;

	ck_wlock(&sdata->instance_lock);
	HASH_FIND_INT(sdata->disconnected_sessions, &session_id, session);
	if (!session)
		goto out_unlock;
	HASH_DEL(sdata->disconnected_sessions, session);
	sdata->stats.disconnected--;
	ret = session->userid;
	dealloc(session);
out_unlock:
	ck_wunlock(&sdata->instance_lock);

	if (ret != -1)
		LOGINFO("Found old session id %d for userid %d", session_id, ret);
	return ret;
}

static int userid_from_sessionip(sdata_t *sdata, const char *address)
{
	session_t *session, *tmp;
	int ret = -1;

	ck_wlock(&sdata->instance_lock);
	HASH_ITER(hh, sdata->disconnected_sessions, session, tmp) {
		if (!strcmp(session->address, address)) {
			ret = session->userid;
			break;
		}
	}
	if (ret == -1)
		goto out_unlock;
	HASH_DEL(sdata->disconnected_sessions, session);
	sdata->stats.disconnected--;
	dealloc(session);
out_unlock:
	ck_wunlock(&sdata->instance_lock);

	if (ret != -1)
		LOGINFO("Found old session address %s for userid %d", address, ret);
	return ret;
}

/* Extranonce1 must be set here. Needs to be entered with client holding a ref
 * count. */
static json_t *parse_subscribe(stratum_instance_t *client, const int64_t client_id, const json_t *params_val)
{
	ckpool_t *ckp = client->ckp;
	sdata_t *sdata, *ckp_sdata = ckp->data;
	int session_id = 0, userid = -1;
	bool old_match = false;
	char sessionid[12];
	int arr_size;
	json_t *ret;
	int n2len;

	if (unlikely(!json_is_array(params_val))) {
		stratum_send_message(ckp_sdata, client, "Invalid json: params not an array");
		return json_string("params not an array");
	}

	sdata = select_sdata(ckp, ckp_sdata, 0);
	if (unlikely(!ckp->node && (!sdata || !sdata->current_workbase))) {
		LOGWARNING("Failed to provide subscription due to no %s", sdata ? "current workbase" : "sdata");
		stratum_send_message(ckp_sdata, client, "Pool Initialising");
		return json_string("Initialising");
	}

	arr_size = json_array_size(params_val);
	/* NOTE useragent is NULL prior to this so should not be used in code
	 * till after this point */
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
			session_id = int_from_sessionid(buf);
			LOGDEBUG("Found old session id %d", session_id);
		}
		if (!ckp->proxy && session_id && !passthrough_subclient(client_id)) {
			if ((client->enonce1_64 = disconnected_sessionid_exists(sdata, session_id, client_id))) {
				sprintf(client->enonce1, "%016lx", client->enonce1_64);
				old_match = true;

				ck_rlock(&ckp_sdata->workbase_lock);
				__fill_enonce1data(sdata->current_workbase, client);
				ck_runlock(&ckp_sdata->workbase_lock);
			}
		}
	} else
		client->useragent = ckzalloc(1);

	/* We got what we needed */
	if (ckp->node)
		return NULL;

	if (ckp->proxy) {
		/* Use the session_id to tell us which user this was.
			* If it's not available, see if there's an IP address
			* which matches a recently disconnected session. */
		if (session_id)
			userid = userid_from_sessionid(ckp_sdata, session_id);
		if (userid == -1)
			userid = userid_from_sessionip(ckp_sdata, client->address);
		if (userid != -1) {
			sdata_t *user_sdata = select_sdata(ckp, ckp_sdata, userid);

			if (user_sdata)
				sdata = user_sdata;
		}
	}

	client->sdata = sdata;
	if (ckp->proxy) {
		LOGINFO("Current %d, selecting proxy %d:%d for client %"PRId64, ckp_sdata->proxy->id,
			sdata->subproxy->id, sdata->subproxy->subid, client->id);
	}

	if (!old_match) {
		/* Create a new extranonce1 based on a uint64_t pointer */
		if (!new_enonce1(ckp, ckp_sdata, sdata, client)) {
			stratum_send_message(sdata, client, "Pool full of clients");
			client->reject = 3;
			return json_string("proxy full");
		}
		LOGINFO("Set new subscription %"PRId64" to new enonce1 %lx string %s", client->id,
			client->enonce1_64, client->enonce1);
	} else {
		LOGINFO("Set new subscription %"PRId64" to old matched enonce1 %lx string %s",
			client->id, client->enonce1_64, client->enonce1);
	}

	/* Workbases will exist if sdata->current_workbase is not NULL */
	ck_rlock(&sdata->workbase_lock);
	n2len = sdata->workbases->enonce2varlen;
	sprintf(sessionid, "%08x", client->session_id);
	JSON_CPACK(ret, "[[[s,s]],s,i]", "mining.notify", sessionid, client->enonce1,
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

/* Sanity check to prevent clock adjustments backwards from screwing up stats */
static double sane_tdiff(tv_t *end, tv_t *start)
{
	double tdiff = tvdiff(end, start);

	if (unlikely(tdiff < 0.001))
		tdiff = 0.001;
	return tdiff;
}

static void decay_client(stratum_instance_t *client, double diff, tv_t *now_t)
{
	double tdiff = sane_tdiff(now_t, &client->last_decay);

	decay_time(&client->dsps1, diff, tdiff, MIN1);
	decay_time(&client->dsps5, diff, tdiff, MIN5);
	decay_time(&client->dsps60, diff, tdiff, HOUR);
	decay_time(&client->dsps1440, diff, tdiff, DAY);
	decay_time(&client->dsps10080, diff, tdiff, WEEK);
	copy_tv(&client->last_decay, now_t);
}

static void decay_worker(worker_instance_t *worker, double diff, tv_t *now_t)
{
	double tdiff = sane_tdiff(now_t, &worker->last_decay);

	decay_time(&worker->dsps1, diff, tdiff, MIN1);
	decay_time(&worker->dsps5, diff, tdiff, MIN5);
	decay_time(&worker->dsps60, diff, tdiff, HOUR);
	decay_time(&worker->dsps1440, diff, tdiff, DAY);
	decay_time(&worker->dsps10080, diff, tdiff, WEEK);
	copy_tv(&worker->last_decay, now_t);
}

static void decay_user(user_instance_t *user, double diff, tv_t *now_t)
{
	double tdiff = sane_tdiff(now_t, &user->last_decay);

	decay_time(&user->dsps1, diff, tdiff, MIN1);
	decay_time(&user->dsps5, diff, tdiff, MIN5);
	decay_time(&user->dsps60, diff, tdiff, HOUR);
	decay_time(&user->dsps1440, diff, tdiff, DAY);
	decay_time(&user->dsps10080, diff, tdiff, WEEK);
	copy_tv(&user->last_decay, now_t);
}

/* Enter holding a reference count */
static void read_userstats(ckpool_t *ckp, user_instance_t *user)
{
	int tvsec_diff = 0, ret;
	char s[512];
	json_t *val;
	FILE *fp;
	tv_t now;

	snprintf(s, 511, "%s/users/%s", ckp->logdir, user->username);
	fp = fopen(s, "re");
	if (!fp) {
		LOGINFO("User %s does not have a logfile to read", user->username);
		return;
	}
	memset(s, 0, 512);
	ret = fread(s, 1, 511, fp);
	fclose(fp);
	if (ret < 1) {
		LOGINFO("Failed to read user %s logfile", user->username);
		return;
	}
	val = json_loads(s, 0, NULL);
	if (!val) {
		LOGINFO("Failed to json decode user %s logfile: %s", user->username, s);
		return;
	}

	tv_time(&now);
	copy_tv(&user->last_share, &now);
	copy_tv(&user->last_decay, &now);
	user->dsps1 = dsps_from_key(val, "hashrate1m");
	user->dsps5 = dsps_from_key(val, "hashrate5m");
	user->dsps60 = dsps_from_key(val, "hashrate1hr");
	user->dsps1440 = dsps_from_key(val, "hashrate1d");
	user->dsps10080 = dsps_from_key(val, "hashrate7d");
	json_get_int64(&user->last_update.tv_sec, val, "lastupdate");
	json_get_int64(&user->shares, val, "shares");
	json_get_double(&user->best_diff, val, "bestshare");
	LOGINFO("Successfully read user %s stats %f %f %f %f %f %f", user->username,
		user->dsps1, user->dsps5, user->dsps60, user->dsps1440,
		user->dsps10080, user->best_diff);
	json_decref(val);
	if (user->last_update.tv_sec)
		tvsec_diff = now.tv_sec - user->last_update.tv_sec - 60;
	if (tvsec_diff > 60) {
		LOGINFO("Old user stats indicate not logged for %d seconds, decaying stats",
			tvsec_diff);
		decay_user(user, 0, &now);
	}
}

/* Enter holding a reference count */
static void read_workerstats(ckpool_t *ckp, worker_instance_t *worker)
{
	int tvsec_diff = 0, ret;
	char s[512];
	json_t *val;
	FILE *fp;
	tv_t now;

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

	tv_time(&now);
	copy_tv(&worker->last_share, &now);
	copy_tv(&worker->last_decay, &now);
	worker->dsps1 = dsps_from_key(val, "hashrate1m");
	worker->dsps5 = dsps_from_key(val, "hashrate5m");
	worker->dsps60 = dsps_from_key(val, "hashrate1hr");
	worker->dsps1440 = dsps_from_key(val, "hashrate1d");
	worker->dsps10080 = dsps_from_key(val, "hashrate7d");
	json_get_double(&worker->best_diff, val, "bestshare");
	json_get_int64(&worker->last_update.tv_sec, val, "lastupdate");
	json_get_int64(&worker->shares, val, "shares");
	LOGINFO("Successfully read worker %s stats %f %f %f %f %f", worker->workername,
		worker->dsps1, worker->dsps5, worker->dsps60, worker->dsps1440, worker->best_diff);
	json_decref(val);
	if (worker->last_update.tv_sec)
		tvsec_diff = now.tv_sec - worker->last_update.tv_sec - 60;
	if (tvsec_diff > 60) {
		LOGINFO("Old worker stats indicate not logged for %d seconds, decaying stats",
			tvsec_diff);
		decay_worker(worker, 0, &now);
	}
}

#define DEFAULT_AUTH_BACKOFF	(3)  /* Set initial backoff to 3 seconds */

static user_instance_t *__create_user(sdata_t *sdata, const char *username)
{
	user_instance_t *user = ckzalloc(sizeof(user_instance_t));

	user->auth_backoff = DEFAULT_AUTH_BACKOFF;
	strcpy(user->username, username);
	user->id = ++sdata->user_instance_id;
	HASH_ADD_STR(sdata->user_instances, username, user);
	return user;
}

/* Find user by username or create one if it doesn't already exist */
static user_instance_t *get_user(sdata_t *sdata, const char *username)
{
	user_instance_t *user;

	ck_wlock(&sdata->instance_lock);
	HASH_FIND_STR(sdata->user_instances, username, user);
	if (unlikely(!user))
		user = __create_user(sdata, username);
	ck_wunlock(&sdata->instance_lock);

	return user;
}

static worker_instance_t *__create_worker(user_instance_t *user, const char *workername)
{
	worker_instance_t *worker = ckzalloc(sizeof(worker_instance_t));

	worker->workername = strdup(workername);
	worker->user_instance = user;
	DL_APPEND(user->worker_instances, worker);
	worker->start_time = time(NULL);
	return worker;
}

static worker_instance_t *__get_worker(user_instance_t *user, const char *workername)
{
	worker_instance_t *worker = NULL, *tmp;

	DL_FOREACH(user->worker_instances, tmp) {
		if (!safecmp(workername, tmp->workername)) {
			worker = tmp;
			break;
		}
	}
	return worker;
}

/* Find worker amongst a user's workers by workername or create one if it
 * doesn't yet exist. */
static worker_instance_t *get_worker(sdata_t *sdata, user_instance_t *user, const char *workername)
{
	worker_instance_t *worker;

	ck_wlock(&sdata->instance_lock);
	worker = __get_worker(user, workername);
	if (!worker)
		worker = __create_worker(user, workername);
	ck_wunlock(&sdata->instance_lock);

	return worker;
}

/* This simply strips off the first part of the workername and matches it to a
 * user or creates a new one. Needs to be entered with client holding a ref
 * count. */
static user_instance_t *generate_user(ckpool_t *ckp, stratum_instance_t *client,
				      const char *workername)
{
	char *base_username = strdupa(workername), *username;
	bool new_user = false, new_worker = false;
	sdata_t *sdata = ckp->data;
	user_instance_t *user;
	int len;

	username = strsep(&base_username, "._");
	if (!username || !strlen(username))
		username = base_username;
	len = strlen(username);
	if (unlikely(len > 127))
		username[127] = '\0';

	ck_wlock(&sdata->instance_lock);
	HASH_FIND_STR(sdata->user_instances, username, user);
	if (!user) {
		/* New user instance. Secondary user id will be NULL */
		user = __create_user(sdata, username);
		new_user = true;
	}
	client->user_instance = user;
	client->worker_instance = __get_worker(user, workername);
	/* Create one worker instance for combined data from workers of the
	 * same name */
	if (!client->worker_instance) {
		client->worker_instance = __create_worker(user, workername);
		new_worker = true;
	}
	DL_APPEND(user->clients, client);
	__inc_worker(sdata,user);
	ck_wunlock(&sdata->instance_lock);

	if (CKP_STANDALONE(ckp) && new_user)
		read_userstats(ckp, user);
	if (CKP_STANDALONE(ckp) && new_worker)
		read_workerstats(ckp, client->worker_instance);

	if (new_user && !ckp->proxy) {
		/* Is this a btc address based username? */
		if (len > 26 && len < 35)
			user->btcaddress = test_address(ckp, username);
		LOGNOTICE("Added new user %s%s", username, user->btcaddress ?
			  " as address based registration" : "");
	}

	return user;
}

static void set_worker_mindiff(ckpool_t *ckp, const char *workername, int mindiff);

static void parse_worker_diffs(ckpool_t *ckp, json_t *worker_array)
{
	json_t *worker_entry;
	char *workername;
	size_t index;
	int mindiff;

	json_array_foreach(worker_array, index, worker_entry) {
		json_get_string(&workername, worker_entry, "workername");
		json_get_int(&mindiff, worker_entry, "difficultydefault");
		set_worker_mindiff(ckp, workername, mindiff);
	}
}

/* Send this to the database and parse the response to authorise a user
 * and get SUID parameters back. We don't add these requests to the sdata->ckdbqueue
 * since we have to wait for the response but this is done from the authoriser
 * thread so it won't hold anything up but other authorisations. Needs to be
 * entered with client holding a ref count. */
static int send_recv_auth(stratum_instance_t *client)
{
	user_instance_t *user = client->user_instance;
	ckpool_t *ckp = client->ckp;
	sdata_t *sdata = ckp->data;
	char *buf = NULL, *json_msg;
	bool contended = false;
	size_t responselen = 0;
	char cdfield[64];
	int ret = 1;
	json_t *val;
	ts_t now;

	ts_realtime(&now);
	sprintf(cdfield, "%lu,%lu", now.tv_sec, now.tv_nsec);

	val = json_object();
	json_set_string(val, "username", user->username);
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
	if (user->btcaddress)
		json_msg = ckdb_msg(ckp, sdata, val, ID_ADDRAUTH);
	else
		json_msg = ckdb_msg(ckp, sdata, val, ID_AUTH);
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
	} else
		contended = true;

	free(json_msg);
	/* Leave ample room for response based on buf length */
	if (likely(buf))
		responselen = strlen(buf);
	if (likely(responselen > 0)) {
		char *cmd = NULL, *secondaryuserid = NULL, *response;
		worker_instance_t *worker = client->worker_instance;
		json_error_t err_val;
		json_t *val = NULL;
		int offset = 0;

		LOGINFO("Got ckdb response: %s", buf);
		response = alloca(responselen);
		memset(response, 0, responselen);
		if (unlikely(sscanf(buf, "%*d.%*d.%c%n", response, &offset) < 1)) {
			LOGWARNING("Got1 unparseable ckdb auth response: %s", buf);
			goto out_fail;
		}
		strcpy(response+1, buf+offset);
		if (!strchr(response, '=')) {
			if (cmdmatch(response, "failed"))
				goto out;
			LOGWARNING("Got2 unparseable ckdb auth response: %s", buf);
			goto out_fail;
		}
		cmd = response;
		strsep(&cmd, "=");
		LOGINFO("User %s Worker %s got auth response: %s  cmd: %s",
			user->username, client->workername,
			response, cmd);
		val = json_loads(cmd, 0, &err_val);
		if (unlikely(!val))
			LOGWARNING("AUTH JSON decode failed(%d): %s", err_val.line, err_val.text);
		else {
			json_t *worker_array = json_object_get(val, "workers");

			json_get_string(&secondaryuserid, val, "secondaryuserid");
			parse_worker_diffs(ckp, worker_array);
			client->suggest_diff = worker->mindiff;
			user->auth_time = time(NULL);
		}
		if (secondaryuserid && (!safecmp(response, "ok.authorise") ||
					!safecmp(response, "ok.addrauth"))) {
			if (!user->secondaryuserid)
				user->secondaryuserid = secondaryuserid;
			else
				dealloc(secondaryuserid);
			ret = 0;
		}
		if (likely(val))
			json_decref(val);
		goto out;
	}
	if (contended)
		LOGWARNING("Prolonged lock contention for ckdb while trying to authorise");
	else {
		if (!sdata->ckdb_offline)
			LOGWARNING("Got no auth response from ckdb :(");
		else
			LOGNOTICE("No auth response for %s from offline ckdb", user->username);
	}
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

	/* Read off any cached mindiff from previous auths */
	client->suggest_diff = client->worker_instance->mindiff;

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

static void check_global_user(ckpool_t *ckp, user_instance_t *user, stratum_instance_t *client)
{
	sdata_t *sdata = ckp->data;
	proxy_t *proxy = best_proxy(sdata);
	int proxyid = proxy->id;
	char buf[256];

	sprintf(buf, "globaluser=%d:%d:%"PRId64":%s,%s", proxyid, user->id, client->id,
		user->username, client->password);
	send_generator(ckp, buf, GEN_LAX);
}

/* Needs to be entered with client holding a ref count. */
static json_t *parse_authorise(stratum_instance_t *client, const json_t *params_val,
			       json_t **err_val, int *errnum)
{
	user_instance_t *user;
	ckpool_t *ckp = client->ckp;
	const char *buf, *pass;
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
	if (!memcmp(buf, ".", 1) || !memcmp(buf, "_", 1)) {
		*err_val = json_string("Empty username parameter");
		goto out;
	}
	if (strchr(buf, '/')) {
		*err_val = json_string("Invalid character in username");
		goto out;
	}
	pass = json_string_value(json_array_get(params_val, 1));
	user = generate_user(ckp, client, buf);
	client->user_id = user->id;
	ts_realtime(&now);
	client->start_time = now.tv_sec;
	/* NOTE workername is NULL prior to this so should not be used in code
	 * till after this point */
	client->workername = strdup(buf);
	if (pass)
		client->password = strndup(pass, 64);
	else
		client->password = strdup("");
	if (user->failed_authtime) {
		time_t now_t = time(NULL);

		if (now_t < user->failed_authtime + user->auth_backoff) {
			if (!user->throttled) {
				user->throttled = true;
				LOGNOTICE("Client %"PRId64" %s worker %s rate limited due to failed auth attempts",
					  client->id, client->address, buf);
			} else{
				LOGINFO("Client %"PRId64" %s worker %s rate limited due to failed auth attempts",
					client->id, client->address, buf);
			}
			client->dropped = true;
			goto out;
		}
	}
	if (CKP_STANDALONE(ckp))
		ret = true;
	else {
		/* Preauth workers for the first 10 minutes after the user is
		 * first authorised by ckdb to avoid floods of worker auths.
		 * *errnum is implied zero already so ret will be set true */
		if (user->auth_time && time(NULL) - user->auth_time < 600)
			client->suggest_diff = client->worker_instance->mindiff;
		else
			*errnum = send_recv_auth(client);
		if (!*errnum)
			ret = true;
		else if (*errnum < 0 && user->secondaryuserid) {
			/* This user has already been authorised but ckdb is
			 * offline so we assume they already exist but add the
			 * auth request to the queued messages. */
			queue_delayed_auth(client);
			ret = true;
		}
	}
	if (ret) {
		client->authorised = ret;
		user->authorised = ret;
		if (ckp->proxy) {
			LOGNOTICE("Authorised client %"PRId64" to proxy %d:%d, worker %s as user %s",
				  client->id, client->proxyid, client->subproxyid, buf, user->username);
			if (ckp->userproxy)
				check_global_user(ckp, user, client);
		} else {
			LOGNOTICE("Authorised client %"PRId64" worker %s as user %s",
				  client->id, buf, user->username);
		}
		user->auth_backoff = DEFAULT_AUTH_BACKOFF; /* Reset auth backoff time */
		user->throttled = false;
	} else {
		LOGNOTICE("Client %"PRId64" %s worker %s failed to authorise as user %s",
			  client->id, client->address, buf,user->username);
		user->failed_authtime = time(NULL);
		user->auth_backoff <<= 1;
		/* Cap backoff time to 10 mins */
		if (user->auth_backoff > 600)
			user->auth_backoff = 600;
	}
	/* We can set this outside of lock safely */
	client->authorising = false;
out:
	return json_boolean(ret);
}

/* Needs to be entered with client holding a ref count. */
static void stratum_send_diff(sdata_t *sdata, const stratum_instance_t *client)
{
	json_t *json_msg;

	JSON_CPACK(json_msg, "{s[I]soss}", "params", client->diff, "id", json_null(),
			     "method", "mining.set_difficulty");
	stratum_add_send(sdata, json_msg, client->id, SM_DIFF);
}

/* Needs to be entered with client holding a ref count. */
static void stratum_send_message(sdata_t *sdata, const stratum_instance_t *client, const char *msg)
{
	json_t *json_msg;

	JSON_CPACK(json_msg, "{sosss[s]}", "id", json_null(), "method", "client.show_message",
			     "params", msg);
	stratum_add_send(sdata, json_msg, client->id, SM_MSG);
}

static double time_bias(const double tdiff, const double period)
{
	double dexp = tdiff / period;

	/* Sanity check to prevent silly numbers for double accuracy **/
	if (unlikely(dexp > 36))
		dexp = 36;
	return 1.0 - 1.0 / exp(dexp);
}

static void upstream_shares(ckpool_t *ckp, const char *workername, const int64_t diff)
{
	char buf[256];

	sprintf(buf, "upstream={\"method\":\"shares\",\"workername\":\"%s\",\"diff\":%"PRId64"}\n",
		workername, diff);
	send_proc(ckp->connector, buf);
}

/* Needs to be entered with client holding a ref count. */
static void add_submit(ckpool_t *ckp, stratum_instance_t *client, const double diff, const bool valid,
		       const bool submit)
{
	sdata_t *ckp_sdata = ckp->data, *sdata = client->sdata;
	worker_instance_t *worker = client->worker_instance;
	double tdiff, bdiff, dsps, drr, network_diff, bias;
	user_instance_t *user = client->user_instance;
	int64_t next_blockid, optimal;
	tv_t now_t;

	mutex_lock(&ckp_sdata->stats_lock);
	if (valid) {
		ckp_sdata->stats.unaccounted_shares++;
		ckp_sdata->stats.unaccounted_diff_shares += diff;
	} else
		ckp_sdata->stats.unaccounted_rejects += diff;
	mutex_unlock(&ckp_sdata->stats_lock);

	/* Count only accepted and stale rejects in diff calculation. */
	if (valid) {
		worker->shares += diff;
		user->shares += diff;
		/* Send shares to the upstream pool in trusted remote node */
		if (ckp->remote)
			upstream_shares(ckp, worker->workername, diff);
	} else if (!submit)
		return;

	if (ckp->node)
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

	decay_client(client, diff, &now_t);
	copy_tv(&client->last_share, &now_t);

	decay_worker(worker, diff, &now_t);
	copy_tv(&worker->last_share, &now_t);
	worker->idle = false;

	decay_user(user, diff, &now_t);
	copy_tv(&user->last_share, &now_t);
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

	LOGINFO("Client %"PRId64" biased dsps %.2f dsps %.2f drr %.2f adjust diff from %"PRId64" to: %"PRId64" ",
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
test_blocksolve(const stratum_instance_t *client, const workbase_t *wb, const uchar *data,
		const uchar *hash, const double diff, const char *coinbase, int cblen,
		const char *nonce2, const char *nonce)
{
	int transactions = wb->transactions + 1;
	char hexcoinbase[1024], blockhash[68];
	sdata_t *sdata = client->sdata;
	json_t *val = NULL, *val_copy;
	char *gbt_block, varint[12];
	ckpool_t *ckp = wb->ckp;
	ckmsg_t *block_ckmsg;
	char cdfield[64];
	uchar swap[32];
	ts_t ts_now;

	/* Submit anything over 99.9% of the diff in case of rounding errors */
	if (diff < sdata->current_workbase->network_diff * 0.999)
		return;

	LOGWARNING("Possible block solve diff %f !", diff);
	/* Can't submit a block in proxy mode without the transactions */
	if (!ckp->node && wb->proxy)
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
static double submission_diff(const stratum_instance_t *client, const workbase_t *wb, const char *nonce2,
			      const uint32_t ntime32, const char *nonce, uchar *hash)
{
	unsigned char merkle_root[32], merkle_sha[64];
	uint32_t *data32, *swap32, benonce32;
	char *coinbase, data[80];
	uchar swap[80], hash1[32];
	int cblen, i;
	double ret;

	coinbase = alloca(wb->coinb1len + wb->enonce1constlen + wb->enonce1varlen + wb->enonce2varlen + wb->coinb2len);
	memcpy(coinbase, wb->coinb1bin, wb->coinb1len);
	cblen = wb->coinb1len;
	memcpy(coinbase + cblen, &client->enonce1bin, wb->enonce1constlen + wb->enonce1varlen);
	cblen += wb->enonce1constlen + wb->enonce1varlen;
	hex2bin(coinbase + cblen, nonce2, wb->enonce2varlen);
	cblen += wb->enonce2varlen;
	memcpy(coinbase + cblen, wb->coinb2bin, wb->coinb2len);
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

/* Optimised for the common case where shares are new */
static bool new_share(sdata_t *sdata, const uchar *hash, const int64_t wb_id)
{
	share_t *share = ckzalloc(sizeof(share_t)), *match = NULL;
	bool ret = true;

	memcpy(share->hash, hash, 32);
	share->workbase_id = wb_id;

	mutex_lock(&sdata->share_lock);
	sdata->shares_generated++;
	HASH_FIND(hh, sdata->shares, hash, 32, match);
	if (likely(!match))
		HASH_ADD(hh, sdata->shares, hash, 32, share);
	mutex_unlock(&sdata->share_lock);

	if (unlikely(match)) {
		dealloc(share);
		ret = false;
	}
	return ret;
}

static void update_client(const stratum_instance_t *client, const int64_t client_id);

/* Submit a share in proxy mode to the parent pool. workbase_lock is held.
 * Needs to be entered with client holding a ref count. */
static void submit_share(stratum_instance_t *client, const int64_t jobid, const char *nonce2,
			 const char *ntime, const char *nonce)
{
	ckpool_t *ckp = client->ckp;
	json_t *json_msg;
	char enonce2[32];
	char *msg;

	sprintf(enonce2, "%s%s", client->enonce1var, nonce2);
	JSON_CPACK(json_msg, "{sIsssssssIsIsi}", "jobid", jobid, "nonce2", enonce2,
			     "ntime", ntime, "nonce", nonce, "client_id", client->id,
			     "proxy", client->proxyid, "subproxy", client->subproxyid);
	msg = json_dumps(json_msg, JSON_COMPACT);
	json_decref(json_msg);
	send_generator(ckp, msg, GEN_LAX);
	free(msg);
}

static void upstream_best_diff(ckpool_t *ckp, const char *workername, const double diff)
{
	char buf[256];

	sprintf(buf, "upstream={\"method\":\"bestshare\",\"workername\":\"%s\",\"diff\":%lf}\n",
		workername, diff);
	send_proc(ckp->connector, buf);
}

static void set_best_diff(ckpool_t *ckp, user_instance_t *user, worker_instance_t *worker, const double sdiff)
{
	if (sdiff > worker->best_diff) {
		worker->best_diff = sdiff;
		if (ckp->remote)
			upstream_best_diff(ckp, worker->workername, sdiff);
	}
	if (sdiff > user->best_diff)
		user->best_diff = sdiff;
}

#define JSON_ERR(err) json_string(SHARE_ERR(err))

/* Needs to be entered with client holding a ref count. */
static json_t *parse_submit(stratum_instance_t *client, json_t *json_msg,
			    const json_t *params_val, json_t **err_val)
{
	bool share = false, result = false, invalid = true, submit = false;
	user_instance_t *user = client->user_instance;
	double diff = client->diff, wdiff = 0, sdiff = -1;
	char hexhash[68] = {}, sharehash[32], cdfield[64];
	const char *workername, *job_id, *ntime, *nonce;
	char *fname = NULL, *s, *nonce2;
	sdata_t *sdata = client->sdata;
	enum share_err err = SE_NONE;
	ckpool_t *ckp = client->ckp;
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
	workername = json_string_value(json_array_get(params_val, 0));
	if (unlikely(!workername || !strlen(workername))) {
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
	if (safecmp(workername, client->workername)) {
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
		if (!sdata->current_workbase) {
			ck_runlock(&sdata->workbase_lock);

			return json_boolean(false);
		}
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
		LOGINFO("User %s worker %s client %"PRId64" new best diff %lf", user->username,
			worker->workername, client->id, sdiff);
		set_best_diff(ckp, user, worker, sdiff);
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
				LOGINFO("Accepted client %"PRId64" share diff %.1f/%.0f/%s: %s",
					client->id, sdiff, diff, wdiffsuffix, hexhash);
				result = true;
			} else {
				err = SE_DUPE;
				json_set_string(json_msg, "reject-reason", SHARE_ERR(err));
				LOGINFO("Rejected client %"PRId64" dupe diff %.1f/%.0f/%s: %s",
					client->id, sdiff, diff, wdiffsuffix, hexhash);
				submit = false;
			}
		} else {
			err = SE_HIGH_DIFF;
			LOGINFO("Rejected client %"PRId64" high diff %.1f/%.0f/%s: %s",
				client->id, sdiff, diff, wdiffsuffix, hexhash);
			json_set_string(json_msg, "reject-reason", SHARE_ERR(err));
			submit = false;
		}
	}  else
		LOGINFO("Rejected client %"PRId64" invalid share %s", client->id, SHARE_ERR(err));

	/* Submit share to upstream pool in proxy mode. We submit valid and
	 * stale shares and filter out the rest. */
	if (wb && wb->proxy && submit) {
		LOGINFO("Submitting share upstream: %s", hexhash);
		submit_share(client, id, nonce2, ntime, nonce);
	}

	add_submit(ckp, client, diff, result, submit);

	/* Now write to the pool's sharelog. */
	val = json_object();
	json_set_int(val, "workinfoid", id);
	json_set_int(val, "clientid", client->id);
	json_set_string(val, "enonce1", client->enonce1);
	if (!CKP_STANDALONE(ckp))
		json_set_string(val, "secondaryuserid", user->secondaryuserid);
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
	json_set_string(val, "username", user->username);

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
		else if (client->first_invalid && client->first_invalid < now_t - 180 && client->reject < 3) {
			LOGNOTICE("Client %"PRId64" rejecting for 180s, disconnecting", client->id);
			if (ckp->node)
				connector_drop_client(ckp, client->id);
			else
				stratum_send_message(sdata, client, "Disconnecting for continuous invalid shares");
			client->reject = 3;
		} else if (client->first_invalid && client->first_invalid < now_t - 120 && client->reject < 2) {
			LOGNOTICE("Client %"PRId64" rejecting for 120s, reconnecting", client->id);
			stratum_send_message(sdata, client, "Reconnecting for continuous invalid shares");
			reconnect_client(sdata, client);
			client->reject = 2;
		} else if (client->first_invalid && client->first_invalid < now_t - 60 && !client->reject) {
			LOGNOTICE("Client %"PRId64" rejecting for 60s, sending update", client->id);
			update_client(client, client->id);
			client->reject = 1;
		}
	} else if (client->reject < 3) {
		client->first_invalid = 0;
		client->reject = 0;
	}

	if (!share) {
		val = json_object();
		json_set_int(val, "clientid", client->id);
		if (!CKP_STANDALONE(ckp))
			json_set_string(val, "secondaryuserid", user->secondaryuserid);
		json_set_string(val, "enonce1", client->enonce1);
		json_set_int(val, "workinfoid", sdata->current_workbase->id);
		json_set_string(val, "workername", client->workername);
		json_set_string(val, "username", user->username);
		json_object_set(val, "error", *err_val);
		json_set_int(val, "errn", err);
		json_set_string(val, "createdate", cdfield);
		json_set_string(val, "createby", "code");
		json_set_string(val, "createcode", __func__);
		json_set_string(val, "createinet", ckp->serverurl[client->server]);
		ckdbq_add(ckp, ID_SHAREERR, val);
		LOGINFO("Invalid share from client %"PRId64": %s", client->id, client->workername);
	}
	free(fname);
	return json_boolean(result);
}

/* Must enter with workbase_lock held */
static json_t *__stratum_notify(const workbase_t *wb, const bool clean)
{
	json_t *val;

	JSON_CPACK(val, "{s:[ssssosssb],s:o,s:s}",
			"params",
			wb->idstring,
			wb->prevhash,
			wb->coinb1,
			wb->coinb2,
			json_deep_copy(wb->merkle_array),
			wb->bbversion,
			wb->nbit,
			wb->ntime,
			clean,
			"id", json_null(),
			"method", "mining.notify");
	return val;
}

static void stratum_broadcast_update(sdata_t *sdata, const workbase_t *wb, const bool clean)
{
	json_t *json_msg;

	ck_rlock(&sdata->workbase_lock);
	json_msg = __stratum_notify(wb, clean);
	ck_runlock(&sdata->workbase_lock);

	stratum_broadcast(sdata, json_msg, SM_UPDATE);
}

/* For sending a single stratum template update */
static void stratum_send_update(sdata_t *sdata, const int64_t client_id, const bool clean)
{
	ckpool_t *ckp = sdata->ckp;
	json_t *json_msg;

	if (unlikely(!sdata->current_workbase)) {
		if (!ckp->proxy)
			LOGWARNING("No current workbase to send stratum update");
		else
			LOGDEBUG("No current workbase to send stratum update for client %"PRId64, client_id);
		return;
	}

	ck_rlock(&sdata->workbase_lock);
	json_msg = __stratum_notify(sdata->current_workbase, clean);
	ck_runlock(&sdata->workbase_lock);

	stratum_add_send(sdata, json_msg, client_id, SM_UPDATE);
}

static void send_json_err(sdata_t *sdata, const int64_t client_id, json_t *id_val, const char *err_msg)
{
	json_t *val;

	JSON_CPACK(val, "{soss}", "id", json_deep_copy(id_val), "error", err_msg);
	stratum_add_send(sdata, val, client_id, SM_ERROR);
}

/* Needs to be entered with client holding a ref count. */
static void update_client(const stratum_instance_t *client, const int64_t client_id)
{
	sdata_t *sdata = client->sdata;

	stratum_send_update(sdata, client_id, true);
	stratum_send_diff(sdata, client);
}

static json_params_t
*create_json_params(const int64_t client_id, const json_t *method, const json_t *params,
		    const json_t *id_val)
{
	json_params_t *jp = ckalloc(sizeof(json_params_t));

	jp->method = json_deep_copy(method);
	jp->params = json_deep_copy(params);
	jp->id_val = json_deep_copy(id_val);
	jp->client_id = client_id;
	return jp;
}

static void set_worker_mindiff(ckpool_t *ckp, const char *workername, int mindiff)
{
	stratum_instance_t *client;
	sdata_t *sdata = ckp->data;
	worker_instance_t *worker;
	user_instance_t *user;

	/* Find the user first */
	user = user_by_workername(sdata, workername);

	/* Then find the matching worker user */
	worker = get_worker(sdata, user, workername);

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
	DL_FOREACH(user->clients, client) {
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
static void suggest_diff(stratum_instance_t *client, const char *method, const json_t *params_val)
{
	json_t *arr_val = json_array_get(params_val, 0);
	sdata_t *sdata = client->ckp->data;
	int64_t sdiff;

	if (unlikely(!client_active(client))) {
		LOGNOTICE("Attempted to suggest diff on unauthorised client %"PRId64, client->id);
		return;
	}
	if (arr_val && json_is_integer(arr_val))
		sdiff = json_integer_value(arr_val);
	else if (sscanf(method, "mining.suggest_difficulty(%"PRId64, &sdiff) != 1) {
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

/* Send diff first when sending the first stratum template after subscribing */
static void init_client(sdata_t *sdata, const stratum_instance_t *client, const int64_t client_id)
{
	stratum_send_diff(sdata, client);
	stratum_send_update(sdata, client_id, true);
}

static void add_mining_node(ckpool_t *ckp, sdata_t *sdata, stratum_instance_t *client)
{
	client->node = true;

	ck_wlock(&sdata->instance_lock);
	DL_APPEND(sdata->node_instances, client);
	ck_wunlock(&sdata->instance_lock);

	LOGWARNING("Added client %"PRId64" %s as mining node on server %d:%s", client->id,
		   client->address, client->server, ckp->serverurl[client->server]);
}

/* Enter with client holding ref count */
static void parse_method(ckpool_t *ckp, sdata_t *sdata, stratum_instance_t *client,
			 const int64_t client_id, json_t *id_val, json_t *method_val,
			 json_t *params_val)
{
	const char *method;

	/* Random broken clients send something not an integer as the id so we
	 * copy the json item for id_val as is for the response. By far the
	 * most common messages will be shares so look for those first */
	method = json_string_value(method_val);
	if (likely(cmdmatch(method, "mining.submit") && client->authorised)) {
		json_params_t *jp = create_json_params(client_id, method_val, params_val, id_val);

		ckmsgq_add(sdata->sshareq, jp);
		return;
	}

	if (cmdmatch(method, "mining.term")) {
		LOGDEBUG("Mining terminate requested from %"PRId64" %s", client_id, client->address);
		drop_client(ckp, sdata, client_id);
		return;
	}

	if (cmdmatch(method, "mining.subscribe")) {
		json_t *val, *result_val;

		if (unlikely(client->subscribed)) {
			LOGNOTICE("Client %"PRId64" %s trying to subscribe twice",
				  client_id, client->address);
			return;
		}
		result_val = parse_subscribe(client, client_id, params_val);
		/* Shouldn't happen, sanity check */
		if (unlikely(!result_val)) {
			LOGWARNING("parse_subscribe returned NULL result_val");
			return;
		}
		val = json_object();
		json_object_set_new_nocheck(val, "result", result_val);
		json_object_set_nocheck(val, "id", id_val);
		json_object_set_new_nocheck(val, "error", json_null());
		stratum_add_send(sdata, val, client_id, SM_SUBSCRIBERESULT);
		if (likely(client->subscribed))
			init_client(sdata, client, client_id);
		return;
	}

	if (unlikely(cmdmatch(method, "mining.remote"))) {
		char buf[256];

		/* Add this client as a trusted remote node in the connector and
		 * drop the client in the stratifier */
		if (!ckp->trusted[client->server]) {
			LOGNOTICE("Dropping client %"PRId64" %s trying to authorise as remote node on non trusted server %d",
				  client_id, client->address, client->server);
			connector_drop_client(ckp, client_id);
		} else {
			snprintf(buf, 255, "remote=%"PRId64, client_id);
			send_proc(ckp->connector, buf);
		}
		client->remote = true;
		return;
	}

	if (unlikely(cmdmatch(method, "mining.node"))) {
		char buf[256];

		/* Add this client as a passthrough in the connector and
		 * add it to the list of mining nodes in the stratifier */
		if (!ckp->nodeserver[client->server]) {
			LOGNOTICE("Dropping client %"PRId64" %s trying to authorise as node on non node server %d",
				  client_id, client->address, client->server);
			connector_drop_client(ckp, client_id);
			drop_client(ckp, sdata, client_id);
		} else {
			add_mining_node(ckp, sdata, client);
			snprintf(buf, 255, "passthrough=%"PRId64, client_id);
			send_proc(ckp->connector, buf);
		}
		return;
	}

	if (unlikely(cmdmatch(method, "mining.passthrough"))) {
		char buf[256];

		/* We need to inform the connector process that this client
		 * is a passthrough and to manage its messages accordingly. No
		 * data from this client id should ever come back to this
		 * stratifier after this so drop the client in the stratifier. */
		LOGNOTICE("Adding passthrough client %"PRId64" %s", client_id, client->address);
		snprintf(buf, 255, "passthrough=%"PRId64, client_id);
		send_proc(ckp->connector, buf);
		drop_client(ckp, sdata, client_id);
		return;
	}

	/* We shouldn't really allow unsubscribed users to authorise first but
	 * some broken stratum implementations do that and we can handle it. */
	if (cmdmatch(method, "mining.auth")) {
		json_params_t *jp;

		if (unlikely(client->authorised)) {
			LOGNOTICE("Client %"PRId64" %s trying to authorise twice",
				  client_id, client->address);
			return;
		}
		jp = create_json_params(client_id, method_val, params_val, id_val);
		ckmsgq_add(sdata->sauthq, jp);
		return;
	}

	/* We should only accept requests from subscribed and authed users here
	 * on */
	if (!client->subscribed) {
		LOGINFO("Dropping %s from unsubscribed client %"PRId64" %s", method,
			client_id, client->address);
		connector_drop_client(ckp, client_id);
		return;
	}

	/* We should only accept authorised requests from here on */
	if (!client->authorised) {
		LOGINFO("Dropping %s from unauthorised client %"PRId64" %s", method,
			client_id, client->address);
		return;
	}

	if (cmdmatch(method, "mining.suggest")) {
		suggest_diff(client, method, params_val);
		return;
	}

	/* Covers both get_transactions and get_txnhashes */
	if (cmdmatch(method, "mining.get")) {
		json_params_t *jp = create_json_params(client_id, method_val, params_val, id_val);

		ckmsgq_add(sdata->stxnq, jp);
		return;
	}

	/* Unhandled message here */
	LOGINFO("Unhandled client %"PRId64" %s method %s", client_id, client->address, method);
	return;
}

static void free_smsg(smsg_t *msg)
{
	json_decref(msg->json_msg);
	free(msg);
}

/* Even though we check the results locally in node mode, check the upstream
 * results in case of runs of invalids. */
static void parse_share_result(ckpool_t *ckp, stratum_instance_t *client, json_t *val)
{
	time_t now_t;
	ts_t now;

	if (likely(json_is_true(val))) {
		client->upstream_invalid = 0;
		return;
	}
	ts_realtime(&now);
	now_t = now.tv_sec;
	if (client->upstream_invalid < client->last_share.tv_sec || !client->upstream_invalid)
		client->upstream_invalid = now_t;
	else if (client->upstream_invalid && client->upstream_invalid < now_t - 150) {
		LOGNOTICE("Client %"PRId64" upstream rejects for 150s, disconnecting", client->id);
		connector_drop_client(ckp, client->id);
		client->reject = 3;
	}
}

static void parse_diff(stratum_instance_t *client, json_t *val)
{
	double diff = json_number_value(json_array_get(val, 0));

	LOGINFO("Set client %"PRId64" to diff %lf", client->id, diff);
	client->diff = diff;
}

static void parse_subscribe_result(stratum_instance_t *client, json_t *val)
{
	int len;

	strncpy(client->enonce1, json_string_value(json_array_get(val, 1)), 16);
	len = strlen(client->enonce1) / 2;
	hex2bin(client->enonce1bin, client->enonce1, len);
	memcpy(&client->enonce1_64, client->enonce1bin, 8);
	LOGINFO("Client %"PRId64" got enonce1 %lx string %s", client->id, client->enonce1_64, client->enonce1);
}

static void parse_authorise_result(stratum_instance_t *client, json_t *val)
{
	client->authorised = json_is_true(val);
	LOGDEBUG("Client %"PRId64" is %sauthorised", client->id, client->authorised ? "" : "not ");
}

static int node_msg_type(json_t *val)
{
	int i, ret = -1;
	char *method;

	if (!val)
		goto out;
	if (!json_get_string(&method, val, "node.method"))
		goto out;
	for (i = 0; i < SM_NONE; i++) {
		if (!strcmp(method, stratum_msgs[i])) {
			ret = i;
			break;
		}
	}
	json_object_del(val, "node.method");
out:
	if (ret < 0 && json_get_string(&method, val, "method")) {
		if (!safecmp(method, "mining.submit"))
			ret = SM_SHARE;
		else if (!safecmp(method, "mining.notify"))
			ret = SM_UPDATE;
		else if (!safecmp(method, "mining.subscribe"))
			ret = SM_SUBSCRIBE;
		else if (cmdmatch(method, "mining.auth"))
			ret = SM_AUTH;
		else if (cmdmatch(method, "mining.get"))
			ret = SM_TXNS;
		else if (cmdmatch(method, "mining.suggest_difficulty"))
			ret = SM_SUGGESTDIFF;
	}
	return ret;
}

static void parse_remote_shares(sdata_t *sdata, json_t *val, const char *buf)
{
	json_t *workername_val = json_object_get(val, "workername");
	worker_instance_t *worker;
	const char *workername;
	user_instance_t *user;
	int64_t diff;
	tv_t now_t;

	workername = json_string_value(workername_val);
	if (unlikely(!workername_val || !workername)) {
		LOGWARNING("Failed to get workername from remote message %s", buf);
		return;
	}
	if (unlikely(!json_get_int64(&diff, val, "diff") || diff < 1)) {
		LOGWARNING("Unable to parse valid diff from remote message %s", buf);
		return;
	}
	user = user_by_workername(sdata, workername);
	user->authorised = true;
	worker = get_worker(sdata, user, workername);

	mutex_lock(&sdata->stats_lock);
	sdata->stats.unaccounted_shares++;
	sdata->stats.unaccounted_diff_shares += diff;
	mutex_unlock(&sdata->stats_lock);

	worker->shares += diff;
	user->shares += diff;
	tv_time(&now_t);

	decay_worker(worker, diff, &now_t);
	copy_tv(&worker->last_share, &now_t);
	worker->idle = false;

	LOGINFO("Added %"PRId64" remote shares to worker %s", diff, workername);
}

static void parse_best_remote(ckpool_t *ckp, sdata_t *sdata, json_t *val, const char *buf)
{
	json_t *workername_val = json_object_get(val, "workername");
	worker_instance_t *worker;
	const char *workername;
	user_instance_t *user;
	double diff;

	workername = json_string_value(workername_val);
	if (unlikely(!workername_val || !workername)) {
		LOGWARNING("Failed to get workername from remote message %s", buf);
		return;
	}
	if (unlikely(!json_get_double(&diff, val, "diff") || diff <= 0)) {
		LOGWARNING("Unable to parse valid diff from remote message %s", buf);
		return;
	}
	user = user_by_workername(sdata, workername);
	user->authorised = true;
	worker = get_worker(sdata, user, workername);

	LOGINFO("Checking best diff of %lf for worker %s", diff, workername);
	set_best_diff(ckp, user, worker, diff);
}

static void parse_trusted_msg(ckpool_t *ckp, sdata_t *sdata, json_t *val, const char *buf)
{
	json_t *method_val = json_object_get(val, "method");
	const char *method;

	LOGDEBUG("Got remote message %s", buf);
	method = json_string_value(method_val);
	if (unlikely(!method_val || !method)) {
		LOGWARNING("Failed to get method from remote message %s", buf);
		return;
	}
	if (likely(!safecmp(method, "shares")))
		parse_remote_shares(sdata, val, buf);
	else if (!safecmp(method, "bestshare"))
		parse_best_remote(ckp, sdata, val, buf);
	else
		LOGWARNING("unrecognised trusted message %s", buf);
}

/* Entered with client holding ref count */
static void node_client_msg(ckpool_t *ckp, json_t *val, const char *buf, stratum_instance_t *client)
{
	json_t *params, *method, *res_val, *id_val, *err_val = NULL;
	int msg_type = node_msg_type(val);
	sdata_t *sdata = ckp->data;
	json_params_t *jp;
	int errnum;

	if (msg_type < 0) {
		LOGERR("Missing client %"PRId64" node method from %s", client->id, buf);
		return;
	}
	LOGDEBUG("Got client %"PRId64" node method %d:%s", client->id, msg_type, stratum_msgs[msg_type]);
	id_val = json_object_get(val, "id");
	method = json_object_get(val, "method");
	params = json_object_get(val, "params");
	res_val = json_object_get(val, "result");
	switch (msg_type) {
		case SM_SHARE:
			jp = create_json_params(client->id, method, params, id_val);
			ckmsgq_add(sdata->sshareq, jp);
			break;
		case SM_SHARERESULT:
			parse_share_result(ckp, client, res_val);
			break;
		case SM_DIFF:
			parse_diff(client, params);
			break;
		case SM_SUBSCRIBE:
			parse_subscribe(client, client->id, params);
			break;
		case SM_SUBSCRIBERESULT:
			parse_subscribe_result(client, res_val);
			break;
		case SM_AUTH:
			parse_authorise(client, params, &err_val, &errnum);
			break;
		case SM_AUTHRESULT:
			parse_authorise_result(client, res_val);
			break;
		default:
			break;
	}
}

static void parse_node_msg(ckpool_t *ckp, json_t *val, const char *buf)
{
	int msg_type = node_msg_type(val);

	if (msg_type < 0) {
		LOGERR("Missing node method from %s", buf);
		return;
	}
	LOGDEBUG("Got node method %d:%s", msg_type, stratum_msgs[msg_type]);
	switch (msg_type) {
		case SM_WORKINFO:
			add_node_base(ckp, val);
			break;
		default:
			break;
	}
}

/* Entered with client holding ref count */
static void parse_instance_msg(ckpool_t *ckp, sdata_t *sdata, smsg_t *msg, stratum_instance_t *client)
{
	json_t *val = msg->json_msg, *id_val, *method, *params;
	int64_t client_id = msg->client_id;
	int delays = 0;

	if (client->reject == 3) {
		LOGINFO("Dropping client %"PRId64" %s tagged for lazy invalidation",
			client_id, client->address);
		connector_drop_client(ckp, client_id);
		return;
	}

	/* Return back the same id_val even if it's null or not existent. */
	id_val = json_object_get(val, "id");

	method = json_object_get(val, "method");
	if (unlikely(!method)) {
		json_t *res_val = json_object_get(val, "result");

		/* Is this a spurious result or ping response? */
		if (res_val) {
			const char *result = json_string_value(res_val);

			if (!safecmp(result, "pong"))
				LOGDEBUG("Received pong from client %"PRId64, client_id);
			else
				LOGDEBUG("Received spurious response %s from client %"PRId64,
					 result ? result : "", client_id);
			return;
		}
		send_json_err(sdata, client_id, id_val, "-3:method not found");
		return;
	}
	if (unlikely(!json_is_string(method))) {
		send_json_err(sdata, client_id, id_val, "-1:method is not string");
		return;
	}
	params = json_object_get(val, "params");
	if (unlikely(!params)) {
		send_json_err(sdata, client_id, id_val, "-1:params not found");
		return;
	}
	/* At startup we block until there's a current workbase otherwise we
	 * will reject miners with the initialising message. A slightly delayed
	 * response to subscribe is better tolerated. */
	while (unlikely(!ckp->proxy && !sdata->current_workbase)) {
		cksleep_ms(100);
		if (!(++delays % 50))
			LOGWARNING("%d Second delay waiting for bitcoind at startup", delays / 10);
	}
	parse_method(ckp, sdata, client, client_id, id_val, method, params);
}

static void srecv_process(ckpool_t *ckp, char *buf)
{
	bool noid = false, dropped = false;
	char address[INET6_ADDRSTRLEN];
	sdata_t *sdata = ckp->data;
	stratum_instance_t *client;
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
		if (ckp->node)
			parse_node_msg(ckp, msg->json_msg, buf);
		else
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
	strcpy(address, json_string_value(val));
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
	client = __instance_by_id(sdata, msg->client_id);
	/* If client_id instance doesn't exist yet, create one */
	if (unlikely(!client)) {
		noid = true;
		client = __stratum_add_instance(ckp, msg->client_id, address, server);
	} else if (unlikely(client->dropped))
		dropped = true;
	if (likely(!dropped))
		__inc_instance_ref(client);
	ck_wunlock(&sdata->instance_lock);

	if (unlikely(dropped)) {
		/* Client may be NULL here */
		LOGNOTICE("Stratifier skipped dropped instance %"PRId64" message from server %d",
			  msg->client_id, server);
		connector_drop_client(ckp, msg->client_id);
		free_smsg(msg);
		goto out;
	}
	if (unlikely(noid))
		LOGINFO("Stratifier added instance %"PRId64" server %d", client->id, server);

	if (client->remote)
		parse_trusted_msg(ckp, sdata, msg->json_msg, buf);
	else if (ckp->node)
		node_client_msg(ckp, msg->json_msg, buf, client);
	else
		parse_instance_msg(ckp, sdata, msg, client);
	free_smsg(msg);
	dec_instance_ref(sdata, client);
out:
	free(buf);
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
	s = json_dumps(msg->json_msg, JSON_COMPACT);
	send_proc(ckp->connector, s);
	free(s);
	free_smsg(msg);
}

static void discard_json_params(json_params_t *jp)
{
	json_decref(jp->method);
	json_decref(jp->params);
	if (jp->id_val)
		json_decref(jp->id_val);
	free(jp);
}

static void steal_json_id(json_t *val, json_params_t *jp)
{
	/* Steal the id_val as is to avoid a copy */
	json_object_set_new_nocheck(val, "id", jp->id_val);
	jp->id_val = NULL;
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
		LOGINFO("Share processor failed to find client id %"PRId64" in hashtable!", client_id);
		goto out;
	}
	if (unlikely(!client->authorised)) {
		LOGDEBUG("Client %"PRId64" no longer authorised to submit shares", client_id);
		goto out_decref;
	}
	json_msg = json_object();
	result_val = parse_submit(client, json_msg, jp->params, &err_val);
	json_object_set_new_nocheck(json_msg, "result", result_val);
	json_object_set_new_nocheck(json_msg, "error", err_val ? err_val : json_null());
	steal_json_id(json_msg, jp);
	stratum_add_send(sdata, json_msg, client_id, SM_SHARERESULT);
out_decref:
	dec_instance_ref(sdata, client);
out:
	discard_json_params(jp);
}

/* As ref_instance_by_id but only returns clients not authorising or authorised,
 * and sets the authorising flag */
static stratum_instance_t *preauth_ref_instance_by_id(sdata_t *sdata, const int64_t id)
{
	stratum_instance_t *client;

	ck_wlock(&sdata->instance_lock);
	client = __instance_by_id(sdata, id);
	if (client) {
		if (client->dropped || client->authorising || client->authorised)
			client = NULL;
		else {
			__inc_instance_ref(client);
			client->authorising = true;
		}
	}
	ck_wunlock(&sdata->instance_lock);

	return client;
}

static void sauth_process(ckpool_t *ckp, json_params_t *jp)
{
	json_t *result_val, *json_msg, *err_val = NULL;
	stratum_instance_t *client;
	sdata_t *sdata = ckp->data;
	int mindiff, errnum = 0;
	int64_t client_id;

	client_id = jp->client_id;

	client = preauth_ref_instance_by_id(sdata, client_id);
	if (unlikely(!client)) {
		LOGINFO("Authoriser failed to find client id %"PRId64" in hashtable!", client_id);
		goto out;
	}

	result_val = parse_authorise(client, jp->params, &err_val, &errnum);
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
	steal_json_id(json_msg, jp);
	stratum_add_send(sdata, json_msg, client_id, SM_AUTHRESULT);

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
	discard_json_params(jp);

}

static void parse_ckdb_cmd(ckpool_t *ckp, const char *cmd)
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
static bool test_and_set(bool *val, mutex_t *lock)
{
	bool ret;

	mutex_lock(lock);
	ret = *val;
	*val = true;
	mutex_unlock(lock);

	return ret;
}

static bool test_and_clear(bool *val, mutex_t *lock)
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
	size_t responselen = 0;
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

	/* Process any requests from ckdb that are heartbeat responses with
	 * specific requests. */
	if (likely(buf))
		responselen = strlen(buf);
	if (likely(responselen > 0)) {
		char *response = alloca(responselen);
		int offset = 0;

		memset(response, 0, responselen);
		if (sscanf(buf, "%*d.%*d.%c%n", response, &offset) > 0) {
			strcpy(response+1, buf+offset);
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
				LOGWARNING("Got ckdb failure response: %s", buf);
		} else
			LOGWARNING("Got bad ckdb response: %s", buf);
		free(buf);
	}
}

static int transactions_by_jobid(sdata_t *sdata, const int64_t id)
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

static json_t *txnhashes_by_jobid(sdata_t *sdata, const int64_t id)
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
	steal_json_id(val, jp);
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
		LOGINFO("send_transactions failed to find client id %"PRId64" in hashtable!",
			jp->client_id);
		goto out;
	}

	now_t = time(NULL);
	if (now_t - client->last_txns < ckp->update_interval) {
		LOGNOTICE("Rate limiting get_txnhashes on client %"PRId64"!", jp->client_id);
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
	stratum_add_send(sdata, val, jp->client_id, SM_TXNSRESULT);
out:
	if (client)
		dec_instance_ref(sdata, client);
	discard_json_params(jp);
}

/* Called 32 times per min, we send the updated stats to ckdb of those users
 * who have gone 1 minute between updates. This ends up staggering stats to
 * avoid floods of stat data coming at once. */
static void update_workerstats(ckpool_t *ckp, sdata_t *sdata)
{
	json_entry_t *json_list = NULL, *entry, *tmpentry;
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
			json_t *val;
			int elapsed;

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
			entry = ckalloc(sizeof(json_entry_t));
			entry->val = val;
			DL_APPEND(json_list, entry);
		}
	}
	ck_runlock(&sdata->instance_lock);

	/* Add all entries outside of the instance lock */
	DL_FOREACH_SAFE(json_list, entry, tmpentry) {
		ckdbq_add(ckp, ID_WORKERSTATS, entry->val);
		DL_DELETE(json_list, entry);
		free(entry);
	}
}

static void add_log_entry(log_entry_t **entries, char **fname, char **buf)
{
	log_entry_t *entry = ckalloc(sizeof(log_entry_t));

	entry->fname = *fname;
	*fname = NULL;
	entry->buf = *buf;
	*buf = NULL;
	DL_APPEND(*entries, entry);
}

static void dump_log_entries(log_entry_t **entries)
{
	log_entry_t *entry, *tmpentry;
	FILE *fp;

	DL_FOREACH_SAFE(*entries, entry, tmpentry) {
		DL_DELETE(*entries, entry);
		fp = fopen(entry->fname, "we");
		if (likely(fp)) {
			fprintf(fp, "%s", entry->buf);
			fclose(fp);
		} else
			LOGERR("Failed to fopen %s in dump_log_entries", entry->fname);
		free(entry->fname);
		free(entry->buf);
		free(entry);
	}
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
		double ghs, ghs1, ghs5, ghs15, ghs60, ghs360, ghs1440, ghs10080, per_tdiff;
		char suffix1[16], suffix5[16], suffix15[16], suffix60[16], cdfield[64];
		char suffix360[16], suffix1440[16], suffix10080[16];
		stratum_instance_t *client, *tmp;
		log_entry_t *log_entries = NULL;
		user_instance_t *user, *tmpuser;
		char_entry_t *char_list = NULL;
		int idle_workers = 0;
		char *fname, *s, *sp;
		tv_t now, diff;
		ts_t ts_now;
		json_t *val;
		FILE *fp;
		int i;

		tv_time(&now);
		timersub(&now, &stats->start_time, &diff);

		ck_rlock(&sdata->instance_lock);
		HASH_ITER(hh, sdata->stratum_instances, client, tmp) {
			if (!client_active(client))
				continue;

			per_tdiff = tvdiff(&now, &client->last_share);
			/* Decay times per connected instance */
			if (per_tdiff > 60) {
				/* No shares for over a minute, decay to 0 */
				decay_client(client, 0, &now);
				idle_workers++;
				if (per_tdiff > 600)
					client->idle = true;
				continue;
			}
		}

		HASH_ITER(hh, sdata->user_instances, user, tmpuser) {
			worker_instance_t *worker;
			bool idle = false;

			if (!user->authorised)
				continue;

			/* Decay times per worker */
			DL_FOREACH(user->worker_instances, worker) {
				per_tdiff = tvdiff(&now, &worker->last_share);
				if (per_tdiff > 60) {
					decay_worker(worker, 0, &now);
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

				ghs = worker->dsps10080 * nonces;
				suffix_string(ghs, suffix10080, 16, 0);

				copy_tv(&worker->last_update, &now);

				JSON_CPACK(val, "{ss,ss,ss,ss,ss,si,sI,sf}",
						"hashrate1m", suffix1,
						"hashrate5m", suffix5,
						"hashrate1hr", suffix60,
						"hashrate1d", suffix1440,
						"hashrate7d", suffix10080,
						"lastupdate", now.tv_sec,
						"shares", worker->shares,
						"bestshare", worker->best_diff);

				ASPRINTF(&fname, "%s/workers/%s", ckp->logdir, worker->workername);
				s = json_dumps(val, JSON_NO_UTF8 | JSON_PRESERVE_ORDER | JSON_EOL);
				add_log_entry(&log_entries, &fname, &s);
				json_decref(val);
			}

			/* Decay times per user */
			per_tdiff = tvdiff(&now, &user->last_share);
			if (per_tdiff > 60) {
				decay_user(user, 0, &now);
				idle = true;
			}
			ghs = user->dsps1 * nonces;
			suffix_string(ghs, suffix1, 16, 0);

			ghs = user->dsps5 * nonces;
			suffix_string(ghs, suffix5, 16, 0);

			ghs = user->dsps60 * nonces;
			suffix_string(ghs, suffix60, 16, 0);

			ghs = user->dsps1440 * nonces;
			suffix_string(ghs, suffix1440, 16, 0);

			ghs = user->dsps10080 * nonces;
			suffix_string(ghs, suffix10080, 16, 0);

			copy_tv(&user->last_update, &now);

			JSON_CPACK(val, "{ss,ss,ss,ss,ss,si,si,sI,sf}",
					"hashrate1m", suffix1,
					"hashrate5m", suffix5,
					"hashrate1hr", suffix60,
					"hashrate1d", suffix1440,
					"hashrate7d", suffix10080,
					"lastupdate", now.tv_sec,
					"workers", user->workers,
					"shares", user->shares,
					"bestshare", user->best_diff);

			ASPRINTF(&fname, "%s/users/%s", ckp->logdir, user->username);
			s = json_dumps(val, JSON_NO_UTF8 | JSON_PRESERVE_ORDER | JSON_EOL);
			add_log_entry(&log_entries, &fname, &s);
			if (!idle) {
				s = json_dumps(val, JSON_NO_UTF8 | JSON_PRESERVE_ORDER);
				ASPRINTF(&sp, "User %s:%s", user->username, s);
				dealloc(s);
				add_msg_entry(&char_list, &sp);
			}
			json_decref(val);
		}
		ck_runlock(&sdata->instance_lock);

		/* Dump log entries out of instance_lock */
		dump_log_entries(&log_entries);
		notice_msg_entries(&char_list);

		ghs1 = stats->dsps1 * nonces;
		suffix_string(ghs1, suffix1, 16, 0);

		ghs5 = stats->dsps5 * nonces;
		suffix_string(ghs5, suffix5, 16, 0);

		ghs15 = stats->dsps15 * nonces;
		suffix_string(ghs15, suffix15, 16, 0);

		ghs60 = stats->dsps60 * nonces;
		suffix_string(ghs60, suffix60, 16, 0);

		ghs360 = stats->dsps360 * nonces;
		suffix_string(ghs360, suffix360, 16, 0);

		ghs1440 = stats->dsps1440 * nonces;
		suffix_string(ghs1440, suffix1440, 16, 0);

		ghs10080 = stats->dsps10080 * nonces;
		suffix_string(ghs10080, suffix10080, 16, 0);

		ASPRINTF(&fname, "%s/pool/pool.status", ckp->logdir);
		fp = fopen(fname, "we");
		if (unlikely(!fp))
			LOGERR("Failed to fopen %s", fname);
		dealloc(fname);

		JSON_CPACK(val, "{si,si,si,si,si,si}",
				"runtime", diff.tv_sec,
				"lastupdate", now.tv_sec,
				"Users", stats->users,
				"Workers", stats->workers,
				"Idle", idle_workers,
				"Disconnected", stats->disconnected);
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
				"SPS1m", stats->sps1,
				"SPS5m", stats->sps5,
				"SPS15m", stats->sps15,
				"SPS1h", stats->sps60);
		s = json_dumps(val, JSON_NO_UTF8 | JSON_PRESERVE_ORDER);
		json_decref(val);
		LOGNOTICE("Pool:%s", s);
		fprintf(fp, "%s\n", s);
		dealloc(s);
		fclose(fp);

		if (ckp->proxy && sdata->proxy) {
			proxy_t *proxy, *proxytmp, *subproxy, *subtmp;

			mutex_lock(&sdata->proxy_lock);
			JSON_CPACK(val, "{sI,si,si}",
				   "current", sdata->proxy->id,
				   "active", HASH_COUNT(sdata->proxies),
				   "total", sdata->proxy_count);
			mutex_unlock(&sdata->proxy_lock);

			s = json_dumps(val, JSON_NO_UTF8 | JSON_PRESERVE_ORDER);
			json_decref(val);
			LOGNOTICE("Proxy:%s", s);
			dealloc(s);

			mutex_lock(&sdata->proxy_lock);
			HASH_ITER(hh, sdata->proxies, proxy, proxytmp) {
				JSON_CPACK(val, "{sI,si,sI,sb}",
					   "id", proxy->id,
					   "subproxies", proxy->subproxy_count,
					   "clients", proxy->combined_clients,
					   "alive", !proxy->dead);
				s = json_dumps(val, JSON_NO_UTF8 | JSON_PRESERVE_ORDER);
				json_decref(val);
				ASPRINTF(&sp, "Proxies:%s", s);
				dealloc(s);
				add_msg_entry(&char_list, &sp);
				HASH_ITER(sh, proxy->subproxies, subproxy, subtmp) {
					JSON_CPACK(val, "{sI,si,si,sI,sI,sf,sb}",
						   "id", subproxy->id,
						   "subid", subproxy->subid,
						   "nonce2len", subproxy->nonce2len,
						   "clients", subproxy->bound_clients,
						   "maxclients", subproxy->max_clients,
						   "diff", subproxy->diff,
						   "alive", !subproxy->dead);
					s = json_dumps(val, JSON_NO_UTF8 | JSON_PRESERVE_ORDER);
					json_decref(val);
					ASPRINTF(&sp, "Subproxies:%s", s);
					dealloc(s);
					add_msg_entry(&char_list, &sp);
				}
			}
			mutex_unlock(&sdata->proxy_lock);
			info_msg_entries(&char_list);
		}

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

			decay_time(&stats->sps1, stats->unaccounted_shares, 1.875, MIN1);
			decay_time(&stats->sps5, stats->unaccounted_shares, 1.875, MIN5);
			decay_time(&stats->sps15, stats->unaccounted_shares, 1.875, MIN15);
			decay_time(&stats->sps60, stats->unaccounted_shares, 1.875, HOUR);

			decay_time(&stats->dsps1, stats->unaccounted_diff_shares, 1.875, MIN1);
			decay_time(&stats->dsps5, stats->unaccounted_diff_shares, 1.875, MIN5);
			decay_time(&stats->dsps15, stats->unaccounted_diff_shares, 1.875, MIN15);
			decay_time(&stats->dsps60, stats->unaccounted_diff_shares, 1.875, HOUR);
			decay_time(&stats->dsps360, stats->unaccounted_diff_shares, 1.875, HOUR6);
			decay_time(&stats->dsps1440, stats->unaccounted_diff_shares, 1.875, DAY);
			decay_time(&stats->dsps10080, stats->unaccounted_diff_shares, 1.875, WEEK);

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

static void read_poolstats(ckpool_t *ckp)
{
	char *s = alloca(4096), *pstats, *dsps, *sps;
	sdata_t *sdata = ckp->data;
	pool_stats_t *stats = &sdata->stats;
	int tvsec_diff = 0, ret;
	tv_t now, last;
	json_t *val;
	FILE *fp;

	snprintf(s, 4095, "%s/pool/pool.status", ckp->logdir);
	fp = fopen(s, "re");
	if (!fp) {
		LOGINFO("Pool does not have a logfile to read");
		return;
	}
	memset(s, 0, 4096);
	ret = fread(s, 1, 4095, fp);
	fclose(fp);
	if (ret < 1 || !strlen(s)) {
		LOGDEBUG("No string to read in pool logfile");
		return;
	}
	/* Strip out end of line terminators */
	pstats = strsep(&s, "\n");
	dsps = strsep(&s, "\n");
	sps = strsep(&s, "\n");
	if (!s) {
		LOGINFO("Failed to find EOL in pool logfile");
		return;
	}
	val = json_loads(pstats, 0, NULL);
	if (!val) {
		LOGINFO("Failed to json decode pstats line from pool logfile: %s", pstats);
		return;
	}
	tv_time(&now);
	last.tv_sec = 0;
	json_get_int64(&last.tv_sec, val, "lastupdate");
	json_decref(val);
	LOGINFO("Successfully read pool pstats: %s", pstats);

	val = json_loads(dsps, 0, NULL);
	if (!val) {
		LOGINFO("Failed to json decode dsps line from pool logfile: %s", sps);
		return;
	}
	stats->dsps1 = dsps_from_key(val, "hashrate1m");
	stats->dsps5 = dsps_from_key(val, "hashrate5m");
	stats->dsps15 = dsps_from_key(val, "hashrate15m");
	stats->dsps60 = dsps_from_key(val, "hashrate1hr");
	stats->dsps360 = dsps_from_key(val, "hashrate6hr");
	stats->dsps1440 = dsps_from_key(val, "hashrate1d");
	stats->dsps10080 = dsps_from_key(val, "hashrate7d");
	json_decref(val);
	LOGINFO("Successfully read pool dsps: %s", dsps);

	val = json_loads(sps, 0, NULL);
	if (!val) {
		LOGINFO("Failed to json decode sps line from pool logfile: %s", dsps);
		return;
	}
	json_get_double(&stats->sps1, val, "SPS1m");
	json_get_double(&stats->sps5, val, "SPS5m");
	json_get_double(&stats->sps15, val, "SPS15m");
	json_get_double(&stats->sps60, val, "SPS1h");
	json_decref(val);

	LOGINFO("Successfully read pool sps: %s", sps);
	if (last.tv_sec)
		tvsec_diff = now.tv_sec - last.tv_sec - 60;
	if (tvsec_diff > 60) {
		LOGNOTICE("Old pool stats indicate pool down for %d seconds, decaying stats",
			  tvsec_diff);
		decay_time(&stats->sps1, 0, tvsec_diff, MIN1);
		decay_time(&stats->sps5, 0, tvsec_diff, MIN5);
		decay_time(&stats->sps15, 0, tvsec_diff, MIN15);
		decay_time(&stats->sps60, 0, tvsec_diff, HOUR);

		decay_time(&stats->dsps1, 0, tvsec_diff, MIN1);
		decay_time(&stats->dsps5, 0, tvsec_diff, MIN5);
		decay_time(&stats->dsps15, 0, tvsec_diff, MIN15);
		decay_time(&stats->dsps60, 0, tvsec_diff, HOUR);
		decay_time(&stats->dsps360, 0, tvsec_diff, HOUR6);
		decay_time(&stats->dsps1440, 0, tvsec_diff, DAY);
		decay_time(&stats->dsps10080, 0, tvsec_diff, WEEK);
	}
}

/* Braindead check to see if this btcaddress is an M of N script address which
 * is currently unsupported as a generation address. */
static bool script_address(const char *btcaddress)
{
	return btcaddress[0] == '3';
}

int stratifier(proc_instance_t *pi)
{
	pthread_t pth_blockupdate, pth_statsupdate, pth_heartbeat;
	ckpool_t *ckp = pi->ckp;
	int ret = 1, threads;
	int64_t randomiser;
	char *buf = NULL;
	sdata_t *sdata;

	LOGWARNING("%s stratifier starting", ckp->name);
	sdata = ckzalloc(sizeof(sdata_t));
	ckp->data = sdata;
	sdata->ckp = ckp;
	sdata->verbose = true;

	/* Wait for the generator to have something for us */
	do {
		if (!ping_main(ckp)) {
			ret = 1;
			goto out;
		}
		if (ckp->proxy)
			break;
		buf = send_recv_proc(ckp->generator, "ping");
	} while (!buf);
	dealloc(buf);

	if (!ckp->proxy) {
		if (!test_address(ckp, ckp->btcaddress)) {
			LOGEMERG("Fatal: btcaddress invalid according to bitcoind");
			goto out;
		}

		/* Store this for use elsewhere */
		hex2bin(scriptsig_header_bin, scriptsig_header, 41);
		if (script_address(ckp->btcaddress)) {
			address_to_scripttxn(sdata->pubkeytxnbin, ckp->btcaddress);
			sdata->pubkeytxnlen = 23;
		} else {
			address_to_pubkeytxn(sdata->pubkeytxnbin, ckp->btcaddress);
			sdata->pubkeytxnlen = 25;
		}

		if (test_address(ckp, ckp->donaddress)) {
			ckp->donvalid = true;
			if (script_address(ckp->donaddress)) {
				sdata->donkeytxnlen = 23;
				address_to_scripttxn(sdata->donkeytxnbin, ckp->donaddress);
			} else {
				sdata->donkeytxnlen = 25;
				address_to_pubkeytxn(sdata->donkeytxnbin, ckp->donaddress);
			}
		}
	}

	randomiser = time(NULL);
	sdata->enonce1_64 = htole64(randomiser);
	/* Set the initial id to time as high bits so as to not send the same
	 * id on restarts */
	randomiser <<= 32;
	if (!ckp->proxy)
		sdata->blockchange_id = sdata->workbase_id = randomiser;

	if (!ckp->serverurls) {
		ckp->serverurl[0] = "127.0.0.1";
		ckp->serverurls = 1;
	}
	cklock_init(&sdata->instance_lock);
	cksem_init(&sdata->update_sem);
	cksem_post(&sdata->update_sem);

	mutex_init(&sdata->ckdb_lock);
	mutex_init(&sdata->ckdb_msg_lock);
	/* Create half as many share processing and receiving threads as there
	 * are CPUs */
	threads = sysconf(_SC_NPROCESSORS_ONLN) / 2 ? : 1;
	sdata->sshareq = create_ckmsgqs(ckp, "sprocessor", &sshare_process, threads);
	sdata->ssends = create_ckmsgq(ckp, "ssender", &ssend_process);
	sdata->sauthq = create_ckmsgq(ckp, "authoriser", &sauth_process);
	sdata->stxnq = create_ckmsgq(ckp, "stxnq", &send_transactions);
	sdata->srecvs = create_ckmsgqs(ckp, "sreceiver", &srecv_process, threads);
	if (!CKP_STANDALONE(ckp)) {
		sdata->ckdbq = create_ckmsgq(ckp, "ckdbqueue", &ckdbq_process);
		create_pthread(&pth_heartbeat, ckdb_heartbeat, ckp);
	}
	read_poolstats(ckp);

	cklock_init(&sdata->workbase_lock);
	if (!ckp->proxy)
		create_pthread(&pth_blockupdate, blockupdate, ckp);
	else {
		mutex_init(&sdata->proxy_lock);
	}

	mutex_init(&sdata->stats_lock);
	if (!ckp->passthrough || ckp->node)
		create_pthread(&pth_statsupdate, statsupdate, ckp);

	mutex_init(&sdata->share_lock);
	mutex_init(&sdata->block_lock);

	create_unix_receiver(pi);

	LOGWARNING("%s stratifier ready", ckp->name);

	ret = stratum_loop(ckp, pi);
out:
	if (ckp->proxy) {
		proxy_t *proxy, *tmpproxy;

		mutex_lock(&sdata->proxy_lock);
		HASH_ITER(hh, sdata->proxies, proxy, tmpproxy) {
			HASH_DEL(sdata->proxies, proxy);
			dealloc(proxy);
		}
		mutex_unlock(&sdata->proxy_lock);
	}
	dealloc(ckp->data);
	return process_exit(ckp, pi, ret);
}
