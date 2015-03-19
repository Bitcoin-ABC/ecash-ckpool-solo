/*
 * Copyright 1995-2015 Andrew Smith
 * Copyright 2014 Con Kolivas
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#include "ckdb.h"

/* TODO: any tree/list accessed in new threads needs
 *  to ensure all code using those trees/lists use locks
 * This code's lock implementation is equivalent to table level locking
 * Consider adding row level locking (a per kitem usage count) if needed
 * TODO: verify all tables with multithread access are locked
 */

/* Startup
 * -------
 * During startup we load the DB and track where it is up to with
 *  dbstatus, we then reload "ckpool's ckdb logfiles" (CCLs) based
 *  on dbstatus
 * Once the DB is loaded, we can immediately start receiving ckpool
 *  messages since ckpool already has logged all messages to the CLLs
 *  and ckpool only verifies authorise responses
 *  Thus we can queue all messages:
 *	workinfo, shares, shareerror, ageworkinfo, poolstats, userstats
 *	and blocks
 *  with an ok.queued reply to ckpool, to be processed after the reload
 *  completes and just process authorise messages immediately while the
 *  reload runs
 * We start the ckpool message queue after loading
 *  the users, idcontrol and workers DB tables, before loading the
 *  much larger DB tables so that ckdb is effectively ready for messages
 *  almost immediately
 * The first ckpool message allows us to know where ckpool is up to
 *  in the CCLs and thus where to stop processing the CCLs to stay in
 *  sync with ckpool
 * If ckpool isn't running, then the reload will complete at the end of
 *  the last CCL file, however if the 1st message arrives from ckpool while
 *  processing the CCLs, that will mark the point where to stop processing
 *  but can also produce a fatal error at the end of processing, reporting
 *  the ckpool message, if the message was not found in the CCL processing
 *  after the message was received
 *  This can be caused by two circumstances:
 *  1) the disk had not yet written it to the CCL when ckdb read EOF and
 *	ckpool was started at about the same time as the reload completed.
 *	This can be seen if the message displayed in the fatal error IS NOT
 *	in ckdb's message logfile.
 *	A ckdb restart will resolve this
 *  2) ckpool was started at the time of the end of the reload, but the
 *	message was written to disk and found in the CCL before it was
 *	processed in the message queue.
 *	This can be seen if the message displayed in the fatal error IS in
 *	ckdb's message logfile and means the messages after it in ckdb's
 *	message logfile have already been processed.
 *	Again, a ckdb restart will resolve this
 *  In both the above (very rare) cases, if ckdb was to continue running,
 *  it would break the synchronisation and could cause DB problems, so
 *  ckdb aborting and needing a complete restart resolves it
 * The users table, required for the authorise messages, is always updated
 *  immediately
 */

/* Reload data needed
 * ------------------
 * After the DB load completes, load "ckpool's ckdb logfile" (CCL), and
 * all later CCLs, that contains the oldest date of all of the following:
 *  RAM shares: oldest DB sharesummary firstshare where complete='n'
 *	All shares before this have been summarised to the DB with
 *	complete='a' (or 'y') and were deleted from RAM
 *	If there are none with complete='n' but are others in the DB,
 *	then the newest firstshare is used
 *  RAM shareerrors: as above
 *  DB+RAM sharesummary: created from shares, so as above
 *	Some shares after this may have been summarised to other
 *	sharesummary complete='n', but for any such sharesummary
 *	we reset it back to the first share found and it will
 *	correct itself during the CCL reload
 *	TODO: Verify that all DB sharesummaries with complete='n'
 *	have done this
 *  DB+RAM workinfo: start from newest DB createdate workinfo
 *  RAM auths: none (we store them in RAM only)
 *  DB+RAM poolstats: newest createdate poolstats
 *	TODO: subtract how much we need in RAM of the 'between'
 *	non db records - will depend on TODO: pool stats reporting
 *	requirements
 *  RAM userstats: none (we simply store the last one found)
 *  DB+RAM workers: created by auths so are simply ignore if they
 *	already exist
 *  DB+RAM blocks: resolved by workinfo - any unsaved blocks (if any)
 *	will be after the last DB workinfo
 *  RAM workerstatus: all except last_idle are set at the end of the
 *	CCL reload
 *	Code currently doesn't use last_idle
 *  RAM accountbalance: TODO: created as data is loaded
 *
 *  idcontrol: only userid reuse is critical and the user is added
 *	immeditately to the DB before replying to the add message
 *
 *  Tables that are/will be written straight to the DB, so are OK:
 *	users, useraccounts, paymentaddresses, payments,
 *	accountadjustment, optioncontrol, miningpayouts, payouts,
 *	eventlog, workmarkers, markersummary
 *
 * The code deals with the issue of 'now' when reloading by:
 *  createdate is considered 'now' for all data during a reload and is
 *  a mandatory field always checked for in ckpool data
 * Implementing this is simple by assuming 'now' is always createdate
 *  i.e. during reload but also during normal running to avoid timing
 *  issues with ckpool data
 * Other data supplies the current time to the functions that require
 *  'now' since that data is not part of a reload
 *
 * During reload, any data before the calculated reload stamp for
 *  that data is discarded
 * Any data that matches the reload stamp is processed with an
 *  ignore duplicates flag for all except as below.
 * Any data after the stamp, is processed normally for all except:
 *  1) shares/shareerrors: any record that matches an incomplete DB
 *	sharesummary that hasn't been reset, will reset the sharesummary
 *	so that the sharesummary will be recalculated
 *	The record is processed normally with or without the reset
 *	If the sharesummary is complete, the record is discarded
 *  2) ageworkinfo records are also handled by the shares date
 *	while processing, any records already aged are not updated
 *	and a warning is displayed if there were any matching shares
 *	Any ageworkinfos that match a workmarker are ignored with an error
 *	message
 */

static bool socketer_using_data;
static bool summariser_using_data;
static bool marker_using_data;
static bool logger_using_data;
static bool listener_using_data;

char *EMPTY = "";

static char *db_name;
static char *db_user;
static char *db_pass;

// Currently hard coded at 4 characters
static char *status_chars = "|/-\\";

static char *restorefrom;

// Only accessed in here
static bool markersummary_auto;

int switch_state = SWITCH_STATE_ALL;

// disallow: '/' '.' '_' and FLDSEP
const char *userpatt = "^[^/\\._"FLDSEPSTR"]*$";
const char *mailpatt = "^[A-Za-z0-9_-][A-Za-z0-9_\\.-]*@[A-Za-z0-9][A-Za-z0-9\\.-]*[A-Za-z0-9]$";
const char *idpatt = "^[_A-Za-z][_A-Za-z0-9]*$";
const char *intpatt = "^[0-9][0-9]*$";
const char *hashpatt = "^[A-Fa-f0-9]*$";
/* BTC addresses start with '1' (one) or '3' (three),
 *  exclude: capital 'I' (eye), capital 'O' (oh),
 *  lowercase 'l' (elle) and '0' (zero)
 *  and with a simple test must be ADDR_MIN_LEN to ADDR_MAX_LEN (ckdb.h)
 * bitcoind is used to fully validate them when required */
const char *addrpatt = "^[13][A-HJ-NP-Za-km-z1-9]*$";

// So the records below have the same 'name' as the klist
const char Transfer[] = "Transfer";

// older version missing field defaults
static TRANSFER auth_1 = { "poolinstance", "", auth_1.svalue };
K_ITEM auth_poolinstance = { Transfer, NULL, NULL, (void *)(&auth_1) };
static TRANSFER auth_2 = { "preauth", FALSE_STR, auth_2.svalue };
K_ITEM auth_preauth = { Transfer, NULL, NULL, (void *)(&auth_2) };
static TRANSFER poolstats_1 = { "elapsed", "0", poolstats_1.svalue };
K_ITEM poolstats_elapsed = { Transfer, NULL, NULL, (void *)(&poolstats_1) };
static TRANSFER userstats_1 = { "elapsed", "0", userstats_1.svalue };
K_ITEM userstats_elapsed = { Transfer, NULL, NULL, (void *)(&userstats_1) };
static TRANSFER userstats_2 = { "workername", "all", userstats_2.svalue };
K_ITEM userstats_workername = { Transfer, NULL, NULL, (void *)(&userstats_2) };
static TRANSFER userstats_3 = { "idle", FALSE_STR, userstats_3.svalue };
K_ITEM userstats_idle = { Transfer, NULL, NULL, (void *)(&userstats_3) };
static TRANSFER userstats_4 = { "eos", TRUE_STR, userstats_4.svalue };
K_ITEM userstats_eos = { Transfer, NULL, NULL, (void *)(&userstats_4) };

static TRANSFER shares_1 = { "secondaryuserid", TRUE_STR, shares_1.svalue };
K_ITEM shares_secondaryuserid = { Transfer, NULL, NULL, (void *)(&shares_1) };
static TRANSFER shareerrors_1 = { "secondaryuserid", TRUE_STR, shareerrors_1.svalue };
K_ITEM shareerrors_secondaryuserid = { Transfer, NULL, NULL, (void *)(&shareerrors_1) };
// Time limit that this problem occurred
// 24-Aug-2014 05:20+00 (1st one shortly after this)
tv_t missing_secuser_min = { 1408857600L, 0L };
// 24-Aug-2014 06:00+00
tv_t missing_secuser_max = { 1408860000L, 0L };

LOADSTATUS dbstatus;

POOLSTATUS pool = { 0, START_POOL_HEIGHT, 0, 0, 0, 0, 0, 0 };

// Ensure long long and int64_t are both 8 bytes (and thus also the same)
#define ASSERT1(condition) __maybe_unused static char sizeof_longlong_must_be_8[(condition)?1:-1]
#define ASSERT2(condition) __maybe_unused static char sizeof_int64_t_must_be_8[(condition)?1:-1]
ASSERT1(sizeof(long long) == 8);
ASSERT2(sizeof(int64_t) == 8);

const tv_t default_expiry = { DEFAULT_EXPIRY, 0L };
const tv_t date_eot = { DATE_S_EOT, DATE_uS_EOT };
const tv_t date_begin = { DATE_BEGIN, 0L };

// argv -y - don't run in ckdb mode, just confirm sharesummaries
bool confirm_sharesummary;

/* Optional workinfoid range -Y to supply when confirming sharesummaries
 * N.B. if you specify -Y it will enable -y, so -y isn't also required
 *
 * Default (NULL) is to confirm all aged sharesummaries
 * Default should normally be used every time
 *  The below options are mainly for debugging or
 *   a quicker confirm if required due to not running confirms regularly
 *  TODO: ... once the code includes flagging confirmed sharesummaries
 * Valid options are:
 *	bNNN - confirm all workinfoid's from the previous db block before
 *		NNN (or 0) up to the workinfoid of the 1st db block height
 *		equal or after NNN
 *	wNNN - confirm all workinfoid's from NNN up to the last aged
 *		sharesummary
 *	rNNN-MMM - confirm all workinfoid's from NNN to MMM inclusive
 *	cNNN-MMM - check the CCL record timestamps then exit
 *	i - just show the DB load information then exit
 */
static char *confirm_range;
static int confirm_block;
static int64_t confirm_range_start;
static int64_t confirm_range_finish;
static bool confirm_check_createdate;
static int64_t ccl_mismatch_abs;
static int64_t ccl_mismatch;
static double ccl_mismatch_min;
static double ccl_mismatch_max;
static int64_t ccl_unordered_abs;
static int64_t ccl_unordered;
static double ccl_unordered_most;

// The workinfoid range we are processing
int64_t confirm_first_workinfoid;
int64_t confirm_last_workinfoid;
/* Stop the reload 11min after the 'last' workinfoid+1 appears
 * ckpool uses 10min - but add 1min to be sure */
#define WORKINFO_AGE 660
static tv_t confirm_finish;

static tv_t reload_timestamp;

/* Allow overriding the workinfoid range used in the db load of
 * workinfo and sharesummary */
int64_t dbload_workinfoid_start = -1;
int64_t dbload_workinfoid_finish = MAXID;
// Only restrict sharesummary, not workinfo
bool dbload_only_sharesummary = false;

/* If the above restriction - on sharesummaries - is after the last marks
 *  then this means the sharesummaries can't be summarised into
 *  markersummaries and pplns payouts may not be correct */
bool sharesummary_marks_limit = false;

// DB users,workers load is complete
bool db_users_complete = false;
// DB load is complete
bool db_load_complete = false;
// Different input data handling
bool reloading = false;
// Data load is complete
bool startup_complete = false;
// Tell everyone to die
bool everyone_die = false;

/* These are included in cmd_homepage
 *  to help identify when ckpool locks up (or dies) */
tv_t last_heartbeat;
tv_t last_workinfo;
tv_t last_share;
tv_t last_share_inv;
tv_t last_auth;
cklock_t last_lock;

static cklock_t fpm_lock;
static char *first_pool_message;
static sem_t socketer_sem;

char *btc_server = "http://127.0.0.1:8330";
char *btc_auth;
int btc_timeout = 5;

char *by_default = "code";
char *inet_default = "127.0.0.1";
char *id_default = "42";

// LOGQUEUE
K_LIST *logqueue_free;
K_STORE *logqueue_store;

// WORKQUEUE
K_LIST *workqueue_free;
K_STORE *workqueue_store;
mutex_t wq_waitlock;
pthread_cond_t wq_waitcond;

// HEARTBEATQUEUE
K_LIST *heartbeatqueue_free;
K_STORE *heartbeatqueue_store;

// TRANSFER
K_LIST *transfer_free;

// USERS
K_TREE *users_root;
K_TREE *userid_root;
K_LIST *users_free;
K_STORE *users_store;

// USERATTS
K_TREE *useratts_root;
K_LIST *useratts_free;
K_STORE *useratts_store;

// WORKERS
K_TREE *workers_root;
K_LIST *workers_free;
K_STORE *workers_store;

// PAYMENTADDRESSES
K_TREE *paymentaddresses_root;
K_TREE *paymentaddresses_create_root;
K_LIST *paymentaddresses_free;
K_STORE *paymentaddresses_store;

// PAYMENTS
K_TREE *payments_root;
K_LIST *payments_free;
K_STORE *payments_store;

// ACCOUNTBALANCE
K_TREE *accountbalance_root;
K_LIST *accountbalance_free;
K_STORE *accountbalance_store;

// ACCOUNTADJUSTMENT
K_TREE *accountadjustment_root;
K_LIST *accountadjustment_free;
K_STORE *accountadjustment_store;

// IDCONTROL
// These are only used for db access - not stored in memory
//K_TREE *idcontrol_root;
K_LIST *idcontrol_free;
K_STORE *idcontrol_store;

// OPTIONCONTROL
K_TREE *optioncontrol_root;
K_LIST *optioncontrol_free;
K_STORE *optioncontrol_store;

// WORKINFO workinfo.id.json={...}
K_TREE *workinfo_root;
// created during data load then destroyed since not needed later
K_TREE *workinfo_height_root;
K_LIST *workinfo_free;
K_STORE *workinfo_store;
// one in the current block
K_ITEM *workinfo_current;
// first workinfo of current block
tv_t last_bc;
// current network diff
double current_ndiff;

// SHARES shares.id.json={...}
K_TREE *shares_root;
K_LIST *shares_free;
K_STORE *shares_store;

// SHAREERRORS shareerrors.id.json={...}
K_TREE *shareerrors_root;
K_LIST *shareerrors_free;
K_STORE *shareerrors_store;

// SHARESUMMARY
K_TREE *sharesummary_root;
K_TREE *sharesummary_workinfoid_root;
K_LIST *sharesummary_free;
K_STORE *sharesummary_store;

// BLOCKS block.id.json={...}
const char *blocks_new = "New";
const char *blocks_confirm = "1-Confirm";
const char *blocks_42 = "Matured";
const char *blocks_orphan = "Orphan";
const char *blocks_unknown = "?Unknown?";

K_TREE *blocks_root;
K_LIST *blocks_free;
K_STORE *blocks_store;
tv_t blocks_stats_time;
bool blocks_stats_rebuild = true;

// MININGPAYOUTS
K_TREE *miningpayouts_root;
K_LIST *miningpayouts_free;
K_STORE *miningpayouts_store;

// PAYOUTS
K_TREE *payouts_root;
K_TREE *payouts_id_root;
K_LIST *payouts_free;
K_STORE *payouts_store;
cklock_t process_pplns_lock;

/*
// EVENTLOG
K_TREE *eventlog_root;
K_LIST *eventlog_free;
K_STORE *eventlog_store;
*/

// AUTHS authorise.id.json={...}
K_TREE *auths_root;
K_LIST *auths_free;
K_STORE *auths_store;

// POOLSTATS poolstats.id.json={...}
K_TREE *poolstats_root;
K_LIST *poolstats_free;
K_STORE *poolstats_store;

// USERSTATS userstats.id.json={...}
K_TREE *userstats_root;
K_LIST *userstats_free;
K_STORE *userstats_store;
// Awaiting EOS
K_STORE *userstats_eos_store;

// WORKERSTATUS from various incoming data
K_TREE *workerstatus_root;
K_LIST *workerstatus_free;
K_STORE *workerstatus_store;

// MARKERSUMMARY
K_TREE *markersummary_root;
K_TREE *markersummary_userid_root;
K_LIST *markersummary_free;
K_STORE *markersummary_store;

// WORKMARKERS
K_TREE *workmarkers_root;
K_TREE *workmarkers_workinfoid_root;
K_LIST *workmarkers_free;
K_STORE *workmarkers_store;

// MARKS
K_TREE *marks_root;
K_LIST *marks_free;
K_STORE *marks_store;

const char *marktype_block = "Block End";
const char *marktype_pplns = "Payout Begin";
const char *marktype_shift_begin = "Shift Begin";
const char *marktype_shift_end = "Shift End";
const char *marktype_other_begin = "Other Begin";
const char *marktype_other_finish = "Other Finish";

const char *marktype_block_fmt = "Block %"PRId32" fin";
const char *marktype_pplns_fmt = "Payout %"PRId32" stt";
const char *marktype_shift_begin_fmt = "Shift stt: %s";
const char *marktype_shift_end_fmt = "Shift fin: %s";
const char *marktype_other_begin_fmt = "stt: %s";
const char *marktype_other_finish_fmt = "fin: %s";

// For getting back the shift code/name
const char *marktype_shift_begin_skip = "Shift stt: ";
const char *marktype_shift_end_skip = "Shift fin: ";

static char logname[512];
static char *dbcode;

// low spec version of rotating_log() - no locking
static bool rotating_log_nolock(char *msg)
{
	char *filename;
	FILE *fp;
	bool ok = false;

	filename = rotating_filename(logname, time(NULL));
	fp = fopen(filename, "a+e");
	if (unlikely(!fp)) {
		LOGERR("Failed to fopen %s in rotating_log!", filename);
		goto stageleft;
	}
	fprintf(fp, "%s\n", msg);
	fclose(fp);
	ok = true;

stageleft:
	free(filename);

	return ok;
}

static void log_queue_message(char *msg)
{
	K_ITEM *lq_item;
	LOGQUEUE *lq;

	K_WLOCK(logqueue_free);
	lq_item = k_unlink_head(logqueue_free);
	DATA_LOGQUEUE(lq, lq_item);
	lq->msg = strdup(msg);
	if (!(lq->msg))
		quithere(1, "malloc (%d) OOM", (int)strlen(msg));
	k_add_tail(logqueue_store, lq_item);
	K_WUNLOCK(logqueue_free);
}

void logmsg(int loglevel, const char *fmt, ...)
{
	int logfd = 0;
	char *buf = NULL;
	struct tm tm;
	time_t now_t;
	va_list ap;
	char stamp[128];
	char *extra = EMPTY;
	char tzinfo[16];
	char tzch;
	long minoff, hroff;

	if (loglevel > global_ckp->loglevel)
		return;

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
	snprintf(stamp, sizeof(stamp),
			"[%d-%02d-%02d %02d:%02d:%02d%s]",
			tm.tm_year + 1900,
			tm.tm_mon + 1,
			tm.tm_mday,
			tm.tm_hour,
			tm.tm_min,
			tm.tm_sec,
			tzinfo);

	if (!fmt) {
		fprintf(stderr, "%s %s() called without fmt\n", stamp, __func__);
		return;
	}

	if (!global_ckp)
		extra = " !!NULL global_ckp!!";
	else
		logfd = global_ckp->logfd;

	va_start(ap, fmt);
	VASPRINTF(&buf, fmt, ap);
	va_end(ap);

	if (logfd) {
		FILE *LOGFP = global_ckp->logfp;

		flock(logfd, LOCK_EX);
		fprintf(LOGFP, "%s %s", stamp, buf);
		if (loglevel <= LOG_ERR && errno != 0)
			fprintf(LOGFP, " with errno %d: %s", errno, strerror(errno));
		errno = 0;
		fprintf(LOGFP, "\n");
		flock(logfd, LOCK_UN);
	}
	if (loglevel <= LOG_WARNING) {
		if (loglevel <= LOG_ERR && errno != 0) {
			fprintf(stderr, "%s %s with errno %d: %s%s\n",
					stamp, buf, errno, strerror(errno), extra);
			errno = 0;
		} else
			fprintf(stderr, "%s %s%s\n", stamp, buf, extra);
		fflush(stderr);
	}
	free(buf);
}

void setnow(tv_t *now)
{
	ts_t spec;
	spec.tv_sec = 0;
	spec.tv_nsec = 0;
	clock_gettime(CLOCK_REALTIME, &spec);
	now->tv_sec = spec.tv_sec;
	now->tv_usec = spec.tv_nsec / 1000;
}

// Limits are all +/-1s since on the live machine all were well within that
static void check_createdate_ccl(char *cmd, tv_t *cd)
{
	static tv_t last_cd;
	static char last_cmd[CMD_SIZ+1];
	char cd_buf1[DATE_BUFSIZ], cd_buf2[DATE_BUFSIZ];
	char *filename;
	double td;

	if (cd->tv_sec < reload_timestamp.tv_sec ||
	    cd->tv_sec >= (reload_timestamp.tv_sec + ROLL_S)) {
		ccl_mismatch_abs++;
		td = tvdiff(cd, &reload_timestamp);
		if (td < -1 || td > ROLL_S + 1) {
			ccl_mismatch++;
			filename = rotating_filename("", reload_timestamp.tv_sec);
			tv_to_buf(cd, cd_buf1, sizeof(cd_buf1));
			LOGERR("%s(): CCL contains mismatch data: cmd:%s CCL:%.10s cd:%s",
				__func__, cmd, filename, cd_buf1);
			free(filename);
		}
		if (ccl_mismatch_min > td)
			ccl_mismatch_min = td;
		if (ccl_mismatch_max < td)
			ccl_mismatch_max = td;
	}

	td = tvdiff(cd, &last_cd);
	if (td < 0.0) {
		ccl_unordered_abs++;
		if (ccl_unordered_most > td)
			ccl_unordered_most = td;
	}
	if (td < -1.0) {
		ccl_unordered++;
		tv_to_buf(&last_cd, cd_buf1, sizeof(cd_buf1));
		tv_to_buf(cd, cd_buf2, sizeof(cd_buf2));
		LOGERR("%s(): CCL time unordered: %s<->%s %ld,%ld<->%ld,%ld %s<->%s",
			__func__, last_cmd, cmd, last_cd.tv_sec,last_cd.tv_usec,
			cd->tv_sec, cd->tv_usec, cd_buf1, cd_buf2);
	}

	copy_tv(&last_cd, cd);
	STRNCPY(last_cmd, cmd);
}

static uint64_t ticks;
static time_t last_tick;

void tick()
{
	time_t now;
	char ch;

	now = time(NULL);
	if (now != last_tick) {
		last_tick = now;
		ch = status_chars[ticks++ & 0x3];
		putchar(ch);
		putchar('\r');
		fflush(stdout);
	}
}

PGconn *dbconnect()
{
	char conninfo[256];
	PGconn *conn;
	int i, retry = 10;

	snprintf(conninfo, sizeof(conninfo),
		 "host=127.0.0.1 dbname=%s user=%s%s%s",
		 db_name, db_user,
		 db_pass ? " password=" : "",
		 db_pass ? db_pass : "");

	conn = PQconnectdb(conninfo);
	if (PQstatus(conn) != CONNECTION_OK) {
		LOGERR("%s(): Failed 1st connect to db '%s'", __func__, pqerrmsg(conn));
		LOGERR("%s(): Retrying for %d seconds ...", __func__, retry);
		for (i = 0; i < retry; i++) {
			sleep(1);
			conn = PQconnectdb(conninfo);
			if (PQstatus(conn) == CONNECTION_OK) {
				LOGWARNING("%s(): Connected on attempt %d", __func__, i+2);
				return conn;
			}
		}
		quithere(1, "ERR: Failed to connect %d times to db '%s'",
			 retry+1, pqerrmsg(conn));
	}
	return conn;
}

/* Load tables required to support auths,adduser,chkpass and newid
 * N.B. idcontrol is DB internal so is always ready
 * OptionControl is loaded first in case it is needed by other loads
 *  (though not yet)
 */
static bool getdata1()
{
	PGconn *conn = dbconnect();
	bool ok = true;

	if (!(ok = check_db_version(conn)))
		goto matane;
	if (!(ok = optioncontrol_fill(conn)))
		goto matane;
	if (!(ok = users_fill(conn)))
		goto matane;
	ok = workers_fill(conn);

matane:

	PQfinish(conn);
	return ok;
}

/* Load blocks first to allow data range settings to know
 * the blocks info for setting limits for tables in getdata3()
 */
static bool getdata2()
{
	PGconn *conn = dbconnect();
	bool ok = blocks_fill(conn);

	PQfinish(conn);

	return ok;
}

static bool getdata3()
{
	PGconn *conn = dbconnect();
	bool ok = true;

	if (!confirm_sharesummary) {
		if (!(ok = paymentaddresses_fill(conn)) || everyone_die)
			goto sukamudai;
		if (!(ok = payments_fill(conn)) || everyone_die)
			goto sukamudai;
		if (!(ok = miningpayouts_fill(conn)) || everyone_die)
			goto sukamudai;
		if (!(ok = payouts_fill(conn)) || everyone_die)
			goto sukamudai;
	}
	if (!(ok = workinfo_fill(conn)) || everyone_die)
		goto sukamudai;
	/* marks must be loaded before sharesummary
	 * since sharesummary looks at the marks data */
	if (!(ok = marks_fill(conn)) || everyone_die)
		goto sukamudai;
	if (!(ok = workmarkers_fill(conn)) || everyone_die)
		goto sukamudai;
	if (!(ok = markersummary_fill(conn)) || everyone_die)
		goto sukamudai;
	if (!(ok = sharesummary_fill(conn)) || everyone_die)
		goto sukamudai;
	if (!confirm_sharesummary) {
		if (!(ok = useratts_fill(conn)) || everyone_die)
			goto sukamudai;
		ok = poolstats_fill(conn);
	}

sukamudai:

	PQfinish(conn);
	return ok;
}

static bool reload_from(tv_t *start);

static bool reload()
{
	char buf[DATE_BUFSIZ+1];
	char *filename;
	tv_t start;
	char *reason;
	FILE *fp;

	tv_to_buf(&(dbstatus.oldest_sharesummary_firstshare_n), buf, sizeof(buf));
	LOGWARNING("%s(): %s oldest DB incomplete sharesummary", __func__, buf);
	tv_to_buf(&(dbstatus.newest_sharesummary_firstshare_ay), buf, sizeof(buf));
	LOGWARNING("%s(): %s newest DB complete sharesummary", __func__, buf);
	tv_to_buf(&(dbstatus.newest_createdate_workinfo), buf, sizeof(buf));
	LOGWARNING("%s(): %s newest DB workinfo", __func__, buf);
	tv_to_buf(&(dbstatus.newest_createdate_poolstats), buf, sizeof(buf));
	LOGWARNING("%s(): %s newest DB poolstats", __func__, buf);
	tv_to_buf(&(dbstatus.newest_createdate_blocks), buf, sizeof(buf));
	LOGWARNING("%s(): %s newest DB blocks (ignored)", __func__, buf);

	if (dbstatus.oldest_sharesummary_firstshare_n.tv_sec)
		copy_tv(&(dbstatus.sharesummary_firstshare), &(dbstatus.oldest_sharesummary_firstshare_n));
	else
		copy_tv(&(dbstatus.sharesummary_firstshare), &(dbstatus.newest_sharesummary_firstshare_ay));

	copy_tv(&start, &(dbstatus.sharesummary_firstshare));
	reason = "sharesummary";
	if (!tv_newer(&start, &(dbstatus.newest_createdate_workinfo))) {
		copy_tv(&start, &(dbstatus.newest_createdate_workinfo));
		reason = "workinfo";
	}
	if (!tv_newer(&start, &(dbstatus.newest_createdate_poolstats))) {
		copy_tv(&start, &(dbstatus.newest_createdate_poolstats));
		reason = "poolstats";
	}

	tv_to_buf(&start, buf, sizeof(buf));
	LOGWARNING("%s() restart timestamp %s for %s", __func__, buf, reason);

	if (start.tv_sec < DATE_BEGIN) {
		start.tv_sec = DATE_BEGIN;
		start.tv_usec = 0L;
		filename = rotating_filename(restorefrom, start.tv_sec);
		fp = fopen(filename, "re");
		if (fp)
			fclose(fp);
		else {
			mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
			int fd = open(filename, O_CREAT|O_RDONLY, mode);
			if (fd == -1) {
				int ern = errno;
				quithere(1, "Couldn't create '%s' (%d) %s",
					 filename, ern, strerror(ern));
			}
			close(fd);
		}
		free(filename);
	}
	return reload_from(&start);
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

		LOGWARNING("File %s exists", path);
		fp = fopen(path, "re");
		if (!fp) {
			LOGEMERG("Failed to open file %s", path);
			return false;
		}
		ret = fscanf(fp, "%d", &oldpid);
		fclose(fp);
		if (ret == 1 && !(kill(oldpid, 0))) {
			if (!ckp->killold) {
				LOGEMERG("Process %s pid %d still exists, start ckpool with -k if you wish to kill it",
					 path, oldpid);
				return false;
			}
			if (kill(oldpid, 9)) {
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

static void create_process_unixsock(proc_instance_t *pi)
{
	unixsock_t *us = &pi->us;

	us->path = strdup(pi->ckp->socket_dir);
	realloc_strcat(&us->path, pi->sockname);
	LOGDEBUG("Opening %s", us->path);
	us->sockd = open_unix_server(us->path);
	if (unlikely(us->sockd < 0))
		quit(1, "Failed to open %s socket", pi->sockname);
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

static void clean_up(ckpool_t *ckp)
{
	rm_namepid(&ckp->main);
	dealloc(ckp->socket_dir);
	fclose(ckp->logfp);
}

static void alloc_storage()
{
	workqueue_free = k_new_list("WorkQueue", sizeof(WORKQUEUE),
					ALLOC_WORKQUEUE, LIMIT_WORKQUEUE, true);
	workqueue_store = k_new_store(workqueue_free);

	heartbeatqueue_free = k_new_list("HeartBeatQueue", sizeof(HEARTBEATQUEUE),
					 ALLOC_HEARTBEATQUEUE,
					 LIMIT_HEARTBEATQUEUE, true);
	heartbeatqueue_store = k_new_store(heartbeatqueue_free);

	transfer_free = k_new_list(Transfer, sizeof(TRANSFER),
					ALLOC_TRANSFER, LIMIT_TRANSFER, true);
	transfer_free->dsp_func = dsp_transfer;

	users_free = k_new_list("Users", sizeof(USERS),
					ALLOC_USERS, LIMIT_USERS, true);
	users_store = k_new_store(users_free);
	users_root = new_ktree();
	userid_root = new_ktree();

	useratts_free = k_new_list("Useratts", sizeof(USERATTS),
					ALLOC_USERATTS, LIMIT_USERATTS, true);
	useratts_store = k_new_store(useratts_free);
	useratts_root = new_ktree();

	optioncontrol_free = k_new_list("OptionControl", sizeof(OPTIONCONTROL),
					ALLOC_OPTIONCONTROL,
					LIMIT_OPTIONCONTROL, true);
	optioncontrol_store = k_new_store(optioncontrol_free);
	optioncontrol_root = new_ktree();

	workers_free = k_new_list("Workers", sizeof(WORKERS),
					ALLOC_WORKERS, LIMIT_WORKERS, true);
	workers_store = k_new_store(workers_free);
	workers_root = new_ktree();

	paymentaddresses_free = k_new_list("PaymentAddresses",
					   sizeof(PAYMENTADDRESSES),
					   ALLOC_PAYMENTADDRESSES,
					   LIMIT_PAYMENTADDRESSES, true);
	paymentaddresses_store = k_new_store(paymentaddresses_free);
	paymentaddresses_root = new_ktree();
	paymentaddresses_create_root = new_ktree();
	paymentaddresses_free->dsp_func = dsp_paymentaddresses;

	payments_free = k_new_list("Payments", sizeof(PAYMENTS),
					ALLOC_PAYMENTS, LIMIT_PAYMENTS, true);
	payments_store = k_new_store(payments_free);
	payments_root = new_ktree();

	accountbalance_free = k_new_list("AccountBalance", sizeof(ACCOUNTBALANCE),
					ALLOC_ACCOUNTBALANCE, LIMIT_ACCOUNTBALANCE, true);
	accountbalance_store = k_new_store(accountbalance_free);
	accountbalance_root = new_ktree();

	idcontrol_free = k_new_list("IDControl", sizeof(IDCONTROL),
					ALLOC_IDCONTROL, LIMIT_IDCONTROL, true);
	idcontrol_store = k_new_store(idcontrol_free);

	workinfo_free = k_new_list("WorkInfo", sizeof(WORKINFO),
					ALLOC_WORKINFO, LIMIT_WORKINFO, true);
	workinfo_store = k_new_store(workinfo_free);
	workinfo_root = new_ktree();
	if (!confirm_sharesummary)
		workinfo_height_root = new_ktree();

	shares_free = k_new_list("Shares", sizeof(SHARES),
					ALLOC_SHARES, LIMIT_SHARES, true);
	shares_store = k_new_store(shares_free);
	shares_root = new_ktree();

	shareerrors_free = k_new_list("ShareErrors", sizeof(SHAREERRORS),
					ALLOC_SHAREERRORS, LIMIT_SHAREERRORS, true);
	shareerrors_store = k_new_store(shareerrors_free);
	shareerrors_root = new_ktree();

	sharesummary_free = k_new_list("ShareSummary", sizeof(SHARESUMMARY),
					ALLOC_SHARESUMMARY, LIMIT_SHARESUMMARY, true);
	sharesummary_store = k_new_store(sharesummary_free);
	sharesummary_root = new_ktree();
	sharesummary_workinfoid_root = new_ktree();
	sharesummary_free->dsp_func = dsp_sharesummary;

	blocks_free = k_new_list("Blocks", sizeof(BLOCKS),
					ALLOC_BLOCKS, LIMIT_BLOCKS, true);
	blocks_store = k_new_store(blocks_free);
	blocks_root = new_ktree();
	blocks_free->dsp_func = dsp_blocks;

	miningpayouts_free = k_new_list("MiningPayouts", sizeof(MININGPAYOUTS),
					ALLOC_MININGPAYOUTS, LIMIT_MININGPAYOUTS, true);
	miningpayouts_store = k_new_store(miningpayouts_free);
	miningpayouts_root = new_ktree();

	payouts_free = k_new_list("Payouts", sizeof(PAYOUTS),
					ALLOC_PAYOUTS, LIMIT_PAYOUTS, true);
	payouts_store = k_new_store(payouts_free);
	payouts_root = new_ktree();
	payouts_id_root = new_ktree();

	auths_free = k_new_list("Auths", sizeof(AUTHS),
					ALLOC_AUTHS, LIMIT_AUTHS, true);
	auths_store = k_new_store(auths_free);
	auths_root = new_ktree();

	poolstats_free = k_new_list("PoolStats", sizeof(POOLSTATS),
					ALLOC_POOLSTATS, LIMIT_POOLSTATS, true);
	poolstats_store = k_new_store(poolstats_free);
	poolstats_root = new_ktree();

	userstats_free = k_new_list("UserStats", sizeof(USERSTATS),
					ALLOC_USERSTATS, LIMIT_USERSTATS, true);
	userstats_store = k_new_store(userstats_free);
	userstats_eos_store = k_new_store(userstats_free);
	userstats_root = new_ktree();
	userstats_free->dsp_func = dsp_userstats;

	workerstatus_free = k_new_list("WorkerStatus", sizeof(WORKERSTATUS),
					ALLOC_WORKERSTATUS, LIMIT_WORKERSTATUS, true);
	workerstatus_store = k_new_store(workerstatus_free);
	workerstatus_root = new_ktree();

	markersummary_free = k_new_list("MarkerSummary", sizeof(MARKERSUMMARY),
					ALLOC_MARKERSUMMARY, LIMIT_MARKERSUMMARY, true);
	markersummary_store = k_new_store(markersummary_free);
	markersummary_root = new_ktree();
	markersummary_userid_root = new_ktree();
	markersummary_free->dsp_func = dsp_markersummary;

	workmarkers_free = k_new_list("WorkMarkers", sizeof(WORKMARKERS),
					ALLOC_WORKMARKERS, LIMIT_WORKMARKERS, true);
	workmarkers_store = k_new_store(workmarkers_free);
	workmarkers_root = new_ktree();
	workmarkers_workinfoid_root = new_ktree();
	workmarkers_free->dsp_func = dsp_workmarkers;

	marks_free = k_new_list("Marks", sizeof(MARKS),
				ALLOC_MARKS, LIMIT_MARKS, true);
	marks_store = k_new_store(marks_free);
	marks_root = new_ktree();
}

#define FREE_TREE(_tree) \
	if (_tree ## _root) \
		_tree ## _root = free_ktree(_tree ## _root, NULL) \

#define FREE_STORE(_list) \
	if (_list ## _store) \
		_list ## _store = k_free_store(_list ## _store) \

#define FREE_LIST(_list) \
	if (_list ## _free) \
		_list ## _free = k_free_list(_list ## _free) \

#define FREE_STORE_DATA(_list) \
	if (_list ## _store) { \
		K_ITEM *_item = _list ## _store->head; \
		while (_item) { \
			free_ ## _list ## _data(_item); \
			_item = _item->next; \
		} \
		_list ## _store = k_free_store(_list ## _store); \
	}

#define FREE_LIST_DATA(_list) \
	if (_list ## _free) { \
		K_ITEM *_item = _list ## _free->head; \
		while (_item) { \
			free_ ## _list ## _data(_item); \
			_item = _item->next; \
		} \
		_list ## _free = k_free_list(_list ## _free); \
	}

#define FREE_LISTS(_list) FREE_STORE(_list); FREE_LIST(_list)

#define FREE_ALL(_list) FREE_TREE(_list); FREE_LISTS(_list)

static void dealloc_storage()
{
	LOGWARNING("%s() logqueue ...", __func__);

	FREE_LISTS(logqueue);

	FREE_TREE(marks);
	FREE_STORE_DATA(marks);
	FREE_LIST_DATA(marks);

	FREE_TREE(workmarkers_workinfoid);
	FREE_TREE(workmarkers);
	FREE_STORE_DATA(workmarkers);
	FREE_LIST_DATA(workmarkers);

	LOGWARNING("%s() markersummary ...", __func__);

	FREE_TREE(markersummary_userid);
	FREE_TREE(markersummary);
	FREE_STORE_DATA(markersummary);
	FREE_LIST_DATA(markersummary);

	FREE_ALL(workerstatus);

	LOGWARNING("%s() userstats ...", __func__);

	FREE_STORE(userstats_eos);
	FREE_ALL(userstats);

	LOGWARNING("%s() poolstats ...", __func__);

	FREE_ALL(poolstats);
	FREE_ALL(auths);

	FREE_TREE(payouts_id);
	FREE_ALL(payouts);

	FREE_ALL(miningpayouts);
	FREE_ALL(blocks);

	LOGWARNING("%s() sharesummary ...", __func__);

	FREE_TREE(sharesummary_workinfoid);
	FREE_TREE(sharesummary);
	FREE_STORE_DATA(sharesummary);
	FREE_LIST_DATA(sharesummary);

	FREE_ALL(shareerrors);
	FREE_ALL(shares);

	LOGWARNING("%s() workinfo ...", __func__);

	FREE_TREE(workinfo_height);
	FREE_TREE(workinfo);
	FREE_STORE_DATA(workinfo);
	FREE_LIST_DATA(workinfo);

	FREE_LISTS(idcontrol);
	FREE_ALL(accountbalance);
	FREE_ALL(payments);

	FREE_TREE(paymentaddresses_create);
	FREE_ALL(paymentaddresses);
	FREE_ALL(workers);

	FREE_TREE(optioncontrol);
	FREE_STORE_DATA(optioncontrol);
	FREE_LIST_DATA(optioncontrol);

	FREE_ALL(useratts);

	FREE_TREE(userid);
	FREE_ALL(users);

	LOGWARNING("%s() transfer/heartbeatqueue/workqueue ...", __func__);

	FREE_LIST(transfer);
	FREE_LISTS(heartbeatqueue);
	FREE_LISTS(workqueue);

	LOGWARNING("%s() finished", __func__);
}

static bool setup_data()
{
	K_TREE_CTX ctx[1];
	K_ITEM look, *found;
	WORKINFO wi, *wic, *wif;

	cklock_init(&fpm_lock);
	cksem_init(&socketer_sem);
	mutex_init(&wq_waitlock);
	cond_init(&wq_waitcond);

	alloc_storage();

	if (!getdata1() || everyone_die)
		return false;

	db_users_complete = true;
	cksem_post(&socketer_sem);

	if (!getdata2() || everyone_die)
		return false;

	if (dbload_workinfoid_start != -1) {
		LOGWARNING("WARNING: dbload starting at workinfoid %"PRId64,
			   dbload_workinfoid_start);
		if (dbload_only_sharesummary)
			LOGWARNING("NOTICE: dbload only restricting sharesummary");
	}

	if (!getdata3() || everyone_die)
		return false;

	db_load_complete = true;

	if (!reload() || everyone_die)
		return false;

	set_block_share_counters();

	if (everyone_die)
		return false;

	workerstatus_ready();

	workinfo_current = last_in_ktree(workinfo_height_root, ctx);
	if (workinfo_current) {
		DATA_WORKINFO(wic, workinfo_current);
		STRNCPY(wi.coinbase1, wic->coinbase1);
		wi.createdate.tv_sec = 0L;
		wi.createdate.tv_usec = 0L;
		INIT_WORKINFO(&look);
		look.data = (void *)(&wi);
		// Find the first workinfo for this height
		found = find_after_in_ktree(workinfo_height_root, &look, cmp_workinfo_height, ctx);
		if (found) {
			DATA_WORKINFO(wif, found);
			copy_tv(&last_bc,  &(wif->createdate));
		}
		// No longer needed
		workinfo_height_root = free_ktree(workinfo_height_root, NULL);
	}

	return true;
}

static enum cmd_values breakdown(K_TREE **trf_root, K_STORE **trf_store,
				 char *buf, int *which_cmds, char *cmd,
				 char *id, tv_t *now, tv_t *cd)
{
	char reply[1024] = "";
	TRANSFER *transfer;
	K_TREE_CTX ctx[1];
	K_ITEM *item = NULL;
	char *cmdptr, *idptr, *next, *eq, *end, *was;
	char *data = NULL, *tmp;
	bool noid = false;
	size_t siz;

	*trf_root = NULL;
	*trf_store = NULL;
	*which_cmds = CMD_UNSET;
	*cmd = *id = '\0';
	copy_tv(cd, now); // default cd to 'now'

	cmdptr = strdup(buf);
	idptr = strchr(cmdptr, '.');
	if (!idptr || !*idptr)
		noid = true;
	else {
		*(idptr++) = '\0';
		data = strchr(idptr, '.');
		if (data)
			*(data++) = '\0';
		STRNCPYSIZ(id, idptr, ID_SIZ);
	}

	STRNCPYSIZ(cmd, cmdptr, CMD_SIZ);
	for (*which_cmds = 0; ckdb_cmds[*which_cmds].cmd_val != CMD_END; (*which_cmds)++) {
		if (strcasecmp(cmd, ckdb_cmds[*which_cmds].cmd_str) == 0)
			break;
	}

	if (ckdb_cmds[*which_cmds].cmd_val == CMD_END) {
		LOGERR("Listener received unknown command: '%s'", buf);
		free(cmdptr);
		return CMD_REPLY;
	}

	if (noid) {
		if (ckdb_cmds[*which_cmds].noid) {
			*id = '\0';
			free(cmdptr);
			return ckdb_cmds[*which_cmds].cmd_val;
		}

		STRNCPYSIZ(id, cmdptr, ID_SIZ);
		LOGERR("Listener received invalid (noid) message: '%s'", buf);
		free(cmdptr);
		return CMD_REPLY;
	}

	*trf_root = new_ktree();
	*trf_store = k_new_store(transfer_free);
	next = data;
	if (next && strncmp(next, JSON_TRANSFER, JSON_TRANSFER_LEN) == 0) {
		// It's json
		next += JSON_TRANSFER_LEN;
		was = next;
		while (*next == ' ')
			next++;
		if (*next != JSON_BEGIN) {
			LOGERR("JSON_BEGIN '%c' was: %.32s...",
				JSON_BEGIN, tmp = safe_text(was));
			free(tmp);
			free(cmdptr);
			return CMD_REPLY;
		}
		next++;
		// while we have a new quoted name
		while (*next == JSON_STR) {
			was = next;
			end = ++next;
			// look for the end quote
			while (*end && *end != JSON_STR) {
				if (*(end++) == JSON_ESC)
					end++;
			}
			if (!*end) {
				LOGERR("JSON name no trailing '%c' was: %.32s...",
					JSON_STR, tmp = safe_text(was));
				free(tmp);
				free(cmdptr);
				return CMD_REPLY;
			}
			if (next == end) {
				LOGERR("JSON zero length name was: %.32s...",
					tmp = safe_text(was));
				free(tmp);
				free(cmdptr);
				return CMD_REPLY;
			}
			*(end++) = '\0';
			K_WLOCK(transfer_free);
			item = k_unlink_head(transfer_free);
			K_WUNLOCK(transfer_free);
			DATA_TRANSFER(transfer, item);
			STRNCPY(transfer->name, next);
			was = next = end;
			while (*next == ' ')
				next++;
			// we have a name, now expect a value after it
			if (*next != JSON_VALUE) {
				LOGERR("JSON_VALUE '%c' '%s' was: %.32s...",
					JSON_VALUE, transfer->name,
					tmp = safe_text(was));
				free(tmp);
				free(cmdptr);
				K_WLOCK(transfer_free);
				k_add_head(transfer_free, item);
				K_WUNLOCK(transfer_free);
				return CMD_REPLY;
			}
			was = ++next;
			while (*next == ' ')
				next++;
			if (*next == JSON_STR) {
				end = ++next;
				// A quoted value must have a terminating quote
				while (*end && *end != JSON_STR) {
					if (*(end++) == JSON_ESC)
						end++;
				}
				if (!*end) {
					LOGERR("JSON '%s' value was: %.32s...",
						transfer->name,
						tmp = safe_text(was));
					free(tmp);
					free(cmdptr);
					K_WLOCK(transfer_free);
					k_add_head(transfer_free, item);
					K_WUNLOCK(transfer_free);
					return CMD_REPLY;
				}
				siz = end - next;
				end++;
			} else if (*next == JSON_ARRAY) {
				// Only merklehash for now
				if (strcmp(transfer->name, "merklehash")) {
					LOGERR("JSON '%s' can't be an array",
						transfer->name);
					free(cmdptr);
					K_WLOCK(transfer_free);
					k_add_head(transfer_free, item);
					K_WUNLOCK(transfer_free);
					return CMD_REPLY;
				}
				end = ++next;
				/* No structure testing for now since we
				 *  don't expect merklehash to get it wrong,
				 *  and if it does, it will show up as some
				 *  other error anyway */
				while (*end && *end != JSON_ARRAY_END)
					end++;
				if (end < next+1) {
					LOGERR("JSON '%s' zero length value "
						"was: %.32s...",
						transfer->name,
						tmp = safe_text(was));
					free(tmp);
					free(cmdptr);
					K_WLOCK(transfer_free);
					k_add_head(transfer_free, item);
					K_WUNLOCK(transfer_free);
					return CMD_REPLY;
				}
				siz = end - next;
				end++;
			} else {
				end = next;
				// A non quoted value ends on SEP, END or space
				while (*end && *end != JSON_SEP &&
				       *end != JSON_END && *end != ' ') {
						end++;
				}
				if (!*end) {
					LOGERR("JSON '%s' value was: %.32s...",
						transfer->name,
						tmp = safe_text(was));
					free(tmp);
					free(cmdptr);
					K_WLOCK(transfer_free);
					k_add_head(transfer_free, item);
					K_WUNLOCK(transfer_free);
					return CMD_REPLY;
				}
				if (next == end) {
					LOGERR("JSON '%s' zero length value "
						"was: %.32s...",
						transfer->name,
						tmp = safe_text(was));
					free(tmp);
					free(cmdptr);
					K_WLOCK(transfer_free);
					k_add_head(transfer_free, item);
					K_WUNLOCK(transfer_free);
					return CMD_REPLY;
				}
				siz = end - next;
			}
			if (siz >= sizeof(transfer->svalue)) {
				transfer->mvalue = malloc(siz+1);
				STRNCPYSIZ(transfer->mvalue, next, siz+1);
			} else {
				STRNCPYSIZ(transfer->svalue, next, siz+1);
				transfer->mvalue = transfer->svalue;
			}
			*trf_root = add_to_ktree(*trf_root, item, cmp_transfer);
			k_add_head(*trf_store, item);

			// find the separator then move to the next name
			next = end;
			while (*next == ' ')
				next++;
			if (*next == JSON_SEP) {
				next++;
				while (*next == ' ')
					next++;
			}
		}
		if (*next != JSON_END) {
			LOGERR("JSON_END '%c' was: %.32s...",
				JSON_END, tmp = safe_text(next));
			free(tmp);
			free(cmdptr);
			if (item) {
				K_WLOCK(transfer_free);
				k_add_head(transfer_free, item);
				K_WUNLOCK(transfer_free);
			}
			return CMD_REPLY;
		}
	} else {
		K_WLOCK(transfer_free);
		while (next && *next) {
			data = next;
			next = strchr(data, FLDSEP);
			if (next)
				*(next++) = '\0';

			eq = strchr(data, '=');
			if (!eq)
				eq = EMPTY;
			else
				*(eq++) = '\0';

			item = k_unlink_head(transfer_free);
			DATA_TRANSFER(transfer, item);
			STRNCPY(transfer->name, data);
			STRNCPY(transfer->svalue, eq);
			transfer->mvalue = transfer->svalue;

			if (find_in_ktree(*trf_root, item, cmp_transfer, ctx)) {
				if (transfer->mvalue != transfer->svalue)
					FREENULL(transfer->mvalue);
				k_add_head(transfer_free, item);
			} else {
				*trf_root = add_to_ktree(*trf_root, item, cmp_transfer);
				k_add_head(*trf_store, item);
			}
		}
		K_WUNLOCK(transfer_free);
	}
	if (ckdb_cmds[*which_cmds].createdate) {
		item = require_name(*trf_root, "createdate", 10, NULL, reply, sizeof(reply));
		if (!item) {
			free(cmdptr);
			return CMD_REPLY;
		}

		DATA_TRANSFER(transfer, item);
		txt_to_ctv("createdate", transfer->mvalue, cd, sizeof(*cd));
		if (cd->tv_sec == 0) {
			LOGERR("%s(): failed, %s has invalid createdate '%s'",
				__func__, cmdptr, transfer->mvalue);
			free(cmdptr);
			return CMD_REPLY;
		}
		if (confirm_check_createdate)
			check_createdate_ccl(cmd, cd);
	}
	free(cmdptr);
	return ckdb_cmds[*which_cmds].cmd_val;
}

static void check_blocks()
{
	K_TREE_CTX ctx[1];
	K_ITEM *b_item;
	BLOCKS *blocks;

	K_RLOCK(blocks_free);
	// Find the oldest block BLOCKS_NEW or BLOCKS_CONFIRM
	b_item = first_in_ktree(blocks_root, ctx);
	while (b_item) {
		DATA_BLOCKS(blocks, b_item);
		if (!blocks->ignore &&
		    CURRENT(&(blocks->expirydate)) &&
		    (blocks->confirmed[0] == BLOCKS_NEW ||
		     blocks->confirmed[0] == BLOCKS_CONFIRM))
			break;
		b_item = next_in_ktree(ctx);
	}
	K_RUNLOCK(blocks_free);

	// None
	if (!b_item)
		return;

	btc_blockstatus(blocks);
}

static void pplns_block(BLOCKS *blocks)
{
	if (sharesummary_marks_limit) {
		LOGEMERG("%s() sharesummary marks limit, block %"PRId32" payout skipped",
			 __func__, blocks->height);
		return;
	}

	// Give it a sec after the block summarisation
	sleep(1);

	process_pplns(blocks->height, blocks->blockhash, NULL);
}

static void summarise_blocks()
{
	K_ITEM *b_item, *b_prev, *wi_item, ss_look, *ss_item;
	K_ITEM wm_look, *wm_item, ms_look, *ms_item;
	K_TREE_CTX ctx[1], ss_ctx[1], ms_ctx[1];
	double diffacc, diffinv, shareacc, shareinv;
	tv_t now, elapsed_start, elapsed_finish;
	int64_t elapsed, wi_start, wi_finish;
	BLOCKS *blocks, *prev_blocks;
	WORKINFO *prev_workinfo;
	SHARESUMMARY looksharesummary, *sharesummary;
	WORKMARKERS lookworkmarkers, *workmarkers;
	MARKERSUMMARY lookmarkersummary, *markersummary;
	bool has_ss = false, has_ms = false, ok;
	int32_t hi, prev_hi;

	setnow(&now);

	K_RLOCK(blocks_free);
	// Find the oldest, stats pending, not new, block
	b_item = first_in_ktree(blocks_root, ctx);
	while (b_item) {
		DATA_BLOCKS(blocks, b_item);
		if (CURRENT(&(blocks->expirydate)) &&
		    blocks->statsconfirmed[0] == BLOCKS_STATSPENDING &&
		    blocks->confirmed[0] != BLOCKS_NEW)
			break;
		b_item = next_in_ktree(ctx);
	}
	K_RUNLOCK(blocks_free);

	// None
	if (!b_item)
		return;

	wi_finish = blocks->workinfoid;
	hi = 0;
	K_RLOCK(workinfo_free);
	if (workinfo_current) {
		WORKINFO *wic;
		DATA_WORKINFO(wic, workinfo_current);
		hi = coinbase1height(wic->coinbase1);
	}
	K_RUNLOCK(workinfo_free);

	// Wait at least for the (badly named) '2nd' confirm
	if (hi == 0 || blocks->height >= (hi - 1))
		return;

	diffacc = diffinv = shareacc = shareinv = 0;
	elapsed = 0;
	K_RLOCK(blocks_free);
	b_prev = find_prev_blocks(blocks->height);
	K_RUNLOCK(blocks_free);
	if (!b_prev) {
		wi_start = 0;
		elapsed_start.tv_sec = elapsed_start.tv_usec = 0L;
		prev_hi = 0;
	} else {
		DATA_BLOCKS(prev_blocks, b_prev);
		wi_start = prev_blocks->workinfoid;
		wi_item = find_workinfo(wi_start, NULL);
		if (!wi_item) {
			// This will repeat until fixed ...
			LOGERR("%s() block %d, but prev %d wid "
				"%"PRId64" is missing",
				__func__, blocks->height,
				prev_blocks->height,
				prev_blocks->workinfoid);
			return;
		}
		DATA_WORKINFO(prev_workinfo, wi_item);
		copy_tv(&elapsed_start, &(prev_workinfo->createdate));
		prev_hi = prev_blocks->height;
	}
	elapsed_finish.tv_sec = elapsed_finish.tv_usec = 0L;

	// Add up the sharesummaries, abort if any SUMMARY_NEW
	looksharesummary.workinfoid = wi_finish;
	looksharesummary.userid = MAXID;
	looksharesummary.workername = EMPTY;
	INIT_SHARESUMMARY(&ss_look);
	ss_look.data = (void *)(&looksharesummary);

	// For now, just lock all 3
	K_RLOCK(sharesummary_free);
	K_RLOCK(workmarkers_free);
	K_RLOCK(markersummary_free);

	ss_item = find_before_in_ktree(sharesummary_workinfoid_root, &ss_look,
					cmp_sharesummary_workinfoid, ss_ctx);
	DATA_SHARESUMMARY_NULL(sharesummary, ss_item);
	while (ss_item && sharesummary->workinfoid > wi_start) {
		if (sharesummary->complete[0] == SUMMARY_NEW) {
			// Not aged yet
			K_RUNLOCK(markersummary_free);
			K_RUNLOCK(workmarkers_free);
			K_RUNLOCK(sharesummary_free);
			return;
		}
		has_ss = true;
		if (elapsed_start.tv_sec == 0 ||
		    !tv_newer(&elapsed_start, &(sharesummary->firstshare))) {
			copy_tv(&elapsed_start, &(sharesummary->firstshare));
		}
		if (tv_newer(&elapsed_finish, &(sharesummary->lastshare)))
			copy_tv(&elapsed_finish, &(sharesummary->lastshare));

		diffacc += sharesummary->diffacc;
		diffinv += sharesummary->diffsta + sharesummary->diffdup +
			   sharesummary->diffhi + sharesummary-> diffrej;
		shareacc += sharesummary->shareacc;
		shareinv += sharesummary->sharesta + sharesummary->sharedup +
			    sharesummary->sharehi + sharesummary-> sharerej;

		ss_item = prev_in_ktree(ss_ctx);
		DATA_SHARESUMMARY_NULL(sharesummary, ss_item);
	}

	// Add in the workmarkers...markersummaries
	lookworkmarkers.expirydate.tv_sec = default_expiry.tv_sec;
	lookworkmarkers.expirydate.tv_usec = default_expiry.tv_usec;
	lookworkmarkers.workinfoidend = wi_finish+1;
	INIT_WORKMARKERS(&wm_look);
	wm_look.data = (void *)(&lookworkmarkers);
	wm_item = find_before_in_ktree(workmarkers_workinfoid_root, &wm_look,
				       cmp_workmarkers_workinfoid, ctx);
	DATA_WORKMARKERS_NULL(workmarkers, wm_item);
	while (wm_item &&
	       CURRENT(&(workmarkers->expirydate)) &&
	       workmarkers->workinfoidend > wi_start) {

		if (workmarkers->workinfoidstart < wi_start) {
			LOGEMERG("%s() workmarkers %"PRId64"/%s/%"PRId64
				 "/%"PRId64"/%s/%s crosses block "
				 "%"PRId32"/%"PRId64" boundary",
				 __func__, workmarkers->markerid,
				 workmarkers->poolinstance,
				 workmarkers->workinfoidstart,
				 workmarkers->workinfoidend,
				 workmarkers->description,
				 workmarkers->status, hi, wi_finish);
		}
		if (WMPROCESSED(workmarkers->status)) {
			lookmarkersummary.markerid = workmarkers->markerid;
			lookmarkersummary.userid = MAXID;
			lookmarkersummary.workername = EMPTY;
			INIT_MARKERSUMMARY(&ms_look);
			ms_look.data = (void *)(&lookmarkersummary);
			ms_item = find_before_in_ktree(markersummary_root, &ms_look,
						       cmp_markersummary, ms_ctx);
			DATA_MARKERSUMMARY_NULL(markersummary, ms_item);
			while (ms_item && markersummary->markerid == workmarkers->markerid) {
				has_ms = true;
				if (elapsed_start.tv_sec == 0 ||
				    !tv_newer(&elapsed_start, &(markersummary->firstshare))) {
					copy_tv(&elapsed_start, &(markersummary->firstshare));
				}
				if (tv_newer(&elapsed_finish, &(markersummary->lastshare)))
					copy_tv(&elapsed_finish, &(markersummary->lastshare));

				diffacc += markersummary->diffacc;
				diffinv += markersummary->diffsta + markersummary->diffdup +
					   markersummary->diffhi + markersummary-> diffrej;
				shareacc += markersummary->shareacc;
				shareinv += markersummary->sharesta + markersummary->sharedup +
					    markersummary->sharehi + markersummary-> sharerej;

				ms_item = prev_in_ktree(ms_ctx);
				DATA_MARKERSUMMARY_NULL(markersummary, ms_item);
			}
		}
		wm_item = prev_in_ktree(ctx);
		DATA_WORKMARKERS_NULL(workmarkers, wm_item);
	}

	K_RUNLOCK(markersummary_free);
	K_RUNLOCK(workmarkers_free);
	K_RUNLOCK(sharesummary_free);

	if (!has_ss && !has_ms) {
		// This will repeat each call here until fixed ...
		LOGERR("%s() block %d, after block %d, no sharesummaries "
			"or markersummaries after %"PRId64" up to %"PRId64,
			__func__, blocks->height,
			prev_hi, wi_start, wi_finish);
		return;
	}

	elapsed = (int64_t)(tvdiff(&elapsed_finish, &elapsed_start) + 0.5);
	ok = blocks_stats(NULL, blocks->height, blocks->blockhash,
			  diffacc, diffinv, shareacc, shareinv, elapsed,
			  by_default, (char *)__func__, inet_default, &now);

	if (ok) {
		LOGWARNING("%s() block %d, stats confirmed "
			   "%0.f/%.0f/%.0f/%.0f/%"PRId64,
			   __func__, blocks->height,
			   diffacc, diffinv, shareacc, shareinv, elapsed);

		// Now the summarisation is confirmed, generate the payout data
		pplns_block(blocks);
	} else {
		LOGERR("%s() block %d, failed to confirm stats",
			__func__, blocks->height);
	}
}

static void *summariser(__maybe_unused void *arg)
{
	int i;

	pthread_detach(pthread_self());

	rename_proc("db_summariser");

	while (!everyone_die && !startup_complete)
		cksleep_ms(42);

	summariser_using_data = true;

	while (!everyone_die) {
		for (i = 0; i < 5; i++) {
			if (!everyone_die)
				sleep(1);
		}
		if (everyone_die)
			break;
		else
			check_blocks();

		for (i = 0; i < 4; i++) {
			if (!everyone_die)
				sleep(1);
		}
		if (everyone_die)
			break;
		else
			summarise_blocks();

		for (i = 0; i < 4; i++) {
			if (!everyone_die)
				sleep(1);
		}
	}

	summariser_using_data = false;

	return NULL;
}

#define SHIFT_WORDS 26
static char *shift_words[] =
{
	"akatsuki",
	"belldandy",
	"charlotte",
	"darkchii",
	"elen",
	"felli",
	"gin",
	"hitagi",
	"ichiko",
	"juvia",
	"kosaki",
	"lucy",
	"mutsumi",
	"nodoka",
	"origami",
	"paru",
	"quinn",
	"rika",
	"sena",
	"tsubasa",
	"ur",
	"valentina",
	"winry",
	"xenovia",
	"yuno",
	"zekken"
};

#define ASSERT4(condition) __maybe_unused static char shift_words_must_have_ ## SHIFT_WORDS ## _words[(condition)?1:-1]
ASSERT4((sizeof(shift_words) == (sizeof(char *) * SHIFT_WORDS)));

// Number of workinfoids per shift
#define WID_PER_SHIFT 100

static void make_a_shift_mark()
{
	K_TREE_CTX ss_ctx[1], m_ctx[1], wi_ctx[1], b_ctx[1];
	K_ITEM *ss_item = NULL, *m_item = NULL, *m_sh_item = NULL, *wi_item;
	K_ITEM *b_item = NULL;
	K_ITEM wi_look, ss_look;
	SHARESUMMARY *sharesummary, looksharesummary;
	WORKINFO *workinfo, lookworkinfo;
	BLOCKS *blocks = NULL;
	MARKS *marks = NULL, *sh_marks = NULL;
	int64_t ss_age_wid, last_marks_wid, marks_wid, prev_wid;
	bool was_block = false, ok;
	char cd_buf[DATE_BUFSIZ], cd_buf2[DATE_BUFSIZ];
	int used_wid;

	/* If there are no CURRENT marks, make the first one by
	 *  finding the first CURRENT workinfo and use that
	 *  to create a MARKTYPE_OTHER_BEGIN for the pool
	 * This will keep being checked when the pool first starts
	 *  until the first workinfo is created, but once the first
	 *  marks has been created it will skip over the if code
	 *  forever after that */
	K_RLOCK(marks_free);
	m_item = last_in_ktree(marks_root, m_ctx);
	K_RUNLOCK(marks_free);
	DATA_MARKS_NULL(marks, m_item);
	// Mark sorting means all CURRENT will be on the end
	if (!m_item || !CURRENT(&(marks->expirydate))) {
		K_RLOCK(workinfo_free);
		wi_item = first_in_ktree(workinfo_root, wi_ctx);
		DATA_WORKINFO_NULL(workinfo, wi_item);
		if (!wi_item) {
			K_RUNLOCK(workinfo_free);
			LOGWARNING("%s() ckdb workinfo:'%s' marks:'%s' ..."
				   " start ckpool!", __func__,
				   "none", m_item ? "expired" : "none");
			return;
		}
		while (wi_item && !CURRENT(&(workinfo->expirydate))) {
			wi_item = next_in_ktree(wi_ctx);
			DATA_WORKINFO_NULL(workinfo, wi_item);
		}
		if (!wi_item) {
			K_RUNLOCK(workinfo_free);
			LOGWARNING("%s() ckdb workinfo:'%s' marks:'%s' ..."
				   " start ckpool!", __func__,
				   "expired", m_item ? "expired" : "none");
			return;
		}
		K_RUNLOCK(workinfo_free);
		char description[TXT_BIG+1];
		tv_t now;
		ok = marks_description(description, sizeof(description),
					MARKTYPE_OTHER_BEGIN_STR, 0, NULL,
					"Pool Start");
		if (!ok)
			return;

		setnow(&now);
		ok = marks_process(NULL, true, EMPTY, workinfo->workinfoid,
				   description, EMPTY, MARKTYPE_OTHER_BEGIN_STR,
				   MARK_USED_STR, (char *)by_default,
				   (char *)__func__, (char *)inet_default,
				   &now, NULL);
		if (ok) {
			LOGWARNING("%s() FIRST mark %"PRId64"/%s/%s/%s/",
				   __func__, workinfo->workinfoid,
				   MARKTYPE_OTHER_BEGIN_STR, MARK_USED_STR,
				   description);
		}
		return;
	}

	/* Find the last !new sharesummary workinfoid
	 * If the shift needs to go beyond this, then it's not ready yet */
	ss_age_wid = 0;
	K_RLOCK(sharesummary_free);
	ss_item = first_in_ktree(sharesummary_workinfoid_root, ss_ctx);
	while (ss_item) {
		DATA_SHARESUMMARY(sharesummary, ss_item);
		if (sharesummary->complete[0] == SUMMARY_NEW)
			break;
		if (ss_age_wid < sharesummary->workinfoid)
			ss_age_wid = sharesummary->workinfoid;
		ss_item = next_in_ktree(ss_ctx);
	}
	K_RUNLOCK(sharesummary_free);
	if (ss_item) {
		tv_to_buf(&(sharesummary->lastshare), cd_buf, sizeof(cd_buf));
		tv_to_buf(&(sharesummary->createdate), cd_buf2, sizeof(cd_buf2));
		LOGDEBUG("%s() last sharesummary %s/%s/%"PRId64"/%s/%s",
			 __func__, sharesummary->complete,
			 sharesummary->workername,
			 ss_age_wid, cd_buf, cd_buf2);
	}
	LOGDEBUG("%s() age sharesummary limit wid %"PRId64, __func__, ss_age_wid);

	// Find the last CURRENT mark, the shift starts after this
	K_RLOCK(marks_free);
	m_item = last_in_ktree(marks_root, m_ctx);
	if (m_item) {
		DATA_MARKS(marks, m_item);
		if (!CURRENT(&(marks->expirydate))) {
			/* This means there are no CURRENT marks
			 *  since they are sorted all CURRENT last */
			m_item = NULL;
		} else {
			wi_item = find_workinfo(marks->workinfoid, wi_ctx);
			if (!wi_item) {
				K_RUNLOCK(marks_free);
				LOGEMERG("%s() ERR last mark "
					 "%"PRId64"/%s/%s/%s/%s"
					 " workinfoid is missing!",
					 __func__, marks->workinfoid,
					 marks_marktype(marks->marktype),
					 marks->status, marks->description,
					 marks->extra);
				return;
			}
			/* Find the last shift so we can determine
			 *  the next shift description
			 * This will normally be the last mark,
			 *  but manual marks may change that */
			m_sh_item = m_item;
			while (m_sh_item) {
				DATA_MARKS(sh_marks, m_sh_item);
				if (!CURRENT(&(sh_marks->expirydate))) {
					m_sh_item = NULL;
					break;
				}
				if (sh_marks->marktype[0] == MARKTYPE_SHIFT_END ||
				    sh_marks->marktype[0] == MARKTYPE_SHIFT_BEGIN)
					break;
				m_sh_item = prev_in_ktree(m_ctx);
			}
			if (m_sh_item) {
				wi_item = find_workinfo(sh_marks->workinfoid, wi_ctx);
				if (!wi_item) {
					K_RUNLOCK(marks_free);
					LOGEMERG("%s() ERR last shift mark "
						 "%"PRId64"/%s/%s/%s/%s "
						 "workinfoid is missing!",
						 __func__,
						 sh_marks->workinfoid,
						 marks_marktype(sh_marks->marktype),
						 sh_marks->status,
						 sh_marks->description,
						 sh_marks->extra);
					return;
				}
			}
		}
	}
	K_RUNLOCK(marks_free);

	if (m_item) {
		last_marks_wid = marks->workinfoid;
		LOGDEBUG("%s() last mark %"PRId64"/%s/%s/%s/%s",
			 __func__, marks->workinfoid,
			 marks_marktype(marks->marktype),
			 marks->status, marks->description,
			 marks->extra);
	} else {
		last_marks_wid = 0;
		LOGDEBUG("%s() no last mark", __func__);
	}

	if (m_sh_item) {
		if (m_sh_item == m_item)
			LOGDEBUG("%s() last shift mark = last mark", __func__);
		else {
			LOGDEBUG("%s() last shift mark %"PRId64"/%s/%s/%s/%s",
				 __func__, sh_marks->workinfoid,
				 marks_marktype(sh_marks->marktype),
				 sh_marks->status, sh_marks->description,
				 sh_marks->extra);
		}
	} else
		LOGDEBUG("%s() no last shift mark", __func__);

	if (m_item) {
		/* First block after the last mark
		 * Shift must stop at or before this
		 * N.B. any block, even 'New' */
		K_RLOCK(blocks_free);
		b_item = first_in_ktree(blocks_root, b_ctx);
		while (b_item) {
			DATA_BLOCKS(blocks, b_item);
			if (CURRENT(&(blocks->expirydate)) &&
			    blocks->workinfoid > marks->workinfoid)
				break;
			b_item = next_in_ktree(b_ctx);
		}
		K_RUNLOCK(blocks_free);
	}

	if (b_item) {
		tv_to_buf(&(blocks->createdate), cd_buf, sizeof(cd_buf));
		LOGDEBUG("%s() block after last mark %"PRId32"/%"PRId64"/%s",
			 __func__, blocks->height, blocks->workinfoid,
			 blocks_confirmed(blocks->confirmed));
	} else {
		if (!m_item)
			LOGDEBUG("%s() no last mark = no last block", __func__);
		else
			LOGDEBUG("%s() no block since last mark", __func__);
	}

	INIT_WORKINFO(&wi_look);
	INIT_SHARESUMMARY(&ss_look);

	// Start from the workinfoid after the last mark
	lookworkinfo.workinfoid = last_marks_wid;
	lookworkinfo.expirydate.tv_sec = default_expiry.tv_sec;
	lookworkinfo.expirydate.tv_usec = default_expiry.tv_usec;
	wi_look.data = (void *)(&lookworkinfo);
	K_RLOCK(workinfo_free);
	wi_item = find_after_in_ktree(workinfo_root, &wi_look, cmp_workinfo, wi_ctx);
	K_RUNLOCK(workinfo_free);
	marks_wid = 0;
	used_wid = 0;
	prev_wid = 0;
	while (wi_item) {
		DATA_WORKINFO(workinfo, wi_item);
		if (CURRENT(&(workinfo->expirydate))) {
			/* Did we meet or exceed the !new ss limit?
			 *  for now limit it to BEFORE ss_age_wid
			 * This will mean the shifts are created ~30s later */
			if (workinfo->workinfoid >= ss_age_wid) {
				LOGDEBUG("%s() not enough aged workinfos (%d)",
					 __func__, used_wid);
				return;
			}
			/* Did we find a pool restart? i.e. a wid skip
			 * These will usually be a much larger jump,
			 *  however the pool should never skip any */
			if (prev_wid > 0 &&
			    (workinfo->workinfoid - prev_wid) > 6) {
				marks_wid = prev_wid;
				LOGDEBUG("%s() OK shift stops at pool restart"
					 " count %d(%d) workinfoid %"PRId64
					 " next wid %"PRId64,
					 __func__, used_wid, WID_PER_SHIFT,
					 marks_wid, workinfo->workinfoid);
				break;
			}
			prev_wid = workinfo->workinfoid;
			// Did we hit the next block?
			if (b_item && workinfo->workinfoid == blocks->workinfoid) {
				LOGDEBUG("%s() OK shift stops at block limit",
					 __func__);
				marks_wid = workinfo->workinfoid;
				was_block = true;
				break;
			}
			// Does workinfo have (aged) sharesummaries?
			looksharesummary.workinfoid = workinfo->workinfoid;
			looksharesummary.userid = MAXID;
			looksharesummary.workername = EMPTY;
			ss_look.data = (void *)(&looksharesummary);
			K_RLOCK(sharesummary_free);
			ss_item = find_before_in_ktree(sharesummary_workinfoid_root, &ss_look,
							cmp_sharesummary_workinfoid, ss_ctx);
			K_RUNLOCK(sharesummary_free);
			DATA_SHARESUMMARY_NULL(sharesummary, ss_item);
			if (ss_item &&
			    sharesummary->workinfoid == workinfo->workinfoid) {
				/* Not aged = shift not complete
				 * Though, it shouldn't happen */
				if (sharesummary->complete[0] == SUMMARY_NEW) {
					tv_to_buf(&(sharesummary->lastshare),
						  cd_buf, sizeof(cd_buf));
					tv_to_buf(&(sharesummary->createdate),
						  cd_buf2, sizeof(cd_buf2));
					LOGEMERG("%s() ERR unaged sharesummary "
						 "%s/%s/%"PRId64"/%s/%s",
						 __func__, sharesummary->complete,
						 sharesummary->workername,
						 sharesummary->workinfoid,
						 cd_buf, cd_buf2);
					return;
				}
			}
			if (++used_wid >= WID_PER_SHIFT) {
				// We've got a full shift
				marks_wid = workinfo->workinfoid;
				LOGDEBUG("%s() OK shift stops at count"
					 " %d(%d) workinfoid %"PRId64,
					 __func__, used_wid,
					 WID_PER_SHIFT, marks_wid);
				break;
			}
		}
		K_RLOCK(workinfo_free);
		wi_item = next_in_ktree(wi_ctx);
		K_RUNLOCK(workinfo_free);
	}

	// Create the shift mark
	if (marks_wid) {
		char shift[TXT_BIG+1] = { '\0' };
		char des[TXT_BIG+1] = { '\0' };
		char extra[TXT_BIG+1] = { '\0' };
		char shifttype[TXT_FLAG+1] = { MARKTYPE_SHIFT_END, '\0' };
		char blocktype[TXT_FLAG+1] = { MARKTYPE_BLOCK, '\0' };
		char status[TXT_FLAG+1] = { MARK_READY, '\0' };
		int word = 0;
		char *invalid = NULL, *code, *space;
		const char *skip = NULL;
		size_t len;
		tv_t now;

		/* Shift description is shiftcode(createdate)
		 *  + a space + shift_words
		 * shift_words is incremented every shift */
		if (m_sh_item) {
			skip = NULL;
			switch (sh_marks->marktype[0]) {
				case MARKTYPE_BLOCK:
				case MARKTYPE_PPLNS:
				case MARKTYPE_OTHER_BEGIN:
				case MARKTYPE_OTHER_FINISH:
					// Reset
					word = 0;
					break;
				case MARKTYPE_SHIFT_END:
					skip = marktype_shift_end_skip;
					break;
				case MARKTYPE_SHIFT_BEGIN:
					skip = marktype_shift_begin_skip;
					break;
				default:
					invalid = "unkown marktype";
					break;
			}
			if (skip) {
				len = strlen(skip);
				if (strncmp(sh_marks->description, skip, len) != 0)
					invalid = "inv des (skip)";
				else {
					code = sh_marks->description + len;
					space = strchr(code, ' ');
					if (!space)
						invalid = "inv des (space)";
					else {
						space++;
						if (*space < 'a' || *space > 'z')
							invalid = "inv des (a-z)";
						else
							word = (*space - 'a' + 1) % SHIFT_WORDS;
					}
				}
			}
			if (invalid) {
				LOGEMERG("%s() ERR %s mark %"PRId64"/%s/%s/%s",
					 __func__, invalid,
					 sh_marks->workinfoid,
					 marks_marktype(sh_marks->marktype),
					 sh_marks->status,
					 sh_marks->description);
				return;
			}
		}
		snprintf(shift, sizeof(shift), "%s %s",
			 shiftcode(&(workinfo->createdate)),
			 shift_words[word]);

		LOGDEBUG("%s() shift='%s'", __func__, shift);

		if (!marks_description(des, sizeof(des), shifttype, 0, shift, NULL))
			return;

		LOGDEBUG("%s() des='%s'", __func__, des);

		if (was_block) {
			// Put the block description in extra
			if (!marks_description(extra, sizeof(extra), blocktype,
						blocks->height, NULL, NULL))
				return;

			LOGDEBUG("%s() extra='%s'", __func__, extra);
		}

		setnow(&now);
		ok = marks_process(NULL, true, EMPTY, marks_wid, des, extra,
				   shifttype, status, (char *)by_default,
				   (char *)__func__, (char *)inet_default,
				   &now, NULL);

		if (ok) {
			LOGWARNING("%s() mark %"PRId64"/%s/%s/%s/%s/",
				   __func__, marks_wid, shifttype, status,
				   des, extra);
		}
	} else
		LOGDEBUG("%s() no marks wid", __func__);
}

static void make_a_workmarker()
{
	char msg[1024] = "";
	tv_t now;
	bool ok;

	setnow(&now);
	ok = workmarkers_generate(NULL, msg, sizeof(msg),
				  (char *)by_default, (char *)__func__,
				  (char *)inet_default, &now, NULL, false);
	if (!ok)
		LOGERR("%s() ERR %s", __func__, msg);
}

static void *marker(__maybe_unused void *arg)
{
	int i;

	pthread_detach(pthread_self());

	rename_proc("db_marker");

	while (!everyone_die && !startup_complete)
		cksleep_ms(42);

	if (sharesummary_marks_limit) {
		LOGEMERG("%s() ALERT: dbload -w disables shift processing",
			 __func__);
		return NULL;
	}

	marker_using_data = true;

/* TODO: trigger this every workinfo change?
 *  note that history catch up would also mean the tigger would
 *  catch up at most 100 missing marks per shift
 *  however, also, a workinfo change means a sharesummary DB update,
 *  so would be best to (usually) wait until that is done
 * OR: avoid writing the sharesummaries to the DB at all
 *  and only write the markersummaries? - since 100 workinfoid shifts
 *  will usually mean that markersummaries are less than every hour
 *  (and a reload processes more than an hour) */

	while (!everyone_die) {
		for (i = 0; i < 5; i++) {
			if (!everyone_die)
				sleep(1);
		}
		if (everyone_die)
			break;
		else
			make_a_shift_mark();

		for (i = 0; i < 4; i++) {
			if (!everyone_die)
				sleep(1);
		}
		if (everyone_die)
			break;
		else
			make_a_workmarker();

		for (i = 0; i < 4; i++) {
			if (!everyone_die)
				sleep(1);
		}
		if (everyone_die)
			break;
		else {
			if (markersummary_auto)
				make_markersummaries(false, NULL, NULL, NULL, NULL, NULL);
		}
	}

	marker_using_data = false;

	return NULL;
}

static void *logger(__maybe_unused void *arg)
{
	K_ITEM *lq_item;
	LOGQUEUE *lq;
	char buf[128];
	tv_t now, then;
	int count;

	pthread_detach(pthread_self());

	snprintf(buf, sizeof(buf), "db%s_logger", dbcode);
	rename_proc(buf);

	logger_using_data = true;

	setnow(&now);
	snprintf(buf, sizeof(buf), "logstart.%ld,%ld",
				   now.tv_sec, now.tv_usec);
	LOGFILE(buf);

	while (!everyone_die) {
		K_WLOCK(logqueue_free);
		lq_item = k_unlink_head(logqueue_store);
		K_WUNLOCK(logqueue_free);
		while (lq_item) {
			DATA_LOGQUEUE(lq, lq_item);
			LOGFILE(lq->msg);
			FREENULL(lq->msg);

			K_WLOCK(logqueue_free);
			k_add_head(logqueue_free, lq_item);
			if (!everyone_die)
				lq_item = k_unlink_head(logqueue_store);
			else
				lq_item = NULL;
			K_WUNLOCK(logqueue_free);
		}
		cksleep_ms(42);
	}

	K_WLOCK(logqueue_free);
	count = logqueue_store->count;
	setnow(&now);
	snprintf(buf, sizeof(buf), "logstopping.%d.%ld,%ld",
				   count, now.tv_sec, now.tv_usec);
	LOGFILE(buf);
	if (count)
		LOGERR("%s", buf);
	lq_item = logqueue_store->head;
	copy_tv(&then, &now);
	while (lq_item) {
		DATA_LOGQUEUE(lq, lq_item);
		LOGFILE(lq->msg);
		FREENULL(lq->msg);
		count--;
		setnow(&now);
		if ((now.tv_sec - then.tv_sec) > 10) {
			snprintf(buf, sizeof(buf), "logging ... %d", count);
			LOGERR("%s", buf);
			copy_tv(&then, &now);
		}
		lq_item = lq_item->next;
	}
	K_WUNLOCK(logqueue_free);

	logger_using_data = false;

	setnow(&now);
	snprintf(buf, sizeof(buf), "logstop.%ld,%ld",
				   now.tv_sec, now.tv_usec);
	LOGFILE(buf);
	LOGWARNING("%s", buf);

	return NULL;
}

#define STORELASTREPLY(_cmd) do { \
		if (last_ ## _cmd) \
			free(last_ ## _cmd); \
		last_ ## _cmd = buf; \
		buf = NULL; \
		if (reply_ ## _cmd) \
			free(reply_ ## _cmd); \
		reply_ ## _cmd = rep; \
	} while (0)

static void *socketer(__maybe_unused void *arg)
{
	proc_instance_t *pi = (proc_instance_t *)arg;
	unixsock_t *us = &pi->us;
	char *end, *ans = NULL, *rep = NULL, *buf = NULL, *dot;
	char cmd[CMD_SIZ+1], id[ID_SIZ+1], reply[1024+1];
	char *last_auth = NULL, *reply_auth = NULL;
	char *last_addrauth = NULL, *reply_addrauth = NULL;
	char *last_chkpass = NULL, *reply_chkpass = NULL;
	char *last_adduser = NULL, *reply_adduser = NULL;
	char *last_newpass = NULL, *reply_newpass = NULL;
	char *last_userset = NULL, *reply_userset = NULL;
	char *last_workerset = NULL, *reply_workerset = NULL;
	char *last_newid = NULL, *reply_newid = NULL;
	char *last_setatts = NULL, *reply_setatts = NULL;
	char *last_setopts = NULL, *reply_setopts = NULL;
	char *last_userstatus = NULL, *reply_userstatus = NULL;
	char *last_web = NULL, *reply_web = NULL;
	char *reply_last, duptype[CMD_SIZ+1];
	enum cmd_values cmdnum;
	int sockd, which_cmds;
	WORKQUEUE *workqueue;
	TRANSFER *transfer;
	K_STORE *trf_store;
	K_TREE *trf_root;
	K_ITEM *item;
	size_t siz;
	tv_t now, cd;
	bool dup, want_first, show_dup;
	int loglevel, oldloglevel;

	pthread_detach(pthread_self());

	rename_proc("db_socketer");

	while (!everyone_die && !db_users_complete)
		cksem_mswait(&socketer_sem, 420);

	socketer_using_data = true;

	want_first = true;
	while (!everyone_die) {
		if (buf)
			dealloc(buf);
		sockd = accept(us->sockd, NULL, NULL);
		if (sockd < 0) {
			LOGERR("Failed to accept on socket in listener");
			break;
		}

		cmdnum = CMD_UNSET;
		trf_root = NULL;
		trf_store = NULL;

		buf = recv_unix_msg(sockd);
		// Once we've read the message
		setnow(&now);
		if (buf) {
			end = buf + strlen(buf) - 1;
			// strip trailing \n and \r
			while (end >= buf && (*end == '\n' || *end == '\r'))
				*(end--) = '\0';
		}
		if (!buf || !*buf) {
			// An empty message wont get a reply
			if (!buf)
				LOGWARNING("Failed to get message in listener");
			else
				LOGWARNING("Empty message in listener");
		} else {
			/* For duplicates:
			 *  Queued pool messages are handled by the queue code
			 *   but since they reply ok.queued that message can
			 *   be returned every time here
			 *  System: repeat process them
			 *  Web: current php web sends a timestamp of seconds
			 *	 so duplicate code will only trigger if the same
			 *	 message is sent within the same second and thus
			 *	 will effectively reduce the processing load for
			 *	 sequential duplicates
			 *   As per the 'if' list below,
			 *    remember individual last messages and replies and
			 *    repeat the reply without reprocessing the message
			 *   The rest are remembered in the same buffer 'web'
			 *    so a duplicate will not be seen if another 'web'
			 *    command arrived between two duplicate commands
			 */
			dup = false;
			show_dup = true;
			// These are ordered approximately most likely first
			if (last_auth && strcmp(last_auth, buf) == 0) {
				reply_last = reply_auth;
				dup = true;
			} else if (last_chkpass && strcmp(last_chkpass, buf) == 0) {
				reply_last = reply_chkpass;
				dup = true;
			} else if (last_adduser && strcmp(last_adduser, buf) == 0) {
				reply_last = reply_adduser;
				dup = true;
			} else if (last_newpass && strcmp(last_newpass, buf) == 0) {
				reply_last = reply_newpass;
				dup = true;
			} else if (last_newid && strcmp(last_newid, buf) == 0) {
				reply_last = reply_newid;
				dup = true;
			} else if (last_addrauth && strcmp(last_addrauth, buf) == 0) {
				reply_last = reply_addrauth;
				dup = true;
			} else if (last_userset && strcmp(last_userset, buf) == 0) {
				reply_last = reply_userset;
				dup = true;
			} else if (last_workerset && strcmp(last_workerset, buf) == 0) {
				reply_last = reply_workerset;
				dup = true;
			} else if (last_setatts && strcmp(last_setatts, buf) == 0) {
				reply_last = reply_setatts;
				dup = true;
			} else if (last_setopts && strcmp(last_setopts, buf) == 0) {
				reply_last = reply_setopts;
				dup = true;
			} else if (last_userstatus && strcmp(last_userstatus, buf) == 0) {
				reply_last = reply_userstatus;
				dup = true;
			} else if (last_web && strcmp(last_web, buf) == 0) {
				reply_last = reply_web;
				dup = true;
				show_dup = false;
			}
			if (dup) {
				send_unix_msg(sockd, reply_last);
				STRNCPY(duptype, buf);
				dot = strchr(duptype, '.');
				if (dot)
					*dot = '\0';
				snprintf(reply, sizeof(reply), "%s%ld,%ld.%s",
					 LOGDUP, now.tv_sec, now.tv_usec, duptype);
				LOGQUE(reply);
				if (show_dup)
					LOGWARNING("Duplicate '%s' message received", duptype);
				else
					LOGDEBUG("Duplicate '%s' message received", duptype);
			} else {
				LOGQUE(buf);
				cmdnum = breakdown(&trf_root, &trf_store, buf, &which_cmds, cmd, id, &now, &cd);
				switch (cmdnum) {
					case CMD_REPLY:
						snprintf(reply, sizeof(reply), "%s.%ld.?.", id, now.tv_sec);
						send_unix_msg(sockd, reply);
						break;
					case CMD_SHUTDOWN:
						LOGWARNING("Listener received shutdown message, terminating ckdb");
						snprintf(reply, sizeof(reply), "%s.%ld.ok.exiting", id, now.tv_sec);
						send_unix_msg(sockd, reply);
						everyone_die = true;
						break;
					case CMD_PING:
						LOGDEBUG("Listener received ping request");
						snprintf(reply, sizeof(reply), "%s.%ld.ok.pong", id, now.tv_sec);
						send_unix_msg(sockd, reply);
						break;
					case CMD_VERSION:
						LOGDEBUG("Listener received version request");
						snprintf(reply, sizeof(reply),
							 "%s.%ld.ok.CKDB V%s",
							 id, now.tv_sec, CKDB_VERSION);
						send_unix_msg(sockd, reply);
						break;
					case CMD_LOGLEVEL:
						if (!*id) {
							LOGDEBUG("Listener received loglevel, currently %d",
								 pi->ckp->loglevel);
							snprintf(reply, sizeof(reply),
								 "%s.%ld.ok.loglevel currently %d",
								 id, now.tv_sec,
								 pi->ckp->loglevel);
						} else {
							oldloglevel = pi->ckp->loglevel;
							loglevel = atoi(id);
							LOGDEBUG("Listener received loglevel %d currently %d A",
								 loglevel, oldloglevel);
							if (loglevel < LOG_EMERG || loglevel > LOG_DEBUG) {
								snprintf(reply, sizeof(reply),
									 "%s.%ld.ERR.invalid loglevel %d"
									 " - currently %d",
									 id, now.tv_sec,
									 loglevel, oldloglevel);
							} else {
								pi->ckp->loglevel = loglevel;
								snprintf(reply, sizeof(reply),
									 "%s.%ld.ok.loglevel now %d - was %d",
									 id, now.tv_sec,
									 pi->ckp->loglevel, oldloglevel);
							}
							// Do this twice since the loglevel may have changed
							LOGDEBUG("Listener received loglevel %d currently %d B",
								 loglevel, oldloglevel);
						}
						send_unix_msg(sockd, reply);
						break;
					case CMD_FLUSH:
						LOGDEBUG("Listener received flush request");
						snprintf(reply, sizeof(reply),
							 "%s.%ld.ok.splash",
							 id, now.tv_sec);
						send_unix_msg(sockd, reply);
						fflush(stdout);
						fflush(stderr);
						if (global_ckp && global_ckp->logfd)
							fflush(global_ckp->logfp);
						break;
					// Always process immediately:
					case CMD_AUTH:
					case CMD_ADDRAUTH:
					case CMD_HEARTBEAT:
						// First message from the pool
						if (want_first) {
							ck_wlock(&fpm_lock);
							first_pool_message = strdup(buf);
							ck_wunlock(&fpm_lock);
							want_first = false;
						}
					case CMD_CHKPASS:
					case CMD_ADDUSER:
					case CMD_NEWPASS:
					case CMD_USERSET:
					case CMD_WORKERSET:
					case CMD_GETATTS:
					case CMD_SETATTS:
					case CMD_EXPATTS:
					case CMD_GETOPTS:
					case CMD_SETOPTS:
					case CMD_BLOCKLIST:
					case CMD_NEWID:
					case CMD_STATS:
					case CMD_USERSTATUS:
						ans = ckdb_cmds[which_cmds].func(NULL, cmd, id, &now,
										 by_default,
										 (char *)__func__,
										 inet_default,
										 &cd, trf_root);
						siz = strlen(ans) + strlen(id) + 32;
						rep = malloc(siz);
						snprintf(rep, siz, "%s.%ld.%s", id, now.tv_sec, ans);
						send_unix_msg(sockd, rep);
						FREENULL(ans);
						switch (cmdnum) {
							case CMD_AUTH:
								STORELASTREPLY(auth);
								break;
							case CMD_ADDRAUTH:
								STORELASTREPLY(addrauth);
								break;
							case CMD_CHKPASS:
								STORELASTREPLY(chkpass);
								break;
							case CMD_ADDUSER:
								STORELASTREPLY(adduser);
								break;
							case CMD_NEWPASS:
								STORELASTREPLY(newpass);
								break;
							case CMD_USERSET:
								STORELASTREPLY(userset);
								break;
							case CMD_WORKERSET:
								STORELASTREPLY(workerset);
								break;
							case CMD_NEWID:
								STORELASTREPLY(newid);
								break;
							case CMD_SETATTS:
								STORELASTREPLY(setatts);
								break;
							case CMD_SETOPTS:
								STORELASTREPLY(setopts);
								break;
							case CMD_USERSTATUS:
								STORELASTREPLY(userstatus);
								break;
							// The rest
							default:
								free(rep);
						}
						rep = NULL;
						break;
					// Process, but reject (loading) until startup_complete
					case CMD_HOMEPAGE:
					case CMD_ALLUSERS:
					case CMD_WORKERS:
					case CMD_PAYMENTS:
					case CMD_PPLNS:
					case CMD_PPLNS2:
					case CMD_PAYOUTS:
					case CMD_MPAYOUTS:
					case CMD_SHIFTS:
					case CMD_DSP:
					case CMD_BLOCKSTATUS:
						if (!startup_complete) {
							snprintf(reply, sizeof(reply),
								 "%s.%ld.loading.%s",
								 id, now.tv_sec, cmd);
							send_unix_msg(sockd, reply);
						} else {
							ans = ckdb_cmds[which_cmds].func(NULL, cmd, id, &now,
											 by_default,
											 (char *)__func__,
											 inet_default,
											 &cd, trf_root);
							siz = strlen(ans) + strlen(id) + 32;
							rep = malloc(siz);
							snprintf(rep, siz, "%s.%ld.%s", id, now.tv_sec, ans);
							send_unix_msg(sockd, rep);
							FREENULL(ans);
							if (cmdnum == CMD_DSP)
								free(rep);
							else {
								if (last_web)
									free(last_web);
								last_web = buf;
								buf = NULL;
								if (reply_web)
									free(reply_web);
								reply_web = rep;
							}
							rep = NULL;
						}
						break;
					/* Process, but reject (loading) until startup_complete
					 * and don't test for duplicates */
					case CMD_MARKS:
						if (!startup_complete) {
							snprintf(reply, sizeof(reply),
								 "%s.%ld.loading.%s",
								 id, now.tv_sec, cmd);
							send_unix_msg(sockd, reply);
						} else {
							ans = ckdb_cmds[which_cmds].func(NULL, cmd, id, &now,
											 by_default,
											 (char *)__func__,
											 inet_default,
											 &cd, trf_root);
							siz = strlen(ans) + strlen(id) + 32;
							rep = malloc(siz);
							snprintf(rep, siz, "%s.%ld.%s", id, now.tv_sec, ans);
							send_unix_msg(sockd, rep);
							FREENULL(ans);
							FREENULL(rep);
						}
						break;
					// Always queue (ok.queued)
					case CMD_SHARELOG:
					case CMD_POOLSTAT:
					case CMD_USERSTAT:
					case CMD_WORKERSTAT:
					case CMD_BLOCK:
						// First message from the pool
						if (want_first) {
							ck_wlock(&fpm_lock);
							first_pool_message = strdup(buf);
							ck_wunlock(&fpm_lock);
							want_first = false;
						}

						snprintf(reply, sizeof(reply),
							 "%s.%ld.ok.queued",
							 id, now.tv_sec);
						send_unix_msg(sockd, reply);

						K_WLOCK(workqueue_free);
						item = k_unlink_head(workqueue_free);
						K_WUNLOCK(workqueue_free);

						DATA_WORKQUEUE(workqueue, item);
						workqueue->buf = buf;
						buf = NULL;
						workqueue->which_cmds = which_cmds;
						workqueue->cmdnum = cmdnum;
						STRNCPY(workqueue->cmd, cmd);
						STRNCPY(workqueue->id, id);
						copy_tv(&(workqueue->now), &now);
						STRNCPY(workqueue->by, by_default);
						STRNCPY(workqueue->code, __func__);
						STRNCPY(workqueue->inet, inet_default);
						copy_tv(&(workqueue->cd), &cd);
						workqueue->trf_root = trf_root;
						trf_root = NULL;
						workqueue->trf_store = trf_store;
						trf_store = NULL;

						K_WLOCK(workqueue_free);
						k_add_tail(workqueue_store, item);
						K_WUNLOCK(workqueue_free);
						mutex_lock(&wq_waitlock);
						pthread_cond_signal(&wq_waitcond);
						mutex_unlock(&wq_waitlock);
						break;
					// Code error
					default:
						LOGEMERG("%s() CODE ERROR unhandled message %d %.32s...",
							 __func__, cmdnum, buf);
						snprintf(reply, sizeof(reply),
							 "%s.%ld.failed.code",
							 id, now.tv_sec);
						send_unix_msg(sockd, reply);
						break;
				}
			}
		}
		close(sockd);

		tick();

		if (trf_root)
			trf_root = free_ktree(trf_root, NULL);
		if (trf_store) {
			item = trf_store->head;
			while (item) {
				DATA_TRANSFER(transfer, item);
				if (transfer->mvalue != transfer->svalue)
					FREENULL(transfer->mvalue);
				item = item->next;
			}
			K_WLOCK(transfer_free);
			k_list_transfer_to_head(trf_store, transfer_free);
			trf_store = k_free_store(trf_store);
			if (transfer_free->count == transfer_free->total &&
			    transfer_free->total > ALLOC_TRANSFER * CULL_TRANSFER)
				k_cull_list(transfer_free);
			K_WUNLOCK(transfer_free);
		}
	}

	socketer_using_data = false;

	if (buf)
		dealloc(buf);
	// TODO: if anyone cares, free all the dup buffers :P
	close_unix_socket(us->sockd, us->path);

	return NULL;
}

static bool reload_line(PGconn *conn, char *filename, uint64_t count, char *buf)
{
	char cmd[CMD_SIZ+1], id[ID_SIZ+1];
	enum cmd_values cmdnum;
	char *end, *ans;
	int which_cmds;
	K_STORE *trf_store = NULL;
	K_TREE *trf_root = NULL;
	TRANSFER *transfer;
	K_ITEM *item;
	tv_t now, cd;
	bool finished;

	// Once we've read the message
	setnow(&now);
	if (buf) {
		end = buf + strlen(buf) - 1;
		// strip trailing \n and \r
		while (end >= buf && (*end == '\n' || *end == '\r'))
			*(end--) = '\0';
	}
	if (!buf || !*buf) {
		if (!buf)
			LOGERR("%s() NULL message line %"PRIu64, __func__, count);
		else
			LOGERR("%s() Empty message line %"PRIu64, __func__, count);
	} else {
		finished = false;
		ck_wlock(&fpm_lock);
		if (first_pool_message && strcmp(first_pool_message, buf) == 0)
			finished = true;
		ck_wunlock(&fpm_lock);
		if (finished) {
			LOGERR("%s() reload completed, ckpool queue match at line %"PRIu64, __func__, count);
			return true;
		}

		LOGQUE(buf);
		cmdnum = breakdown(&trf_root, &trf_store, buf, &which_cmds, cmd, id, &now, &cd);
		switch (cmdnum) {
			// Ignore
			case CMD_REPLY:
				break;
			// Shouldn't be there
			case CMD_SHUTDOWN:
			case CMD_PING:
			case CMD_VERSION:
			case CMD_LOGLEVEL:
			case CMD_FLUSH:
			// Non pool commands, shouldn't be there
			case CMD_ADDUSER:
			case CMD_NEWPASS:
			case CMD_CHKPASS:
			case CMD_USERSET:
			case CMD_WORKERSET:
			case CMD_BLOCKLIST:
			case CMD_BLOCKSTATUS:
			case CMD_NEWID:
			case CMD_PAYMENTS:
			case CMD_WORKERS:
			case CMD_ALLUSERS:
			case CMD_HOMEPAGE:
			case CMD_GETATTS:
			case CMD_SETATTS:
			case CMD_EXPATTS:
			case CMD_GETOPTS:
			case CMD_SETOPTS:
			case CMD_DSP:
			case CMD_STATS:
			case CMD_PPLNS:
			case CMD_PPLNS2:
			case CMD_PAYOUTS:
			case CMD_MPAYOUTS:
			case CMD_SHIFTS:
			case CMD_USERSTATUS:
			case CMD_MARKS:
				LOGERR("%s() Message line %"PRIu64" '%s' - invalid - ignored",
					__func__, count, cmd);
				break;
			case CMD_AUTH:
			case CMD_ADDRAUTH:
			case CMD_HEARTBEAT:
			case CMD_POOLSTAT:
			case CMD_USERSTAT:
			case CMD_WORKERSTAT:
			case CMD_BLOCK:
				if (confirm_sharesummary)
					break;
			case CMD_SHARELOG:
				ans = ckdb_cmds[which_cmds].func(conn, cmd, id, &now,
								 by_default,
								 (char *)__func__,
								 inet_default,
								 &cd, trf_root);
				if (ans)
					free(ans);
				break;
			default:
				// Force this switch to be updated if new cmds are added
				quithere(1, "%s line %"PRIu64" '%s' - not handled by reload",
					 filename, count, cmd);
				break;
		}

		if (trf_root)
			trf_root = free_ktree(trf_root, NULL);
		if (trf_store) {
			item = trf_store->head;
			while (item) {
				DATA_TRANSFER(transfer, item);
				if (transfer->mvalue != transfer->svalue)
					FREENULL(transfer->mvalue);
				item = item->next;
			}
			K_WLOCK(transfer_free);
			k_list_transfer_to_head(trf_store, transfer_free);
			K_WUNLOCK(transfer_free);
			trf_store = k_free_store(trf_store);
		}
	}

	tick();

	return false;
}

// 10Mb for now - transactiontree can be large
#define MAX_READ (10 * 1024 * 1024)
static char *reload_buf;

static bool logline(char *buf, int siz, FILE *fp, char *filename)
{
	char *ret;

	ret = fgets_unlocked(buf, siz, fp);
	if (!ret && ferror(fp)) {
		int err = errno;
		quithere(1, "Read failed on %s (%d) '%s'",
			    filename, err, strerror(err));
	}
	if (ret)
		return true;
	else
		return false;
}

static struct decomp {
	char *ext;
	char *fmt;
} dec_list[] = {
	{ ".bz2", "bzcat -q '%s'" },
	{ ".gz",  "zcat -q '%s'" },
	{ ".lrz", "lrzip -q -d -o - '%s'" },
	{ NULL, NULL }
};

static bool logopen(char **filename, FILE **fp, bool *apipe)
{
	char buf[1024];
	char *name;
	size_t len;
	int i;

	*apipe = false;

	*fp = NULL;
	*fp = fopen(*filename, "re");
	if (*fp)
		return true;

	for (i = 0; dec_list[i].ext; i++) {
		len = strlen(*filename) + strlen(dec_list[i].ext);
		name = malloc(len + 1);
		if (!name)
			quithere(1, "(%d) OOM", (int)len);
		strcpy(name, *filename);
		strcat(name, dec_list[i].ext);
		if (access(name, R_OK))
			free(name);
		else {
			snprintf(buf, sizeof(buf), dec_list[i].fmt, name);
			*fp = popen(buf, "re");
			if (!(*fp)) {
				int errn = errno;
				quithere(1, "Failed to pipe (%d) \"%s\"",
					 errn, buf);
			} else {
				*apipe = true;
				free(*filename);
				*filename = name;
				return true;
			}
		}
	}
	return false;
}

/* If the reload start file is missing and -r was specified correctly:
 *	touch the filename reported in "Failed to open 'filename'",
 *	if ckdb aborts at the beginning of the reload, then start again */
static bool reload_from(tv_t *start)
{
	PGconn *conn = NULL;
	char buf[DATE_BUFSIZ+1], run[DATE_BUFSIZ+1];
	size_t rflen = strlen(restorefrom);
	char *missingfirst = NULL, *missinglast = NULL;
	int missing_count;
	int processing;
	bool finished = false, matched = false, ret = true, ok, apipe = false;
	char *filename = NULL;
	uint64_t count, total;
	tv_t now, begin;
	double diff;
	FILE *fp = NULL;

	reload_buf = malloc(MAX_READ);
	if (!reload_buf)
		quithere(1, "(%d) OOM", MAX_READ);

	reloading = true;

	copy_tv(&reload_timestamp, start);
	reload_timestamp.tv_sec -= reload_timestamp.tv_sec % ROLL_S;

	tv_to_buf(start, buf, sizeof(buf));
	tv_to_buf(&reload_timestamp, run, sizeof(run));
	LOGWARNING("%s(): from %s (stamp %s)", __func__, buf, run);

	filename = rotating_filename(restorefrom, reload_timestamp.tv_sec);
	if (!logopen(&filename, &fp, &apipe))
		quithere(1, "Failed to open '%s'", filename);

	setnow(&now);
	copy_tv(&begin, &now);
	tvs_to_buf(&now, run, sizeof(run));
	snprintf(reload_buf, MAX_READ, "reload.%s.s0", run);
	LOGQUE(reload_buf);

	conn = dbconnect();

	total = 0;
	processing = 0;
	while (!everyone_die && !finished) {
		LOGWARNING("%s(): processing %s", __func__, filename);
		processing++;
		count = 0;

		while (!everyone_die && !matched &&
			logline(reload_buf, MAX_READ, fp, filename))
				matched = reload_line(conn, filename, ++count, reload_buf);

		LOGWARNING("%s(): %sread %"PRIu64" line%s from %s",
			   __func__,
			   everyone_die ? "Shutdown, aborting - " : "",
			   count, count == 1 ? "" : "s",
			   filename);
		total += count;
		if (apipe) {
			pclose(fp);
			if (count == 0) {
				quithere(1, "ABORTING - No data returned from "
					    "compressed file \"%s\"",
					    filename);
			}
		} else
			fclose(fp);
		free(filename);
		if (everyone_die || matched)
			break;
		reload_timestamp.tv_sec += ROLL_S;
		if (confirm_sharesummary && tv_newer(&confirm_finish, &reload_timestamp)) {
			LOGWARNING("%s(): confirm range complete", __func__);
			break;
		}
		filename = rotating_filename(restorefrom, reload_timestamp.tv_sec);
		ok = logopen(&filename, &fp, &apipe);
		if (!ok) {
			missingfirst = strdup(filename);
			FREENULL(filename);
			errno = 0;
			missing_count = 1;
			setnow(&now);
			now.tv_sec += ROLL_S;
			while (42) {
				reload_timestamp.tv_sec += ROLL_S;
				/* WARNING: if the system clock is wrong, any CCLs
				 * missing or not created due to a ckpool outage of
				 * an hour or more can stop the reload early and
				 * cause DB problems! Though, the clock being wrong
				 * can screw up ckpool and ckdb anyway ... */
				if (!tv_newer(&reload_timestamp, &now)) {
					finished = true;
					break;
				}
				filename = rotating_filename(restorefrom, reload_timestamp.tv_sec);
				ok = logopen(&filename, &fp, &apipe);
				if (ok)
					break;
				errno = 0;
				if (missing_count++ > 1)
					free(missinglast);
				missinglast = strdup(filename);
				FREENULL(filename);
			}
			if (missing_count == 1)
				LOGWARNING("%s(): skipped %s", __func__, missingfirst+rflen);
			else {
				LOGWARNING("%s(): skipped %d files from %s to %s",
					   __func__, missing_count, missingfirst+rflen, missinglast+rflen);
				FREENULL(missinglast);
			}
			FREENULL(missingfirst);
		}
	}

	PQfinish(conn);

	setnow(&now);
	diff = tvdiff(&now, &begin);
	if (diff == 0)
		diff = 1;

	snprintf(reload_buf, MAX_READ, "reload.%s.%"PRIu64, run, total);
	LOGQUE(reload_buf);
	LOGWARNING("%s(): read %d file%s, total %"PRIu64" line%s %.2f/s",
		   __func__,
		   processing, processing == 1 ? "" : "s",
		   total, total == 1 ? "" : "s", (total / diff));

	if (everyone_die)
		return true;

	if (!matched) {
		ck_wlock(&fpm_lock);
		if (first_pool_message) {
			LOGERR("%s() reload completed without finding ckpool queue match '%.32s'...",
				__func__, first_pool_message);
			LOGERR("%s() restart ckdb to resolve this", __func__);
			ret = false;
		}
		ck_wunlock(&fpm_lock);
	}

	reloading = false;
	FREENULL(reload_buf);
	return ret;
}

static void process_queued(PGconn *conn, K_ITEM *wq_item)
{
	static char *last_buf = NULL;
	WORKQUEUE *workqueue;
	TRANSFER *transfer;
	K_ITEM *item;
	char *ans;

	DATA_WORKQUEUE(workqueue, wq_item);

	// Simply ignore the (very rare) duplicates
	if (!last_buf || strcmp(workqueue->buf, last_buf)) {
		ans = ckdb_cmds[workqueue->which_cmds].func(conn, workqueue->cmd, workqueue->id,
							    &(workqueue->now), workqueue->by,
							    workqueue->code, workqueue->inet,
							    &(workqueue->cd), workqueue->trf_root);
		free(ans);
	}

	if (last_buf)
		free(last_buf);
	last_buf = workqueue->buf;

	workqueue->trf_root = free_ktree(workqueue->trf_root, NULL);
	item = workqueue->trf_store->head;
	while (item) {
		DATA_TRANSFER(transfer, item);
		if (transfer->mvalue != transfer->svalue)
			FREENULL(transfer->mvalue);
		item = item->next;
	}
	K_WLOCK(transfer_free);
	k_list_transfer_to_head(workqueue->trf_store, transfer_free);
	K_WUNLOCK(transfer_free);
	workqueue->trf_store = k_free_store(workqueue->trf_store);

	K_WLOCK(workqueue_free);
	k_add_head(workqueue_free, wq_item);
	if (workqueue_free->count == workqueue_free->total &&
	    workqueue_free->total > ALLOC_WORKQUEUE * CULL_WORKQUEUE)
		k_cull_list(workqueue_free);
	K_WUNLOCK(workqueue_free);
}

// TODO: equivalent of api_allow
static void *listener(void *arg)
{
	PGconn *conn = NULL;
	pthread_t log_pt;
	pthread_t sock_pt;
	pthread_t summ_pt;
	pthread_t mark_pt;
	K_ITEM *wq_item;
	time_t now;
	int wqcount, wqgot;

	logqueue_free = k_new_list("LogQueue", sizeof(LOGQUEUE),
					ALLOC_LOGQUEUE, LIMIT_LOGQUEUE, true);
	logqueue_store = k_new_store(logqueue_free);

	create_pthread(&log_pt, logger, NULL);

	create_pthread(&sock_pt, socketer, arg);

	create_pthread(&summ_pt, summariser, NULL);

	create_pthread(&mark_pt, marker, NULL);

	rename_proc("db_listener");

	listener_using_data = true;

	if (!setup_data()) {
		if (!everyone_die) {
			LOGEMERG("ABORTING");
			everyone_die = true;
		}
		return NULL;
	}

	if (!everyone_die) {
		K_RLOCK(workqueue_store);
		wqcount = workqueue_store->count;
		K_RUNLOCK(workqueue_store);

		LOGWARNING("%s(): ckdb ready, queue %d", __func__, wqcount);

		/* Until startup_complete, the values should be ignored
		 * Setting them to 'now' means that they won't time out
		 *  until after startup_complete */
		ck_wlock(&last_lock);
		setnow(&last_heartbeat);
		copy_tv(&last_workinfo, &last_heartbeat);
		copy_tv(&last_share, &last_heartbeat);
		copy_tv(&last_share_inv, &last_heartbeat);
		copy_tv(&last_auth, &last_heartbeat);
		ck_wunlock(&last_lock);

		startup_complete = true;
	}

	// Process queued work
	conn = dbconnect();
	now = time(NULL);
	wqgot = 0;
	while (!everyone_die) {
		K_WLOCK(workqueue_store);
		wq_item = k_unlink_head(workqueue_store);
		K_WUNLOCK(workqueue_store);

		/* Don't keep a connection for more than ~10s or ~10000 items
		 *  but always have a connection open */
		if ((time(NULL) - now) > 10 || wqgot > 10000) {
			PQfinish(conn);
			conn = dbconnect();
			now = time(NULL);
			wqgot = 0;
		}

		if (wq_item) {
			wqgot++;
			process_queued(conn, wq_item);
			tick();
		} else {
			const ts_t tsdiff = {0, 420000000};
			tv_t now;
			ts_t abs;

			tv_time(&now);
			tv_to_ts(&abs, &now);
			timeraddspec(&abs, &tsdiff);

			mutex_lock(&wq_waitlock);
			cond_timedwait(&wq_waitcond, &wq_waitlock, &abs);
			mutex_unlock(&wq_waitlock);
		}
	}

	listener_using_data = false;

	if (conn)
		PQfinish(conn);

	return NULL;
}

/* TODO: This will be way faster traversing both trees simultaneously
 *  rather than traversing one and searching the other, then repeating
 *  in reverse. Will change it later */
static void compare_summaries(K_TREE *leftsum, char *leftname,
			      K_TREE *rightsum, char *rightname,
			      bool show_missing, bool show_diff)
{
	K_TREE_CTX ctxl[1], ctxr[1];
	K_ITEM look, *lss, *rss;
	char cd_buf[DATE_BUFSIZ];
	SHARESUMMARY looksharesummary, *l_ss, *r_ss;
	uint64_t total, ok, missing, diff;
	uint64_t first_used = 0, last_used = 0;
	int64_t miss_first = 0, miss_last = 0;
	tv_t miss_first_cd = {0,0}, miss_last_cd = {0,0};
	int64_t diff_first = 0, diff_last = 0;
	tv_t diff_first_cd = {0,0}, diff_last_cd = {0,0};
	char cd_buf1[DATE_BUFSIZ], cd_buf2[DATE_BUFSIZ];

	looksharesummary.workinfoid = confirm_first_workinfoid;
	looksharesummary.userid = -1;
	looksharesummary.workername = EMPTY;
	INIT_SHARESUMMARY(&look);
	look.data = (void *)(&looksharesummary);

	total = ok = missing = diff = 0;
	lss = find_after_in_ktree(leftsum, &look, cmp_sharesummary_workinfoid, ctxl);
	while (lss) {
		DATA_SHARESUMMARY(l_ss, lss);
		if (l_ss->workinfoid > confirm_last_workinfoid)
			break;

		total++;

		if (first_used == 0)
			first_used = l_ss->workinfoid;
		last_used = l_ss->workinfoid;

		rss = find_in_ktree(rightsum, lss, cmp_sharesummary_workinfoid, ctxr);
		DATA_SHARESUMMARY_NULL(r_ss, rss);
		if (!rss) {
			missing++;
			if (miss_first == 0) {
				miss_first = l_ss->workinfoid;
				copy_tv(&miss_first_cd, &(l_ss->createdate));
			}
			miss_last = l_ss->workinfoid;
			copy_tv(&miss_last_cd, &(l_ss->createdate));
			if (show_missing) {
				LOGERR("ERROR: %s %"PRId64"/%s/%ld,%ld %.19s missing from %s",
					leftname,
					l_ss->workinfoid,
					l_ss->workername,
					l_ss->createdate.tv_sec,
					l_ss->createdate.tv_usec,
					tv_to_buf(&(l_ss->createdate), cd_buf, sizeof(cd_buf)),
					rightname);
			}
		} else if (r_ss->diffacc != l_ss->diffacc) {
			diff++;
			if (show_diff) {
				if (diff_first == 0) {
					diff_first = l_ss->workinfoid;
					copy_tv(&diff_first_cd, &(l_ss->createdate));
				}
				diff_last = l_ss->workinfoid;
				copy_tv(&diff_last_cd, &(l_ss->createdate));
				LOGERR("ERROR: %"PRId64"/%s/%ld,%ld %.19s - diffacc: %s: %.0f %s: %.0f",
					l_ss->workinfoid,
					l_ss->workername,
					l_ss->createdate.tv_sec,
					l_ss->createdate.tv_usec,
					tv_to_buf(&(l_ss->createdate), cd_buf, sizeof(cd_buf)),
					leftname,
					l_ss->diffacc,
					rightname,
					r_ss->diffacc);
			}
		} else
			ok++;

		lss = next_in_ktree(ctxl);
	}

	LOGERR("RESULT: %s->%s Total %"PRIu64" workinfoid %"PRId64"-%"PRId64
		" %s missing: %"PRIu64" different: %"PRIu64,
		leftname, rightname, total, first_used, last_used,
		rightname, missing, diff);
	if (miss_first) {
		tv_to_buf(&miss_first_cd, cd_buf1, sizeof(cd_buf1));
		tv_to_buf(&miss_last_cd, cd_buf2, sizeof(cd_buf2));
		LOGERR(" workinfoid range for missing: %"PRId64"-%"PRId64
			" (%s .. %s)",
			miss_first, miss_last, cd_buf1, cd_buf2);
	}
	if (show_diff && diff_first) {
		tv_to_buf(&diff_first_cd, cd_buf1, sizeof(cd_buf1));
		tv_to_buf(&diff_last_cd, cd_buf2, sizeof(cd_buf2));
		LOGERR(" workinfoid range for differences: %"PRId64"-%"PRId64
			" (%s .. %s)",
			diff_first, diff_last, cd_buf1, cd_buf2);
	}
}

/* TODO: have a seperate option to find/store missing workinfo/shares/etc
 *  from the reload files, in a supplied UTC time range
 *  since there is no automatic way to get them in the DB after later ones
 *  have been stored e.g. a database failure/recovery or short outage but
 *  later workinfos/shares/etc have been stored so earlier ones will not be
 *  picked up by the reload
 * However, will need to deal with, via reporting an error and/or abort,
 *  if a stored workinfoid is in a range that has already been paid
 *  and the payment is now wrong */
static void confirm_reload()
{
	K_TREE *sharesummary_workinfoid_save;
	__maybe_unused K_TREE *sharesummary_save;
	__maybe_unused K_TREE *workinfo_save;
	K_ITEM b_look, wi_look, *wi_item, *wif_item, *wil_item;
	K_ITEM *b_begin_item, *b_end_item;
	K_ITEM *ss_begin_item, *ss_end_item;
	WORKINFO lookworkinfo, *workinfo;
	BLOCKS lookblocks, *b_blocks, *e_blocks;
	SHARESUMMARY *b_ss, *e_ss;
	K_TREE_CTX ctx[1];
	char buf[DATE_BUFSIZ+1];
	char *first_reason;
	char *last_reason;
	char cd_buf[DATE_BUFSIZ];
	char first_buf[64], last_buf[64];
	char *filename;
	tv_t start;
	FILE *fp;

// TODO: // abort reload when we get an age after the end of a workinfo after the Xs after the last workinfo before the end

	wif_item = first_in_ktree(workinfo_root, ctx);
	wil_item = last_in_ktree(workinfo_root, ctx);

	if (!wif_item || !wil_item) {
		LOGWARNING("%s(): DB contains no workinfo records", __func__);
		return;
	}

	DATA_WORKINFO(workinfo, wif_item);
	tv_to_buf(&(workinfo->createdate), cd_buf, sizeof(cd_buf));
	LOGWARNING("%s(): DB first workinfoid %"PRId64" %s",
		   __func__, workinfo->workinfoid, cd_buf);

	DATA_WORKINFO(workinfo, wil_item);
	tv_to_buf(&(workinfo->createdate), cd_buf, sizeof(cd_buf));
	LOGWARNING("%s(): DB last workinfoid %"PRId64" %s",
		   __func__, workinfo->workinfoid, cd_buf);

	b_begin_item = first_in_ktree(blocks_root, ctx);
	b_end_item = last_in_ktree(blocks_root, ctx);

	if (!b_begin_item || !b_end_item)
		LOGWARNING("%s(): DB contains no blocks :(", __func__);
	else {
		DATA_BLOCKS(b_blocks, b_begin_item);
		DATA_BLOCKS(e_blocks, b_end_item);
		tv_to_buf(&(b_blocks->createdate), cd_buf, sizeof(cd_buf));
		LOGWARNING("%s(): DB first block %d/%"PRId64" %s",
			   __func__,
			   b_blocks->height,
			   b_blocks->workinfoid,
			   cd_buf);
		tv_to_buf(&(e_blocks->createdate),
			  cd_buf, sizeof(cd_buf));
		LOGWARNING("%s(): DB last block %d/%"PRId64" %s",
			   __func__,
			   e_blocks->height,
			   e_blocks->workinfoid,
			   cd_buf);
	}

	ss_begin_item = first_in_ktree(sharesummary_workinfoid_root, ctx);
	ss_end_item = last_in_ktree(sharesummary_workinfoid_root, ctx);

	if (!ss_begin_item || !ss_end_item)
		LOGWARNING("%s(): DB contains no sharesummary records", __func__);
	else {
		DATA_SHARESUMMARY(b_ss, ss_begin_item);
		DATA_SHARESUMMARY(e_ss, ss_end_item);
		tv_to_buf(&(b_ss->createdate), cd_buf, sizeof(cd_buf));
		LOGWARNING("%s(): DB first sharesummary %"PRId64"/%s %s",
			   __func__,
			   b_ss->workinfoid,
			   b_ss->workername,
			   cd_buf);
		tv_to_buf(&(e_ss->createdate), cd_buf, sizeof(cd_buf));
		LOGWARNING("%s(): DB last sharesummary %"PRId64"/%s %s",
			   __func__,
			   e_ss->workinfoid,
			   e_ss->workername,
			   cd_buf);
	}

	/* The first workinfo we should process
	 * With no y records we should start from the beginning (0)
	 * With any y records, we should start from the oldest of: y+1 and a
	 *  which can produce y records as reload a's, if a is used */
	if (dbstatus.newest_workinfoid_y > 0) {
		confirm_first_workinfoid = dbstatus.newest_workinfoid_y + 1;
		if (confirm_first_workinfoid > dbstatus.oldest_workinfoid_a) {
			confirm_first_workinfoid = dbstatus.oldest_workinfoid_a;
			first_reason = "oldest aged";
		} else
			first_reason = "newest confirmed+1";
	} else
		first_reason = "0 - none confirmed";

	/* The last workinfo we should process
	 * The reason for going past the last 'a' up to before
	 *  the first 'n' is in case there were shares missed between them -
	 *  but that should only be the case with a code bug -
	 *  so it checks that */
	if (dbstatus.newest_workinfoid_a > 0) {
		confirm_last_workinfoid = dbstatus.newest_workinfoid_a;
		last_reason = "newest aged";
	}
	if (confirm_last_workinfoid < dbstatus.oldest_workinfoid_n) {
		confirm_last_workinfoid = dbstatus.oldest_workinfoid_n - 1;
		last_reason = "oldest new-1";
	}
	if (confirm_last_workinfoid == 0) {
		LOGWARNING("%s(): there are no unconfirmed sharesummary records in the DB",
			   __func__);
		return;
	}

	INIT_BLOCKS(&b_look);
	INIT_WORKINFO(&wi_look);

	// Do this after above code for checking and so we can use the results
	if (confirm_range && *confirm_range) {
		switch(tolower(confirm_range[0])) {
			case 'b':
				// First DB record of the block = or after confirm_block
				lookblocks.height = confirm_block;
				lookblocks.blockhash[0] = '\0';
				b_look.data = (void *)(&lookblocks);
				b_end_item = find_after_in_ktree(blocks_root, &b_look, cmp_blocks, ctx);
				if (!b_end_item) {
					LOGWARNING("%s(): no DB block height found matching or after %d",
						   __func__, confirm_block);
					return;
				}
				DATA_BLOCKS(e_blocks, b_end_item);
				confirm_last_workinfoid = e_blocks->workinfoid;

				// Now find the last DB record of the previous block
				lookblocks.height = e_blocks->height;
				lookblocks.blockhash[0] = '\0';
				b_look.data = (void *)(&lookblocks);
				b_begin_item = find_before_in_ktree(blocks_root, &b_look, cmp_blocks, ctx);
				if (!b_begin_item)
					confirm_first_workinfoid = 0;
				else {
					DATA_BLOCKS(b_blocks, b_begin_item);
					// First DB record of the block 'begin'
					lookblocks.height = b_blocks->height;
					lookblocks.blockhash[0] = '\0';
					b_look.data = (void *)(&lookblocks);
					b_begin_item = find_after_in_ktree(blocks_root, &b_look, cmp_blocks, ctx);
					// Not possible
					if (!b_begin_item)
						confirm_first_workinfoid = 0;
					else {
						DATA_BLOCKS(b_blocks, b_begin_item);
						confirm_first_workinfoid = b_blocks->workinfoid;
					}
				}
				snprintf(first_buf, sizeof(first_buf),
					 "block %d",
					 b_begin_item ? b_blocks->height : 0);
				first_reason = first_buf;
				snprintf(last_buf, sizeof(last_buf),
					 "block %d",
					 e_blocks->height);
				last_reason = last_buf;
				break;
			case 'i':
				LOGWARNING("%s(): info displayed - exiting", __func__);
				exit(0);
			case 'c':
			case 'r':
				confirm_first_workinfoid = confirm_range_start;
				confirm_last_workinfoid = confirm_range_finish;
				first_reason = "start range";
				last_reason = "end range";
				break;
			case 'w':
				confirm_first_workinfoid = confirm_range_start;
				// last from default
				if (confirm_last_workinfoid < confirm_first_workinfoid) {
					LOGWARNING("%s(): no unconfirmed sharesummary records before start",
						   __func__);
					return;
				}
				first_reason = "start range";
				break;
			default:
				quithere(1, "Code fail");
		}
	}

	/* These two below find the closest valid workinfo to the ones chosen
	 * however we still use the original ones chosen to select/ignore data */

	/* Find the workinfo before confirm_first_workinfoid+1
	 * i.e. the one we want or the previous before it */
	lookworkinfo.workinfoid = confirm_first_workinfoid + 1;
	lookworkinfo.expirydate.tv_sec = date_begin.tv_sec;
	lookworkinfo.expirydate.tv_usec = date_begin.tv_usec;
	wi_look.data = (void *)(&lookworkinfo);
	wi_item = find_before_in_ktree(workinfo_root, &wi_look, cmp_workinfo, ctx);
	if (wi_item) {
		DATA_WORKINFO(workinfo, wi_item);
		copy_tv(&start, &(workinfo->createdate));
		if (workinfo->workinfoid != confirm_first_workinfoid) {
			LOGWARNING("%s() start workinfo not found ... using time of %"PRId64,
				   __func__, workinfo->workinfoid);
		}
	} else {
		if (confirm_first_workinfoid == 0) {
			start.tv_sec = start.tv_usec = 0;
			LOGWARNING("%s() no start workinfo found ... "
				   "using time 0", __func__);
		} else {
			// Abort, otherwise reload will reload all log files
			LOGERR("%s(): Start workinfoid doesn't exist, "
			       "use 0 to mean from the beginning of time",
			       __func__);
			return;
		}
	}

	/* Find the workinfo after confirm_last_workinfoid-1
	 * i.e. the one we want or the next after it */
	lookworkinfo.workinfoid = confirm_last_workinfoid - 1;
	lookworkinfo.expirydate.tv_sec = date_eot.tv_sec;
	lookworkinfo.expirydate.tv_usec = date_eot.tv_usec;
	wi_look.data = (void *)(&lookworkinfo);
	wi_item = find_after_in_ktree(workinfo_root, &wi_look, cmp_workinfo, ctx);
	if (wi_item) {
		DATA_WORKINFO(workinfo, wi_item);
		/* Now find the one after the one we found to determine the
		 * confirm_finish timestamp */
		lookworkinfo.workinfoid = workinfo->workinfoid;
		lookworkinfo.expirydate.tv_sec = date_eot.tv_sec;
		lookworkinfo.expirydate.tv_usec = date_eot.tv_usec;
		wi_look.data = (void *)(&lookworkinfo);
		wi_item = find_after_in_ktree(workinfo_root, &wi_look, cmp_workinfo, ctx);
		if (wi_item) {
			DATA_WORKINFO(workinfo, wi_item);
			copy_tv(&confirm_finish, &(workinfo->createdate));
			confirm_finish.tv_sec += WORKINFO_AGE;
		} else {
			confirm_finish.tv_sec = date_eot.tv_sec;
			confirm_finish.tv_usec = date_eot.tv_usec;
		}
	} else {
		confirm_finish.tv_sec = date_eot.tv_sec;
		confirm_finish.tv_usec = date_eot.tv_usec;
		LOGWARNING("%s() no finish workinfo found ... using EOT", __func__);
	}

	LOGWARNING("%s() workinfo range: %"PRId64" to %"PRId64" ('%s' to '%s')",
		   __func__, confirm_first_workinfoid, confirm_last_workinfoid,
		   first_reason, last_reason);

	tv_to_buf(&start, buf, sizeof(buf));
	LOGWARNING("%s() load start timestamp %s", __func__, buf);
	tv_to_buf(&confirm_finish, buf, sizeof(buf));
	LOGWARNING("%s() load finish timestamp %s", __func__, buf);

	/* Save the DB info for comparing to the reload
	 * i.e. the reload will generate from scratch all the
	 * sharesummaries and workinfo from the CCLs */
	sharesummary_workinfoid_save = sharesummary_workinfoid_root;
	sharesummary_save = sharesummary_root;
	workinfo_save = workinfo_root;

	sharesummary_workinfoid_root = new_ktree();
	sharesummary_root = new_ktree();
	workinfo_root = new_ktree();

	if (start.tv_sec < DATE_BEGIN) {
		start.tv_sec = DATE_BEGIN;
		start.tv_usec = 0L;
		filename = rotating_filename(restorefrom, start.tv_sec);
		fp = fopen(filename, "re");
		if (fp)
			fclose(fp);
		else {
			mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
			int fd = open(filename, O_CREAT|O_RDONLY, mode);
			if (fd == -1) {
				int ern = errno;
				quithere(1, "Couldn't create '%s' (%d) %s",
					 filename, ern, strerror(ern));
			}
			close(fd);
		}
		free(filename);
	}

	if (!reload_from(&start)) {
		LOGEMERG("%s() ABORTING from reload_from()", __func__);
		return;
	}

	if (confirm_check_createdate) {
		LOGERR("%s(): CCL mismatches %"PRId64"/%"PRId64" %.6f/%.6f unordered "
			"%"PRId64"/%"PRId64" %.6f",
			__func__, ccl_mismatch, ccl_mismatch_abs,
			ccl_mismatch_min, ccl_mismatch_max,
			ccl_unordered, ccl_unordered_abs, ccl_unordered_most);
		return;
	}

	compare_summaries(sharesummary_workinfoid_save, "DB",
			  sharesummary_workinfoid_root, "ReLoad",
			  true, true);
	compare_summaries(sharesummary_workinfoid_root, "ReLoad",
			  sharesummary_workinfoid_save, "DB",
			  true, false);
}

// TODO: handle workmarkers/markersummaries
static void confirm_summaries()
{
	pthread_t log_pt;
	char *range, *minus;

	// Simple value check to abort early
	if (confirm_range && *confirm_range) {
		switch(tolower(confirm_range[0])) {
			case 'b':
			case 'c':
			case 'r':
			case 'w':
				if (strlen(confirm_range) < 2) {
					LOGEMERG("%s() invalid confirm range length '%s'",
						 __func__, confirm_range);
					return;
				}
				break;
			case 'i':
				break;
			default:
				LOGEMERG("%s() invalid confirm range '%s'",
					 __func__, confirm_range);
				return;
		}
		switch(tolower(confirm_range[0])) {
			case 'b':
				confirm_block = atoi(confirm_range+1);
				if (confirm_block <= 0) {
					LOGEMERG("%s() invalid confirm block '%s' - must be >0",
						 __func__, confirm_range);
					return;
				}
				break;
			case 'i':
				break;
			case 'c':
				confirm_check_createdate = true;
			case 'r':
				range = strdup(confirm_range);
				minus = strchr(range+1, '-');
				if (!minus || minus == range+1) {
					LOGEMERG("%s() invalid confirm range '%s' - must be %cNNN-MMM",
						 __func__, confirm_range, tolower(confirm_range[0]));
					return;
				}
				*(minus++) = '\0';
				confirm_range_start = atoll(range+1);
				if (confirm_range_start <= 0) {
					LOGEMERG("%s() invalid confirm start in '%s' - must be >0",
						 __func__, confirm_range);
					return;
				}
				confirm_range_finish = atoll(minus);
				if (confirm_range_finish <= 0) {
					LOGEMERG("%s() invalid confirm finish in '%s' - must be >0",
						 __func__, confirm_range);
					return;
				}
				if (confirm_range_finish < confirm_range_start) {
					LOGEMERG("%s() invalid confirm range in '%s' - finish < start",
						 __func__, confirm_range);
					return;
				}
				free(range);
				dbload_workinfoid_start = confirm_range_start - 1;
				dbload_workinfoid_finish = confirm_range_finish + 1;
				break;
			case 'w':
				confirm_range_start = atoll(confirm_range+1);
				if (confirm_range_start <= 0) {
					LOGEMERG("%s() invalid confirm start '%s' - must be >0",
						 __func__, confirm_range);
					return;
				}
		}
	}

	logqueue_free = k_new_list("LogQueue", sizeof(LOGQUEUE),
					ALLOC_LOGQUEUE, LIMIT_LOGQUEUE, true);
	logqueue_store = k_new_store(logqueue_free);

	create_pthread(&log_pt, logger, NULL);

	rename_proc("dby_confirmer");

	alloc_storage();

	if (!getdata1()) {
		LOGEMERG("%s() ABORTING from getdata1()", __func__);
		return;
	}

	if (!getdata2()) {
		LOGEMERG("%s() ABORTING from getdata2()", __func__);
		return;
	}

	if (!getdata3()) {
		LOGEMERG("%s() ABORTING from getdata3()", __func__);
		return;
	}

	confirm_reload();
}

static void check_restore_dir(char *name)
{
	struct stat statbuf;

	if (!restorefrom) {
		restorefrom = strdup("logs");
		if (!restorefrom)
			quithere(1, "OOM");
	}

	if (!(*restorefrom))
		quit(1, "ERR: '-r dir' can't be empty");

	trail_slash(&restorefrom);

	if (stat(restorefrom, &statbuf))
		quit(1, "ERR: -r '%s' directory doesn't exist", restorefrom);

	restorefrom = realloc(restorefrom, strlen(restorefrom)+strlen(name)+1);
	if (!restorefrom)
		quithere(1, "OOM");

	strcat(restorefrom, name);
}

static struct option long_options[] = {
	{ "config",		required_argument,	0,	'c' },
	{ "dbname",		required_argument,	0,	'd' },
	{ "help",		no_argument,		0,	'h' },
	{ "killold",		no_argument,		0,	'k' },
	{ "loglevel",		required_argument,	0,	'l' },
	// markersummary = enable markersummary auto generation
	{ "markersummary",	no_argument,		0,	'm' },
	{ "name",		required_argument,	0,	'n' },
	{ "dbpass",		required_argument,	0,	'p' },
	{ "btc-pass",		required_argument,	0,	'P' },
	{ "ckpool-logdir",	required_argument,	0,	'r' },
	{ "logdir",		required_argument,	0,	'R' },
	{ "sockdir",		required_argument,	0,	's' },
	{ "btc-server",		required_argument,	0,	'S' },
	{ "btc-timeout",	required_argument,	0,	't' },
	{ "dbuser",		required_argument,	0,	'u' },
	{ "btc-user",		required_argument,	0,	'U' },
	{ "version",		no_argument,		0,	'v' },
	{ "workinfoid",		required_argument,	0,	'w' },
	{ "confirm",		no_argument,		0,	'y' },
	{ "confirmrange",	required_argument,	0,	'Y' },
	{ 0, 0, 0, 0 }
};

static void sighandler(int sig)
{
	LOGWARNING("Received signal %d, shutting down", sig);
	everyone_die = true;
	cksleep_ms(420);
	exit(0);
}

int main(int argc, char **argv)
{
	struct sigaction handler;
	char *btc_user = "user";
	char *btc_pass = "p";
	char buf[512];
	ckpool_t ckp;
	int c, ret, i = 0, j;
	char *kill;
	tv_t now;

	printf("CKDB Master V%s (C) Kano (see source code)\n", CKDB_VERSION);

	feenableexcept(FE_DIVBYZERO | FE_INVALID | FE_OVERFLOW);

	global_ckp = &ckp;
	memset(&ckp, 0, sizeof(ckp));
	ckp.loglevel = LOG_NOTICE;

	while ((c = getopt_long(argc, argv, "c:d:hkl:mn:p:P:r:R:s:S:t:u:U:vw:yY:", long_options, &i)) != -1) {
		switch(c) {
			case 'c':
				ckp.config = strdup(optarg);
				break;
			case 'd':
				db_name = strdup(optarg);
				kill = optarg;
				while (*kill)
					*(kill++) = ' ';
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
			case 'l':
				ckp.loglevel = atoi(optarg);
				if (ckp.loglevel < LOG_EMERG || ckp.loglevel > LOG_DEBUG) {
					quit(1, "Invalid loglevel (range %d - %d): %d",
					     LOG_EMERG, LOG_DEBUG, ckp.loglevel);
				}
				break;
			case 'm':
				markersummary_auto = true;
				break;
			case 'n':
				ckp.name = strdup(optarg);
				break;
			case 'p':
				db_pass = strdup(optarg);
				kill = optarg;
				if (*kill)
					*(kill++) = ' ';
				while (*kill)
					*(kill++) = '\0';
				break;
			case 'P':
				btc_pass = strdup(optarg);
				kill = optarg;
				if (*kill)
					*(kill++) = ' ';
				while (*kill)
					*(kill++) = '\0';
				break;
			case 'r':
				restorefrom = strdup(optarg);
				break;
			case 'R':
				ckp.logdir = strdup(optarg);
				break;
			case 's':
				ckp.socket_dir = strdup(optarg);
				break;
			case 'S':
				btc_server = strdup(optarg);
				break;
			case 't':
				btc_timeout = atoi(optarg);
				break;
			case 'u':
				db_user = strdup(optarg);
				kill = optarg;
				while (*kill)
					*(kill++) = ' ';
				break;
			case 'U':
				btc_user = strdup(optarg);
				kill = optarg;
				while (*kill)
					*(kill++) = ' ';
				break;
			case 'v':
				exit(0);
			case 'w':
				// Don't use this :)
				{
					char *ptr = optarg;
					int64_t start;

					if (*ptr == 's') {
						dbload_only_sharesummary = true;
						ptr++;
					}

					start = atoll(ptr);
					if (start < 0) {
						quit(1, "Invalid workinfoid start"
						     " %"PRId64" - must be >= 0",
						     start);
					}
					dbload_workinfoid_start = start;
				}
				break;
			case 'y':
				confirm_sharesummary = true;
				break;
			case 'Y':
				confirm_range = strdup(optarg);
				// Auto enable it also
				confirm_sharesummary = true;
				break;
		}
	}

	snprintf(buf, sizeof(buf), "%s:%s", btc_user, btc_pass);
	btc_auth = http_base64(buf);
	bzero(buf, sizeof(buf));

	if (confirm_sharesummary)
		dbcode = "y";
	else
		dbcode = "";

	if (!db_name)
		db_name = "ckdb";
	if (!db_user)
		db_user = "postgres";
	if (!ckp.name)
		ckp.name = "ckdb";
	snprintf(buf, 15, "%s%s", ckp.name, dbcode);
	prctl(PR_SET_NAME, buf, 0, 0, 0);
	memset(buf, 0, 15);

	check_restore_dir(ckp.name);

	if (!ckp.config) {
		ckp.config = strdup(ckp.name);
		realloc_strcat(&ckp.config, ".conf");
	}

	if (!ckp.socket_dir) {
		ckp.socket_dir = strdup("/opt/");
		realloc_strcat(&ckp.socket_dir, ckp.name);
	}
	trail_slash(&ckp.socket_dir);

	/* Ignore sigpipe */
	signal(SIGPIPE, SIG_IGN);

	ret = mkdir(ckp.socket_dir, 0770);
	if (ret && errno != EEXIST)
		quit(1, "Failed to make directory %s", ckp.socket_dir);

//	parse_config(&ckp);

	if (!ckp.logdir)
		ckp.logdir = strdup("dblogs");

	/* Create the log directory */
	trail_slash(&ckp.logdir);
	ret = mkdir(ckp.logdir, 0700);
	if (ret && errno != EEXIST)
		quit(1, "Failed to make log directory %s", ckp.logdir);

	/* Create the logfile */
	sprintf(buf, "%s%s%s.log", ckp.logdir, ckp.name, dbcode);
	ckp.logfp = fopen(buf, "ae");
	if (!ckp.logfp)
		quit(1, "Failed to open log file %s", buf);
	ckp.logfd = fileno(ckp.logfp);

	snprintf(logname, sizeof(logname), "%s%s-db%s-",
				ckp.logdir, ckp.name, dbcode);

	setnow(&now);
	srandom((unsigned int)(now.tv_usec * 4096 + now.tv_sec % 4096));

	ckp.main.ckp = &ckp;
	ckp.main.processname = strdup("main");

	cklock_init(&last_lock);
	cklock_init(&process_pplns_lock);

	if (confirm_sharesummary) {
		// TODO: add a system lock to stop running 2 at once?
		confirm_summaries();
		everyone_die = true;
	} else {
		ckp.main.sockname = strdup("listener");
		write_namepid(&ckp.main);
		create_process_unixsock(&ckp.main);

		create_pthread(&ckp.pth_listener, listener, &ckp.main);

		handler.sa_handler = sighandler;
		handler.sa_flags = 0;
		sigemptyset(&handler.sa_mask);
		sigaction(SIGTERM, &handler, NULL);
		sigaction(SIGINT, &handler, NULL);

		/* Shutdown from here if the listener is sent a shutdown message */
		join_pthread(ckp.pth_listener);
	}

	time_t start, trigger, curr;
	char *msg = NULL;

	trigger = start = time(NULL);
	while (socketer_using_data || summariser_using_data ||
		logger_using_data || listener_using_data ||
		marker_using_data) {
		msg = NULL;
		curr = time(NULL);
		if (curr - start > 4) {
			if (curr - trigger > 4) {
				msg = "Shutdown initial delay";
			} else if (curr - trigger > 2) {
				msg = "Shutdown delay";
			}
		}
		if (msg) {
			trigger = curr;
			printf("%s %ds due to%s%s%s%s%s\n",
				msg, (int)(curr - start),
				socketer_using_data ? " socketer" : EMPTY,
				summariser_using_data ? " summariser" : EMPTY,
				logger_using_data ? " logger" : EMPTY,
				listener_using_data ? " listener" : EMPTY,
				marker_using_data ? " marker" : EMPTY);
			fflush(stdout);
		}
		sleep(1);
	}

	dealloc_storage();

	clean_up(&ckp);

	return 0;
}
