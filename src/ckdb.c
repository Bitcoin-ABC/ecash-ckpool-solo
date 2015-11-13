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
 *  in the CCLs - see reload_from() for how this is handled
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

bool genpayout_auto;
bool markersummary_auto;

enum free_modes free_mode = FREE_MODE_FAST;

int switch_state = SWITCH_STATE_ALL;

// disallow: '/' WORKSEP1 WORKSEP2 and FLDSEP
const char *userpatt = "^[^/"WORKSEP1PATT WORKSEP2STR FLDSEPSTR"]*$";
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
// Strings in socket transfer: space to '~' excluding '='
const char *strpatt = "^[ -<>-~]*$";

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
 * TODO: update to include markersummaries
 *	-Y/-y isn't currently usable since it won't work without the update
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

// DB optioncontrol,users,workers,useratts load is complete
bool db_users_complete = false;
// DB load is complete
bool db_load_complete = false;
// Different input data handling
bool reloading = false;
// Start marks processing during a larger reload
static bool reloaded_N_files = false;
// Data load is complete
bool startup_complete = false;
// Set to true the first time workqueue reaches 0 after startup
static bool reload_queue_complete = false;
// Tell everyone to die
bool everyone_die = false;
// Set to true every time a store is created
static bool seqdata_reload_lost = false;

/* These are included in cmd_homepage
 *  to help identify when ckpool locks up (or dies) */
tv_t last_heartbeat;
tv_t last_workinfo;
tv_t last_share;
tv_t last_share_acc;
tv_t last_share_inv;
tv_t last_auth;
cklock_t last_lock;

static cklock_t fpm_lock;
static char *first_pool_message;
static sem_t socketer_sem;

char *btc_server = "http://127.0.0.1:8330";
char *btc_auth;
int btc_timeout = 5;
cklock_t btc_lock;

char *by_default = "code";
char *inet_default = "127.0.0.1";
char *id_default = "42";

// LOGQUEUE
K_LIST *logqueue_free;
K_STORE *logqueue_store;

// MSGLINE
K_LIST *msgline_free;
K_STORE *msgline_store;

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

// SEQSET
K_LIST *seqset_free;
K_STORE *seqset_store;
char *seqnam[SEQ_MAX];
static cklock_t seq_lock;

// SEQTRANS
K_LIST *seqtrans_free;

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
K_TREE *shares_early_root;
K_STORE *shares_early_store;

double diff_percent = DIFF_VAL(DIFF_PERCENT_DEFAULT);

// SHAREERRORS shareerrors.id.json={...}
K_TREE *shareerrors_root;
K_LIST *shareerrors_free;
K_STORE *shareerrors_store;
K_TREE *shareerrors_early_root;
K_STORE *shareerrors_early_store;

// SHARESUMMARY
K_TREE *sharesummary_root;
K_TREE *sharesummary_workinfoid_root;
K_LIST *sharesummary_free;
K_STORE *sharesummary_store;
// Pool total sharesummary stats
K_TREE *sharesummary_pool_root;
K_STORE *sharesummary_pool_store;

// BLOCKS block.id.json={...}
const char *blocks_new = "New";
const char *blocks_confirm = "1-Confirm";
const char *blocks_42 = "Matured";
const char *blocks_orphan = "Orphan";
const char *blocks_reject = "Unworthy";
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
K_TREE *payouts_wid_root;
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
// Pool total markersummary stats
K_TREE *markersummary_pool_root;
K_STORE *markersummary_pool_store;

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

// USERINFO from various incoming data
K_TREE *userinfo_root;
K_LIST *userinfo_free;
K_STORE *userinfo_store;

static char logname_db[512];
static char logname_io[512];
static char *dbcode;

// low spec version of rotating_log() - no locking
static bool rotating_log_nolock(char *msg, char *prefix)
{
	char *filename;
	FILE *fp;
	bool ok = false;

	filename = rotating_filename(prefix, time(NULL));
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

static void log_queue_message(char *msg, bool db)
{
	K_ITEM *lq_item;
	LOGQUEUE *lq;

	K_WLOCK(logqueue_free);
	lq_item = k_unlink_head(logqueue_free);
	DATA_LOGQUEUE(lq, lq_item);
	lq->msg = strdup(msg);
	if (!(lq->msg))
		quithere(1, "malloc (%d) OOM", (int)strlen(msg));
	lq->db = db;
	k_add_tail(logqueue_store, lq_item);
	K_WUNLOCK(logqueue_free);
}

void logmsg(int loglevel, const char *fmt, ...)
{
	int logfd = 0;
	char *buf = NULL;
	struct tm tm;
	tv_t now_tv;
	int ms;
	va_list ap;
	char stamp[128];
	char *extra = EMPTY;
	char tzinfo[16];
	char tzch;
	long minoff, hroff;

	if (loglevel > global_ckp->loglevel)
		return;

	tv_time(&now_tv);
	ms = (int)(now_tv.tv_usec / 1000);
	localtime_r(&(now_tv.tv_sec), &tm);
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
			"[%d-%02d-%02d %02d:%02d:%02d.%03d%s]",
			tm.tm_year + 1900,
			tm.tm_mon + 1,
			tm.tm_mday,
			tm.tm_hour,
			tm.tm_min,
			tm.tm_sec, ms,
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

/* Limits are all +/-1s since on the live machine all were well within that
 * TODO: not thread safe */
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
	if (!(ok = workers_fill(conn)))
		goto matane;
	ok = useratts_fill(conn);

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
		/* FYI must be after blocks */
		if (!(ok = payments_fill(conn)) || everyone_die)
			goto sukamudai;
		if (!(ok = miningpayouts_fill(conn)) || everyone_die)
			goto sukamudai;
	}
	if (!(ok = workinfo_fill(conn)) || everyone_die)
		goto sukamudai;
	if (!(ok = marks_fill(conn)) || everyone_die)
		goto sukamudai;
	/* must be after workinfo */
	if (!(ok = workmarkers_fill(conn)) || everyone_die)
		goto sukamudai;
	if (!confirm_sharesummary) {
		/* must be after workmarkers */
		if (!(ok = payouts_fill(conn)) || everyone_die)
			goto sukamudai;
	}
	if (!(ok = markersummary_fill(conn)) || everyone_die)
		goto sukamudai;
	if (!confirm_sharesummary && !everyone_die)
		ok = poolstats_fill(conn);

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

	tv_to_buf(&(dbstatus.newest_createdate_workmarker_workinfo),
		  buf, sizeof(buf));
	LOGWARNING("%s(): %s newest DB workmarker wid %"PRId64,
		   __func__, buf,
		   dbstatus.newest_workmarker_workinfoid);
	tv_to_buf(&(dbstatus.newest_createdate_workinfo), buf, sizeof(buf));
	LOGWARNING("%s(): %s newest DB workinfo wid %"PRId64,
		   __func__, buf, dbstatus.newest_workinfoid);
	tv_to_buf(&(dbstatus.newest_createdate_poolstats), buf, sizeof(buf));
	LOGWARNING("%s(): %s newest DB poolstats (ignored)", __func__, buf);
	tv_to_buf(&(dbstatus.newest_createdate_blocks), buf, sizeof(buf));
	LOGWARNING("%s(): %"PRId32"/%s newest DB blocks (ignored)",
		   __func__, dbstatus.newest_height_blocks, buf);

	copy_tv(&start, &(dbstatus.newest_createdate_workmarker_workinfo));
	reason = "workmarkers";
	if (!tv_newer(&start, &(dbstatus.newest_createdate_workinfo))) {
		copy_tv(&start, &(dbstatus.newest_createdate_workinfo));
		reason = "workinfo";
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
				LOGEMERG("Process %s pid %d still exists, start"
					 " ckpool with -k if you wish to kill it",
					 path, oldpid);
				return false;
			}
			if (kill(oldpid, 9)) {
				LOGEMERG("Unable to kill old process %s pid %d",
					 path, oldpid);
				return false;
			}
			LOGWARNING("Killing off old process %s pid %d",
				   path, oldpid);
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
	size_t len;
	int seq;

	seqset_free = k_new_list("SeqSet", sizeof(SEQSET),
				 ALLOC_SEQSET, LIMIT_SEQSET, true);
	seqset_store = k_new_store(seqset_free);

	// Map the SEQ_NNN values to their cmd names
	seqnam[0] = strdup(SEQALL);
	for (seq = 0; ckdb_cmds[seq].cmd_val != CMD_END; seq++) {
		if (ckdb_cmds[seq].seq != SEQ_NONE) {
			if (seqnam[ckdb_cmds[seq].seq]) {
				quithere(1, "Name map in cddb_cmds[] to seqnam"
					    " isn't unique - seq %d is listed"
					    " twice as %s and %s",
					    seq, seqnam[ckdb_cmds[seq].seq],
					    ckdb_cmds[seq].cmd_str);
			}
			len = strlen(SEQPRE) + strlen(ckdb_cmds[seq].cmd_str) + 1;
			seqnam[ckdb_cmds[seq].seq] = malloc(len);
			if (!(seqnam[ckdb_cmds[seq].seq]))
				quithere(1, "malloc (%d) OOM", (int)len);
			snprintf(seqnam[ckdb_cmds[seq].seq], len, "%s%s",
				 SEQPRE, ckdb_cmds[seq].cmd_str);
		}
	}
	for (seq = 0; seq < SEQ_MAX; seq++) {
		if (seqnam[seq] == NULL) {
			quithere(1, "Name map in cddb_cmds[] is incomplete - "
				    " %d is missing", seq);
		}
	}

	seqtrans_free = k_new_list("SeqTrans", sizeof(SEQTRANS),
				   ALLOC_SEQTRANS, LIMIT_SEQTRANS, true);

	msgline_free = k_new_list("MsgLine", sizeof(MSGLINE),
					ALLOC_MSGLINE, LIMIT_MSGLINE, true);
	msgline_store = k_new_store(msgline_free);

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
	users_root = new_ktree(cmp_users);
	userid_root = new_ktree(cmp_userid);

	useratts_free = k_new_list("Useratts", sizeof(USERATTS),
					ALLOC_USERATTS, LIMIT_USERATTS, true);
	useratts_store = k_new_store(useratts_free);
	useratts_root = new_ktree(cmp_useratts);

	optioncontrol_free = k_new_list("OptionControl", sizeof(OPTIONCONTROL),
					ALLOC_OPTIONCONTROL,
					LIMIT_OPTIONCONTROL, true);
	optioncontrol_store = k_new_store(optioncontrol_free);
	optioncontrol_root = new_ktree(cmp_optioncontrol);

	workers_free = k_new_list("Workers", sizeof(WORKERS),
					ALLOC_WORKERS, LIMIT_WORKERS, true);
	workers_store = k_new_store(workers_free);
	workers_root = new_ktree(cmp_workers);

	paymentaddresses_free = k_new_list("PaymentAddresses",
					   sizeof(PAYMENTADDRESSES),
					   ALLOC_PAYMENTADDRESSES,
					   LIMIT_PAYMENTADDRESSES, true);
	paymentaddresses_store = k_new_store(paymentaddresses_free);
	paymentaddresses_root = new_ktree(cmp_paymentaddresses);
	paymentaddresses_create_root = new_ktree(cmp_payaddr_create);
	paymentaddresses_free->dsp_func = dsp_paymentaddresses;

	payments_free = k_new_list("Payments", sizeof(PAYMENTS),
					ALLOC_PAYMENTS, LIMIT_PAYMENTS, true);
	payments_store = k_new_store(payments_free);
	payments_root = new_ktree(cmp_payments);

	accountbalance_free = k_new_list("AccountBalance", sizeof(ACCOUNTBALANCE),
					ALLOC_ACCOUNTBALANCE, LIMIT_ACCOUNTBALANCE, true);
	accountbalance_store = k_new_store(accountbalance_free);
	accountbalance_root = new_ktree(cmp_accountbalance);

	idcontrol_free = k_new_list("IDControl", sizeof(IDCONTROL),
					ALLOC_IDCONTROL, LIMIT_IDCONTROL, true);
	idcontrol_store = k_new_store(idcontrol_free);

	workinfo_free = k_new_list("WorkInfo", sizeof(WORKINFO),
					ALLOC_WORKINFO, LIMIT_WORKINFO, true);
	workinfo_store = k_new_store(workinfo_free);
	workinfo_root = new_ktree(cmp_workinfo);
	if (!confirm_sharesummary)
		workinfo_height_root = new_ktree(cmp_workinfo_height);

	shares_free = k_new_list("Shares", sizeof(SHARES),
					ALLOC_SHARES, LIMIT_SHARES, true);
	shares_store = k_new_store(shares_free);
	shares_early_store = k_new_store(shares_free);
	shares_root = new_ktree(cmp_shares);
	shares_early_root = new_ktree(cmp_shares);

	shareerrors_free = k_new_list("ShareErrors", sizeof(SHAREERRORS),
					ALLOC_SHAREERRORS, LIMIT_SHAREERRORS, true);
	shareerrors_store = k_new_store(shareerrors_free);
	shareerrors_early_store = k_new_store(shareerrors_free);
	shareerrors_root = new_ktree(cmp_shareerrors);
	shareerrors_early_root = new_ktree(cmp_shareerrors);

	sharesummary_free = k_new_list("ShareSummary", sizeof(SHARESUMMARY),
					ALLOC_SHARESUMMARY, LIMIT_SHARESUMMARY, true);
	sharesummary_store = k_new_store(sharesummary_free);
	sharesummary_root = new_ktree(cmp_sharesummary);
	sharesummary_workinfoid_root = new_ktree(cmp_sharesummary_workinfoid);
	sharesummary_free->dsp_func = dsp_sharesummary;
	sharesummary_pool_store = k_new_store(sharesummary_free);
	sharesummary_pool_root = new_ktree(cmp_sharesummary);

	blocks_free = k_new_list("Blocks", sizeof(BLOCKS),
					ALLOC_BLOCKS, LIMIT_BLOCKS, true);
	blocks_store = k_new_store(blocks_free);
	blocks_root = new_ktree(cmp_blocks);
	blocks_free->dsp_func = dsp_blocks;

	miningpayouts_free = k_new_list("MiningPayouts", sizeof(MININGPAYOUTS),
					ALLOC_MININGPAYOUTS, LIMIT_MININGPAYOUTS, true);
	miningpayouts_store = k_new_store(miningpayouts_free);
	miningpayouts_root = new_ktree(cmp_miningpayouts);

	payouts_free = k_new_list("Payouts", sizeof(PAYOUTS),
					ALLOC_PAYOUTS, LIMIT_PAYOUTS, true);
	payouts_store = k_new_store(payouts_free);
	payouts_root = new_ktree(cmp_payouts);
	payouts_id_root = new_ktree(cmp_payouts_id);
	payouts_wid_root = new_ktree(cmp_payouts_wid);

	auths_free = k_new_list("Auths", sizeof(AUTHS),
					ALLOC_AUTHS, LIMIT_AUTHS, true);
	auths_store = k_new_store(auths_free);
	auths_root = new_ktree(cmp_auths);

	poolstats_free = k_new_list("PoolStats", sizeof(POOLSTATS),
					ALLOC_POOLSTATS, LIMIT_POOLSTATS, true);
	poolstats_store = k_new_store(poolstats_free);
	poolstats_root = new_ktree(cmp_poolstats);

	userstats_free = k_new_list("UserStats", sizeof(USERSTATS),
					ALLOC_USERSTATS, LIMIT_USERSTATS, true);
	userstats_store = k_new_store(userstats_free);
	userstats_eos_store = k_new_store(userstats_free);
	userstats_root = new_ktree(cmp_userstats);
	userstats_free->dsp_func = dsp_userstats;

	workerstatus_free = k_new_list("WorkerStatus", sizeof(WORKERSTATUS),
					ALLOC_WORKERSTATUS, LIMIT_WORKERSTATUS, true);
	workerstatus_store = k_new_store(workerstatus_free);
	workerstatus_root = new_ktree(cmp_workerstatus);

	markersummary_free = k_new_list("MarkerSummary", sizeof(MARKERSUMMARY),
					ALLOC_MARKERSUMMARY, LIMIT_MARKERSUMMARY, true);
	markersummary_store = k_new_store(markersummary_free);
	markersummary_root = new_ktree(cmp_markersummary);
	markersummary_userid_root = new_ktree(cmp_markersummary_userid);
	markersummary_free->dsp_func = dsp_markersummary;
	markersummary_pool_store = k_new_store(markersummary_free);
	markersummary_pool_root = new_ktree(cmp_markersummary);

	workmarkers_free = k_new_list("WorkMarkers", sizeof(WORKMARKERS),
					ALLOC_WORKMARKERS, LIMIT_WORKMARKERS, true);
	workmarkers_store = k_new_store(workmarkers_free);
	workmarkers_root = new_ktree(cmp_workmarkers);
	workmarkers_workinfoid_root = new_ktree(cmp_workmarkers_workinfoid);
	workmarkers_free->dsp_func = dsp_workmarkers;

	marks_free = k_new_list("Marks", sizeof(MARKS),
				ALLOC_MARKS, LIMIT_MARKS, true);
	marks_store = k_new_store(marks_free);
	marks_root = new_ktree(cmp_marks);

	userinfo_free = k_new_list("UserInfo", sizeof(USERINFO),
					ALLOC_USERINFO, LIMIT_USERINFO, true);
	userinfo_store = k_new_store(userinfo_free);
	userinfo_root = new_ktree(cmp_userinfo);
}

#define SEQSETMSG(_set, _seqset, _msgtxt, _endtxt) do { \
	char _t_buf[DATE_BUFSIZ]; \
	bool _warn = ((_seqset)->seqdata[SEQ_SHARES].missing > 0) || \
		     ((_seqset)->seqdata[SEQ_SHARES].lost > 0); \
	btu64_to_buf(&((_seqset)->seqstt), _t_buf, sizeof(_t_buf)); \
	LOGWARNING("%s %s: %d/"SEQSTT":%"PRIu64"=%s "SEQPID":%"PRIu64 \
		   " M%"PRIu64"/T%"PRIu64"/L%"PRIu64"/S%"PRIu64"/H%"PRIu64 \
		   "/R%"PRIu64"/OK%"PRIu64" %s v%"PRIu64"/^%"PRIu64"/M%"PRIu64 \
		   "/T%"PRIu64"/L%"PRIu64"/S%"PRIu64"/H%"PRIu64"/R%"PRIu64 \
		   "/OK%"PRIu64" %s v%"PRIu64"/^%"PRIu64"/M%"PRIu64"/T%"PRIu64 \
		   "/L%"PRIu64"/S%"PRIu64"/H%"PRIu64"/R%"PRIu64 \
		   "/OK%"PRIu64"%s", \
		   _warn ? "SEQ" : "Seq", \
		   _msgtxt, _set, (_seqset)->seqstt, _t_buf, \
		   (_seqset)->seqpid, (_seqset)->missing, (_seqset)->trans, \
		   (_seqset)->lost, (_seqset)->stale, (_seqset)->high, \
		   (_seqset)->recovered, (_seqset)->ok, \
		   seqnam[SEQ_ALL], \
		   (_seqset)->seqdata[SEQ_ALL].minseq, \
		   (_seqset)->seqdata[SEQ_ALL].maxseq, \
		   (_seqset)->seqdata[SEQ_ALL].missing, \
		   (_seqset)->seqdata[SEQ_ALL].trans, \
		   (_seqset)->seqdata[SEQ_ALL].lost, \
		   (_seqset)->seqdata[SEQ_ALL].stale, \
		   (_seqset)->seqdata[SEQ_ALL].high, \
		   (_seqset)->seqdata[SEQ_ALL].recovered, \
		   (_seqset)->seqdata[SEQ_ALL].ok, \
		   seqnam[SEQ_SHARES], \
		   (_seqset)->seqdata[SEQ_SHARES].minseq, \
		   (_seqset)->seqdata[SEQ_SHARES].maxseq, \
		   (_seqset)->seqdata[SEQ_SHARES].missing, \
		   (_seqset)->seqdata[SEQ_SHARES].trans, \
		   (_seqset)->seqdata[SEQ_SHARES].lost, \
		   (_seqset)->seqdata[SEQ_SHARES].stale, \
		   (_seqset)->seqdata[SEQ_SHARES].high, \
		   (_seqset)->seqdata[SEQ_SHARES].recovered, \
		   (_seqset)->seqdata[SEQ_SHARES].ok, _endtxt); \
	} while(0)

#define FREE_TREE(_tree) \
	if (_tree ## _root) \
		free_ktree(_tree ## _root, NULL) \

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

/* Write a share missing/lost report to the console - always report set 0
 * It's possible for the set numbers to be wrong and the output to report one
 *  seqset twice if a new seqset arrives between the unlock/lock for writing
 *  the console message - since a new seqset would shuffle the sets down and
 *  if the list was full, move the last one back to the top of the setset_store
 *  list, but this would normally only be when ckpool restarts and also wont
 *  cause a problem since only the last set can be moved and the code checks
 *  if it is the end and also duplicates the set before releasing the lock */
void sequence_report(bool lock)
{
	SEQSET *seqset, seqset_copy;
	K_ITEM *ss_item;
	bool last, miss;
	int set;

	last = false;
	set = 0;
	if (lock)
		ck_wlock(&seq_lock);
	ss_item = seqset_store->head;
	while (!last && ss_item) {
		if (!ss_item->next)
			last = true;
		DATA_SEQSET(seqset, ss_item);
		/* Missing/Trans/Lost should all be 0 for shares */
		if (seqset->seqstt && (set == 0 ||
		    seqset->seqdata[SEQ_SHARES].missing ||
		    seqset->seqdata[SEQ_SHARES].trans ||
		    seqset->seqdata[SEQ_SHARES].lost)) {
			miss = (seqset->seqdata[SEQ_SHARES].missing > 0) ||
				(seqset->seqdata[SEQ_SHARES].lost > 0);
			if (lock) {
				memcpy(&seqset_copy, seqset, sizeof(seqset_copy));
				ck_wunlock(&seq_lock);
				seqset = &seqset_copy;
			}
			SEQSETMSG(set, seqset,
				  miss ? "SHARES MISSING" : "status" , EMPTY);
			if (lock)
				ck_wlock(&seq_lock);
		}
		ss_item = ss_item->next;
		set++;
	}
	if (lock)
		ck_wunlock(&seq_lock);
}

static void dealloc_storage()
{
	SHAREERRORS *shareerrors;
	K_ITEM *s_item;
	char *st = NULL;
	SHARES *shares;
	int seq;

	if (free_mode == FREE_MODE_NONE) {
		LOGWARNING("%s() skipped", __func__);
		return;
	}

	LOGWARNING("%s() logqueue ...", __func__);

	FREE_LISTS(logqueue);

	FREE_ALL(userinfo);

	FREE_TREE(marks);
	FREE_STORE_DATA(marks);
	FREE_LIST_DATA(marks);

	FREE_TREE(workmarkers_workinfoid);
	FREE_TREE(workmarkers);
	FREE_STORE_DATA(workmarkers);
	FREE_LIST_DATA(workmarkers);

	if (free_mode != FREE_MODE_ALL)
		LOGWARNING("%s() markersummary skipped", __func__);
	else {
		LOGWARNING("%s() markersummary ...", __func__);

		FREE_TREE(markersummary_pool);
		k_list_transfer_to_tail(markersummary_pool_store, markersummary_store);
		FREE_STORE(markersummary_pool);
		FREE_TREE(markersummary_userid);
		FREE_TREE(markersummary);
		FREE_STORE_DATA(markersummary);
		FREE_LIST_DATA(markersummary);
	}

	FREE_ALL(workerstatus);

	LOGWARNING("%s() userstats ...", __func__);

	FREE_STORE(userstats_eos);
	FREE_ALL(userstats);

	LOGWARNING("%s() poolstats ...", __func__);

	FREE_ALL(poolstats);
	FREE_ALL(auths);

	FREE_TREE(payouts_wid);
	FREE_TREE(payouts_id);
	FREE_TREE(payouts);
	FREE_STORE_DATA(payouts);
	FREE_LIST_DATA(payouts);

	FREE_ALL(miningpayouts);
	FREE_ALL(blocks);

	LOGWARNING("%s() sharesummary ...", __func__);

	FREE_TREE(sharesummary_pool);
	k_list_transfer_to_tail(sharesummary_pool_store, sharesummary_store);
	FREE_STORE(sharesummary_pool);
	FREE_TREE(sharesummary_workinfoid);
	FREE_TREE(sharesummary);
	FREE_STORE_DATA(sharesummary);
	FREE_LIST_DATA(sharesummary);

	if (shareerrors_early_store->count > 0) {
		LOGERR("%s() *** shareerrors_early count %d ***",
			__func__, shareerrors_early_store->count);
		s_item = shareerrors_early_store->head;
		while (s_item) {
			DATA_SHAREERRORS(shareerrors, s_item);
			LOGERR("%s(): %"PRId64"/%s/%"PRId32"/%s/%ld,%ld",
				__func__,
				shareerrors->workinfoid,
				st = safe_text_nonull(shareerrors->workername),
				shareerrors->errn,
				shareerrors->error,
				shareerrors->createdate.tv_sec,
				shareerrors->createdate.tv_usec);
			FREENULL(st);
			s_item = s_item->next;
		}
	}
	FREE_TREE(shareerrors_early);
	FREE_STORE(shareerrors_early);
	FREE_ALL(shareerrors);
	if (shares_early_store->count > 0) {
		LOGERR("%s() *** shares_early count %d ***",
			__func__, shares_early_store->count);
		s_item = shares_early_store->head;
		while (s_item) {
			DATA_SHARES(shares, s_item);
			LOGERR("%s(): %"PRId64"/%s/%s/%"PRId32"/%ld,%ld",
				__func__,
				shares->workinfoid,
				st = safe_text_nonull(shares->workername),
				shares->nonce,
				shares->errn,
				shares->createdate.tv_sec,
				shares->createdate.tv_usec);
			FREENULL(st);
			s_item = s_item->next;
		}
	}
	FREE_TREE(shares_early);
	FREE_STORE(shares_early);
	FREE_ALL(shares);

	if (free_mode != FREE_MODE_ALL)
		LOGWARNING("%s() workinfo skipped", __func__);
	else {
		LOGWARNING("%s() workinfo ...", __func__);

		FREE_TREE(workinfo_height);
		FREE_TREE(workinfo);
		FREE_STORE_DATA(workinfo);
		FREE_LIST_DATA(workinfo);
	}

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
	FREE_TREE(users);
	FREE_STORE_DATA(users);
	FREE_LIST_DATA(users);

	LOGWARNING("%s() transfer/heartbeatqueue/workqueue ...", __func__);

	FREE_LIST(transfer);
	FREE_LISTS(heartbeatqueue);
	FREE_LISTS(workqueue);
	FREE_LISTS(msgline);

	if (free_mode != FREE_MODE_ALL)
		LOGWARNING("%s() seqset skipped", __func__);
	else {
		LOGWARNING("%s() seqset ...", __func__);
		sequence_report(false);

		FREE_STORE_DATA(seqset);
		FREE_LIST_DATA(seqset);
		FREE_LISTS(seqset);

		// Must be after seqset
		FREE_LIST(seqtrans);

		for (seq = 0; seq < SEQ_MAX; seq++)
			FREENULL(seqnam[seq]);
	}

	LOGWARNING("%s() finished", __func__);
}

static bool setup_data()
{
	K_TREE_CTX ctx[1];
	K_ITEM look, *found;
	WORKINFO wi, *wic, *wif;
	tv_t db_stt, db_fin, rel_stt, rel_fin;
	double min, sec;

	cklock_init(&fpm_lock);
	cksem_init(&socketer_sem);
	mutex_init(&wq_waitlock);
	cond_init(&wq_waitcond);

	LOGWARNING("%sStartup payout generation state is %s",
		   genpayout_auto ? "" : "WARNING: ",
		   genpayout_auto ? "On" : "Off");
	LOGWARNING("%sStartup mark generation state is %s",
		   markersummary_auto ? "" : "WARNING: ",
		   markersummary_auto ? "On" : "Off");

	alloc_storage();

	setnow(&db_stt);

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

	setnow(&db_fin);
	sec = tvdiff(&db_fin, &db_stt);
	min = floor(sec / 60.0);
	sec -= min * 60.0;
	LOGWARNING("dbload complete %.0fm %.3fs", min, sec);

	db_load_complete = true;

	setnow(&rel_stt);

	if (!reload() || everyone_die)
		return false;

	setnow(&rel_fin);
	sec = tvdiff(&rel_fin, &rel_stt);
	min = floor(sec / 60.0);
	sec -= min * 60.0;
	LOGWARNING("reload complete %.0fm %.3fs", min, sec);

	// full lock access since mark processing can occur
	ck_wlock(&process_pplns_lock);
	K_WLOCK(workerstatus_free);
	K_RLOCK(sharesummary_free);
	K_RLOCK(workmarkers_free);
	K_RLOCK(markersummary_free);

	set_block_share_counters();

	if (!everyone_die)
		workerstatus_ready();

	K_RUNLOCK(markersummary_free);
	K_RUNLOCK(workmarkers_free);
	K_RUNLOCK(sharesummary_free);
	K_WUNLOCK(workerstatus_free);
	ck_wunlock(&process_pplns_lock);

	if (everyone_die)
		return false;

	workinfo_current = last_in_ktree(workinfo_height_root, ctx);
	if (workinfo_current) {
		DATA_WORKINFO(wic, workinfo_current);
		STRNCPY(wi.coinbase1, wic->coinbase1);
		DATE_ZERO(&(wi.createdate));
		INIT_WORKINFO(&look);
		look.data = (void *)(&wi);
		// Find the first workinfo for this height
		found = find_after_in_ktree(workinfo_height_root, &look, ctx);
		if (found) {
			DATA_WORKINFO(wif, found);
			copy_tv(&last_bc,  &(wif->createdate));
		}
		// No longer needed
		free_ktree(workinfo_height_root, NULL);
	}

	return true;
}

#define SEQINUSE firstcd.tv_sec

#define RESETSET(_seqset, _n_seqstt, _n_seqpid) do { \
		int _i; \
		(_seqset)->seqstt = (_n_seqstt); \
		(_seqset)->seqpid = (_n_seqpid); \
		for (_i = 0; _i < SEQ_MAX; _i++) { \
			(_seqset)->seqdata[_i].minseq = \
			(_seqset)->seqdata[_i].maxseq = \
			(_seqset)->seqdata[_i].seqbase = \
			(_seqset)->seqdata[_i].missing = \
			(_seqset)->seqdata[_i].trans = \
			(_seqset)->seqdata[_i].lost = \
			(_seqset)->seqdata[_i].stale = \
			(_seqset)->seqdata[_i].high = \
			(_seqset)->seqdata[_i].recovered = \
			(_seqset)->seqdata[_i].ok = 0; \
			(_seqset)->seqdata[_i].SEQINUSE = \
			(_seqset)->seqdata[_i].firstcd.tv_usec = \
			(_seqset)->seqdata[_i].lastcd.tv_sec = \
			(_seqset)->seqdata[_i].lastcd.tv_usec = \
			(_seqset)->seqdata[_i].firsttime.tv_sec = \
			(_seqset)->seqdata[_i].firsttime.tv_usec = \
			(_seqset)->seqdata[_i].lasttime.tv_sec = \
			(_seqset)->seqdata[_i].lasttime.tv_usec = 0L; \
		} \
	} while (0);

#define MISSFLAG cd.tv_sec
#define TRANSFLAG cd.tv_usec

// Test if an item is missing/transient
#define ENTRYISMIS(_seqentry) ((_seqentry)->MISSFLAG == 0)
#define DATAISMIS(_seqdata, _u) \
	ENTRYISMIS(&((_seqdata)->entry[(_u) & ((_seqdata)->size - 1)]))

#define ENTRYONLYMIS(_seqentry) (((_seqentry)->MISSFLAG == 0) && \
				 ((_seqentry)->TRANSFLAG == 0))

#define ENTRYISTRANS(_seqentry) (((_seqentry)->MISSFLAG == 0) && \
				 ((_seqentry)->TRANSFLAG != 0))
#define DATAISTRANS(_seqdata, _u) \
	ENTRYISTRANS(&((_seqdata)->entry[(_u) & ((_seqdata)->size - 1)]))

// Flag an item as missing
#define ENTRYSETMIS(_seqentry, _now) do { \
		(_seqentry)->MISSFLAG = 0; \
		(_seqentry)->TRANSFLAG = 0; \
		(_seqentry)->time.tv_sec = now->tv_sec; \
		(_seqentry)->time.tv_usec = now->tv_usec; \
	} while(0)
#define DATASETMIS(_seqdata, _u, _now) \
	ENTRYSETMIS(&((_seqdata)->entry[(_u) & ((_seqdata)->size - 1)]), _now)

/* Flag an item directly as transient missing -
 *  it will already be missing but we set both flags */
#define ENTRYSETTRANS(_seqentry) do { \
		(_seqentry)->MISSFLAG = 0; \
		(_seqentry)->TRANSFLAG = 1; \
	} while(0)
#define DATASETTRANS(_seqdata, _u) \
	ENTRYSETTRANS(&((_seqdata)->entry[(_u) & ((_seqdata)->size - 1)]))

// Check for transient missing every 2s
#define TRANCHECKLIMIT 2.0
static tv_t last_trancheck;
// Don't let these messages be slowed down by a trans_process()
#define TRANCHKSEQOK(_seq) ((_seq) != SEQ_SHARES && (_seq) != SEQ_AUTH && \
			    (_seq) != SEQ_ADDRAUTH && (_seq) != SEQ_BLOCK)

/* time (now) is used, not cd, since cd is only relevant to reloading
 *  and we don't run trans_process() during reloading
 * We also only know now, not cd, for a missing item
 * This fills in store with a copy of the details of all the new transients
 * N.B. this is called under seq_lock */
static void trans_process(SEQSET *seqset, tv_t *now, K_STORE *store)
{
	SEQDATA *seqdata = NULL;
	SEQENTRY *seqentry = NULL;
	uint64_t zero, top, u;
	SEQTRANS *seqtrans;
	K_ITEM *st_item;
	int seq;

	for (seq = 0; seq < SEQ_MAX; seq++) {
		seqdata = &(seqset->seqdata[seq]);
		if (seqdata->SEQINUSE == 0)
			continue;

		/* run as 2 loops from seqbase to top, then bottom to maxseq
		 * thus we can use seqentry++ rather than calculating it
		 * each time */
		zero = seqdata->seqbase - (seqdata->seqbase & (seqdata->size - 1));
		top = zero + seqdata->size - 1;
		if (top > seqdata->maxseq)
			top = seqdata->maxseq;
		u = seqdata->seqbase;
		seqentry = &(seqdata->entry[seqdata->seqbase & (seqdata->size - 1)]);
		while (u <= top) {
			if (ENTRYONLYMIS(seqentry) &&
			    tvdiff(now, &(seqentry->time)) > seqdata->timelimit) {
				ENTRYSETTRANS(seqentry);
				seqdata->trans++;
				seqset->trans++;
				// N.B. lock inside lock
				K_WLOCK(seqtrans_free);
				st_item = k_unlink_head(seqtrans_free);
				K_WUNLOCK(seqtrans_free);
				DATA_SEQTRANS(seqtrans, st_item);
				seqtrans->seq = seq;
				seqtrans->seqnum = u;
				memcpy(&(seqtrans->entry), seqentry, sizeof(SEQENTRY));
				k_add_head(store, st_item);
			}
			u++;
			seqentry++;
		}

		// 2nd loop isn't needed, we've already covered the full range
		if (top == seqdata->maxseq)
			continue;

		u = zero + seqdata->size;
		seqentry = &(seqdata->entry[0]);
		while (u <= seqdata->maxseq) {
			if (ENTRYONLYMIS(seqentry) &&
			    tvdiff(now, &(seqentry->time)) > seqdata->timelimit) {
				ENTRYSETTRANS(seqentry);
				seqdata->trans++;
				seqset->trans++;
				// N.B. lock inside lock
				K_WLOCK(seqtrans_free);
				st_item = k_unlink_head(seqtrans_free);
				K_WUNLOCK(seqtrans_free);
				DATA_SEQTRANS(seqtrans, st_item);
				seqtrans->seq = seq;
				seqtrans->seqnum = u;
				memcpy(&(seqtrans->entry), seqentry, sizeof(SEQENTRY));
				k_add_head(store, st_item);
			}
			u++;
			seqentry++;
		}
	}
}

static void trans_seq(tv_t *now)
{
	char t_buf[DATE_BUFSIZ], t_buf2[DATE_BUFSIZ];
	K_STORE *store;
	SEQSET *seqset = NULL;
	K_ITEM *item = NULL, *lastitem = NULL;
	SEQTRANS *seqtrans;
	K_ITEM *st_item;
	uint64_t seqstt = 0, seqpid = 0;
	bool more = true;
	int i, j;

	store = k_new_store(seqtrans_free);
	for (i = 0; more; i++) {
		ck_wlock(&seq_lock);
		if (seqset_store->count <= i)
			more = false;
		else {
			item = seqset_store->head;
			for (j = 0; item && j < 0; j++)
				item = item->next;
			if (!item)
				more = false;
			else {
				/* Avoid wasting time reprocessing the item
				 *  if a new set was added outside the lock
				 *  and pushed the sets along one */
				if (item != lastitem) {
					DATA_SEQSET(seqset, item);
					seqstt = seqset->seqstt;
					seqpid = seqset->seqpid;
					if (seqstt)
						trans_process(seqset, now, store);
					else
						more = false;
				}
				lastitem = item;
			}
		}
		if (seqset_store->count <= (i + 1))
			more = false;
		ck_wunlock(&seq_lock);

		st_item = store->tail;
		while (st_item) {
			DATA_SEQTRANS(seqtrans, st_item);
			btu64_to_buf(&seqstt, t_buf, sizeof(t_buf));
			bt_to_buf(&(seqtrans->entry.time.tv_sec), t_buf2,
				  sizeof(t_buf2));
			LOGWARNING("Seq trans %s %"PRIu64" set:%d/%"PRIu64
				   "=%s/%"PRIu64" %s/%s",
				   seqnam[seqtrans->seq], seqtrans->seqnum,
				   i, seqstt, t_buf, seqpid,
				   t_buf2, seqtrans->entry.code);
			st_item = st_item->prev;
		}
		if (store->head) {
			K_WLOCK(seqtrans_free);
			k_list_transfer_to_head(store, seqtrans_free);
			if (seqtrans_free->count == seqtrans_free->total &&
			    seqtrans_free->total >= ALLOC_SEQTRANS * CULL_SEQTRANS)
				k_cull_list(seqtrans_free);
			K_WUNLOCK(seqtrans_free);
		}
	}
	store = k_free_store(store);
}

/* Only called once just before flagging reload as finished
 * Set all the reloadmax variables in all seqdata */
static void seq_reloadmax()
{
	K_ITEM *seqset_item;
	SEQSET *seqset;
	SEQDATA *seqdata;
	int i;

	ck_wlock(&seq_lock);
	if (seqset_store->count > 0) {
		seqset_item = seqset_store->head;
		while (seqset_item) {
			DATA_SEQSET(seqset, seqset_item);
			if (seqset->seqstt) {
				seqdata = seqset->seqdata;
				for (i = 0; i < SEQ_MAX; i++) {
					if (seqdata->SEQINUSE)
						seqdata->reloadmax = seqdata->maxseq;
					seqdata++;
				}
			}
			seqset_item = seqset_item->next;
		}
	}
	ck_wunlock(&seq_lock);
}

/* Most of the extra message logic in here is to avoid putting too many
 *  messages or incorrect messages on the console when errors occur
 * It wont lose msglines from the reload or the queue, since if there is any
 *  problem with any msgline, it will be processed rather than skipped
 * Only valid duplicates, with all 4 sequence numbers (all, cmd, stt, pid)
 *  matching a previous msgline, are flagged DUP to be skipped by the
 *  sequence code */
static bool update_seq(enum seq_num seq, uint64_t n_seqcmd,
			uint64_t n_seqstt, uint64_t n_seqpid,
			char *nam, tv_t *now, tv_t *cd, char *code,
			int seqentryflags, char *msg)
{
	char t_buf[DATE_BUFSIZ], t_buf2[DATE_BUFSIZ], *st = NULL;
	bool firstseq, newseq, expseq, gothigh, okhi, gotstale, gotstalestart;
	SEQSET *seqset = NULL, *seqset0 = NULL, seqset_pre = { 0 };
	SEQSET seqset_exp = { 0 }, seqset_copy = { 0 };
	bool dup, wastrans, doitem, dotime, gotrecover;
	SEQDATA *seqdata;
	SEQENTRY *seqentry, seqentry_copy, *u_entry;
	K_ITEM *seqset_item = NULL, *st_item = NULL, *stl_item = NULL;
	SEQTRANS *seqtrans = NULL, *seqtrans2 = NULL;
	size_t siz, end;
	void *off0, *offn;
	uint64_t u;
	int set = -1, expset = -1, highlimit, i;
	K_STORE *lost = NULL;

	LOGDEBUG("%s() SQ %c:%d/%s/%"PRIu64"/%"PRIu64"/%"PRIu64"/%s '%.80s...",
		 __func__, SECHR(seqentryflags), seq, nam, n_seqcmd, n_seqstt,
		 n_seqpid, code, st = safe_text(msg));
	FREENULL(st);

	firstseq = newseq = expseq = gothigh = okhi = gotstale =
	gotstalestart = dup = wastrans = gotrecover = false;
	ck_wlock(&seq_lock);
	// Get the seqset
	if (seqset_store->count == 0)
		firstseq = true;
	else {
		// Normal processing is: count=1 and head is current
		seqset_item = seqset_store->head;
		DATA_SEQSET(seqset, seqset_item);
		set = 0;
		if (n_seqstt == seqset->seqstt && n_seqpid == seqset->seqpid)
			goto gotseqset;
		// It's not the current set, check the older ones
		while ((seqset_item = seqset_item->next)) {
			DATA_SEQSET(seqset, seqset_item);
			set++;
			if (seqset->seqstt && n_seqstt == seqset->seqstt &&
			    n_seqpid == seqset->seqpid) {
				goto gotseqset;
			}
		}
	} 

	// Need to setup a new seqset
	newseq = true;
	if (!firstseq) {
		// If !seqset_store->head (i.e. a bug) this will quit()
		DATA_SEQSET(seqset0, seqset_store->head);
		// The current seqset (may become the previous)
		memcpy(&seqset_pre, seqset0, sizeof(seqset_pre));
	}
	seqset_item = k_unlink_head_zero(seqset_free);
	if (seqset_item) {
		// Setup a new set - everything is already zero
		DATA_SEQSET(seqset, seqset_item);
		seqset->seqstt = n_seqstt;
		seqset->seqpid = n_seqpid;
		for (i = 0; i < SEQ_MAX; i++) {
			// Unnecessary - but as a reminder
			seqset->seqdata[i].SEQINUSE = 0;
			switch (i) {
			    case SEQ_ALL:
			    case SEQ_SHARES:
				seqset->seqdata[i].size = SEQ_LARGE_SIZ;
				seqset->seqdata[i].timelimit = SEQ_LARGE_TRANS_LIM;
				break;
			    case SEQ_WORKERSTAT:
			    case SEQ_AUTH:
			    case SEQ_ADDRAUTH:
				seqset->seqdata[i].size = SEQ_MEDIUM_SIZ;
				seqset->seqdata[i].timelimit = SEQ_MEDIUM_TRANS_LIM;
				break;
			    default:
				seqset->seqdata[i].size = SEQ_SMALL_SIZ;
				seqset->seqdata[i].timelimit = SEQ_SMALL_TRANS_LIM;
				break;
			}
			siz = seqset->seqdata[i].size;
			if (siz < BASE_SIZ || (siz & (siz-1))) {
				// On the first ever seq record
				quithere(1, "seqdata[%d] size %d (0x%x) is %s %d",
					    i, (int)siz, (int)siz,
					    (siz < BASE_SIZ) ?
						"too small, must be >=" :
						"not a power of",
					    (siz < BASE_SIZ) ? BASE_SIZ : 2);
			}
			highlimit = siz >> HIGH_SHIFT;
			if (highlimit < HIGH_MIN) {
				// On the first ever seq record
				quithere(1, "seqdata[%d] highlimit %d (0x%x) "
					    "is too small, must be >= %d",
					    i, highlimit, highlimit, HIGH_MIN);
			}
			seqset->seqdata[i].highlimit = highlimit;
			seqset->seqdata[i].entry = calloc(siz, sizeof(SEQENTRY));
			end = siz * sizeof(SEQENTRY);
			off0 = &(seqset->seqdata[i].entry[0]);
			offn = &(seqset->seqdata[i].entry[siz]);
			if ((int)end != (offn - off0)) {
				// On the first ever seq record
				quithere(1, "memory size (%d) != structure "
					    "offset (%d) - your cc sux",
					    (int)end, (int)(offn - off0));
			}
			LIST_MEM_ADD_SIZ(seqset_free, end);
		}
	} else {
		/* Expire the oldest set and overwrite it
		 * If this happens during a reload and the expired set is in
		 *  the queue, then this will most likely end up spitting out
		 *  lots of errors since this will cause a chain reaction,
		 *  after the reload completes, of expiring the last set, that
		 *  is ahead in the unprocessed queue, each time the queue
		 *  advances to the next set
		 * This can only happen if the pool restarts SEQ_MAX times
		 *  during the reload ... so it's extremely unlikely but
		 *  also will be obvious in the console log if it happens
		 * The (very unlikely) side effect would be that it could miss
		 *  spotting lost sequence numbers: between the maxseq of a set
		 *  in the reload, and the base of the same set in the queue
		 * The fix is simply to stop ckdb immediately if ckpool is
		 *  constantly failing (SEQ_MAX times during the reload) and
		 *  restart ckdb when ckpool isn't aborting, or if ckpool is
		 *  in a problematic state, start ckdb while ckpool isn't
		 *  running, then start ckpool when ckdb completes it's full
		 *  startup */
		K_ITEM *ss_item;
		SEQSET *ss = NULL;
		int s = 0;
		seqset = NULL;
		seqset_item = NULL;
		ss_item = seqset_store->head;
		while (ss_item) {
			DATA_SEQSET(ss, ss_item);
			if (!seqset) {
				seqset = ss;
				seqset_item = ss_item;
				expset = s;
			} else {
				// choose the last match
				if (ss->seqstt >= seqset->seqstt) {
					seqset = ss;
					seqset_item = ss_item;
					expset = s;
				}
			}
			ss_item = ss_item->next;
			s++;
		}
		// If !seqset_item (i.e. a bug) k_unlink_item() will quit()
		k_unlink_item(seqset_store, seqset_item);
		DATA_SEQSET(seqset, seqset_item);
		memcpy(&seqset_exp, seqset, sizeof(seqset_exp));
		expseq = true;
		RESETSET(seqset, n_seqstt, n_seqpid);
	}
	/* To avoid putting an old set as first in the list, if they are out
	 *  of order, each new set is added depending upon the value of seqstt
	 *  so the current pool is first, to minimise searching seqset_store
	 * The order of the rest isn't as important
	 * N.B. a new set is only created once per ckpool start */
	if (firstseq) {
		k_add_head(seqset_store, seqset_item);
		set = 0;
	} else {
		// seqset0 already is the head
		if (n_seqstt >= seqset0->seqstt) {
			// if new set is >= head then make it the head
			k_add_head(seqset_store, seqset_item);
			set = 0;
		} else {
			// put it next after the head
			k_insert_after(seqset_store, seqset_item,
					seqset_store->head);
			set = 1;
		}
	}

gotseqset:
	doitem = dotime = false;

	seqdata = &(seqset->seqdata[seq]);
	seqentry = &(seqdata->entry[n_seqcmd & (seqdata->size - 1)]);
	if (seqdata->SEQINUSE == 0) {
		// First n_seqcmd for the given seq
		copy_tv(&(seqdata->firsttime), now);
		copy_tv(&(seqdata->lasttime), now);
		copy_tv(&(seqdata->firstcd), cd); // In use
		copy_tv(&(seqdata->lastcd), cd);
		seqdata->minseq = seqdata->maxseq =
		seqdata->seqbase = n_seqcmd;
		doitem = true;
		goto setitemdata;
		// TODO: add a check/message if minseq!=0 and
		//	 it's a 2nd or later set
	}

	if (n_seqcmd > seqdata->maxseq) {
		/* New seq above maxseq */
		if ((n_seqcmd - seqdata->maxseq) > seqdata->highlimit) {
			/* During a reload there may be missing data/gaps if
			 *  there was some problem with the reload data
			 * When we switch from the reload data to the queue
			 *  data, it is also flagged ok since it may also be
			 *  due to lost data at the end, or missing reload files
			 * In both these cases the message will be 'OKHI'
			 *  instead of 'HIGH'
			 * If however this is caused by a corrupt seq number
			 *  then the result will be a large range of lost
			 *  msglines followed by continuous stale msglines
			 *  until it catches up to the corrupt seq number
			 *  Currently the only fix to get rid of the console
			 *   messages is to fix/remove the corrupt high
			 *   msgline from the reload data and restart ckdb
			 *   You would have to stop ckdb first if it is in the
			 *    current hour reload file
			 *  Note of course if it came from the queue it will
			 *   be in the reload data when you restart ckdb */
			if ((seqentryflags & SE_RELOAD) ||
			    (seqdata->maxseq == seqdata->reloadmax))
				okhi = true;

			seqdata->high++;
			seqset->high++;
			memcpy(&seqset_copy, seqset, sizeof(seqset_copy));
			gothigh = true;
		}
		for (u = seqdata->maxseq + 1; u <= n_seqcmd; u++) {
			if ((u - seqdata->seqbase) < seqdata->size) {
				// u is unused
				if (u < n_seqcmd) {
					// Flag skipped ones as missing
					DATASETMIS(seqdata, u, now);
					seqdata->missing++;
					seqset->missing++;
				}
			} else {
				// u is used by (u-size)
				u_entry = &(seqdata->entry[u & (seqdata->size - 1)]);
				if (ENTRYISMIS(u_entry)) {
					/* (u-size) was missing
					 * N.B. lock inside lock */
					K_WLOCK(seqtrans_free);
					st_item = k_unlink_head(seqtrans_free);
					if (u_entry->flags & SE_RELOAD)
						stl_item = k_unlink_head(seqtrans_free);
					K_WUNLOCK(seqtrans_free);
					DATA_SEQTRANS(seqtrans, st_item);
					seqtrans->seqnum = u - seqdata->size;
					memcpy(&(seqtrans->entry), u_entry,
						sizeof(SEQENTRY));
					if (!lost)
						lost = k_new_store(seqtrans_free);
					k_add_tail(lost, st_item);
					seqdata->lost++;
					seqset->lost++;
					if (ENTRYISTRANS(u_entry)) {
						// no longer trans
						seqdata->trans--;
						seqset->trans--;
					}
					if (u == n_seqcmd) {
						// new wont be missing
						seqdata->missing--;
						seqset->missing--;
					} else {
						// new will also be missing
						ENTRYSETMIS(u_entry, now);
					}

					/* Store stale reload entries so we can
					 *  check against any stale queue
					 *  entries and flag them as recovered
					 *  or DUP */
					if (u_entry->flags & SE_RELOAD) {
						DATA_SEQTRANS(seqtrans, stl_item);
						seqtrans->seqnum = u - seqdata->size;
						memcpy(&(seqtrans->entry), u_entry,
							sizeof(SEQENTRY));
						if (!seqdata->reload_lost) {
							seqdata->reload_lost = k_new_store(seqtrans_free);
							seqdata_reload_lost = true;
						}
						k_add_tail(seqdata->reload_lost, stl_item);
					}
				} else {
					// (u-size) wasn't missing
					if (u < n_seqcmd) {
						// Flag skipped as missing
						DATASETMIS(seqdata, u, now);
						seqdata->missing++;
						seqset->missing++;
					}
				}
				seqdata->seqbase++;
			} 
			seqdata->maxseq++;
		}
		// store n_seqcmd
		doitem = true;
		dotime = true;
	} else if (n_seqcmd >= seqdata->seqbase) {
		/* It's within the range thus DUP or missing */
		if (!ENTRYISMIS(seqentry)) {
			dup = true;
			memcpy(&seqset_copy, seqset, sizeof(seqset_copy));
			memcpy(&seqentry_copy, seqentry, sizeof(seqentry_copy));
		} else {
			// Found a missing one
			seqdata->missing--;
			seqset->missing--;
			if (ENTRYISTRANS(seqentry)) {
				seqdata->trans--;
				seqset->trans--;
				wastrans = true;
			}
			doitem = true;
			dotime = true;
		}
	} else if (n_seqcmd < seqdata->minseq) {
		/* This would be early during startup, less than minseq
		 * This requires lowering minseq if there's space to lower it
		 *  to n_seqcmd */
		if ((n_seqcmd + seqdata->size) > seqdata->maxseq) {
			// Set all after n_seqcmd but before minseq as missing
			for (u = seqdata->minseq - 1; u > n_seqcmd; u--) {
				DATASETMIS(seqdata, u, now);
				seqdata->minseq--;
				seqdata->seqbase--;
				seqset->missing++;
				seqdata->missing++;
			}
			seqdata->minseq--;
			seqdata->seqbase--;
			doitem = true;
			dotime = true;
		} else {
			// Can't go back that far, so it's stale
			seqdata->stale++;
			seqset->stale++;
			memcpy(&seqset_copy, seqset, sizeof(seqset_copy));
			gotstalestart = true;
		}
	} else {
		/* >=minseq but <seqbase means it's stale
		 * However we want to flag it as a DUP if it is a queued
		 *  msgline that was already processed during the reload
		 *  This can happen if the reload finish seq numbers is
		 *   greater than the first queue seq number + siz
		 *   i.e. a long reload where the queue gets large enough
		 *	  to cause this */
		st_item = NULL;
		if (seqdata->reload_lost) {
			st_item = seqdata->reload_lost->head;
			// seqnum order is not guaranteed
			while (st_item) {
				DATA_SEQTRANS(seqtrans, st_item);
				if (seqtrans->seqnum == n_seqcmd)
					break;
				st_item = st_item->next;
			}
		}
		if (st_item) {
			// recovered a lost entry
			k_unlink_item(seqtrans_free, st_item);
			// N.B. lock inside lock
			K_WLOCK(seqtrans_free);
			k_add_head(seqtrans_free, st_item);
			K_WUNLOCK(seqtrans_free);
			seqdata->lost--;
			seqset->lost--;
			seqdata->recovered++;
			seqset->recovered++;
			seqdata->ok++;
			seqset->ok++;
			memcpy(&seqset_copy, seqset, sizeof(seqset_copy));
			gotrecover = true;
			goto setitemdata;
		}

		/* Reload will still have all the lost entries
		 *  thus since it's not lost/recovered, it must be a DUP */
		if (seqentryflags & SE_RELOAD) {
			memcpy(&seqset_copy, seqset, sizeof(seqset_copy));
			dup = true;
			goto setitemdata;
		}

		/* Before we've synced up the queue and still not discarded
		 *  the reload lost list, if it's not lost/recovered but
		 *  still in the reload range, it must be a DUP */
		if (seqentryflags & SE_EARLYSOCK && n_seqcmd <= seqdata->reloadmax) {
			memcpy(&seqset_copy, seqset, sizeof(seqset_copy));
			dup = true;
			goto setitemdata;
		}

		// Reload lost list is gone or it's after the reload range
		seqdata->stale++;
		seqset->stale++;
		memcpy(&seqset_copy, seqset, sizeof(seqset_copy));
		gotstale = true;
	}

setitemdata:
	// Store the new seq if flagged to do so
	if (doitem) {
		seqentry->flags = seqentryflags;
		copy_tv(&(seqentry->time), now);
		copy_tv(&(seqentry->cd), cd);
		STRNCPY(seqentry->code, code);
		seqdata->ok++;
		seqset->ok++;
	}
	if (dotime) {
		if (tv_newer(now, &(seqdata->firsttime)))
			copy_tv(&(seqdata->firsttime), now);
		if (tv_newer(&(seqdata->lasttime), now))
			copy_tv(&(seqdata->lasttime), now);
		if (tv_newer(cd, &(seqdata->firstcd)))
			copy_tv(&(seqdata->firstcd), cd);
		if (tv_newer(&(seqdata->lastcd), cd))
			copy_tv(&(seqdata->lastcd), cd);
	}

	ck_wunlock(&seq_lock);

	if (firstseq) {
		// The first ever SEQ_ALL
		btu64_to_buf(&n_seqstt, t_buf, sizeof(t_buf));
		LOGWARNING("Seq first init: %s:%"PRIu64" "
			   SEQSTT":%"PRIu64"=%s "SEQPID":%"PRIu64,
			   nam, n_seqcmd, n_seqstt, t_buf, n_seqpid);
	} else {
		if (newseq) {
			if (set == 0)
				SEQSETMSG(0, &seqset_pre, "previous", EMPTY);
			else
				SEQSETMSG(0, &seqset_pre, "current", EMPTY);
		}
		if (expseq) {
			SEQSETMSG(expset, &seqset_exp, "discarded old", " for:");
		}
		if (newseq || expseq) {
			btu64_to_buf(&n_seqstt, t_buf, sizeof(t_buf));
			LOGWARNING("Seq created new: set:%d %s:%"PRIu64" "
				   SEQSTT":%"PRIu64"=%s "SEQPID":%"PRIu64,
				   set, nam, n_seqcmd, n_seqstt, t_buf,
				   n_seqpid);
		}
	}

	if (dup) {
		int level = LOG_WARNING;
		/* If one is SE_RELOAD and the other is SE_EARLYSOCK or
		 *  SE_SOCKET then it's not unexpected, so only use LOG_DEBUG
		 * Technically SE_SOCKET is unexpected, except that at the end
		 *  of the reload sync there may still be pool messages that
		 *  haven't got into the queue yet - it wouldn't be expected
		 *  for there to be many since it would be ckdb emptying the
		 *  queue faster than it is filling due to the reload delay -
		 *  but either way they don't need to be reported */
		if (((seqentry_copy.flags | seqentryflags) & SE_RELOAD) &&
		    ((seqentry_copy.flags | seqentryflags) & (SE_EARLYSOCK | SE_SOCKET)))
			level = LOG_DEBUG;
		btu64_to_buf(&n_seqstt, t_buf, sizeof(t_buf));
		bt_to_buf(&(cd->tv_sec), t_buf2, sizeof(t_buf2));
		LOGMSG(level, "SEQ dup%s %c:%c %s %"PRIu64" set:%d/%"PRIu64
				"=%s/%"PRIu64" %s/%s -vs- v%"PRIu64"/^%"PRIu64
				"/M%"PRIu64"/T%"PRIu64"/L%"PRIu64"/S%"PRIu64
				"/H%"PRIu64"/OK%"PRIu64" cmd=%.42s...",
				(level == LOG_DEBUG) ? "*" : EMPTY,
				SECHR(seqentryflags), SECHR(seqentry_copy.flags),
				nam, n_seqcmd, set, n_seqstt, t_buf, n_seqpid,
				t_buf2, code,
				seqset_copy.seqdata[seq].minseq,
				seqset_copy.seqdata[seq].maxseq,
				seqset_copy.seqdata[seq].missing,
				seqset_copy.seqdata[seq].trans,
				seqset_copy.seqdata[seq].lost,
				seqset_copy.seqdata[seq].stale,
				seqset_copy.seqdata[seq].high,
				seqset_copy.seqdata[seq].ok,
				st = safe_text(msg));
		FREENULL(st);
	}

	if (wastrans || gotrecover) {
		btu64_to_buf(&n_seqstt, t_buf, sizeof(t_buf));
		bt_to_buf(&(cd->tv_sec), t_buf2, sizeof(t_buf2));
		LOGWARNING("%s %s %"PRIu64" set:%d/%"PRIu64"=%s/%"PRIu64
			   " %s/%s",
			   gotrecover ? "SEQ recovered" : "Seq found trans",
			   nam, n_seqcmd, set, n_seqstt, t_buf, n_seqpid,
			   t_buf2, code);
	}

	if (gotstale || gotstalestart || gothigh) {
		btu64_to_buf(&n_seqstt, t_buf, sizeof(t_buf));
		bt_to_buf(&(cd->tv_sec), t_buf2, sizeof(t_buf2));
		LOGWARNING("SEQ %s %s%s %"PRIu64" set:%d/%"PRIu64"=%s/%"PRIu64
			   " %s/%s v%"PRIu64"/^%"PRIu64"/M%"PRIu64"/T%"PRIu64
			   "/L%"PRIu64"/S%"PRIu64"/H%"PRIu64"/OK%"PRIu64
			   " cmd=%.42s...",
			   gothigh ? (okhi ? "OKHI" : "HIGH") : "stale",
			   gotstalestart ? "STARTUP " : EMPTY,
			   nam, n_seqcmd, set, n_seqstt, t_buf, n_seqpid,
			   t_buf2, code,
			   seqset_copy.seqdata[seq].minseq,
			   seqset_copy.seqdata[seq].maxseq,
			   seqset_copy.seqdata[seq].missing,
			   seqset_copy.seqdata[seq].trans,
			   seqset_copy.seqdata[seq].lost,
			   seqset_copy.seqdata[seq].stale,
			   seqset_copy.seqdata[seq].high,
			   seqset_copy.seqdata[seq].ok,
			   st = safe_text(msg));
		FREENULL(st);
	}
	if (reload_queue_complete && TRANCHKSEQOK(seq)) {
		if (last_trancheck.tv_sec == 0)
			setnow(&last_trancheck);
		else {
			if (tvdiff(now, &last_trancheck) > TRANCHECKLIMIT) {
				trans_seq(now);
				setnow(&last_trancheck);
			}
		}
	}

	if (lost && lost->head) {
		int tran = 0, miss = 0;
		uint64_t prev = 0;
		char range_buf[256];
		bool isrange = false;
		st_item = lost->head;
		while (st_item) {
			DATA_SEQTRANS(seqtrans, st_item);
			st_item = st_item->next;
			DATA_SEQTRANS_NULL(seqtrans2, st_item);

			if (ENTRYISTRANS(&(seqtrans->entry)))
				tran++;
			else
				miss++;

			// Output the messages as ranges if they are
			if (st_item && seqtrans2->seqnum == (seqtrans->seqnum+1)) {
				if (!prev)
					prev = seqtrans->seqnum;
				continue;
			}
			if (prev) {
				isrange = true;
				snprintf(range_buf, sizeof(range_buf),
					 "RANGE %d tran %d miss %"PRIu64
					 "-%"PRIu64,
					 tran, miss, prev,
					 seqtrans->seqnum);
				prev = 0;
			} else {
				isrange = false;
				snprintf(range_buf, sizeof(range_buf),
					 "%s %"PRIu64,
					 ENTRYISTRANS(&(seqtrans->entry)) ?
					 "tran" : "miss",
					 seqtrans->seqnum);
			}
			// consumed
			tran = miss = 0;

			btu64_to_buf(&n_seqstt, t_buf, sizeof(t_buf));
			bt_to_buf(&(seqtrans->entry.time.tv_sec), t_buf2,
				   sizeof(t_buf2));
			LOGWARNING("SEQ lost %s %s set:%d/%"PRIu64"=%s/%"PRIu64
				   " %s%s/%s",
				   seqnam[seq], range_buf, set,
				   n_seqstt, t_buf, n_seqpid,
				   isrange ? "last: " : EMPTY,
				   t_buf2, seqtrans->entry.code);
		}
		K_WLOCK(seqtrans_free);
		k_list_transfer_to_head(lost, seqtrans_free);
		if (seqtrans_free->count == seqtrans_free->total &&
		    seqtrans_free->total >= ALLOC_SEQTRANS * CULL_SEQTRANS)
			k_cull_list(seqtrans_free);
		K_WUNLOCK(seqtrans_free);
	}

	if (lost)
		lost = k_free_store(lost);

	return dup;
}

static enum cmd_values process_seq(MSGLINE *msgline)
{
	bool dupall, dupcmd;
	char *st = NULL;

	dupall = update_seq(SEQ_ALL, msgline->n_seqall, msgline->n_seqstt,
			    msgline->n_seqpid, SEQALL, &(msgline->now),
			    &(msgline->cd), msgline->code,
			    msgline->seqentryflags, msgline->msg);
	dupcmd = update_seq(ckdb_cmds[msgline->which_cmds].seq,
			    msgline->n_seqcmd, msgline->n_seqstt,
			    msgline->n_seqpid, msgline->seqcmdnam,
			    &(msgline->now), &(msgline->cd), msgline->code,
			    msgline->seqentryflags, msgline->msg);

	if (dupall != dupcmd) {
		// Bad/corrupt data or a code bug
		LOGEMERG("SEQ INIMICAL %s/%"PRIu64"=%s %s/%"PRIu64"=%s "
			 "cmd=%.32s...",
			 seqnam[SEQ_ALL], msgline->n_seqall,
			 dupall ? "DUP" : "notdup",
			 msgline->seqcmdnam, msgline->n_seqcmd,
			 dupcmd ? "DUP" : "notdup",
			 st = safe_text_nonull(msgline->msg));
		FREENULL(st);
	}

	/* The norm is: neither is a dup, so reply with ok to process
	 * If only one is a dup then that's a corrupt message or a bug
	 *  so simply try to process it as normal */
	if (!dupall || !dupcmd)
		return ckdb_cmds[msgline->which_cmds].cmd_val;

	/* It's a dup */
	return CMD_DUPSEQ;
}

static void setup_seq(K_ITEM *seqall, MSGLINE *msgline)
{
	K_ITEM *seqstt, *seqpid, *seqcmd, *i_code;
	char *err = NULL, *st = NULL;
	size_t len, off;

	msgline->n_seqall = atol(transfer_data(seqall));
	if ((seqstt = find_transfer(msgline->trf_root, SEQSTT)))
		msgline->n_seqstt = atol(transfer_data(seqstt));

	/* Ignore SEQSTTIGN sequence information
	 * This allows us to manually generate ckpool data and send it
	 *  to ckdb using ckpmsg - if SEQSTT == SEQSTTIGN
	 * SEQALL must exist but the value is ignored
	 * SEQPID and SEQcmd don't need to exist and are ignored */
	if (msgline->n_seqstt == SEQSTTIGN) {
		LOGWARNING("%s(): SEQIGN in %.42s...",
			   __func__, st = safe_text(msgline->msg));
		FREENULL(st);
		return;
	}

	if ((seqpid = find_transfer(msgline->trf_root, SEQPID)))
		msgline->n_seqpid = atol(transfer_data(seqpid));
	msgline->seqcmdnam = seqnam[ckdb_cmds[msgline->which_cmds].seq];
	if ((seqcmd = find_transfer(msgline->trf_root, msgline->seqcmdnam)))
		msgline->n_seqcmd = atol(transfer_data(seqcmd));

	/* Make one message with the initial seq missing/value problems ...
	 *  that should never happen if seqall is present */
	if (!seqstt || !seqpid || !seqcmd ||
	    (seqstt && msgline->n_seqstt < DATE_BEGIN) ||
	    (seqpid && msgline->n_seqpid <= 0)) {
		APPEND_REALLOC_INIT(err, off, len);
		APPEND_REALLOC(err, off, len, "SEQ ERROR: command ");
		APPEND_REALLOC(err, off, len, msgline->cmd);
		if (!seqstt || !seqpid || !seqcmd) {
			APPEND_REALLOC(err, off, len, " - missing");
			if (!seqstt)
				APPEND_REALLOC(err, off, len, BLANK SEQSTT);
			if (!seqpid)
				APPEND_REALLOC(err, off, len, BLANK SEQPID);
			if (!seqcmd) {
				APPEND_REALLOC(err, off, len, BLANK);
				APPEND_REALLOC(err, off, len,
						msgline->seqcmdnam);
			}
		}
		if (seqstt && msgline->n_seqstt < DATE_BEGIN) {
			APPEND_REALLOC(err, off, len, " - invalid "SEQSTT":'");
			st = safe_text_nonull(transfer_data(seqstt));
			APPEND_REALLOC(err, off, len, st);
			FREENULL(st);
			APPEND_REALLOC(err, off, len, "'");
		}
		if (seqpid && msgline->n_seqpid <= 0) {
			APPEND_REALLOC(err, off, len, " - invalid "SEQPID":'");
			st = safe_text_nonull(transfer_data(seqpid));
			APPEND_REALLOC(err, off, len, st);
			FREENULL(st);
			APPEND_REALLOC(err, off, len, "'");
		}
		APPEND_REALLOC(err, off, len, " - msg='");
		APPEND_REALLOC(err, off, len, msgline->msg);
		APPEND_REALLOC(err, off, len, "'");
		LOGMSGBUF(LOG_EMERG, err);
		FREENULL(err);

		return;
	}

	msgline->hasseq = true;

	if ((i_code = find_transfer(msgline->trf_root, CODETRF))) {
		msgline->code = transfer_data(i_code);
		if (!(*(msgline->code)))
			msgline->code = NULL;
	}
	if (!(msgline->code)) {
		if ((i_code = find_transfer(msgline->trf_root, BYTRF)))
			msgline->code = transfer_data(i_code);
		else
			msgline->code = EMPTY;
	}
}

static enum cmd_values breakdown(K_ITEM **ml_item, char *buf, tv_t *now,
				 int seqentryflags)
{
	char reply[1024] = "";
	TRANSFER *transfer;
	K_TREE_CTX ctx[1];
	MSGLINE *msgline;
	K_ITEM *t_item = NULL, *cd_item = NULL, *seqall;
	char *cmdptr, *idptr, *next, *eq, *end, *was;
	char *data = NULL, *st = NULL, *st2 = NULL;
	bool noid = false;
	size_t siz;

	K_WLOCK(msgline_free);
	*ml_item = k_unlink_head_zero(msgline_free);
	K_WUNLOCK(msgline_free);
	DATA_MSGLINE(msgline, *ml_item);
	msgline->which_cmds = CMD_UNSET;
	copy_tv(&(msgline->now), now);
	copy_tv(&(msgline->cd), now); // default cd to 'now'
	msgline->msg = strdup(buf);
	msgline->seqentryflags = seqentryflags;

	cmdptr = strdup(buf);
	idptr = strchr(cmdptr, '.');
	if (!idptr || !*idptr)
		noid = true;
	else {
		*(idptr++) = '\0';
		data = strchr(idptr, '.');
		if (data)
			*(data++) = '\0';
		STRNCPY(msgline->id, idptr);
	}

	STRNCPY(msgline->cmd, cmdptr);
	for (msgline->which_cmds = 0;
	     ckdb_cmds[msgline->which_cmds].cmd_val != CMD_END;
	     (msgline->which_cmds)++) {
		if (strcasecmp(msgline->cmd,
				ckdb_cmds[msgline->which_cmds].cmd_str) == 0)
			break;
	}

	if (ckdb_cmds[msgline->which_cmds].cmd_val == CMD_END) {
		LOGQUE(buf, false);
		LOGERR("Listener received unknown command: '%.42s...",
			st2 = safe_text(buf));
		FREENULL(st2);
		goto nogood;
	}

	if (ckdb_cmds[msgline->which_cmds].access & ACCESS_POOL)
		LOGQUE(buf, true);
	else
		LOGQUE(buf, false);

	if (noid) {
		if (ckdb_cmds[msgline->which_cmds].noid) {
			free(cmdptr);
			return ckdb_cmds[msgline->which_cmds].cmd_val;
		}

		LOGERR("Listener received invalid (noid) message: '%.42s...",
			st2 = safe_text(buf));
		FREENULL(st2);
		goto nogood;
	}

	msgline->trf_root = new_ktree(cmp_transfer);
	msgline->trf_store = k_new_store(transfer_free);
	next = data;
	if (next && strncmp(next, JSON_TRANSFER, JSON_TRANSFER_LEN) == 0) {
		// It's json
		next += JSON_TRANSFER_LEN;
		was = next;
		while (*next == ' ')
			next++;
		if (*next != JSON_BEGIN) {
			LOGERR("JSON_BEGIN '%c' was:%.32s... buf=%.32s...",
				JSON_BEGIN, st = safe_text(was),
				st2 = safe_text(buf));
			FREENULL(st);
			FREENULL(st2);
			goto nogood;
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
				LOGERR("JSON name no trailing '%c' "
					"was:%.32s... buf=%.32s...",
					JSON_STR, st = safe_text(was),
					st2 = safe_text(buf));
				FREENULL(st);
				FREENULL(st2);
				goto nogood;
			}
			if (next == end) {
				LOGERR("JSON zero length name was:%.32s..."
					" buf=%.32s...",
					st = safe_text(was),
					st2 = safe_text(buf));
				FREENULL(st);
				FREENULL(st2);
				goto nogood;
			}
			*(end++) = '\0';
			K_WLOCK(transfer_free);
			t_item = k_unlink_head(transfer_free);
			K_WUNLOCK(transfer_free);
			DATA_TRANSFER(transfer, t_item);
			STRNCPY(transfer->name, next);
			was = next = end;
			while (*next == ' ')
				next++;
			// we have a name, now expect a value after it
			if (*next != JSON_VALUE) {
				LOGERR("JSON_VALUE '%c' '%s' was:%.32s..."
					" buf=%.32s...",
					JSON_VALUE, transfer->name,
					st = safe_text(was),
					st2 = safe_text(buf));
				FREENULL(st);
				FREENULL(st2);
				goto nogood;
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
					LOGERR("JSON '%s' value was:%.32s..."
						" buf=%.32s...",
						transfer->name,
						st = safe_text(was),
						st2 = safe_text(buf));
					FREENULL(st);
					FREENULL(st2);
					goto nogood;
				}
				siz = end - next;
				end++;
			} else if (*next == JSON_ARRAY) {
				// Only merklehash for now
				if (strcmp(transfer->name, "merklehash")) {
					LOGERR("JSON '%s' can't be an array"
						" buf=%.32s...",
						transfer->name,
						st2 = safe_text(buf));
					FREENULL(st2);
					goto nogood;
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
						"was:%.32s... buf=%.32s...",
						transfer->name,
						st = safe_text(was),
						st2 = safe_text(buf));
					FREENULL(st);
					FREENULL(st2);
					goto nogood;
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
					LOGERR("JSON '%s' value was:%.32s..."
						" buf=%.32s...",
						transfer->name,
						st = safe_text(was),
						st2 = safe_text(buf));
					FREENULL(st);
					FREENULL(st2);
					goto nogood;
				}
				if (next == end) {
					LOGERR("JSON '%s' zero length value "
						"was:%.32s... buf=%.32s...",
						transfer->name,
						st = safe_text(was),
						st2 = safe_text(buf));
					FREENULL(st);
					FREENULL(st2);
					goto nogood;
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
			add_to_ktree(msgline->trf_root, t_item);
			k_add_head(msgline->trf_store, t_item);
			t_item = NULL;

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
			LOGERR("JSON_END '%c' was:%.32s... buf=%.32s...",
				JSON_END, st = safe_text(next),
				st2 = safe_text(buf));
			FREENULL(st);
			FREENULL(st2);
			goto nogood;
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

			t_item = k_unlink_head(transfer_free);
			DATA_TRANSFER(transfer, t_item);
			STRNCPY(transfer->name, data);
			STRNCPY(transfer->svalue, eq);
			transfer->mvalue = transfer->svalue;

			// Discard duplicates
			if (find_in_ktree(msgline->trf_root, t_item, ctx)) {
				if (transfer->mvalue != transfer->svalue)
					FREENULL(transfer->mvalue);
				k_add_head(transfer_free, t_item);
			} else {
				add_to_ktree(msgline->trf_root, t_item);
				k_add_head(msgline->trf_store, t_item);
			}
		}
		K_WUNLOCK(transfer_free);
	}

	seqall = find_transfer(msgline->trf_root, SEQALL);
	if (ckdb_cmds[msgline->which_cmds].createdate) {
		cd_item = require_name(msgline->trf_root, CDTRF, 10, NULL,
					reply, sizeof(reply));
		if (!cd_item)
			goto nogood;

		DATA_TRANSFER(transfer, cd_item);
		txt_to_ctv(CDTRF, transfer->mvalue, &(msgline->cd),
			   sizeof(msgline->cd));
		if (msgline->cd.tv_sec == 0) {
			LOGERR("%s(): failed, %s has invalid "CDTRF" '%s'",
				__func__, cmdptr, transfer->mvalue);
			goto nogood;
		}
		if (confirm_check_createdate)
			check_createdate_ccl(msgline->cmd, &(msgline->cd));
		if (seqall) {
			setup_seq(seqall, msgline);
			free(cmdptr);
			return ckdb_cmds[msgline->which_cmds].cmd_val;
		} else {
			/* It's OK to load old data from the CCLs
			 *  but socket data must contain SEQALL ...
			 *  even in manually generated data */
			if (startup_complete) {
				LOGEMERG("%s(): *** ckpool needs upgrading? - "
					 "missing "SEQALL" from '%s' ckpool "
					 "data in '%s'",
					 __func__, cmdptr,
					 st = safe_text_nonull(buf));
				FREENULL(st);
			}
		}
	} else {
		/* Bug somewhere or createdate flag missing
		 * This ignores/discards all seq info */
		if (seqall) {
			LOGWARNING("%s(): msg '%s' shouldn't contain "SEQALL
				   " in '%s'",
				   __func__, cmdptr,
				   st = safe_text_nonull(buf));
			FREENULL(st);
		}
	}
	free(cmdptr);
	return ckdb_cmds[msgline->which_cmds].cmd_val;
nogood:
	if (t_item) {
		K_WLOCK(transfer_free);
		k_add_head(transfer_free, t_item);
		K_WUNLOCK(transfer_free);
	}
	free(cmdptr);
	return CMD_REPLY;
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
		hi = wic->height;
	}
	K_RUNLOCK(workinfo_free);

	// Wait at least for the (badly named) '2nd' confirm
	if (hi == 0 || blocks->height >= (hi - 1))
		return;

	diffacc = diffinv = shareacc = shareinv = 0;
	elapsed = 0;
	K_RLOCK(blocks_free);
	b_prev = find_prev_blocks(blocks->height, NULL);
	K_RUNLOCK(blocks_free);
	if (!b_prev) {
		wi_start = 0;
		DATE_ZERO(&elapsed_start);
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
	DATE_ZERO(&elapsed_finish);

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
					ss_ctx);
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
		if (sharesummary->diffacc > 0) {
			if (elapsed_start.tv_sec == 0 ||
			    !tv_newer(&elapsed_start, &(sharesummary->firstshareacc))) {
				copy_tv(&elapsed_start, &(sharesummary->firstshareacc));
			}
			if (tv_newer(&elapsed_finish, &(sharesummary->lastshareacc)))
				copy_tv(&elapsed_finish, &(sharesummary->lastshareacc));
		}

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
				       ctx);
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
						       ms_ctx);
			DATA_MARKERSUMMARY_NULL(markersummary, ms_item);
			while (ms_item && markersummary->markerid == workmarkers->markerid) {
				has_ms = true;
				if (markersummary->diffacc > 0) {
					if (elapsed_start.tv_sec == 0 ||
					    !tv_newer(&elapsed_start, &(markersummary->firstshareacc))) {
						copy_tv(&elapsed_start, &(markersummary->firstshareacc));
					}
					if (tv_newer(&elapsed_finish, &(markersummary->lastshareacc)))
						copy_tv(&elapsed_finish, &(markersummary->lastshareacc));
				}

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
		if (genpayout_auto)
			pplns_block(blocks);
		else {
			LOGWARNING("%s() Auto payout generation disabled",
				   __func__);
		}
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

	/* Don't do any summarisation until the reload queue completes coz:
	 * 1) It locks/accesses a lot of data - workinfo/markersummary that
	 *    can slow down the reload
	 * 2) If you stop and restart ckdb this wont affect the restart point
	 *    Thus it's OK to do it later
	 * 3) It does I/O to bitcoind which is slow ...
	 * 4) It triggers the payout generation which also accesses a lot of
	 *    data - workinfo/markersummary - but it wont affect a later
	 *    restart point if it hasn't been done. Thus it's OK to do it later
	 */
	while (!everyone_die && !reload_queue_complete)
		cksleep_ms(42);

	if (!everyone_die) {
		LOGWARNING("%s() Start processing...", __func__);
		summariser_using_data = true;
	}

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
	"tenshi",
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

// A diff change will end the current shift if it occurs after this block
#define SHIFT_DIFF_BLOCK 376500

// optioncontrol name to override the SHIFT_DIFF_BLOCK value
#define SHIFT_DIFF_BLOCK_STR "ShiftDiffBlock"

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
	int64_t shiftdiffblock = SHIFT_DIFF_BLOCK;
	char wi_bits[TXT_SML+1];
	bool was_block = false, ok, oc_look = true;
	char cd_buf[DATE_BUFSIZ], cd_buf2[DATE_BUFSIZ], cd_buf3[DATE_BUFSIZ];
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
		tv_to_buf(&(sharesummary->lastshareacc), cd_buf, sizeof(cd_buf));
		tv_to_buf(&(sharesummary->lastshare), cd_buf2, sizeof(cd_buf2));
		tv_to_buf(&(sharesummary->createdate), cd_buf3, sizeof(cd_buf3));
		LOGDEBUG("%s() last sharesummary %s/%s/%"PRId64"/%s/%s/%s",
			 __func__, sharesummary->complete,
			 sharesummary->workername,
			 ss_age_wid, cd_buf, cd_buf2, cd_buf3);
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
	wi_item = find_after_in_ktree(workinfo_root, &wi_look, wi_ctx);
	K_RUNLOCK(workinfo_free);
	marks_wid = 0;
	used_wid = 0;
	prev_wid = 0;
	wi_bits[0] = '\0';
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
			if (wi_bits[0] == '\0')
				STRNCPY(wi_bits, workinfo->bits);
			else {
				/* Make sure you set the SHIFT_DIFF_BLOCK_STR
				 *  optioncontrol if you changed ckdb to V1.323
				 *  before the diff change, before the block=
				 *  SHIFT_DIFF_BLOCK default value
				 * This however, would only affect a reload
				 *  after that if the reload crossed the
				 *  previous diff change and the shifts had not
				 *  already been stored in the DB (i.e. next to
				 *  zero probability)
				 * However a DB rollback and reload across that
				 *  diff change would be affected */
				if (oc_look) {
					shiftdiffblock = sys_setting(SHIFT_DIFF_BLOCK_STR,
								     SHIFT_DIFF_BLOCK,
								     &date_eot);
					oc_look = false;
				}
				/* Did difficulty change?
				 * Stop at the last workinfo, before the diff
				 *  changed */
				if (strcmp(wi_bits, workinfo->bits) != 0) {
					if (workinfo->height > (int32_t)shiftdiffblock) {
						LOGDEBUG("%s() OK shift stops at diff"
							 " change '%s->%s' %"PRId64
							 "->%"PRId64" height %"PRId32
							 " limit %"PRId64,
							 __func__, wi_bits,
							 workinfo->bits, prev_wid,
							 workinfo->workinfoid,
							 workinfo->height,
							 shiftdiffblock);
						marks_wid = prev_wid;
						break;
					}
				}
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
			ss_item = find_before_in_ktree(sharesummary_workinfoid_root,
							&ss_look, ss_ctx);
			K_RUNLOCK(sharesummary_free);
			DATA_SHARESUMMARY_NULL(sharesummary, ss_item);
			if (ss_item &&
			    sharesummary->workinfoid == workinfo->workinfoid) {
				/* Not aged = shift not complete
				 * Though, it shouldn't happen */
				if (sharesummary->complete[0] == SUMMARY_NEW) {
					tv_to_buf(&(sharesummary->lastshareacc),
						  cd_buf, sizeof(cd_buf));
					tv_to_buf(&(sharesummary->lastshare),
						  cd_buf2, sizeof(cd_buf2));
					tv_to_buf(&(sharesummary->createdate),
						  cd_buf3, sizeof(cd_buf3));
					LOGEMERG("%s() ERR unaged sharesummary "
						 "%s/%s/%"PRId64"/%s/%s/%s",
						 __func__, sharesummary->complete,
						 sharesummary->workername,
						 sharesummary->workinfoid,
						 cd_buf, cd_buf2, cd_buf3);
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

	/* We want this to start during the CCL reload so that if we run a
	 *  large reload and it fails at some point, the next reload will not
	 *  always have to go back to the same reload point as before due to
	 *  no new workmarkers being completed/processed
	 * However, don't start during the first N reload files so that a
	 *  normal ckdb restart reload won't slow down */
	while (!everyone_die && !reloaded_N_files && !reload_queue_complete)
		cksleep_ms(42);

	if (sharesummary_marks_limit) {
		LOGEMERG("%s() ALERT: dbload -w disables shift processing",
			 __func__);
		return NULL;
	}

	if (!everyone_die) {
		LOGWARNING("%s() Start processing...", __func__);
		marker_using_data = true;
	}

	while (!everyone_die) {
		for (i = 0; i < 5; i++) {
			if (!everyone_die)
				sleep(1);
		}
		if (everyone_die)
			break;
		else {
			if (markersummary_auto)
				make_a_shift_mark();
		}

		for (i = 0; i < 4; i++) {
			if (!everyone_die)
				sleep(1);
		}
		if (everyone_die)
			break;
		else {
			if (markersummary_auto)
				make_a_workmarker();
		}

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

	LOGWARNING("%s() Start processing...", __func__);
	logger_using_data = true;

	setnow(&now);
	snprintf(buf, sizeof(buf), "logstart.%ld,%ld",
				   now.tv_sec, now.tv_usec);
	LOGFILE(buf, logname_db);
	LOGFILE(buf, logname_io);

	while (!everyone_die) {
		K_WLOCK(logqueue_free);
		lq_item = k_unlink_head(logqueue_store);
		K_WUNLOCK(logqueue_free);
		while (lq_item) {
			DATA_LOGQUEUE(lq, lq_item);
			if (lq->db)
				LOGFILE(lq->msg, logname_db);
			else
				LOGFILE(lq->msg, logname_io);
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
	LOGFILE(buf, logname_db);
	LOGFILE(buf, logname_io);
	if (count)
		LOGERR("%s", buf);
	lq_item = logqueue_store->head;
	copy_tv(&then, &now);
	while (lq_item) {
		DATA_LOGQUEUE(lq, lq_item);
		if (lq->db)
			LOGFILE(lq->msg, logname_db);
		else
			LOGFILE(lq->msg, logname_io);
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
	LOGFILE(buf, logname_db);
	LOGFILE(buf, logname_io);
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
	// No dup check for pool stats, the SEQ code will handle that
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
	int sockd;
	K_ITEM *wq_item = NULL, *ml_item = NULL;
	WORKQUEUE *workqueue;
	MSGLINE *msgline;
	char reply[1024+1];
	size_t siz;
	tv_t now;
	bool dup, want_first, show_dup, replied;
	int loglevel, oldloglevel;

	pthread_detach(pthread_self());

	rename_proc("db_socketer");

	while (!everyone_die && !db_users_complete)
		cksem_mswait(&socketer_sem, 420);

	if (!everyone_die) {
		LOGWARNING("%s() Start processing...", __func__);
		socketer_using_data = true;
	}

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

		buf = recv_unix_msg_tmo2(sockd, RECV_UNIX_TIMEOUT1, RECV_UNIX_TIMEOUT2);
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
			if (last_chkpass && strcmp(last_chkpass, buf) == 0) {
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
				// dup cant be pool
				LOGQUE(reply, false);
				if (show_dup)
					LOGWARNING("Duplicate '%s' message received", duptype);
				else
					LOGDEBUG("Duplicate '%s' message received", duptype);
			} else {
				int seqentryflags = SE_SOCKET;
				if (!reload_queue_complete)
					seqentryflags = SE_EARLYSOCK;
				cmdnum = breakdown(&ml_item, buf, &now, seqentryflags);
				DATA_MSGLINE(msgline, ml_item);
				replied = false;
				switch (cmdnum) {
					case CMD_REPLY:
						snprintf(reply, sizeof(reply),
							 "%s.%ld.?.",
							 msgline->id,
							 now.tv_sec);
						send_unix_msg(sockd, reply);
						break;
					case CMD_TERMINATE:
						LOGWARNING("Listener received"
							   " terminate message,"
							   " terminating ckdb");
						snprintf(reply, sizeof(reply),
							 "%s.%ld.ok.exiting",
							 msgline->id,
							 now.tv_sec);
						send_unix_msg(sockd, reply);
						everyone_die = true;
						break;
					case CMD_PING:
						LOGDEBUG("Listener received ping"
							 " request");
						snprintf(reply, sizeof(reply),
							 "%s.%ld.ok.pong",
							 msgline->id,
							 now.tv_sec);
						send_unix_msg(sockd, reply);
						break;
					case CMD_VERSION:
						LOGDEBUG("Listener received"
							 " version request");
						snprintf(reply, sizeof(reply),
							 "%s.%ld.ok.CKDB V%s",
							 msgline->id,
							 now.tv_sec,
							 CKDB_VERSION);
						send_unix_msg(sockd, reply);
						break;
					case CMD_LOGLEVEL:
						if (!*(msgline->id)) {
							LOGDEBUG("Listener received"
								 " loglevel, currently %d",
								 pi->ckp->loglevel);
							snprintf(reply, sizeof(reply),
								 "%s.%ld.ok.loglevel"
								 " currently %d",
								 msgline->id,
								 now.tv_sec,
								 pi->ckp->loglevel);
						} else {
							oldloglevel = pi->ckp->loglevel;
							loglevel = atoi(msgline->id);
							LOGDEBUG("Listener received loglevel"
								 " %d currently %d A",
								 loglevel, oldloglevel);
							if (loglevel < LOG_EMERG ||
							    loglevel > LOG_DEBUG) {
								snprintf(reply, sizeof(reply),
									 "%s.%ld.ERR.invalid"
									 " loglevel %d"
									 " - currently %d",
									 msgline->id,
									 now.tv_sec,
									 loglevel,
									 oldloglevel);
							} else {
								pi->ckp->loglevel = loglevel;
								snprintf(reply, sizeof(reply),
									 "%s.%ld.ok.loglevel"
									 " now %d - was %d",
									 msgline->id,
									 now.tv_sec,
									 pi->ckp->loglevel,
									 oldloglevel);
							}
							// Do this twice since the loglevel may have changed
							LOGDEBUG("Listener received loglevel"
								 " %d currently %d B",
								 loglevel, oldloglevel);
						}
						send_unix_msg(sockd, reply);
						break;
					case CMD_FLUSH:
						LOGDEBUG("Listener received"
							 " flush request");
						snprintf(reply, sizeof(reply),
							 "%s.%ld.ok.splash",
							 msgline->id, now.tv_sec);
						send_unix_msg(sockd, reply);
						fflush(stdout);
						fflush(stderr);
						if (global_ckp && global_ckp->logfd)
							fflush(global_ckp->logfp);
						break;
					case CMD_CHKPASS:
					case CMD_2FA:
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
					case CMD_SHSTA:
					case CMD_USERINFO:
					case CMD_BTCSET:
						ans = ckdb_cmds[msgline->which_cmds].func(NULL,
								msgline->cmd,
								msgline->id,
								&(msgline->now),
								by_default,
								(char *)__func__,
								inet_default,
								&(msgline->cd),
								msgline->trf_root);
						siz = strlen(ans) + strlen(msgline->id) + 32;
						rep = malloc(siz);
						snprintf(rep, siz, "%s.%ld.%s",
							 msgline->id,
							 now.tv_sec, ans);
						send_unix_msg(sockd, rep);
						FREENULL(ans);
						switch (cmdnum) {
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
					case CMD_PSHIFT:
					case CMD_DSP:
					case CMD_BLOCKSTATUS:
						if (!startup_complete) {
							snprintf(reply, sizeof(reply),
								 "%s.%ld.loading.%s",
								 msgline->id,
								 now.tv_sec,
								 msgline->cmd);
							send_unix_msg(sockd, reply);
						} else {
							DATA_MSGLINE(msgline, ml_item);
							ans = ckdb_cmds[msgline->which_cmds].func(NULL,
									msgline->cmd,
									msgline->id,
									&(msgline->now),
									by_default,
									(char *)__func__,
									inet_default,
									&(msgline->cd),
									msgline->trf_root);
							siz = strlen(ans) + strlen(msgline->id) + 32;
							rep = malloc(siz);
							snprintf(rep, siz, "%s.%ld.%s",
								 msgline->id,
								 now.tv_sec, ans);
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
					case CMD_QUERY:
						if (!startup_complete) {
							snprintf(reply, sizeof(reply),
								 "%s.%ld.loading.%s",
								 msgline->id,
								 now.tv_sec,
								 msgline->cmd);
							send_unix_msg(sockd, reply);
						} else {
							DATA_MSGLINE(msgline, ml_item);
							ans = ckdb_cmds[msgline->which_cmds].func(NULL,
									msgline->cmd,
									msgline->id,
									&(msgline->now),
									by_default,
									(char *)__func__,
									inet_default,
									&(msgline->cd),
									msgline->trf_root);
							siz = strlen(ans) + strlen(msgline->id) + 32;
							rep = malloc(siz);
							snprintf(rep, siz, "%s.%ld.%s",
								 msgline->id,
								 now.tv_sec, ans);
							send_unix_msg(sockd, rep);
							FREENULL(ans);
							FREENULL(rep);
						}
						break;
					// Always process immediately:
					case CMD_AUTH:
					case CMD_ADDRAUTH:
					case CMD_HEARTBEAT:
						// First message from the pool
						if (want_first) {
							want_first = false;
							ck_wlock(&fpm_lock);
							first_pool_message = strdup(buf);
							ck_wunlock(&fpm_lock);
						}
						DATA_MSGLINE(msgline, ml_item);
						ans = ckdb_cmds[msgline->which_cmds].func(NULL,
								msgline->cmd,
								msgline->id,
								&(msgline->now),
								by_default,
								(char *)__func__,
								inet_default,
								&(msgline->cd),
								msgline->trf_root);
						siz = strlen(ans) + strlen(msgline->id) + 32;
						rep = malloc(siz);
						snprintf(rep, siz, "%s.%ld.%s",
							 msgline->id,
							 now.tv_sec, ans);
						send_unix_msg(sockd, rep);
						FREENULL(ans);
						replied = true;
					// Always queue (ok.queued)
					case CMD_SHARELOG:
					case CMD_POOLSTAT:
					case CMD_USERSTAT:
					case CMD_WORKERSTAT:
					case CMD_BLOCK:
						if (!replied) {
							// First message from the pool
							if (want_first) {
								want_first = false;
								ck_wlock(&fpm_lock);
								first_pool_message = strdup(buf);
								ck_wunlock(&fpm_lock);
							}
							snprintf(reply, sizeof(reply),
								 "%s.%ld.ok.queued",
								 msgline->id,
								 now.tv_sec);
							send_unix_msg(sockd, reply);
						}

						K_WLOCK(workqueue_free);
						wq_item = k_unlink_head(workqueue_free);
						DATA_WORKQUEUE(workqueue, wq_item);
						workqueue->msgline_item = ml_item;
						workqueue->by = by_default;
						workqueue->code =  (char *)__func__;
						workqueue->inet = inet_default;
						k_add_tail(workqueue_store, wq_item);
						/* Stop the reload queue from growing too big
						 * Use a size that should be big enough */
						if (reloading && workqueue_store->count > 250000) {
							K_ITEM *wq2_item = k_unlink_head(workqueue_store);
							K_WUNLOCK(workqueue_free);
							WORKQUEUE *wq;
							DATA_WORKQUEUE(wq, wq2_item);
							K_ITEM *ml_item = wq->msgline_item;
							free_msgline_data(ml_item, true, false);
							K_WLOCK(msgline_free);
							k_add_head(msgline_free, ml_item);
							K_WUNLOCK(msgline_free);
							K_WLOCK(workqueue_free);
							k_add_head(workqueue_free, wq2_item);
						}
						K_WUNLOCK(workqueue_free);
						ml_item = NULL;
						mutex_lock(&wq_waitlock);
						pthread_cond_signal(&wq_waitcond);
						mutex_unlock(&wq_waitlock);
						break;
					// Code error
					default:
						LOGEMERG("%s() CODE ERROR unhandled"
							 " message %d %.32s...",
							 __func__, cmdnum, buf);
						snprintf(reply, sizeof(reply),
							 "%s.%ld.failed.code",
							 msgline->id,
							 now.tv_sec);
						send_unix_msg(sockd, reply);
						break;
				}
			}
		}
		close(sockd);

		if (ml_item) {
			free_msgline_data(ml_item, true, true);
			K_WLOCK(msgline_free);
			k_add_head(msgline_free, ml_item);
			K_WUNLOCK(msgline_free);
			ml_item = NULL;
		}

		tick();
	}

	socketer_using_data = false;

	if (buf)
		dealloc(buf);
	// TODO: if anyone cares, free all the dup buffers :P
	close_unix_socket(us->sockd, us->path);

	return NULL;
}

static void reload_line(PGconn *conn, char *filename, uint64_t count, char *buf)
{
	enum cmd_values cmdnum;
	char *end, *ans, *st = NULL;
	MSGLINE *msgline;
	K_ITEM *ml_item;
	tv_t now;
	bool matched;

	// Once we've read the message
	setnow(&now);
	if (buf) {
		end = buf + strlen(buf) - 1;
		// strip trailing \n and \r
		while (end >= buf && (*end == '\n' || *end == '\r'))
			*(end--) = '\0';
	}
	if (!buf || !*buf) {
		if (!buf) {
			LOGERR("%s() NULL message line %"PRIu64,
				__func__, count);
		} else {
			LOGERR("%s() Empty message line %"PRIu64,
				__func__, count);
		}
	} else {
		matched = false;
		ck_wlock(&fpm_lock);
		if (first_pool_message &&
		    strcmp(first_pool_message, buf) == 0) {
			matched = true;
			FREENULL(first_pool_message);
		}
		ck_wunlock(&fpm_lock);
		if (matched) {
			LOGERR("%s() reload ckpool queue match at line %"PRIu64,
				__func__, count);
		}

		// ml_item is set for all but CMD_REPLY
		cmdnum = breakdown(&ml_item, buf, &now, SE_RELOAD);
		DATA_MSGLINE(msgline, ml_item);
		switch (cmdnum) {
			// Ignore
			case CMD_REPLY:
				break;
			// Shouldn't be there
			case CMD_TERMINATE:
			case CMD_PING:
			case CMD_VERSION:
			case CMD_LOGLEVEL:
			case CMD_FLUSH:
			// Non pool commands, shouldn't be there
			case CMD_ADDUSER:
			case CMD_NEWPASS:
			case CMD_CHKPASS:
			case CMD_2FA:
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
			case CMD_PSHIFT:
			case CMD_SHSTA:
			case CMD_USERINFO:
			case CMD_BTCSET:
			case CMD_QUERY:
				LOGERR("%s() INVALID message line %"PRIu64
					" ignored '%.42s...",
					__func__, count,
					st = safe_text(msgline->msg));
				FREENULL(st);
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
				// This will return the same cmdnum or DUP
				cmdnum = process_seq(msgline);
				if (cmdnum != CMD_DUPSEQ) {
					ans = ckdb_cmds[msgline->which_cmds].func(conn,
							msgline->cmd,
							msgline->id,
							&(msgline->now),
							by_default,
							(char *)__func__,
							inet_default,
							&(msgline->cd),
							msgline->trf_root);
					FREENULL(ans);
				}
				break;
			default:
				// Force this switch to be updated if new cmds are added
				quithere(1, "%s line %"PRIu64" '%s' - not "
					 "handled by reload",
					 filename, count,
					 st = safe_text_nonull(msgline->cmd));
				// Won't get here ...
				FREENULL(st);
				break;
		}

		if (ml_item) {
			free_msgline_data(ml_item, true, true);
			K_WLOCK(msgline_free);
			k_add_head(msgline_free, ml_item);
			K_WUNLOCK(msgline_free);
			ml_item = NULL;
		}
	}

	tick();
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

// How many files need to be processed before flagging reloaded_N_files
#define RELOAD_N_FILES 2
// optioncontrol name to override the above value
#define RELOAD_N_FILES_STR "ReloadNFiles"

// How many lines in a reload file required to count it
#define RELOAD_N_COUNT 1000

/* If the reload start file is missing and -r was specified correctly:
 *	touch the filename reported in "Failed to open 'filename'",
 *	if ckdb aborts at the beginning of the reload, then start again */
static bool reload_from(tv_t *start)
{
	PGconn *conn = NULL;
	char buf[DATE_BUFSIZ+1], run[DATE_BUFSIZ+1];
	size_t rflen = strlen(restorefrom);
	char *missingfirst = NULL, *missinglast = NULL, *st = NULL;
	int missing_count;
	int processing;
	bool finished = false, ret = true, ok, apipe = false;
	char *filename = NULL;
	uint64_t count, total;
	tv_t now, begin;
	double diff;
	FILE *fp = NULL;
	int file_N_limit;

	reload_buf = malloc(MAX_READ);
	if (!reload_buf)
		quithere(1, "(%d) OOM", MAX_READ);

	file_N_limit = (int)sys_setting(RELOAD_N_FILES_STR, RELOAD_N_FILES,
					&date_eot);

	reloading = true;

	copy_tv(&reload_timestamp, start);
	// Go back further - one reload file
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
	LOGQUE(reload_buf, true);
	LOGQUE(reload_buf, false);

	conn = dbconnect();

	total = 0;
	processing = 0;
	while (!everyone_die && !finished) {
		LOGWARNING("%s(): processing %s", __func__, filename);
		processing++;
		count = 0;

		/* Don't abort when matched since breakdown() will remove
		 *  the matching message sequence numbers queued from ckpool
		 * Also since ckpool messages are not in order, we could be
		 *  aborting early and not get the few slightly later out of
		 *  order messages in the log file */
		while (!everyone_die && 
			logline(reload_buf, MAX_READ, fp, filename)) {
				reload_line(conn, filename, ++count, reload_buf);
		}

		LOGWARNING("%s(): %sread %"PRIu64" line%s from %s",
			   __func__,
			   everyone_die ? "Terminate, aborting - " : "",
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
		if (everyone_die)
			break;
		reload_timestamp.tv_sec += ROLL_S;
		if (confirm_sharesummary && tv_newer(&confirm_finish, &reload_timestamp)) {
			LOGWARNING("%s(): confirm range complete", __func__);
			break;
		}

		/* Used by marker() to start mark generation during a longer
		 *  than normal reload */
		if (count > RELOAD_N_COUNT) {
			if (file_N_limit-- < 1)
				reloaded_N_files = true;
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
	LOGQUE(reload_buf, true);
	LOGQUE(reload_buf, false);
	LOGWARNING("%s(): read %d file%s, total %"PRIu64" line%s %.2f/s",
		   __func__,
		   processing, processing == 1 ? "" : "s",
		   total, total == 1 ? "" : "s", (total / diff));

	if (everyone_die)
		return true;

	ck_wlock(&fpm_lock);
	if (first_pool_message) {
		LOGERR("%s() reload didn't find the first ckpool queue '%.32s...",
			__func__, st = safe_text(first_pool_message));
		FREENULL(st);
		FREENULL(first_pool_message);
	}
	ck_wunlock(&fpm_lock);

	seq_reloadmax();

	reloading = false;
	FREENULL(reload_buf);
	return ret;
}

static void process_queued(PGconn *conn, K_ITEM *wq_item)
{
	enum cmd_values cmdnum;
	WORKQUEUE *workqueue;
	MSGLINE *msgline;
	K_ITEM *ml_item;
	char *ans;

	DATA_WORKQUEUE(workqueue, wq_item);
	ml_item = workqueue->msgline_item;
	DATA_MSGLINE(msgline, ml_item);

	/* Queued messages haven't had their seq number check yet
	 * This will return the entries cmdnum or DUP */
	cmdnum = process_seq(msgline);
	switch (cmdnum) {
		case CMD_DUPSEQ:
		// Already replied
		case CMD_AUTH:
		case CMD_ADDRAUTH:
		case CMD_HEARTBEAT:
			break;
		default:
			ans = ckdb_cmds[msgline->which_cmds].func(conn,
					msgline->cmd,
					msgline->id,
					&(msgline->now),
					workqueue->by,
					workqueue->code,
					workqueue->inet,
					&(msgline->cd),
					msgline->trf_root);
			FREENULL(ans);
			break;
	}

	free_msgline_data(ml_item, true, true);
	K_WLOCK(msgline_free);
	k_add_head(msgline_free, ml_item);
	K_WUNLOCK(msgline_free);

	K_WLOCK(workqueue_free);
	k_add_head(workqueue_free, wq_item);
	if (workqueue_free->count == workqueue_free->total &&
	    workqueue_free->total >= ALLOC_WORKQUEUE * CULL_WORKQUEUE)
		k_cull_list(workqueue_free);
	K_WUNLOCK(workqueue_free);
}

static void free_lost(SEQDATA *seqdata)
{
	if (seqdata->reload_lost) {
		K_WLOCK(seqtrans_free);
		k_list_transfer_to_head(seqdata->reload_lost, seqtrans_free);
		if (seqtrans_free->count == seqtrans_free->total &&
		    seqtrans_free->total >= ALLOC_SEQTRANS * CULL_SEQTRANS)
			k_cull_list(seqtrans_free);
		K_WUNLOCK(seqtrans_free);
		seqdata->reload_lost = NULL;
	}
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
	char ooo_buf[256];
	tv_t wq_stt, wq_fin;
	double min, sec;
	int left;
	SEQSET *seqset = NULL;
	SEQDATA *seqdata;
	K_ITEM *ss_item;
	int i;

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
		goto sayonara;
	}

	if (!everyone_die) {
		K_RLOCK(workqueue_store);
		wqcount = workqueue_store->count;
		K_RUNLOCK(workqueue_store);

		LOGWARNING("reload shares OoO %s", ooo_status(ooo_buf, sizeof(ooo_buf)));
		sequence_report(true);

		LOGWARNING("%s(): ckdb ready, queue %d", __func__, wqcount);

		/* Until startup_complete, the values should be ignored
		 * Setting them to 'now' means that they won't time out
		 *  until after startup_complete */
		ck_wlock(&last_lock);
		setnow(&last_heartbeat);
		copy_tv(&last_workinfo, &last_heartbeat);
		copy_tv(&last_share, &last_heartbeat);
		copy_tv(&last_share_acc, &last_heartbeat);
		copy_tv(&last_share_inv, &last_heartbeat);
		copy_tv(&last_auth, &last_heartbeat);
		ck_wunlock(&last_lock);

		startup_complete = true;

		setnow(&wq_stt);
		conn = dbconnect();
		now = time(NULL);
		wqgot = 0;
	}

	// Process queued work
	while (!everyone_die) {
		K_WLOCK(workqueue_store);
		wq_item = k_unlink_head(workqueue_store);
		left = workqueue_store->count;
		K_WUNLOCK(workqueue_store);

		if (left == 0 && wq_stt.tv_sec != 0L)
			setnow(&wq_fin);

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
		}

		if (left == 0 && wq_stt.tv_sec != 0L) {
			sec = tvdiff(&wq_fin, &wq_stt);
			min = floor(sec / 60.0);
			sec -= min * 60.0;
			LOGWARNING("reload queue completed %.0fm %.3fs", min, sec);
			// Used as the flag to display the message once
			wq_stt.tv_sec = 0L;
			reload_queue_complete = true;
		}

		/* Checked outside lock but only changed under lock
		 * This avoids taking out the lock repeatedly and the cleanup
		 *  code is ok if there is nothing to clean up
		 * This would normally only ever be done once */
		if (seqdata_reload_lost && reload_queue_complete) {
			/* Cleanup all the reload_lost stores since
			 *  they should no longer be needed and the ram
			 *  they use should be freed by the next cull */
			ck_wlock(&seq_lock);
			if (seqset_store->count > 0) {
				ss_item = seqset_store->head;
				while (ss_item) {
					DATA_SEQSET(seqset, ss_item);
					if (seqset->seqstt) {
						seqdata = &(seqset->seqdata[0]);
						for (i = 0; i < SEQ_MAX; i++) {
							free_lost(seqdata);
							seqdata++;
						}
					}
					ss_item = ss_item->next;
				}
			}
			seqdata_reload_lost = false;
			ck_wunlock(&seq_lock);
		}

		if (!wq_item) {
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

sayonara:

	listener_using_data = false;

	if (conn)
		PQfinish(conn);

	return NULL;
}

#if 0
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
	lss = find_after_in_ktree(leftsum, &look, ctxl);
	while (lss) {
		DATA_SHARESUMMARY(l_ss, lss);
		if (l_ss->workinfoid > confirm_last_workinfoid)
			break;

		total++;

		if (first_used == 0)
			first_used = l_ss->workinfoid;
		last_used = l_ss->workinfoid;

		rss = find_in_ktree(rightsum, lss, ctxr);
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
#endif

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
#if 0
	TODO: redo this using workmarkers

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
				b_end_item = find_after_in_ktree(blocks_root, &b_look, ctx);
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
				b_begin_item = find_before_in_ktree(blocks_root, &b_look, ctx);
				if (!b_begin_item)
					confirm_first_workinfoid = 0;
				else {
					DATA_BLOCKS(b_blocks, b_begin_item);
					// First DB record of the block 'begin'
					lookblocks.height = b_blocks->height;
					lookblocks.blockhash[0] = '\0';
					b_look.data = (void *)(&lookblocks);
					b_begin_item = find_after_in_ktree(blocks_root, &b_look, ctx);
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
	wi_item = find_before_in_ktree(workinfo_root, &wi_look, ctx);
	if (wi_item) {
		DATA_WORKINFO(workinfo, wi_item);
		copy_tv(&start, &(workinfo->createdate));
		if (workinfo->workinfoid != confirm_first_workinfoid) {
			LOGWARNING("%s() start workinfo not found ... using time of %"PRId64,
				   __func__, workinfo->workinfoid);
		}
	} else {
		if (confirm_first_workinfoid == 0) {
			DATE_ZERO(&start);
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
	wi_item = find_after_in_ktree(workinfo_root, &wi_look, ctx);
	if (wi_item) {
		DATA_WORKINFO(workinfo, wi_item);
		/* Now find the one after the one we found to determine the
		 * confirm_finish timestamp */
		lookworkinfo.workinfoid = workinfo->workinfoid;
		lookworkinfo.expirydate.tv_sec = date_eot.tv_sec;
		lookworkinfo.expirydate.tv_usec = date_eot.tv_usec;
		wi_look.data = (void *)(&lookworkinfo);
		wi_item = find_after_in_ktree(workinfo_root, &wi_look, ctx);
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

	sharesummary_workinfoid_root = new_ktree(cmp_sharesummary_workinfoid);
	sharesummary_root = new_ktree(cmp_sharesummary);
	workinfo_root = new_ktree(cmp_workinfo);

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
#endif
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
	{ "free",		required_argument,	0,	'f' },
	// generate = enable payout pplns auto generation
	{ "generate",		no_argument,		0,	'g' },
	{ "help",		no_argument,		0,	'h' },
	{ "killold",		no_argument,		0,	'k' },
	{ "loglevel",		required_argument,	0,	'l' },
	// marker = enable mark/workmarker/markersummary auto generation
	{ "marker",		no_argument,		0,	'm' },
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

	while ((c = getopt_long(argc, argv, "c:d:ghkl:mn:p:P:r:R:s:S:t:u:U:vw:yY:", long_options, &i)) != -1) {
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
			case 'f':
				if (strcasecmp(optarg, FREE_MODE_ALL_STR) == 0)
					free_mode = FREE_MODE_ALL;
				else if (strcasecmp(optarg, FREE_MODE_NONE_STR) == 0)
					free_mode = FREE_MODE_NONE;
				else if (strcasecmp(optarg, FREE_MODE_FAST_STR) == 0)
					free_mode = FREE_MODE_FAST;
				else {
					quit(1, "Invalid free '%s' must be: "
						FREE_MODE_ALL_STR", "
						FREE_MODE_NONE_STR" or "
						FREE_MODE_FAST_STR,
						optarg);
				}
				break;
			case 'g':
				genpayout_auto = true;
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

	// -db is ckpool messages
	snprintf(logname_db, sizeof(logname_db), "%s%s-db%s-",
				ckp.logdir, ckp.name, dbcode);
	// -io is everything else
	snprintf(logname_io, sizeof(logname_io), "%s%s-io%s-",
				ckp.logdir, ckp.name, dbcode);

	setnow(&now);
	srandom((unsigned int)(now.tv_usec * 4096 + now.tv_sec % 4096));

	ckp.main.ckp = &ckp;
	ckp.main.processname = strdup("main");

	cklock_init(&last_lock);
	cklock_init(&btc_lock);
	cklock_init(&seq_lock);
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

		/* Terminate from here if the listener is sent a terminate message */
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
				msg = "Terminate initial delay";
			} else if (curr - trigger > 2) {
				msg = "Terminate delay";
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
