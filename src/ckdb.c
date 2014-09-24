/*
 * Copyright 1995-2014 Andrew Smith
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
#include <fenv.h>
#include <getopt.h>
#include <jansson.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <stdint.h>
#include <regex.h>
#include <sha2.h>
#ifdef HAVE_LIBPQ_FE_H
#include <libpq-fe.h>
#elif defined (HAVE_POSTGRESQL_LIBPQ_FE_H)
#include <postgresql/libpq-fe.h>
#endif

#include "ckpool.h"
#include "libckpool.h"

#include "klist.h"
#include "ktree.h"

/* TODO: any tree/list accessed in new threads needs
 *  to ensure all code using those trees/lists use locks
 * This code's lock implementation is equivalent to table level locking
 * Consider adding row level locking (a per kitem usage count) if needed
 * TODO: verify all tables with multithread access are locked
 */

#define DB_VLOCK "1"
#define DB_VERSION "0.9.2"
#define CKDB_VERSION DB_VERSION"-0.330"

#define WHERE_FFL " - from %s %s() line %d"
#define WHERE_FFL_HERE __FILE__, __func__, __LINE__
#define WHERE_FFL_PASS file, func, line
#define WHERE_FFL_ARGS __maybe_unused const char *file, \
			__maybe_unused const char *func, \
			__maybe_unused const int line

#define STRINT(x) STRINT2(x)
#define STRINT2(x) #x

// So they can fit into a 1 byte flag field
#define TRUE_STR "Y"
#define FALSE_STR "N"

#define TRUE_CHR 'Y'
#define FALSE_CHR 'N'

#define coinbase1height(_cb1) _coinbase1height(_cb1, WHERE_FFL_HERE)
#define cmp_height(_cb1a, _cb1b) _cmp_height(_cb1a, _cb1b, WHERE_FFL_HERE)

static char *EMPTY = "";
static char *db_name;
static char *db_user;
static char *db_pass;

// Currently hard coded at 4 characters
static char *status_chars = "|/-\\";

static char *restorefrom;

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
 *	and block
 *  with an ok.queued reply to ckpool, to be processed after the reload
 *  completes and just process authorise messages immediately while the
 *  reload runs
 *  This can't cause a duplicate process of an authorise message since a
 *  reload will ignore any messages before the last DB auths message,
 *  however, if ckdb and ckpool get out of sync due to ckpool starting
 *  during the reload (as mentioned below) it is possible for ckdb to
 *  find an authorise message in the CCLs that was processed in the
 *  message queue and thus is already in the DB.
 *  This error would be very rare and also not an issue
 * To avoid this, we start the ckpool message queue after loading
 *  the users, auths, idcontrol and workers DB tables, before loading the
 *  much larger sharesummary, workinfo, userstats and poolstats DB tables
 *  so that ckdb is effectively ready for messages almost immediately
 * The first ckpool message also allows us to know where ckpool is up to
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
 *  immediately and is not affected by ckpool messages until we
 * During the reload, when checking the timeframe for summarisation, we
 *  use the current last userstats createdate as 'now' to avoid touching a
 *  timeframe where data could still be waiting to be loaded
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
 *  DB+RAM auths: start from newest DB createdate auths
 *  DB+RAM poolstats: newest createdate poolstats
 *	TODO: subtract how much we need in RAM of the 'between'
 *	non db records - will depend on TODO: pool stats reporting
 *	requirements
 *  DB+RAM userstats: start of the time band of the latest DB record,
 *	since all data before this has been summarised to the DB
 *	The userstats summarisation always processes the oldest
 *	RAM data to the DB
 *	TODO: multiple pools is not yet handled by ckdb
 *	TODO: handle a pool restart with a different instance name
 *		since this would always make the userstats reload point
 *		just after the instance name was changed - however
 *		this can be handled for now by simply ignoring the
 *		poolinstance
 *  DB+RAM workers: created by auths so auths will resolve it
 *  DB+RAM blocks: resolved by workinfo - any unsaved blocks (if any)
 *	will be after the last DB workinfo
 *  DB+RAM accountbalance (TODO): resolved by shares/workinfo/blocks
 *  RAM workerstatus: all except last_idle are set at the end of the
 *	CCL reload
 *	Code currently doesn't use last_idle
 *
 *  idcontrol: only userid reuse is critical and the user is added
 *	immeditately to the DB before replying to the add message
 *
 *  Tables that are/will be written straight to the DB, so are OK:
 *	users, useraccounts, paymentaddresses, payments,
 *	accountadjustment, optioncontrol, miningpayouts,
 *	eventlog
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
 *  1) userstats: any record that falls in a DB userstats that would
 *	summarise that record is discarded,
 *	otherwise the userstats is processed normally
 *  2) shares/shareerrors: any record that matches an incomplete DB
 *	sharesummary that hasn't been reset, will reset the sharesummary
 *	so that the sharesummary will be recalculated
 *	The record is processed normally with or without the reset
 *	If the sharesummary is complete, the record is discarded
 *  3) ageworkinfo records are also handled by the shares date
 *	while processing, any records already aged are not updated
 *	and a warning is displayed if there were any matching shares
 */

typedef struct loadstatus {
	tv_t oldest_sharesummary_firstshare_n;
	tv_t newest_sharesummary_firstshare_a;
	tv_t newest_sharesummary_firstshare_ay;
	tv_t sharesummary_firstshare; // whichever of above 2 used
	tv_t oldest_sharesummary_firstshare_a;
	tv_t newest_sharesummary_firstshare_y;
	tv_t newest_createdate_workinfo;
	tv_t newest_createdate_auths;
	tv_t newest_createdate_poolstats;
	tv_t newest_starttimeband_userstats;
	tv_t newest_createdate_blocks;
	int64_t oldest_workinfoid_n; // of oldest firstshare sharesummary n
	int64_t oldest_workinfoid_a; // of oldest firstshare sharesummary a
	int64_t newest_workinfoid_a; // of newest firstshare sharesummary a
	int64_t newest_workinfoid_y; // of newest firstshare sharesummary y
} LOADSTATUS;
static LOADSTATUS dbstatus;

// So cmd_getopts works on a new empty pool
#define START_POOL_HEIGHT 2

// Share stats since last block
typedef struct poolstatus {
	int64_t workinfoid; // Last block
	int32_t height;
	double diffacc;
	double diffinv; // Non-acc
	double shareacc;
	double shareinv; // Non-acc
	double best_sdiff; // TODO (maybe)
} POOLSTATUS;
static POOLSTATUS pool = { 0, START_POOL_HEIGHT, 0, 0, 0, 0, 0 };
/* TODO: when we know about orphans, the count reset to zero
 * will need to be undone - i.e. recalculate this data from
 * the memory tables - maybe ... */

// size limit on the command string
#define CMD_SIZ 31
#define ID_SIZ 31

// size to allocate for pgsql text and display (bigger than needed)
#define DATE_BUFSIZ (63+1)
#define CDATE_BUFSIZ (127+1)
#define BIGINT_BUFSIZ (63+1)
#define INT_BUFSIZ (63+1)
#define DOUBLE_BUFSIZ (63+1)

#define TXT_BIG 256
#define TXT_MED 128
#define TXT_SML 64
#define TXT_FLAG 1

// TAB
#define FLDSEP 0x09
#define FLDSEPSTR "\011"

// Ensure long long and int64_t are both 8 bytes (and thus also the same)
#define ASSERT1(condition) __maybe_unused static char sizeof_longlong_must_be_8[(condition)?1:-1]
#define ASSERT2(condition) __maybe_unused static char sizeof_int64_t_must_be_8[(condition)?1:-1]
ASSERT1(sizeof(long long) == 8);
ASSERT2(sizeof(int64_t) == 8);

#define MAXID 0x7fffffffffffffffLL

#define PGOK(_res) ((_res) == PGRES_COMMAND_OK || \
			(_res) == PGRES_TUPLES_OK || \
			(_res) == PGRES_EMPTY_QUERY)

// Clear text printable version of txt up to first '\0'
static char *safe_text(char *txt)
{
	unsigned char *ptr = (unsigned char *)txt;
	size_t len;
	char *ret, *buf;

	if (!txt) {
		buf = strdup("(Null)");
		if (!buf)
			quithere(1, "malloc OOM");
		return buf;
	}

	// Allocate the maximum needed
	len = (strlen(txt)+1)*4+1;
	ret = buf = malloc(len);
	if (!buf)
		quithere(1, "malloc (%d) OOM", (int)len);
	while (*ptr) {
		if (*ptr >= ' ' && *ptr <= '~')
			*(buf++) = *(ptr++);
		else {
			snprintf(buf, 5, "0x%02x", *(ptr++));
			buf += 4;
		}
	}
	strcpy(buf, "0x00");
	return ret;
}

static char *pqerrmsg(PGconn *conn)
{
	char *ptr, *buf = strdup(PQerrorMessage(conn));

	if (!buf)
		quithere(1, "malloc OOM");
	ptr = buf + strlen(buf) - 1;
	while (ptr >= buf && (*ptr == '\n' || *ptr == '\r'))
		*(ptr--) = '\0';
	while (--ptr >= buf) {
		if (*ptr == '\n' || *ptr == '\r' || *ptr == '\t')
			*ptr = ' ';
	}
	return buf;
}

#define PGLOG(__LOG, __str, __rescode, __conn) do { \
		char *__buf = pqerrmsg(__conn); \
		__LOG("%s(): %s failed (%d) '%s'", __func__, \
			__str, (int)rescode, __buf); \
		free(__buf); \
	} while (0)

#define PGLOGERR(_str, _rescode, _conn) PGLOG(LOGERR, _str, _rescode, _conn)
#define PGLOGEMERG(_str, _rescode, _conn) PGLOG(LOGEMERG, _str, _rescode, _conn)

/* N.B. STRNCPY() truncates, whereas txt_to_str() aborts ckdb if src > trg
 * If copying data from the DB, code should always use txt_to_str() since
 * data should never be lost/truncated if it came from the DB -
 * that simply implies a code bug or a database change that must be fixed */
#define STRNCPY(trg, src) do { \
		strncpy((char *)(trg), (char *)(src), sizeof(trg)); \
		trg[sizeof(trg) - 1] = '\0'; \
	} while (0)

#define STRNCPYSIZ(trg, src, siz) do { \
		strncpy((char *)(trg), (char *)(src), siz); \
		trg[siz - 1] = '\0'; \
	} while (0)

#define AR_SIZ 1024

#define APPEND_REALLOC_INIT(_buf, _off, _len) do { \
		_len = AR_SIZ; \
		(_buf) = malloc(_len); \
		if (!(_buf)) \
			quithere(1, "malloc (%d) OOM", (int)_len); \
		(_buf)[0] = '\0'; \
		_off = 0; \
	} while(0)

#define APPEND_REALLOC(_dst, _dstoff, _dstsiz, _src) do { \
		size_t _newlen, _srclen = strlen(_src); \
		_newlen = (_dstoff) + _srclen; \
		if (_newlen >= (_dstsiz)) { \
			_dstsiz = _newlen + AR_SIZ - (_newlen % AR_SIZ); \
			_dst = realloc(_dst, _dstsiz); \
			if (!(_dst)) \
				quithere(1, "realloc (%d) OOM", (int)_dstsiz); \
		} \
		strcpy((_dst)+(_dstoff), _src); \
		_dstoff += _srclen; \
	} while(0)

enum data_type {
	TYPE_STR,
	TYPE_BIGINT,
	TYPE_INT,
	TYPE_TV,
	TYPE_TVS,
	TYPE_CTV,
	TYPE_BLOB,
	TYPE_DOUBLE
};

#define TXT_TO_STR(__nam, __fld, __data) txt_to_str(__nam, __fld, (__data), sizeof(__data))
#define TXT_TO_BIGINT(__nam, __fld, __data) txt_to_bigint(__nam, __fld, &(__data), sizeof(__data))
#define TXT_TO_INT(__nam, __fld, __data) txt_to_int(__nam, __fld, &(__data), sizeof(__data))
#define TXT_TO_TV(__nam, __fld, __data) txt_to_tv(__nam, __fld, &(__data), sizeof(__data))
#define TXT_TO_CTV(__nam, __fld, __data) txt_to_ctv(__nam, __fld, &(__data), sizeof(__data))
#define TXT_TO_BLOB(__nam, __fld, __data) txt_to_blob(__nam, __fld, &(__data))
#define TXT_TO_DOUBLE(__nam, __fld, __data) txt_to_double(__nam, __fld, &(__data), sizeof(__data))

#define PQ_GET_FLD(__res, __row, __name, __fld, __ok) do { \
		int __col = PQfnumber(__res, __name); \
		if (__col == -1) { \
			LOGERR("%s(): Unknown field '%s' row %d", __func__, __name, __row); \
			__ok = false; \
		} else \
			__fld = PQgetvalue(__res, __row, __col); \
	} while (0)

// HISTORY FIELDS
#define HISTORYDATECONTROL ",createdate,createby,createcode,createinet,expirydate"
#define HISTORYDATECOUNT 5

#define HISTORYDATEFLDS(_res, _row, _data, _ok) do { \
		char *_fld; \
		PQ_GET_FLD(_res, _row, "createdate", _fld, _ok); \
		if (!_ok) \
			break; \
		TXT_TO_TV("createdate", _fld, (_data)->createdate); \
		PQ_GET_FLD(_res, _row, "createby", _fld, _ok); \
		if (!_ok) \
			break; \
		TXT_TO_STR("createby", _fld, (_data)->createby); \
		PQ_GET_FLD(_res, _row, "createcode", _fld, _ok); \
		if (!_ok) \
			break; \
		TXT_TO_STR("createcode", _fld, (_data)->createcode); \
		PQ_GET_FLD(_res, _row, "createinet", _fld, _ok); \
		if (!_ok) \
			break; \
		TXT_TO_STR("createinet", _fld, (_data)->createinet); \
		PQ_GET_FLD(_res, _row, "expirydate", _fld, _ok); \
		if (!_ok) \
			break; \
		TXT_TO_TV("expirydate", _fld, (_data)->expirydate); \
	} while (0)

#define HISTORYDATECONTROLFIELDS \
	tv_t createdate; \
	char createby[TXT_SML+1]; \
	char createcode[TXT_MED+1]; \
	char createinet[TXT_MED+1]; \
	tv_t expirydate

#define HISTORYDATEPARAMS(_params, _his_pos, _row) do { \
		_params[_his_pos++] = tv_to_buf(&(_row->createdate), NULL, 0); \
		_params[_his_pos++] = str_to_buf(_row->createby, NULL, 0); \
		_params[_his_pos++] = str_to_buf(_row->createcode, NULL, 0); \
		_params[_his_pos++] = str_to_buf(_row->createinet, NULL, 0); \
		_params[_his_pos++] = tv_to_buf(&(_row->expirydate), NULL, 0); \
	} while (0)

// 6-Jun-6666 06:06:06+00
#define DEFAULT_EXPIRY 148204965966L
// 1-Jun-6666 00:00:00+00
#define COMPARE_EXPIRY 148204512000L

static const tv_t default_expiry = { DEFAULT_EXPIRY, 0L };

// No actual need to test tv_usec
#define CURRENT(_tv) (((_tv)->tv_sec == DEFAULT_EXPIRY) ? true : false)

// 31-Dec-9999 23:59:59+00
#define DATE_S_EOT 253402300799L
#define DATE_uS_EOT 0L
static const tv_t date_eot = { DATE_S_EOT, DATE_uS_EOT };

// All data will be after: 2-Jan-2014 00:00:00+00
#define DATE_BEGIN 1388620800L
static const tv_t date_begin = { DATE_BEGIN, 0L };

#define HISTORYDATEINIT(_row, _cd, _by, _code, _inet) do { \
		_row->createdate.tv_sec = (_cd)->tv_sec; \
		_row->createdate.tv_usec = (_cd)->tv_usec; \
		STRNCPY(_row->createby, _by); \
		STRNCPY(_row->createcode, _code); \
		STRNCPY(_row->createinet, _inet); \
		_row->expirydate.tv_sec = default_expiry.tv_sec; \
		_row->expirydate.tv_usec = default_expiry.tv_usec; \
	} while (0)

// Override _row defaults if transfer fields are present
#define HISTORYDATETRANSFER(_root, _row) do { \
		K_ITEM *__item; \
		TRANSFER *__transfer; \
		__item = optional_name(_root, "createby", 1, NULL); \
		if (__item) { \
			DATA_TRANSFER(__transfer, __item); \
			STRNCPY(_row->createby, __transfer->mvalue); \
		} \
		__item = optional_name(_root, "createcode", 1, NULL); \
		if (__item) { \
			DATA_TRANSFER(__transfer, __item); \
			STRNCPY(_row->createcode, __transfer->mvalue); \
		} \
		__item = optional_name(_root, "createinet", 1, NULL); \
		if (__item) { \
			DATA_TRANSFER(__transfer, __item); \
			STRNCPY(_row->createinet, __transfer->mvalue); \
		} \
	} while (0)

// MODIFY FIELDS
#define MODIFYDATECONTROL ",createdate,createby,createcode,createinet" \
			  ",modifydate,modifyby,modifycode,modifyinet"

#define MODIFYDATECOUNT 8
#define MODIFYUPDATECOUNT 4

#define MODIFYDATEFLDS(_res, _row, _data, _ok) do { \
		char *_fld; \
		PQ_GET_FLD(_res, _row, "createdate", _fld, _ok); \
		if (!_ok) \
			break; \
		TXT_TO_TV("createdate", _fld, (_data)->createdate); \
		PQ_GET_FLD(_res, _row, "createby", _fld, _ok); \
		if (!_ok) \
			break; \
		TXT_TO_STR("createby", _fld, (_data)->createby); \
		PQ_GET_FLD(_res, _row, "createcode", _fld, _ok); \
		if (!_ok) \
			break; \
		TXT_TO_STR("createcode", _fld, (_data)->createcode); \
		PQ_GET_FLD(_res, _row, "createinet", _fld, _ok); \
		if (!_ok) \
			break; \
		TXT_TO_STR("createinet", _fld, (_data)->createinet); \
		PQ_GET_FLD(_res, _row, "modifydate", _fld, _ok); \
		if (!_ok) \
			break; \
		TXT_TO_TV("modifydate", _fld, (_data)->modifydate); \
		PQ_GET_FLD(_res, _row, "modifyby", _fld, _ok); \
		if (!_ok) \
			break; \
		TXT_TO_STR("modifyby", _fld, (_data)->modifyby); \
		PQ_GET_FLD(_res, _row, "modifycode", _fld, _ok); \
		if (!_ok) \
			break; \
		TXT_TO_STR("modifycode", _fld, (_data)->modifycode); \
		PQ_GET_FLD(_res, _row, "modifyinet", _fld, _ok); \
		if (!_ok) \
			break; \
		TXT_TO_STR("modifyinet", _fld, (_data)->modifyinet); \
	} while (0)

#define MODIFYDATECONTROLFIELDS \
	tv_t createdate; \
	char createby[TXT_SML+1]; \
	char createcode[TXT_MED+1]; \
	char createinet[TXT_MED+1]; \
	tv_t modifydate; \
	char modifyby[TXT_SML+1]; \
	char modifycode[TXT_MED+1]; \
	char modifyinet[TXT_MED+1]

#define MODIFYDATEPARAMS(_params, _mod_pos, _row) do { \
		_params[_mod_pos++] = tv_to_buf(&(_row->createdate), NULL, 0); \
		_params[_mod_pos++] = str_to_buf(_row->createby, NULL, 0); \
		_params[_mod_pos++] = str_to_buf(_row->createcode, NULL, 0); \
		_params[_mod_pos++] = str_to_buf(_row->createinet, NULL, 0); \
		_params[_mod_pos++] = tv_to_buf(&(_row->modifydate), NULL, 0); \
		_params[_mod_pos++] = str_to_buf(_row->modifyby, NULL, 0); \
		_params[_mod_pos++] = str_to_buf(_row->modifycode, NULL, 0); \
		_params[_mod_pos++] = str_to_buf(_row->modifyinet, NULL, 0); \
	} while (0)

#define MODIFYUPDATEPARAMS(_params, _mod_pos, _row) do { \
		_params[_mod_pos++] = tv_to_buf(&(_row->modifydate), NULL, 0); \
		_params[_mod_pos++] = str_to_buf(_row->modifyby, NULL, 0); \
		_params[_mod_pos++] = str_to_buf(_row->modifycode, NULL, 0); \
		_params[_mod_pos++] = str_to_buf(_row->modifyinet, NULL, 0); \
	} while (0)

#define MODIFYDATEINIT(_row, _cd, _by, _code, _inet) do { \
		_row->createdate.tv_sec = (_cd)->tv_sec; \
		_row->createdate.tv_usec = (_cd)->tv_usec; \
		STRNCPY(_row->createby, _by); \
		STRNCPY(_row->createcode, _code); \
		STRNCPY(_row->createinet, _inet); \
		_row->modifydate.tv_sec = 0; \
		_row->modifydate.tv_usec = 0; \
		_row->modifyby[0] = '\0'; \
		_row->modifycode[0] = '\0'; \
		_row->modifyinet[0] = '\0'; \
	} while (0)

#define MODIFYUPDATE(_row, _cd, _by, _code, _inet) do { \
		_row->modifydate.tv_sec = (_cd)->tv_sec; \
		_row->modifydate.tv_usec = (_cd)->tv_usec; \
		STRNCPY(_row->modifyby, _by); \
		STRNCPY(_row->modifycode, _code); \
		STRNCPY(_row->modifyinet, _inet); \
	} while (0)

// SIMPLE FIELDS
#define SIMPLEDATECONTROL ",createdate,createby,createcode,createinet"
#define SIMPLEDATECOUNT 4

#define SIMPLEDATEFLDS(_res, _row, _data, _ok) do { \
		char *_fld; \
		PQ_GET_FLD(_res, _row, "createdate", _fld, _ok); \
		if (!_ok) \
			break; \
		TXT_TO_TV("createdate", _fld, (_data)->createdate); \
		PQ_GET_FLD(_res, _row, "createby", _fld, _ok); \
		if (!_ok) \
			break; \
		TXT_TO_STR("createby", _fld, (_data)->createby); \
		PQ_GET_FLD(_res, _row, "createcode", _fld, _ok); \
		if (!_ok) \
			break; \
		TXT_TO_STR("createcode", _fld, (_data)->createcode); \
		PQ_GET_FLD(_res, _row, "createinet", _fld, _ok); \
		if (!_ok) \
			break; \
		TXT_TO_STR("createinet", _fld, (_data)->createinet); \
	} while (0)

#define SIMPLEDATECONTROLFIELDS \
	tv_t createdate; \
	char createby[TXT_SML+1]; \
	char createcode[TXT_MED+1]; \
	char createinet[TXT_MED+1]

#define SIMPLEDATEPARAMS(_params, _his_pos, _row) do { \
		_params[_his_pos++] = tv_to_buf(&(_row->createdate), NULL, 0); \
		_params[_his_pos++] = str_to_buf(_row->createby, NULL, 0); \
		_params[_his_pos++] = str_to_buf(_row->createcode, NULL, 0); \
		_params[_his_pos++] = str_to_buf(_row->createinet, NULL, 0); \
	} while (0)

#define SIMPLEDATEINIT(_row, _cd, _by, _code, _inet) do { \
		_row->createdate.tv_sec = (_cd)->tv_sec; \
		_row->createdate.tv_usec = (_cd)->tv_usec; \
		STRNCPY(_row->createby, _by); \
		STRNCPY(_row->createcode, _code); \
		STRNCPY(_row->createinet, _inet); \
	} while (0)

#define SIMPLEDATEDEFAULT(_row, _cd) do { \
		_row->createdate.tv_sec = (_cd)->tv_sec; \
		_row->createdate.tv_usec = (_cd)->tv_usec; \
		STRNCPY(_row->createby, by_default); \
		STRNCPY(_row->createcode, (char *)__func__); \
		STRNCPY(_row->createinet, inet_default); \
	} while (0)

// Override _row defaults if transfer fields are present
#define SIMPLEDATETRANSFER(_root, _row) do { \
		K_ITEM *__item; \
		TRANSFER *__transfer; \
		__item = optional_name(_root, "createby", 1, NULL); \
		if (__item) { \
			DATA_TRANSFER(__transfer, __item); \
			STRNCPY(_row->createby, __transfer->mvalue); \
		} \
		__item = optional_name(_root, "createcode", 1, NULL); \
		if (__item) { \
			DATA_TRANSFER(__transfer, __item); \
			STRNCPY(_row->createcode, __transfer->mvalue); \
		} \
		__item = optional_name(_root, "createinet", 1, NULL); \
		if (__item) { \
			DATA_TRANSFER(__transfer, __item); \
			STRNCPY(_row->createinet, __transfer->mvalue); \
		} \
	} while (0)

// For easy parameter constant strings
#define PQPARAM1  "$1"
#define PQPARAM2  "$1,$2"
#define PQPARAM3  "$1,$2,$3"
#define PQPARAM4  "$1,$2,$3,$4"
#define PQPARAM5  "$1,$2,$3,$4,$5"
#define PQPARAM6  "$1,$2,$3,$4,$5,$6"
#define PQPARAM7  "$1,$2,$3,$4,$5,$6,$7"
#define PQPARAM8  "$1,$2,$3,$4,$5,$6,$7,$8"
#define PQPARAM9  PQPARAM8 ",$9"
#define PQPARAM10 PQPARAM8 ",$9,$10"
#define PQPARAM11 PQPARAM8 ",$9,$10,$11"
#define PQPARAM12 PQPARAM8 ",$9,$10,$11,$12"
#define PQPARAM13 PQPARAM8 ",$9,$10,$11,$12,$13"
#define PQPARAM14 PQPARAM8 ",$9,$10,$11,$12,$13,$14"
#define PQPARAM15 PQPARAM8 ",$9,$10,$11,$12,$13,$14,$15"
#define PQPARAM16 PQPARAM8 ",$9,$10,$11,$12,$13,$14,$15,$16"
#define PQPARAM22 PQPARAM16 ",$17,$18,$19,$20,$21,$22"
#define PQPARAM27 PQPARAM22 ",$23,$24,$25,$26,$27"

#define PARCHK(_par, _params) do { \
		if (_par != (int)(sizeof(_params)/sizeof(_params[0]))) { \
			quithere(1, "params[] usage (%d) != size (%d)", \
					_par, (int)(sizeof(_params)/sizeof(_params[0]))); \
		} \
	} while (0)

#define PARCHKVAL(_par, _val, _params) do { \
		if (_par != _val) { \
			quithere(1, "params[] usage (%d) != expected (%d)", \
					_par, _val); \
		} \
		if (_val > (int)(sizeof(_params)/sizeof(_params[0]))) { \
			quithere(1, "params[] usage (%d) > size (%d)", \
					_val, (int)(sizeof(_params)/sizeof(_params[0]))); \
		} \
	} while (0)

#define BTC_TO_D(_amt) ((double)((_amt) / 100000000.0))

// argv -y - don't run in ckdb mode, just confirm sharesummaries
static bool confirm_sharesummary;

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
static int64_t confirm_first_workinfoid;
static int64_t confirm_last_workinfoid;
/* Stop the reload 11min after the 'last' workinfoid+1 appears
 * ckpool uses 10min - but add 1min to be sure */
#define WORKINFO_AGE 660
static tv_t confirm_finish;

static tv_t reload_timestamp;

// DB users,workers,auth load is complete
static bool db_auths_complete = false;
// DB load is complete
static bool db_load_complete = false;
// Different input data handling
static bool reloading = false;
// Data load is complete
static bool startup_complete = false;
// Tell everyone to die
static bool everyone_die = false;

static cklock_t fpm_lock;
static char *first_pool_message;
static sem_t socketer_sem;

static const char *userpatt = "^[^/\\._"FLDSEPSTR"]*$"; // disallow: '/' '.' '_' and FLDSEP
static const char *mailpatt = "^[A-Za-z0-9_-][A-Za-z0-9_\\.-]*@[A-Za-z0-9][A-Za-z0-9\\.-]*[A-Za-z0-9]$";
static const char *idpatt = "^[_A-Za-z][_A-Za-z0-9]*$";
static const char *intpatt = "^[0-9][0-9]*$";
static const char *hashpatt = "^[A-Fa-f0-9]*$";

#define JSON_TRANSFER "json="
#define JSON_TRANSFER_LEN (sizeof(JSON_TRANSFER)-1)

// Methods for sharelog (common function for all)
#define STR_WORKINFO "workinfo"
#define STR_SHARES "shares"
#define STR_SHAREERRORS "shareerror"
#define STR_AGEWORKINFO "ageworkinfo"

static char *by_default = "code";
static char *inet_default = "127.0.0.1";

enum cmd_values {
	CMD_UNSET,
	CMD_REPLY, // Means something was wrong - send back reply
	CMD_SHUTDOWN,
	CMD_PING,
	CMD_VERSION,
	CMD_LOGLEVEL,
	CMD_SHARELOG,
	CMD_AUTH,
	CMD_ADDRAUTH,
	CMD_ADDUSER,
	CMD_NEWPASS,
	CMD_CHKPASS,
	CMD_USERSET,
	CMD_POOLSTAT,
	CMD_USERSTAT,
	CMD_BLOCK,
	CMD_BLOCKLIST,
	CMD_BLOCKSTATUS,
	CMD_NEWID,
	CMD_PAYMENTS,
	CMD_WORKERS,
	CMD_ALLUSERS,
	CMD_HOMEPAGE,
	CMD_GETATTS,
	CMD_SETATTS,
	CMD_EXPATTS,
	CMD_GETOPTS,
	CMD_SETOPTS,
	CMD_DSP,
	CMD_STATS,
	CMD_PPLNS,
	CMD_END
};

// For NON-list stack/heap K_ITEMS
#define INIT_GENERIC(_item, _name) do { \
		(_item)->name = _name ## _free->name; \
	} while (0)

#define DATA_GENERIC(_var, _item, _name, _nonull) do { \
		if ((_item) == NULL) { \
			if (_nonull) { \
				quithere(1, "Attempt to cast NULL item data (as '%s')", \
					 _name ## _free->name); \
			} else \
				(_var) = NULL; \
		} else { \
			if ((_item)->name != _name ## _free->name) { \
				quithere(1, "Attempt to cast item '%s' data as '%s'", \
					 (_item)->name, \
					 _name ## _free->name); \
			} \
			(_var) = ((struct _name *)((_item)->data)); \
		} \
	} while (0)

// LOGQUEUE
typedef struct logqueue {
	char *msg;
} LOGQUEUE;

#define ALLOC_LOGQUEUE 1024
#define LIMIT_LOGQUEUE 0
#define INIT_LOGQUEUE(_item) INIT_GENERIC(_item, logqueue)
#define DATA_LOGQUEUE(_var, _item) DATA_GENERIC(_var, _item, logqueue, true)

static K_LIST *logqueue_free;
static K_STORE *logqueue_store;

// WORKQUEUE
typedef struct workqueue {
	char *buf;
	int which_cmds;
	enum cmd_values cmdnum;
	char cmd[CMD_SIZ+1];
	char id[ID_SIZ+1];
	tv_t now;
	char by[TXT_SML+1];
	char code[TXT_MED+1];
	char inet[TXT_MED+1];
	tv_t cd;
	K_TREE *trf_root;
	K_STORE *trf_store;
} WORKQUEUE;

#define ALLOC_WORKQUEUE 1024
#define LIMIT_WORKQUEUE 0
#define CULL_WORKQUEUE 16
#define INIT_WORKQUEUE(_item) INIT_GENERIC(_item, workqueue)
#define DATA_WORKQUEUE(_var, _item) DATA_GENERIC(_var, _item, workqueue, true)

static K_LIST *workqueue_free;
static K_STORE *workqueue_store;
static pthread_mutex_t wq_waitlock;
static pthread_cond_t wq_waitcond;

// TRANSFER
#define NAME_SIZE 63
#define VALUE_SIZE 1023
typedef struct transfer {
	char name[NAME_SIZE+1];
	char svalue[VALUE_SIZE+1];
	char *mvalue;
} TRANSFER;

#define ALLOC_TRANSFER 64
#define LIMIT_TRANSFER 0
#define CULL_TRANSFER 64
#define INIT_TRANSFER(_item) INIT_GENERIC(_item, transfer)
#define DATA_TRANSFER(_var, _item) DATA_GENERIC(_var, _item, transfer, true)

static K_LIST *transfer_free;

#define transfer_data(_item) _transfer_data(_item, WHERE_FFL_HERE)

// For mutiple variable function calls that need the data
static char *_transfer_data(K_ITEM *item, WHERE_FFL_ARGS)
{
	TRANSFER *transfer;
	char *mvalue;

	if (!item) {
		quitfrom(1, file, func, line,
			 "Attempt to use NULL transfer item");
	}
	if (item->name != transfer_free->name) {
		quitfrom(1, file, func, line,
			 "Attempt to cast item '%s' data as '%s'",
			 item->name,
			 transfer_free->name);
	}
	transfer = (TRANSFER *)(item->data);
	if (!transfer) {
		quitfrom(1, file, func, line,
			 "Transfer item has NULL data");
	}
	mvalue = transfer->mvalue;
	if (!mvalue) {
		/* N.B. name and svalue strings will have \0 termination
		 * even if they are both corrupt, since mvalue is NULL */
		quitfrom(1, file, func, line,
			 "Transfer '%s' '%s' has NULL mvalue",
			 transfer->name, transfer->svalue);
	}
	return mvalue;
}

// So the records below have the same 'name' as the klist
static const char Transfer[] = "Transfer";

// older version missing field defaults
static TRANSFER auth_1 = { "poolinstance", "", auth_1.svalue };
static K_ITEM auth_poolinstance = { Transfer, NULL, NULL, (void *)(&auth_1) };
static TRANSFER auth_2 = { "preauth", FALSE_STR, auth_2.svalue };
static K_ITEM auth_preauth = { Transfer, NULL, NULL, (void *)(&auth_2) };
static TRANSFER poolstats_1 = { "elapsed", "0", poolstats_1.svalue };
static K_ITEM poolstats_elapsed = { Transfer, NULL, NULL, (void *)(&poolstats_1) };
static TRANSFER userstats_1 = { "elapsed", "0", userstats_1.svalue };
static K_ITEM userstats_elapsed = { Transfer, NULL, NULL, (void *)(&userstats_1) };
static TRANSFER userstats_2 = { "workername", "all", userstats_2.svalue };
static K_ITEM userstats_workername = { Transfer, NULL, NULL, (void *)(&userstats_2) };
static TRANSFER userstats_3 = { "idle", FALSE_STR, userstats_3.svalue };
static K_ITEM userstats_idle = { Transfer, NULL, NULL, (void *)(&userstats_3) };
static TRANSFER userstats_4 = { "eos", TRUE_STR, userstats_4.svalue };
static K_ITEM userstats_eos = { Transfer, NULL, NULL, (void *)(&userstats_4) };

static TRANSFER shares_1 = { "secondaryuserid", TRUE_STR, shares_1.svalue };
static K_ITEM shares_secondaryuserid = { Transfer, NULL, NULL, (void *)(&shares_1) };
static TRANSFER shareerrors_1 = { "secondaryuserid", TRUE_STR, shareerrors_1.svalue };
static K_ITEM shareerrors_secondaryuserid = { Transfer, NULL, NULL, (void *)(&shareerrors_1) };
// Time limit that this problem occurred
// 24-Aug-2014 05:20+00 (1st one shortly after this)
static tv_t missing_secuser_min = { 1408857600L, 0L };
// 24-Aug-2014 06:00+00
static tv_t missing_secuser_max = { 1408860000L, 0L };

// USERS
typedef struct users {
	int64_t userid;
	char username[TXT_BIG+1];
	// Anything in 'status' disables the account
	char status[TXT_BIG+1];
	char emailaddress[TXT_BIG+1];
	tv_t joineddate;
	char passwordhash[TXT_BIG+1];
	char secondaryuserid[TXT_SML+1];
	char salt[TXT_BIG+1];
	HISTORYDATECONTROLFIELDS;
} USERS;

#define ALLOC_USERS 1024
#define LIMIT_USERS 0
#define INIT_USERS(_item) INIT_GENERIC(_item, users)
#define DATA_USERS(_var, _item) DATA_GENERIC(_var, _item, users, true)
#define DATA_USERS_NULL(_var, _item) DATA_GENERIC(_var, _item, users, false)

#define SHA256SIZHEX	64
#define SHA256SIZBIN	32
#define SALTSIZHEX	32
#define SALTSIZBIN	16

static K_TREE *users_root;
static K_TREE *userid_root;
static K_LIST *users_free;
static K_STORE *users_store;

// USERATTS
typedef struct useratts {
	int64_t userid;
	char attname[TXT_SML+1];
	char status[TXT_BIG+1];
	char attstr[TXT_BIG+1];
	char attstr2[TXT_BIG+1];
	int64_t attnum;
	int64_t attnum2;
	tv_t attdate;
	tv_t attdate2;
	HISTORYDATECONTROLFIELDS;
} USERATTS;

#define ALLOC_USERATTS 1024
#define LIMIT_USERATTS 0
#define INIT_USERATTS(_item) INIT_GENERIC(_item, useratts)
#define DATA_USERATTS(_var, _item) DATA_GENERIC(_var, _item, useratts, true)
#define DATA_USERATTS_NULL(_var, _item) DATA_GENERIC(_var, _item, useratts, false)

static K_TREE *useratts_root;
static K_LIST *useratts_free;
static K_STORE *useratts_store;

// WORKERS
typedef struct workers {
	int64_t workerid;
	int64_t userid;
	char workername[TXT_BIG+1]; // includes username
	int32_t difficultydefault;
	char idlenotificationenabled[TXT_FLAG+1];
	int32_t idlenotificationtime;
	HISTORYDATECONTROLFIELDS;
} WORKERS;

#define ALLOC_WORKERS 1024
#define LIMIT_WORKERS 0
#define INIT_WORKERS(_item) INIT_GENERIC(_item, workers)
#define DATA_WORKERS(_var, _item) DATA_GENERIC(_var, _item, workers, true)
#define DATA_WORKERS_NULL(_var, _item) DATA_GENERIC(_var, _item, workers, false)

static K_TREE *workers_root;
static K_LIST *workers_free;
static K_STORE *workers_store;

#define DIFFICULTYDEFAULT_MIN 10
#define DIFFICULTYDEFAULT_MAX 1000000
#define DIFFICULTYDEFAULT_DEF DIFFICULTYDEFAULT_MIN
#define DIFFICULTYDEFAULT_DEF_STR STRINT(DIFFICULTYDEFAULT_DEF)
#define IDLENOTIFICATIONENABLED "y"
#define IDLENOTIFICATIONDISABLED " "
#define IDLENOTIFICATIONENABLED_DEF IDLENOTIFICATIONDISABLED
#define IDLENOTIFICATIONTIME_MIN 10
#define IDLENOTIFICATIONTIME_MAX 60
#define IDLENOTIFICATIONTIME_DEF IDLENOTIFICATIONTIME_MIN
#define IDLENOTIFICATIONTIME_DEF_STR STRINT(IDLENOTIFICATIONTIME_DEF)

// PAYMENTADDRESSES
typedef struct paymentaddresses {
	int64_t paymentaddressid;
	int64_t userid;
	char payaddress[TXT_BIG+1];
	int32_t payratio;
	HISTORYDATECONTROLFIELDS;
} PAYMENTADDRESSES;

#define ALLOC_PAYMENTADDRESSES 1024
#define LIMIT_PAYMENTADDRESSES 0
#define INIT_PAYMENTADDRESSES(_item) INIT_GENERIC(_item, paymentaddresses)
#define DATA_PAYMENTADDRESSES(_var, _item) DATA_GENERIC(_var, _item, paymentaddresses, true)

static K_TREE *paymentaddresses_root;
static K_LIST *paymentaddresses_free;
static K_STORE *paymentaddresses_store;

// PAYMENTS
typedef struct payments {
	int64_t paymentid;
	int64_t userid;
	tv_t paydate;
	char payaddress[TXT_BIG+1];
	char originaltxn[TXT_BIG+1];
	int64_t amount;
	char committxn[TXT_BIG+1];
	char commitblockhash[TXT_BIG+1];
	HISTORYDATECONTROLFIELDS;
} PAYMENTS;

#define ALLOC_PAYMENTS 1024
#define LIMIT_PAYMENTS 0
#define INIT_PAYMENTS(_item) INIT_GENERIC(_item, payments)
#define DATA_PAYMENTS(_var, _item) DATA_GENERIC(_var, _item, payments, true)
#define DATA_PAYMENTS_NULL(_var, _item) DATA_GENERIC(_var, _item, payments, false)

static K_TREE *payments_root;
static K_LIST *payments_free;
static K_STORE *payments_store;

/* unused yet
// ACCOUNTBALANCE
typedef struct accountbalance {
	int64_t userid;
	int64_t confirmedpaid;
	int64_t confirmedunpaid;
	int64_t pendingconfirm;
	int32_t heightupdate;
	HISTORYDATECONTROLFIELDS;
} ACCOUNTBALANCE;

#define ALLOC_ACCOUNTBALANCE 1024
#define LIMIT_ACCOUNTBALANCE 0
#define INIT_ACCOUNTBALANCE(_item) INIT_GENERIC(_item, accountbalance)
#define DATA_ACCOUNTBALANCE(_var, _item) DATA_GENERIC(_var, _item, accountbalance, true)

static K_TREE *accountbalance_root;
static K_LIST *accountbalance_free;
static K_STORE *accountbalance_store;

// ACCOUNTADJUSTMENT
typedef struct accountadjustment {
	int64_t userid;
	char authority[TXT_BIG+1];
	char *reason;
	int64_t amount;
	HISTORYDATECONTROLFIELDS;
} ACCOUNTADJUSTMENT;

#define ALLOC_ACCOUNTADJUSTMENT 100
#define LIMIT_ACCOUNTADJUSTMENT 0
#define INIT_ACCOUNTADJUSTMENT(_item) INIT_GENERIC(_item, accountadjustment)
#define DATA_ACCOUNTADJUSTMENT(_var, _item) DATA_GENERIC(_var, _item, accountadjustment, true)

static K_TREE *accountadjustment_root;
static K_LIST *accountadjustment_free;
static K_STORE *accountadjustment_store;
*/

// IDCONTROL
typedef struct idcontrol {
	char idname[TXT_SML+1];
	int64_t lastid;
	MODIFYDATECONTROLFIELDS;
} IDCONTROL;

#define ALLOC_IDCONTROL 16
#define LIMIT_IDCONTROL 0
#define INIT_IDCONTROL(_item) INIT_GENERIC(_item, idcontrol)
#define DATA_IDCONTROL(_var, _item) DATA_GENERIC(_var, _item, idcontrol, true)

// These are only used for db access - not stored in memory
//static K_TREE *idcontrol_root;
static K_LIST *idcontrol_free;
static K_STORE *idcontrol_store;

// OPTIONCONTROL
typedef struct optioncontrol {
	char optionname[TXT_SML+1];
	char *optionvalue;
	tv_t activationdate;
	int32_t activationheight;
	HISTORYDATECONTROLFIELDS;
} OPTIONCONTROL;

#define ALLOC_OPTIONCONTROL 64
#define LIMIT_OPTIONCONTROL 0
#define INIT_OPTIONCONTROL(_item) INIT_GENERIC(_item, optioncontrol)
#define DATA_OPTIONCONTROL(_var, _item) DATA_GENERIC(_var, _item, optioncontrol, true)
#define DATA_OPTIONCONTROL_NULL(_var, _item) DATA_GENERIC(_var, _item, optioncontrol, false)

// Value it must default to (to work properly)
#define OPTIONCONTROL_HEIGHT 1

// Test it here rather than obscuring the #define elsewhere
#if ((OPTIONCONTROL_HEIGHT+1) != START_POOL_HEIGHT)
#error "START_POOL_HEIGHT must = (OPTIONCONTROL_HEIGHT+1)"
#endif

static K_TREE *optioncontrol_root;
static K_LIST *optioncontrol_free;
static K_STORE *optioncontrol_store;

// TODO: discarding workinfo,shares
// WORKINFO workinfo.id.json={...}
typedef struct workinfo {
	int64_t workinfoid;
	char poolinstance[TXT_BIG+1];
	char *transactiontree;
	char *merklehash;
	char prevhash[TXT_BIG+1];
	char coinbase1[TXT_BIG+1];
	char coinbase2[TXT_BIG+1];
	char version[TXT_SML+1];
	char bits[TXT_SML+1];
	char ntime[TXT_SML+1];
	int64_t reward;
	HISTORYDATECONTROLFIELDS;
} WORKINFO;

// ~10 hrs
#define ALLOC_WORKINFO 1400
#define LIMIT_WORKINFO 0
#define INIT_WORKINFO(_item) INIT_GENERIC(_item, workinfo)
#define DATA_WORKINFO(_var, _item) DATA_GENERIC(_var, _item, workinfo, true)

static K_TREE *workinfo_root;
// created during data load then destroyed since not needed later
static K_TREE *workinfo_height_root;
static K_LIST *workinfo_free;
static K_STORE *workinfo_store;
// one in the current block
static K_ITEM *workinfo_current;
// first workinfo of current block
static tv_t last_bc;
// current network diff
static double current_ndiff;

// SHARES shares.id.json={...}
typedef struct shares {
	int64_t workinfoid;
	int64_t userid;
	char workername[TXT_BIG+1];
	int32_t clientid;
	char enonce1[TXT_SML+1];
	char nonce2[TXT_BIG+1];
	char nonce[TXT_SML+1];
	double diff;
	double sdiff;
	int32_t errn;
	char error[TXT_SML+1];
	char secondaryuserid[TXT_SML+1];
	HISTORYDATECONTROLFIELDS;
} SHARES;

#define ALLOC_SHARES 10000
#define LIMIT_SHARES 0
#define INIT_SHARES(_item) INIT_GENERIC(_item, shares)
#define DATA_SHARES(_var, _item) DATA_GENERIC(_var, _item, shares, true)

static K_TREE *shares_root;
static K_LIST *shares_free;
static K_STORE *shares_store;

// SHAREERRORS shareerrors.id.json={...}
typedef struct shareerrors {
	int64_t workinfoid;
	int64_t userid;
	char workername[TXT_BIG+1];
	int32_t clientid;
	int32_t errn;
	char error[TXT_SML+1];
	char secondaryuserid[TXT_SML+1];
	HISTORYDATECONTROLFIELDS;
} SHAREERRORS;

#define ALLOC_SHAREERRORS 10000
#define LIMIT_SHAREERRORS 0
#define INIT_SHAREERRORS(_item) INIT_GENERIC(_item, shareerrors)
#define DATA_SHAREERRORS(_var, _item) DATA_GENERIC(_var, _item, shareerrors, true)

static K_TREE *shareerrors_root;
static K_LIST *shareerrors_free;
static K_STORE *shareerrors_store;

// SHARESUMMARY
typedef struct sharesummary {
	int64_t userid;
	char workername[TXT_BIG+1];
	int64_t workinfoid;
	double diffacc;
	double diffsta;
	double diffdup;
	double diffhi;
	double diffrej;
	double shareacc;
	double sharesta;
	double sharedup;
	double sharehi;
	double sharerej;
	int64_t sharecount;
	int64_t errorcount;
	int64_t countlastupdate; // non-DB field
	bool inserted; // non-DB field
	bool saveaged; // non-DB field
	bool reset; // non-DB field
	tv_t firstshare;
	tv_t lastshare;
	double lastdiffacc;
	char complete[TXT_FLAG+1];
	MODIFYDATECONTROLFIELDS;
} SHARESUMMARY;

/* After this many shares added, we need to update the DB record
   The DB record is added with the 1st share */
#define SHARESUMMARY_UPDATE_EVERY 10

#define ALLOC_SHARESUMMARY 10000
#define LIMIT_SHARESUMMARY 0
#define INIT_SHARESUMMARY(_item) INIT_GENERIC(_item, sharesummary)
#define DATA_SHARESUMMARY(_var, _item) DATA_GENERIC(_var, _item, sharesummary, true)
#define DATA_SHARESUMMARY_NULL(_var, _item) DATA_GENERIC(_var, _item, sharesummary, false)

#define SUMMARY_NEW 'n'
#define SUMMARY_COMPLETE 'a'
#define SUMMARY_CONFIRM 'y'

static K_TREE *sharesummary_root;
static K_TREE *sharesummary_workinfoid_root;
static K_LIST *sharesummary_free;
static K_STORE *sharesummary_store;

// BLOCKS block.id.json={...}
typedef struct blocks {
	int32_t height;
	char blockhash[TXT_BIG+1];
	int64_t workinfoid;
	int64_t userid;
	char workername[TXT_BIG+1];
	int32_t clientid;
	char enonce1[TXT_SML+1];
	char nonce2[TXT_BIG+1];
	char nonce[TXT_SML+1];
	int64_t reward;
	char confirmed[TXT_FLAG+1];
	double diffacc;
	double diffinv;
	double shareacc;
	double shareinv;
	int64_t elapsed;
	char statsconfirmed[TXT_FLAG+1];
	HISTORYDATECONTROLFIELDS;
} BLOCKS;

#define ALLOC_BLOCKS 100
#define LIMIT_BLOCKS 0
#define INIT_BLOCKS(_item) INIT_GENERIC(_item, blocks)
#define DATA_BLOCKS(_var, _item) DATA_GENERIC(_var, _item, blocks, true)
#define DATA_BLOCKS_NULL(_var, _item) DATA_GENERIC(_var, _item, blocks, false)

#define BLOCKS_NEW 'n'
#define BLOCKS_NEW_STR "n"
#define BLOCKS_CONFIRM '1'
#define BLOCKS_CONFIRM_STR "1"
#define BLOCKS_42 'F'
#define BLOCKS_42_STR "F"
#define BLOCKS_ORPHAN 'O'
#define BLOCKS_ORPHAN_STR "O"

#define BLOCKS_STATSPENDING FALSE_CHR
#define BLOCKS_STATSPENDING_STR FALSE_STR
#define BLOCKS_STATSCONFIRMED TRUE_CHR
#define BLOCKS_STATSCONFIRMED_STR TRUE_STR

static const char *blocks_new = "New";
static const char *blocks_confirm = "1-Confirm";
static const char *blocks_42 = "42-Confirm";
static const char *blocks_orphan = "Orphan";
static const char *blocks_unknown = "?Unknown?";

#define KANO -27972

static K_TREE *blocks_root;
static K_LIST *blocks_free;
static K_STORE *blocks_store;

// MININGPAYOUTS
typedef struct miningpayouts {
	int64_t miningpayoutid;
	int64_t userid;
	int32_t height;
	char blockhash[TXT_BIG+1];
	int64_t amount;
	HISTORYDATECONTROLFIELDS;
} MININGPAYOUTS;

#define ALLOC_MININGPAYOUTS 1000
#define LIMIT_MININGPAYOUTS 0
#define INIT_MININGPAYOUTS(_item) INIT_GENERIC(_item, miningpayouts)
#define DATA_MININGPAYOUTS(_var, _item) DATA_GENERIC(_var, _item, miningpayouts, true)

static K_TREE *miningpayouts_root;
static K_LIST *miningpayouts_free;
static K_STORE *miningpayouts_store;

/*
// EVENTLOG
typedef struct eventlog {
	int64_t eventlogid;
	char poolinstance[TXT_BIG+1];
	char eventlogcode[TXT_SML+1];
	char *eventlogdescription;
	HISTORYDATECONTROLFIELDS;
} EVENTLOG;

#define ALLOC_EVENTLOG 100
#define LIMIT_EVENTLOG 0
#define INIT_EVENTLOG(_item) INIT_GENERIC(_item, eventlog)
#define DATA_EVENTLOG(_var, _item) DATA_GENERIC(_var, _item, eventlog, true)

static K_TREE *eventlog_root;
static K_LIST *eventlog_free;
static K_STORE *eventlog_store;
*/

// AUTHS authorise.id.json={...}
typedef struct auths {
	int64_t authid;
	char poolinstance[TXT_BIG+1];
	int64_t userid;
	char workername[TXT_BIG+1];
	int32_t clientid;
	char enonce1[TXT_SML+1];
	char useragent[TXT_BIG+1];
	char preauth[TXT_FLAG+1];
	HISTORYDATECONTROLFIELDS;
} AUTHS;

#define ALLOC_AUTHS 1000
#define LIMIT_AUTHS 0
#define INIT_AUTHS(_item) INIT_GENERIC(_item, auths)
#define DATA_AUTHS(_var, _item) DATA_GENERIC(_var, _item, auths, true)

static K_TREE *auths_root;
static K_LIST *auths_free;
static K_STORE *auths_store;

// POOLSTATS poolstats.id.json={...}
// Store every > 9.5m?
// TODO: redo like userstats, but every 10min
#define STATS_PER (9.5*60.0)

typedef struct poolstats {
	char poolinstance[TXT_BIG+1];
	int64_t elapsed;
	int32_t users;
	int32_t workers;
	double hashrate;
	double hashrate5m;
	double hashrate1hr;
	double hashrate24hr;
	bool stored; // Non-db field
	SIMPLEDATECONTROLFIELDS;
} POOLSTATS;

#define ALLOC_POOLSTATS 10000
#define LIMIT_POOLSTATS 0
#define INIT_POOLSTATS(_item) INIT_GENERIC(_item, poolstats)
#define DATA_POOLSTATS(_var, _item) DATA_GENERIC(_var, _item, poolstats, true)
#define DATA_POOLSTATS_NULL(_var, _item) DATA_GENERIC(_var, _item, poolstats, false)

static K_TREE *poolstats_root;
static K_LIST *poolstats_free;
static K_STORE *poolstats_store;

// USERSTATS userstats.id.json={...}
// Pool sends each user (staggered) once per 10m
typedef struct userstats {
	char poolinstance[TXT_BIG+1];
	int64_t userid;
	char workername[TXT_BIG+1];
	int64_t elapsed;
	double hashrate;
	double hashrate5m;
	double hashrate1hr;
	double hashrate24hr;
	bool idle; // Non-db field
	char summarylevel[TXT_FLAG+1]; // Initially SUMMARY_NONE in RAM
	int32_t summarycount;
	tv_t statsdate;
	SIMPLEDATECONTROLFIELDS;
} USERSTATS;

/* USERSTATS protocol includes a boolean 'eos' that when true,
 * we have received the full set of data for the given
 * createdate batch, and thus can move all (complete) records
 * matching the createdate from userstats_eos_store into the tree */

#define ALLOC_USERSTATS 10000
#define LIMIT_USERSTATS 0
#define INIT_USERSTATS(_item) INIT_GENERIC(_item, userstats)
#define DATA_USERSTATS(_var, _item) DATA_GENERIC(_var, _item, userstats, true)
#define DATA_USERSTATS_NULL(_var, _item) DATA_GENERIC(_var, _item, userstats, false)

static K_TREE *userstats_root;
static K_TREE *userstats_statsdate_root; // ordered by statsdate first
static K_TREE *userstats_workerstatus_root; // during data load
static K_LIST *userstats_free;
static K_STORE *userstats_store;
// Awaiting EOS
static K_STORE *userstats_eos_store;
// Temporary while summarising
static K_STORE *userstats_summ;

/* 1.5 x how often we expect to get user's stats from ckpool
 * This is used when grouping the sub-worker stats into a single user
 * We add each worker's latest stats to the total - except we ignore
 * any worker with newest stats being older than USERSTATS_PER_S */
#define USERSTATS_PER_S 900

/* on the allusers page, show any with stats in the last ... */
#define ALLUSERS_LIMIT_S 3600

#define SUMMARY_NONE '0'
#define SUMMARY_DB '1'
#define SUMMARY_FULL '2'

/* Userstats get stored in the DB for each time band of this
 * amount from midnight (UTC+00)
 * Thus we simply put each stats value in the time band of the
 * stat's timestamp
 * Userstats are sumarised in the the same userstats table
 * If USERSTATS_DB_S is close to the expected time per USERSTATS
 * then it will have higher variance i.e. obviously: a higher
 * average of stats per sample will mean a lower SD of the number
 * of stats per sample
 * The #if below ensures USERSTATS_DB_S times an integer = a day
 * so the last band is the same size as the rest -
 * and will graph easily
 * Obvious WARNING - the smaller this is, the more stats in the DB
 * This is summary level '1'
 */
#define USERSTATS_DB_S 3600

#if (((24*60*60) % USERSTATS_DB_S) != 0)
#error "USERSTATS_DB_S times an integer must = a day"
#endif

#if ((24*60*60) < USERSTATS_DB_S)
#error "USERSTATS_DB_S must be at most 1 day"
#endif

/* We summarise and discard userstats that are older than the
 * maximum of USERSTATS_DB_S, USERSTATS_PER_S, ALLUSERS_LIMIT_S
 */
#if (USERSTATS_PER_S > ALLUSERS_LIMIT_S)
 #if (USERSTATS_PER_S > USERSTATS_DB_S)
  #define USERSTATS_AGE USERSTATS_PER_S
 #else
  #define USERSTATS_AGE USERSTATS_DB_S
 #endif
#else
 #if (ALLUSERS_LIMIT_S > USERSTATS_DB_S)
  #define USERSTATS_AGE ALLUSERS_LIMIT_S
 #else
  #define USERSTATS_AGE USERSTATS_DB_S
 #endif
#endif

/* TODO: summarisation of the userstats after this many days are done
 * at the day level and the above stats are deleted from the db
 * Obvious WARNING - the larger this is, the more stats in the DB
 * This is summary level '2'
 */
#define USERSTATS_DB_D 7
#define USERSTATS_DB_DS (USERSTATS_DB_D * (60*60*24))

// true if _new is newer, i.e. _old is before _new
#define tv_newer(_old, _new) (((_old)->tv_sec == (_new)->tv_sec) ? \
				((_old)->tv_usec < (_new)->tv_usec) : \
				((_old)->tv_sec < (_new)->tv_sec))
#define tv_equal(_a, _b) (((_a)->tv_sec == (_b)->tv_sec) && \
				((_a)->tv_usec == (_b)->tv_usec))
// newer OR equal
#define tv_newer_eq(_old, _new) (!(tv_newer(_new, _old)))

// WORKERSTATUS from various incoming data
typedef struct workerstatus {
	int64_t userid;
	char workername[TXT_BIG+1];
	tv_t last_auth;
	tv_t last_share;
	double last_diff;
	tv_t last_stats;
	tv_t last_idle;
	// Below gets reset on each block
	double diffacc;
	double diffinv; // Non-acc
	double diffsta;
	double diffdup;
	double diffhi;
	double diffrej;
	double shareacc;
	double shareinv; // Non-acc
	double sharesta;
	double sharedup;
	double sharehi;
	double sharerej;
} WORKERSTATUS;

#define ALLOC_WORKERSTATUS 1000
#define LIMIT_WORKERSTATUS 0
#define INIT_WORKERSTATUS(_item) INIT_GENERIC(_item, workerstatus)
#define DATA_WORKERSTATUS(_var, _item) DATA_GENERIC(_var, _item, workerstatus, true)

static K_TREE *workerstatus_root;
static K_LIST *workerstatus_free;
static K_STORE *workerstatus_store;

static void _txt_to_data(enum data_type typ, char *nam, char *fld, void *data, size_t siz, WHERE_FFL_ARGS)
{
	char *tmp;

	switch (typ) {
		case TYPE_STR:
			// A database field being bigger than local storage is a fatal error
			if (siz < (strlen(fld)+1)) {
				quithere(1, "Field %s structure size %d is smaller than db %d" WHERE_FFL,
						nam, (int)siz, (int)strlen(fld)+1, WHERE_FFL_PASS);
			}
			strcpy((char *)data, fld);
			break;
		case TYPE_BIGINT:
			if (siz != sizeof(int64_t)) {
				quithere(1, "Field %s bigint incorrect structure size %d - should be %d"
						WHERE_FFL,
						nam, (int)siz, (int)sizeof(int64_t), WHERE_FFL_PASS);
			}
			*((long long *)data) = atoll(fld);
			break;
		case TYPE_INT:
			if (siz != sizeof(int32_t)) {
				quithere(1, "Field %s int incorrect structure size %d - should be %d"
						WHERE_FFL,
						nam, (int)siz, (int)sizeof(int32_t), WHERE_FFL_PASS);
			}
			*((int32_t *)data) = atoi(fld);
			break;
		case TYPE_TV:
			if (siz != sizeof(tv_t)) {
				quithere(1, "Field %s tv_t incorrect structure size %d - should be %d"
						WHERE_FFL,
						nam, (int)siz, (int)sizeof(tv_t), WHERE_FFL_PASS);
			}
			unsigned int yyyy, mm, dd, HH, MM, SS, uS = 0, tz, tzm = 0;
			char pm[2];
			struct tm tm;
			time_t tim;
			int n;
			// A timezone looks like: +10 or +09:30 or -05 etc
			n = sscanf(fld, "%u-%u-%u %u:%u:%u%1[+-]%u:%u",
					&yyyy, &mm, &dd, &HH, &MM, &SS, pm, &tz, &tzm);
			if (n < 8) {
				// allow uS
				n = sscanf(fld, "%u-%u-%u %u:%u:%u.%u%1[+-]%u:%u",
						&yyyy, &mm, &dd, &HH, &MM, &SS, &uS, pm, &tz, &tzm);
				if (n < 9) {
					quithere(1, "Field %s tv_t unhandled date '%s' (%d)" WHERE_FFL,
						 nam, fld, n, WHERE_FFL_PASS);
				}

				if (n < 10)
					tzm = 0;
			} else if (n < 9)
				tzm = 0;
			tm.tm_sec = (int)SS;
			tm.tm_min = (int)MM;
			tm.tm_hour = (int)HH;
			tm.tm_mday = (int)dd;
			tm.tm_mon = (int)mm - 1;
			tm.tm_year = (int)yyyy - 1900;
			tm.tm_isdst = -1;
			tim = timegm(&tm);
			if (tim > COMPARE_EXPIRY) {
				((tv_t *)data)->tv_sec = default_expiry.tv_sec;
				((tv_t *)data)->tv_usec = default_expiry.tv_usec;
			} else {
				tz = tz * 60 + tzm;
				// time was converted ignoring tz - so correct it
				if (pm[0] == '-')
					tim += 60 * tz;
				else
					tim -= 60 * tz;
				((tv_t *)data)->tv_sec = tim;
				((tv_t *)data)->tv_usec = uS;
			}
			break;
		case TYPE_CTV:
			if (siz != sizeof(tv_t)) {
				quithere(1, "Field %s tv_t incorrect structure size %d - should be %d"
						WHERE_FFL,
						nam, (int)siz, (int)sizeof(tv_t), WHERE_FFL_PASS);
			}
			long sec, nsec;
			int c;
			// Caller test for tv_sec=0 for failure
			((tv_t *)data)->tv_sec = 0L;
			((tv_t *)data)->tv_usec = 0L;
			c = sscanf(fld, "%ld,%ld", &sec, &nsec);
			if (c > 0) {
				((tv_t *)data)->tv_sec = (time_t)sec;
				if (c > 1)
					((tv_t *)data)->tv_usec = (nsec + 500) / 1000;
				if (((tv_t *)data)->tv_sec >= COMPARE_EXPIRY) {
					((tv_t *)data)->tv_sec = default_expiry.tv_sec;
					((tv_t *)data)->tv_usec = default_expiry.tv_usec;
				}
			}
			break;
		case TYPE_BLOB:
			tmp = strdup(fld);
			if (!tmp) {
				quithere(1, "Field %s (%d) OOM" WHERE_FFL,
						nam, (int)strlen(fld), WHERE_FFL_PASS);
			}
			*((char **)data) = tmp;
			break;
		case TYPE_DOUBLE:
			if (siz != sizeof(double)) {
				quithere(1, "Field %s int incorrect structure size %d - should be %d"
						WHERE_FFL,
						nam, (int)siz, (int)sizeof(double), WHERE_FFL_PASS);
			}
			*((double *)data) = atof(fld);
			break;
		default:
			quithere(1, "Unknown field %s (%d) to convert" WHERE_FFL,
					nam, (int)typ, WHERE_FFL_PASS);
			break;
	}
}

#define txt_to_str(_nam, _fld, _data, _siz) _txt_to_str(_nam, _fld, _data, _siz, WHERE_FFL_HERE)
#define txt_to_bigint(_nam, _fld, _data, _siz) _txt_to_bigint(_nam, _fld, _data, _siz, WHERE_FFL_HERE)
#define txt_to_int(_nam, _fld, _data, _siz) _txt_to_int(_nam, _fld, _data, _siz, WHERE_FFL_HERE)
#define txt_to_tv(_nam, _fld, _data, _siz) _txt_to_tv(_nam, _fld, _data, _siz, WHERE_FFL_HERE)
#define txt_to_ctv(_nam, _fld, _data, _siz) _txt_to_ctv(_nam, _fld, _data, _siz, WHERE_FFL_HERE)
#define txt_to_blob(_nam, _fld, _data) _txt_to_blob(_nam, _fld, _data, WHERE_FFL_HERE)
#define txt_to_double(_nam, _fld, _data, _siz) _txt_to_double(_nam, _fld, _data, _siz, WHERE_FFL_HERE)

// N.B. STRNCPY* macros truncate, whereas this aborts ckdb if src > trg
static void _txt_to_str(char *nam, char *fld, char data[], size_t siz, WHERE_FFL_ARGS)
{
	_txt_to_data(TYPE_STR, nam, fld, (void *)data, siz, WHERE_FFL_PASS);
}

static void _txt_to_bigint(char *nam, char *fld, int64_t *data, size_t siz, WHERE_FFL_ARGS)
{
	_txt_to_data(TYPE_BIGINT, nam, fld, (void *)data, siz, WHERE_FFL_PASS);
}

static void _txt_to_int(char *nam, char *fld, int32_t *data, size_t siz, WHERE_FFL_ARGS)
{
	_txt_to_data(TYPE_INT, nam, fld, (void *)data, siz, WHERE_FFL_PASS);
}

static void _txt_to_tv(char *nam, char *fld, tv_t *data, size_t siz, WHERE_FFL_ARGS)
{
	_txt_to_data(TYPE_TV, nam, fld, (void *)data, siz, WHERE_FFL_PASS);
}

// Convert msg S,nS to tv_t
static void _txt_to_ctv(char *nam, char *fld, tv_t *data, size_t siz, WHERE_FFL_ARGS)
{
	_txt_to_data(TYPE_CTV, nam, fld, (void *)data, siz, WHERE_FFL_PASS);
}

static void _txt_to_blob(char *nam, char *fld, char **data, WHERE_FFL_ARGS)
{
	_txt_to_data(TYPE_BLOB, nam, fld, (void *)data, 0, WHERE_FFL_PASS);
}

static void _txt_to_double(char *nam, char *fld, double *data, size_t siz, WHERE_FFL_ARGS)
{
	_txt_to_data(TYPE_DOUBLE, nam, fld, (void *)data, siz, WHERE_FFL_PASS);
}

static char *_data_to_buf(enum data_type typ, void *data, char *buf, size_t siz, WHERE_FFL_ARGS)
{
	struct tm tm;

	if (!buf) {
		switch (typ) {
			case TYPE_STR:
			case TYPE_BLOB:
				siz = strlen((char *)data) + 1;
				break;
			case TYPE_BIGINT:
				siz = BIGINT_BUFSIZ;
				break;
			case TYPE_INT:
				siz = INT_BUFSIZ;
				break;
			case TYPE_TV:
			case TYPE_TVS:
				siz = DATE_BUFSIZ;
				break;
			case TYPE_CTV:
				siz = CDATE_BUFSIZ;
				break;
			case TYPE_DOUBLE:
				siz = DOUBLE_BUFSIZ;
				break;
			default:
				quithere(1, "Unknown field (%d) to convert" WHERE_FFL,
						(int)typ, WHERE_FFL_PASS);
				break;
		}

		buf = malloc(siz);
		if (!buf)
			quithere(1, "(%d) OOM" WHERE_FFL, (int)siz, WHERE_FFL_PASS);
	}

	switch (typ) {
		case TYPE_STR:
		case TYPE_BLOB:
			snprintf(buf, siz, "%s", (char *)data);
			break;
		case TYPE_BIGINT:
			snprintf(buf, siz, "%"PRId64, *((uint64_t *)data));
			break;
		case TYPE_INT:
			snprintf(buf, siz, "%"PRId32, *((uint32_t *)data));
			break;
		case TYPE_TV:
			gmtime_r(&(((tv_t *)data)->tv_sec), &tm);
			snprintf(buf, siz, "%d-%02d-%02d %02d:%02d:%02d.%06ld+00",
					   tm.tm_year + 1900,
					   tm.tm_mon + 1,
					   tm.tm_mday,
					   tm.tm_hour,
					   tm.tm_min,
					   tm.tm_sec,
					   (((tv_t *)data)->tv_usec));
			break;
		case TYPE_CTV:
			snprintf(buf, siz, "%ld,%ld",
					   (((tv_t *)data)->tv_sec),
					   (((tv_t *)data)->tv_usec));
			break;
		case TYPE_TVS:
			snprintf(buf, siz, "%ld", (((tv_t *)data)->tv_sec));
			break;
		case TYPE_DOUBLE:
			snprintf(buf, siz, "%f", *((double *)data));
			break;
	}

	return buf;
}

#define str_to_buf(_data, _buf, _siz) _str_to_buf(_data, _buf, _siz, WHERE_FFL_HERE)
#define bigint_to_buf(_data, _buf, _siz) _bigint_to_buf(_data, _buf, _siz, WHERE_FFL_HERE)
#define int_to_buf(_data, _buf, _siz) _int_to_buf(_data, _buf, _siz, WHERE_FFL_HERE)
#define tv_to_buf(_data, _buf, _siz) _tv_to_buf(_data, _buf, _siz, WHERE_FFL_HERE)
#define ctv_to_buf(_data, _buf, _siz) _ctv_to_buf(_data, _buf, _siz, WHERE_FFL_HERE)
#define tvs_to_buf(_data, _buf, _siz) _tvs_to_buf(_data, _buf, _siz, WHERE_FFL_HERE)
//#define blob_to_buf(_data, _buf, _siz) _blob_to_buf(_data, _buf, _siz, WHERE_FFL_HERE)
#define double_to_buf(_data, _buf, _siz) _double_to_buf(_data, _buf, _siz, WHERE_FFL_HERE)

static char *_str_to_buf(char data[], char *buf, size_t siz, WHERE_FFL_ARGS)
{
	return _data_to_buf(TYPE_STR, (void *)data, buf, siz, WHERE_FFL_PASS);
}

static char *_bigint_to_buf(int64_t data, char *buf, size_t siz, WHERE_FFL_ARGS)
{
	return _data_to_buf(TYPE_BIGINT, (void *)(&data), buf, siz, WHERE_FFL_PASS);
}

static char *_int_to_buf(int32_t data, char *buf, size_t siz, WHERE_FFL_ARGS)
{
	return _data_to_buf(TYPE_INT, (void *)(&data), buf, siz, WHERE_FFL_PASS);
}

static char *_tv_to_buf(tv_t *data, char *buf, size_t siz, WHERE_FFL_ARGS)
{
	return _data_to_buf(TYPE_TV, (void *)data, buf, siz, WHERE_FFL_PASS);
}

// Convert tv to S,uS
static char *_ctv_to_buf(tv_t *data, char *buf, size_t siz, WHERE_FFL_ARGS)
{
	return _data_to_buf(TYPE_CTV, (void *)data, buf, siz, WHERE_FFL_PASS);
}

// Convert tv to seconds (ignore uS)
static char *_tvs_to_buf(tv_t *data, char *buf, size_t siz, WHERE_FFL_ARGS)
{
	return _data_to_buf(TYPE_TVS, (void *)data, buf, siz, WHERE_FFL_PASS);
}

/* unused yet
static char *_blob_to_buf(char *data, char *buf, size_t siz, WHERE_FFL_ARGS)
{
	return _data_to_buf(TYPE_BLOB, (void *)data, buf, siz, WHERE_FFL_PASS);
}
*/

static char *_double_to_buf(double data, char *buf, size_t siz, WHERE_FFL_ARGS)
{
	return _data_to_buf(TYPE_DOUBLE, (void *)(&data), buf, siz, WHERE_FFL_PASS);
}

static char logname[512];
static char *dbcode;

// CCLs are every ...
#define ROLL_S 3600

#define LOGQUE(_msg) log_queue_message(_msg)
#define LOGFILE(_msg) rotating_log_nolock(_msg)
#define LOGDUP "dup."

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
	minoff = timezone / 60;
	if (minoff < 0) {
		tzch = '+';
		minoff *= -1;
	} else
		tzch = '-';
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

static void setnow(tv_t *now)
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

#define CKPQ_READ true
#define CKPQ_WRITE false

#define CKPQexec(_conn, _qry, _isread) _CKPQexec(_conn, _qry, _isread, WHERE_FFL_HERE)

// Bug check to ensure no unexpected write txns occur
static PGresult *_CKPQexec(PGconn *conn, const char *qry, bool isread, WHERE_FFL_ARGS)
{
	// It would slow it down, but could check qry for insert/update/...
	if (!isread && confirm_sharesummary)
		quitfrom(1, file, func, line, "BUG: write txn during confirm");

	return PQexec(conn, qry);
}

#define CKPQexecParams(_conn, _qry, _p1, _p2, _p3, _p4, _p5, _p6, _isread) \
		_CKPQexecParams(_conn, _qry, _p1, _p2, _p3, _p4, _p5, _p6, \
				_isread, WHERE_FFL_HERE)

static PGresult *_CKPQexecParams(PGconn *conn, const char *qry,
				 int nParams,
				 const Oid *paramTypes,
				 const char *const * paramValues,
				 const int *paramLengths,
				 const int *paramFormats,
				 int resultFormat,
				 bool isread, WHERE_FFL_ARGS)
{
	// It would slow it down, but could check qry for insert/update/...
	if (!isread && confirm_sharesummary)
		quitfrom(1, file, func, line, "BUG: write txn during confirm");

	return PQexecParams(conn, qry, nParams, paramTypes, paramValues, paramLengths,
			    paramFormats, resultFormat);
}

// Force use CKPQ... for PQ functions in use
#define PQexec CKPQexec
#define PQexecParams CKPQexecParams

static uint64_t ticks;
static time_t last_tick;

static void tick()
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

static void dsp_transfer(K_ITEM *item, FILE *stream)
{
	TRANSFER *t;

	if (!item)
		fprintf(stream, "%s() called with (null) item\n", __func__);
	else {
		DATA_TRANSFER(t, item);
		fprintf(stream, " name='%s' mvalue='%s' malloc=%c\n",
				t->name, t->mvalue,
				(t->svalue == t->mvalue) ? 'N' : 'Y');
	}
}

// order by name asc
static cmp_t cmp_transfer(K_ITEM *a, K_ITEM *b)
{
	TRANSFER *ta, *tb;
	DATA_TRANSFER(ta, a);
	DATA_TRANSFER(tb, b);
	return CMP_STR(ta->name, tb->name);
}

static K_ITEM *find_transfer(K_TREE *trf_root, char *name)
{
	TRANSFER transfer;
	K_TREE_CTX ctx[1];
	K_ITEM look;

	STRNCPY(transfer.name, name);
	INIT_TRANSFER(&look);
	look.data = (void *)(&transfer);
	return find_in_ktree(trf_root, &look, cmp_transfer, ctx);
}

#define optional_name(_root, _name, _len, _patt) \
		_optional_name(_root, _name, _len, _patt, WHERE_FFL_HERE)

static K_ITEM *_optional_name(K_TREE *trf_root, char *name, int len, char *patt,
				WHERE_FFL_ARGS)
{
	TRANSFER *trf;
	K_ITEM *item;
	char *mvalue;
	regex_t re;
	size_t dlen;
	int ret;

	item = find_transfer(trf_root, name);
	if (!item)
		return NULL;

	DATA_TRANSFER(trf, item);
	mvalue = trf->mvalue;
	if (mvalue)
		dlen = strlen(mvalue);
	else
		dlen = 0;
	if (!mvalue || (int)dlen < len) {
		if (!mvalue) {
			LOGERR("%s(): field '%s' NULL (%d) from %s():%d",
				__func__, name, (int)dlen, len, func, line);
		}
		return NULL;
	}

	if (patt) {
		if (regcomp(&re, patt, REG_NOSUB) != 0)
			return NULL;

		ret = regexec(&re, mvalue, (size_t)0, NULL, 0);
		regfree(&re);

		if (ret != 0)
			return NULL;
	}

	return item;
}

#define require_name(_root, _name, _len, _patt, _reply, _siz) \
		_require_name(_root, _name, _len, _patt, _reply, \
				_siz, WHERE_FFL_HERE)

static K_ITEM *_require_name(K_TREE *trf_root, char *name, int len, char *patt,
				char *reply, size_t siz, WHERE_FFL_ARGS)
{
	TRANSFER *trf;
	K_ITEM *item;
	char *mvalue;
	regex_t re;
	size_t dlen;
	int ret;

	item = find_transfer(trf_root, name);
	if (!item) {
		LOGERR("%s(): failed, field '%s' missing from %s():%d",
			__func__, name, func, line);
		snprintf(reply, siz, "failed.missing %s", name);
		return NULL;
	}

	DATA_TRANSFER(trf, item);
	mvalue = trf->mvalue;
	if (mvalue)
		dlen = strlen(mvalue);
	else
		dlen = 0;
	if (!mvalue || (int)dlen < len) {
		LOGERR("%s(): failed, field '%s' short (%s%d<%d) from %s():%d",
			__func__, name, mvalue ? EMPTY : "null",
			(int)dlen, len, func, line);
		snprintf(reply, siz, "failed.short %s", name);
		return NULL;
	}

	if (patt) {
		if (regcomp(&re, patt, REG_NOSUB) != 0) {
			LOGERR("%s(): failed, field '%s' failed to"
				" compile patt from %s():%d",
				__func__, name, func, line);
			snprintf(reply, siz, "failed.REC %s", name);
			return NULL;
		}

		ret = regexec(&re, mvalue, (size_t)0, NULL, 0);
		regfree(&re);

		if (ret != 0) {
			LOGERR("%s(): failed, field '%s' invalid from %s():%d",
				__func__, name, func, line);
			snprintf(reply, siz, "failed.invalid %s", name);
			return NULL;
		}
	}

	return item;
}

static PGconn *dbconnect()
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

static int64_t nextid(PGconn *conn, char *idname, int64_t increment,
			tv_t *cd, char *by, char *code, char *inet)
{
	ExecStatusType rescode;
	bool conned = false;
	PGresult *res;
	char qry[1024];
	char *params[5];
	int n, par = 0;
	int64_t lastid;
	char *field;
	bool ok;

	lastid = 0;

	snprintf(qry, sizeof(qry), "select lastid from idcontrol "
				   "where idname='%s' for update",
				   idname);

	if (conn == NULL) {
		conn = dbconnect();
		conned = true;
	}

	res = PQexec(conn, qry, CKPQ_WRITE);
	rescode = PQresultStatus(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Select", rescode, conn);
		goto cleanup;
	}

	n = PQnfields(res);
	if (n != 1) {
		LOGERR("%s(): Invalid field count - should be %d, but is %d",
			__func__, 1, n);
		goto cleanup;
	}

	n = PQntuples(res);
	if (n < 1) {
		LOGERR("%s(): No matching idname='%s'", __func__, idname);
		goto cleanup;
	}

	ok = true;
	PQ_GET_FLD(res, 0, "lastid", field, ok);
	if (!ok)
		goto cleanup;
	TXT_TO_BIGINT("lastid", field, lastid);

	PQclear(res);

	lastid += increment;
	snprintf(qry, sizeof(qry), "update idcontrol set "
				   "lastid=$1, modifydate=$2, modifyby=$3, "
				   "modifycode=$4, modifyinet=$5 "
				   "where idname='%s'",
				   idname);

	par = 0;
	params[par++] = bigint_to_buf(lastid, NULL, 0);
	params[par++] = tv_to_buf(cd, NULL, 0);
	params[par++] = str_to_buf(by, NULL, 0);
	params[par++] = str_to_buf(code, NULL, 0);
	params[par++] = str_to_buf(inet, NULL, 0);
	PARCHK(par, params);

	res = PQexecParams(conn, qry, par, NULL, (const char **)params, NULL, NULL, 0, CKPQ_WRITE);
	rescode = PQresultStatus(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Update", rescode, conn);
		lastid = 0;
	}

	for (n = 0; n < par; n++)
		free(params[n]);
cleanup:
	PQclear(res);
	if (conned)
		PQfinish(conn);
	return lastid;
}

// order by userid asc,workername asc
static cmp_t cmp_workerstatus(K_ITEM *a, K_ITEM *b)
{
	WORKERSTATUS *wa, *wb;
	DATA_WORKERSTATUS(wa, a);
	DATA_WORKERSTATUS(wb, b);
	cmp_t c = CMP_BIGINT(wa->userid, wb->userid);
	if (c == 0)
		c = CMP_STR(wa->workername, wb->workername);
	return c;
}

/* TODO: replace a lot of the code for all data types that codes finds,
 *  each with specific functions for finding, to centralise the finds,
 *  with passed ctx's */
static K_ITEM *get_workerstatus(int64_t userid, char *workername)
{
	WORKERSTATUS workerstatus;
	K_TREE_CTX ctx[1];
	K_ITEM look, *find;

	workerstatus.userid = userid;
	STRNCPY(workerstatus.workername, workername);

	INIT_WORKERSTATUS(&look);
	look.data = (void *)(&workerstatus);
	K_RLOCK(workerstatus_free);
	find = find_in_ktree(workerstatus_root, &look, cmp_workerstatus, ctx);
	K_RUNLOCK(workerstatus_free);
	return find;
}

/* Worker loading/creation calls this with create = true
 * All others with create = false since the workerstatus should exist
 * Failure is a code bug and a reported error, but handled anyway
 * This has 2 sets of file/func/line to allow 2 levels of traceback
 */
static K_ITEM *_find_create_workerstatus(int64_t userid, char *workername,
					 bool create, const char *file2,
					 const char *func2, const int line2,
					 WHERE_FFL_ARGS)
{
	WORKERSTATUS *row;
	K_ITEM *item;

	item = get_workerstatus(userid, workername);
	if (!item) {
		if (!create) {
			LOGEMERG("%s(): Missing workerstatus %"PRId64"/%s"
				 WHERE_FFL WHERE_FFL,
				 __func__, userid, workername,
				 file2, func2, line2, WHERE_FFL_PASS);
			return NULL;
		}

		K_WLOCK(workerstatus_free);
		item = k_unlink_head(workerstatus_free);

		DATA_WORKERSTATUS(row, item);

		bzero(row, sizeof(*row));
		row->userid = userid;
		STRNCPY(row->workername, workername);

		workerstatus_root = add_to_ktree(workerstatus_root, item, cmp_workerstatus);
		k_add_head(workerstatus_store, item);
		K_WUNLOCK(workerstatus_free);
	}
	return item;
}

#define find_create_workerstatus(_u, _w, _file, _func, _line) \
	_find_create_workerstatus(_u, _w, true, _file, _func, _line, WHERE_FFL_HERE)
#define find_workerstatus(_u, _w, _file, _func, _line) \
	 _find_create_workerstatus(_u, _w, false, _file, _func, _line, WHERE_FFL_HERE)

static cmp_t cmp_userstats_workerstatus(K_ITEM *a, K_ITEM *b);
static cmp_t cmp_sharesummary(K_ITEM *a, K_ITEM *b);

static void zero_on_new_block()
{
	WORKERSTATUS *workerstatus;
	K_TREE_CTX ctx[1];
	K_ITEM *ws_item;

	K_WLOCK(workerstatus_free);
	pool.diffacc = pool.diffinv = pool.shareacc =
	pool.shareinv = pool.best_sdiff = 0;
	ws_item = first_in_ktree(workerstatus_root, ctx);
	while (ws_item) {
		DATA_WORKERSTATUS(workerstatus, ws_item);
		workerstatus->diffacc = workerstatus->diffinv =
		workerstatus->diffsta = workerstatus->diffdup =
		workerstatus->diffhi = workerstatus->diffrej =
		workerstatus->shareacc = workerstatus->shareinv =
		workerstatus->sharesta = workerstatus->sharedup =
		workerstatus->sharehi = workerstatus->sharerej = 0.0;
		ws_item = next_in_ktree(ctx);
	}
	K_WUNLOCK(workerstatus_free);

}

/* Currently only used at the end of the startup
 * Will need to add locking if it's used, later, after startup completes */
static void set_block_share_counters()
{
	K_TREE_CTX ctx[1];
	K_ITEM *ss_item, ss_look, *ws_item;
	WORKERSTATUS *workerstatus;
	SHARESUMMARY *sharesummary, looksharesummary;

	INIT_SHARESUMMARY(&ss_look);

	zero_on_new_block();

	ws_item = NULL;
	/* From the end backwards so we can skip the workinfoid's we don't
	 * want by jumping back to just before the current worker when the
	 * workinfoid goes below the limit */
	K_RLOCK(sharesummary_free);
	ss_item = last_in_ktree(sharesummary_root, ctx);
	while (ss_item) {
		DATA_SHARESUMMARY(sharesummary, ss_item);
		if (sharesummary->workinfoid < pool.workinfoid) {
			// Skip back to the next worker
			looksharesummary.userid = sharesummary->userid;
			STRNCPY(looksharesummary.workername,
				sharesummary->workername);
			looksharesummary.workinfoid = -1;
			ss_look.data = (void *)(&looksharesummary);
			ss_item = find_before_in_ktree(sharesummary_root, &ss_look,
							cmp_sharesummary, ctx);
			continue;
		}

		/* Check for user/workername change for new workerstatus
		 * The tree has user/workername grouped together in order
		 *  so this will only be once per user/workername */
		if (!ws_item ||
		    sharesummary->userid != workerstatus->userid ||
		    strcmp(sharesummary->workername, workerstatus->workername)) {
			/* This is to trigger a console error if it is missing
			 *  since it should always exist
			 * However, it is simplest to simply create it
			 *  and keep going */
			K_RUNLOCK(sharesummary_free);
			ws_item = find_workerstatus(sharesummary->userid,
						    sharesummary->workername,
						    __FILE__, __func__, __LINE__);
			if (!ws_item) {
				ws_item = find_create_workerstatus(sharesummary->userid,
								   sharesummary->workername,
								   __FILE__, __func__, __LINE__);
			}
			K_RLOCK(sharesummary_free);
			DATA_WORKERSTATUS(workerstatus, ws_item);
		}

		pool.diffacc += sharesummary->diffacc;
		pool.diffinv += sharesummary->diffsta + sharesummary->diffdup +
				sharesummary->diffhi + sharesummary->diffrej;
		workerstatus->diffacc += sharesummary->diffacc;
		workerstatus->diffinv += sharesummary->diffsta + sharesummary->diffdup +
					 sharesummary->diffhi + sharesummary->diffrej;
		workerstatus->diffsta += sharesummary->diffsta;
		workerstatus->diffdup += sharesummary->diffdup;
		workerstatus->diffhi += sharesummary->diffhi;
		workerstatus->diffrej += sharesummary->diffrej;
		workerstatus->shareacc += sharesummary->shareacc;
		workerstatus->shareinv += sharesummary->sharesta + sharesummary->sharedup +
					  sharesummary->sharehi + sharesummary->sharerej;
		workerstatus->sharesta += sharesummary->sharesta;
		workerstatus->sharedup += sharesummary->sharedup;
		workerstatus->sharehi += sharesummary->sharehi;
		workerstatus->sharerej += sharesummary->sharerej;

		ss_item = prev_in_ktree(ctx);
	}
	K_RUNLOCK(sharesummary_free);
}

/* All data is loaded, now update workerstatus fields
   TODO: combine set_block_share_counters() with this? */
static void workerstatus_ready()
{
	K_TREE_CTX ws_ctx[1], us_ctx[1], ss_ctx[1];
	K_ITEM *ws_item, us_look, ss_look, *us_item, *ss_item;
	USERSTATS lookuserstats, *userstats;
	SHARESUMMARY looksharesummary, *sharesummary;
	WORKERSTATUS *workerstatus;

	INIT_USERSTATS(&us_look);
	INIT_SHARESUMMARY(&ss_look);
	ws_item = first_in_ktree(workerstatus_root, ws_ctx);
	while (ws_item) {
		DATA_WORKERSTATUS(workerstatus, ws_item);
		lookuserstats.userid = workerstatus->userid;
		STRNCPY(lookuserstats.workername, workerstatus->workername);
		lookuserstats.statsdate.tv_sec = date_eot.tv_sec;
		lookuserstats.statsdate.tv_usec = date_eot.tv_usec;
		us_look.data = (void *)(&lookuserstats);
		us_item = find_before_in_ktree(userstats_workerstatus_root, &us_look,
						cmp_userstats_workerstatus, us_ctx);
		if (us_item) {
			DATA_USERSTATS(userstats, us_item);
			if (userstats->idle) {
				if (tv_newer(&(workerstatus->last_idle),
					     &(userstats->statsdate))) {
					copy_tv(&(workerstatus->last_idle),
						&(userstats->statsdate));
				}
			} else {
				if (tv_newer(&(workerstatus->last_stats),
					     &(userstats->statsdate))) {
					copy_tv(&(workerstatus->last_stats),
						&(userstats->statsdate));
				}
			}
		}

		looksharesummary.userid = workerstatus->userid;
		STRNCPY(looksharesummary.workername, workerstatus->workername);
		looksharesummary.workinfoid = MAXID;
		ss_look.data = (void *)(&looksharesummary);
		K_RLOCK(sharesummary_free);
		ss_item = find_before_in_ktree(sharesummary_root, &ss_look,
					       cmp_sharesummary, ss_ctx);
		K_RUNLOCK(sharesummary_free);
		if (ss_item) {
			DATA_SHARESUMMARY(sharesummary, ss_item);
			if (tv_newer(&(workerstatus->last_share),
				     &(sharesummary->lastshare))) {
				copy_tv(&(workerstatus->last_share),
					&(sharesummary->lastshare));
				workerstatus->last_diff =
					sharesummary->lastdiffacc;
			}
		}

		ws_item = next_in_ktree(ws_ctx);
	}
}

#define workerstatus_update(_auths, _shares, _userstats) \
	_workerstatus_update(_auths, _shares, _userstats, WHERE_FFL_HERE)

static void _workerstatus_update(AUTHS *auths, SHARES *shares,
				 USERSTATS *userstats, WHERE_FFL_ARGS)
{
	WORKERSTATUS *row;
	K_ITEM *item;

	if (auths) {
		item = find_workerstatus(auths->userid, auths->workername,
					 file, func, line);
		if (item) {
			DATA_WORKERSTATUS(row, item);
			if (tv_newer(&(row->last_auth), &(auths->createdate)))
				copy_tv(&(row->last_auth), &(auths->createdate));
		}
	}

	if (startup_complete && shares) {
		if (shares->errn == SE_NONE) {
			pool.diffacc += shares->diff;
			pool.shareacc++;
		} else {
			pool.diffinv += shares->diff;
			pool.shareinv++;
		}
		item = find_workerstatus(shares->userid, shares->workername,
					 file, func, line);
		if (item) {
			DATA_WORKERSTATUS(row, item);
			if (tv_newer(&(row->last_share), &(shares->createdate))) {
				copy_tv(&(row->last_share), &(shares->createdate));
				row->last_diff = shares->diff;
			}
			switch (shares->errn) {
				case SE_NONE:
					row->diffacc += shares->diff;
					row->shareacc++;
					break;
				case SE_STALE:
					row->diffinv += shares->diff;
					row->shareinv++;
					row->diffsta += shares->diff;
					row->sharesta++;
					break;
				case SE_DUPE:
					row->diffinv += shares->diff;
					row->shareinv++;
					row->diffdup += shares->diff;
					row->sharedup++;
					break;
				case SE_HIGH_DIFF:
					row->diffinv += shares->diff;
					row->shareinv++;
					row->diffhi += shares->diff;
					row->sharehi++;
					break;
				default:
					row->diffinv += shares->diff;
					row->shareinv++;
					row->diffrej += shares->diff;
					row->sharerej++;
					break;
			}
		}
	}

	if (startup_complete && userstats) {
		item = find_workerstatus(userstats->userid, userstats->workername,
					 file, func, line);
		if (item) {
			DATA_WORKERSTATUS(row, item);
			if (userstats->idle) {
				if (tv_newer(&(row->last_idle), &(userstats->statsdate)))
					copy_tv(&(row->last_idle), &(userstats->statsdate));
			} else {
				if (tv_newer(&(row->last_stats), &(userstats->statsdate)))
					copy_tv(&(row->last_stats), &(userstats->statsdate));
			}
		}
	}
}

// default tree order by username asc,expirydate desc
static cmp_t cmp_users(K_ITEM *a, K_ITEM *b)
{
	USERS *ua, *ub;
	DATA_USERS(ua, a);
	DATA_USERS(ub, b);
	cmp_t c = CMP_STR(ua->username, ub->username);
	if (c == 0)
		c = CMP_TV(ub->expirydate, ua->expirydate);
	return c;
}

// order by userid asc,expirydate desc
static cmp_t cmp_userid(K_ITEM *a, K_ITEM *b)
{
	USERS *ua, *ub;
	DATA_USERS(ua, a);
	DATA_USERS(ub, b);
	cmp_t c = CMP_BIGINT(ua->userid, ub->userid);
	if (c == 0)
		c = CMP_TV(ub->expirydate, ua->expirydate);
	return c;
}

// Must be R or W locked before call
static K_ITEM *find_users(char *username)
{
	USERS users;
	K_TREE_CTX ctx[1];
	K_ITEM look;

	STRNCPY(users.username, username);
	users.expirydate.tv_sec = default_expiry.tv_sec;
	users.expirydate.tv_usec = default_expiry.tv_usec;

	INIT_USERS(&look);
	look.data = (void *)(&users);
	return find_in_ktree(users_root, &look, cmp_users, ctx);
}

// Must be R or W locked before call
static K_ITEM *find_userid(int64_t userid)
{
	USERS users;
	K_TREE_CTX ctx[1];
	K_ITEM look;

	users.userid = userid;
	users.expirydate.tv_sec = default_expiry.tv_sec;
	users.expirydate.tv_usec = default_expiry.tv_usec;

	INIT_USERS(&look);
	look.data = (void *)(&users);
	return find_in_ktree(userid_root, &look, cmp_userid, ctx);
}

// TODO: endian? (to avoid being all zeros?)
static void make_salt(USERS *users)
{
	long int r1, r2, r3, r4;

	r1 = random();
	r2 = random();
	r3 = random();
	r4 = random();

	__bin2hex(users->salt, (void *)(&r1), 4);
	__bin2hex(users->salt+8, (void *)(&r2), 4);
	__bin2hex(users->salt+16, (void *)(&r3), 4);
	__bin2hex(users->salt+24, (void *)(&r4), 4);
}

static void password_hash(char *username, char *passwordhash, char *salt, char *result, size_t siz)
{
	char tohash[TXT_BIG+1];
	char buf[TXT_BIG+1];
	size_t len, tot;
	char why[1024];

	if (siz < SHA256SIZHEX+1) {
		snprintf(why, sizeof(why),
			 "target result too small (%d/%d)",
			 (int)siz, SHA256SIZHEX+1);
		goto hashfail;
	}

	if (sizeof(buf) < SHA256SIZBIN) {
		snprintf(why, sizeof(why),
			 "temporary target buf too small (%d/%d)",
			 (int)sizeof(buf), SHA256SIZBIN);
		goto hashfail;
	}

	tot = len = strlen(passwordhash) / 2;
	if (len != SHA256SIZBIN) {
		snprintf(why, sizeof(why),
			 "passwordhash wrong size (%d/%d)",
			 (int)len, SHA256SIZBIN);
		goto hashfail;
	}
	if (len > sizeof(tohash)) {
		snprintf(why, sizeof(why),
			 "temporary tohash too small (%d/%d)",
			 (int)sizeof(tohash), (int)len);
		goto hashfail;
	}

	hex2bin(tohash, passwordhash, len);

	len = strlen(salt) / 2;
	if (len != SALTSIZBIN) {
		snprintf(why, sizeof(why),
			 "salt wrong size (%d/%d)",
			 (int)len, SALTSIZBIN);
		goto hashfail;
	}
	if ((tot + len) > sizeof(tohash)) {
		snprintf(why, sizeof(why),
			 "passwordhash+salt too big (%d/%d)",
			 (int)(tot + len), (int)sizeof(tohash));
		goto hashfail;
	}

	hex2bin(tohash+tot, salt, len);
	tot += len;

	sha256((const unsigned char *)tohash, (unsigned int)tot, (unsigned char *)buf);

	__bin2hex(result, (void *)buf, SHA256SIZBIN);

	return;
hashfail:
	LOGERR("%s() Failed to hash '%s' password: %s",
		__func__, username, why);
	result[0] = '\0';
}

static bool check_hash(USERS *users, char *passwordhash)
{
	char hex[SHA256SIZHEX+1];

	if (*(users->salt)) {
		password_hash(users->username, passwordhash, users->salt, hex, sizeof(hex));
		return (strcasecmp(hex, users->passwordhash) == 0);
	} else
		return (strcasecmp(passwordhash, users->passwordhash) == 0);
}

static bool users_pass_email(PGconn *conn, K_ITEM *u_item, char *oldhash,
			     char *newhash, char *email, char *by, char *code,
			     char *inet, tv_t *cd, K_TREE *trf_root)
{
	ExecStatusType rescode;
	bool conned = false;
	K_TREE_CTX ctx[1];
	PGresult *res;
	K_ITEM *item;
	USERS *row, *users;
	char *upd, *ins;
	bool ok = false;
	char *params[5 + HISTORYDATECOUNT];
	bool hash;
	int n, par = 0;

	LOGDEBUG("%s(): change", __func__);

	if (oldhash != NULL)
		hash = true;
	else
		hash = false;

	DATA_USERS(users, u_item);
	// i.e. if oldhash == EMPTY, just overwrite with new
	if (hash && oldhash != EMPTY && !check_hash(users, oldhash))
		return false;

	K_WLOCK(users_free);
	item = k_unlink_head(users_free);
	K_WUNLOCK(users_free);

	DATA_USERS(row, item);
	memcpy(row, users, sizeof(*row));
	// Update one, leave the other
	if (hash) {
		// New salt each password change
		make_salt(row);
		password_hash(row->username, newhash, row->salt,
			      row->passwordhash, sizeof(row->passwordhash));
	} else
		STRNCPY(row->emailaddress, email);

	HISTORYDATEINIT(row, cd, by, code, inet);
	HISTORYDATETRANSFER(trf_root, row);

	upd = "update users set expirydate=$1 where userid=$2 and expirydate=$3";
	par = 0;
	params[par++] = tv_to_buf(cd, NULL, 0);
	params[par++] = bigint_to_buf(row->userid, NULL, 0);
	params[par++] = tv_to_buf((tv_t *)&default_expiry, NULL, 0);
	PARCHKVAL(par, 3, params);

	if (conn == NULL) {
		conn = dbconnect();
		conned = true;
	}

	// Beginning of a write txn
	res = PQexec(conn, "Begin", CKPQ_WRITE);
	rescode = PQresultStatus(res);
	PQclear(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Begin", rescode, conn);
		goto unparam;
	}

	res = PQexecParams(conn, upd, par, NULL, (const char **)params, NULL, NULL, 0, CKPQ_WRITE);
	rescode = PQresultStatus(res);
	PQclear(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Update", rescode, conn);
		goto rollback;
	}

	for (n = 0; n < par; n++)
		free(params[n]);

	par = 0;
	params[par++] = bigint_to_buf(row->userid, NULL, 0);
	params[par++] = tv_to_buf(cd, NULL, 0);
	// Copy them both in - one will be new and one will be old
	params[par++] = str_to_buf(row->emailaddress, NULL, 0);
	params[par++] = str_to_buf(row->passwordhash, NULL, 0);
	// New salt for each password change (or recopy old)
	params[par++] = str_to_buf(row->salt, NULL, 0);
	HISTORYDATEPARAMS(params, par, row);
	PARCHKVAL(par, 5 + HISTORYDATECOUNT, params); // 10 as per ins

	ins = "insert into users "
		"(userid,username,status,emailaddress,joineddate,"
		"passwordhash,secondaryuserid,salt"
		HISTORYDATECONTROL ") select "
		"userid,username,status,$3,joineddate,"
		"$4,secondaryuserid,$5,"
		"$6,$7,$8,$9,$10 from users where "
		"userid=$1 and expirydate=$2";

	res = PQexecParams(conn, ins, par, NULL, (const char **)params, NULL, NULL, 0, CKPQ_WRITE);
	rescode = PQresultStatus(res);
	PQclear(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Insert", rescode, conn);
		goto rollback;
	}

	ok = true;
rollback:
	if (ok)
		res = PQexec(conn, "Commit", CKPQ_WRITE);
	else
		res = PQexec(conn, "Rollback", CKPQ_WRITE);

	PQclear(res);
unparam:
	if (conned)
		PQfinish(conn);
	for (n = 0; n < par; n++)
		free(params[n]);

	K_WLOCK(users_free);
	if (!ok)
		k_add_head(users_free, item);
	else {
		users_root = remove_from_ktree(users_root, u_item, cmp_users, ctx);
		userid_root = remove_from_ktree(userid_root, u_item, cmp_userid, ctx);
		copy_tv(&(users->expirydate), cd);
		users_root = add_to_ktree(users_root, u_item, cmp_users);
		userid_root = add_to_ktree(userid_root, u_item, cmp_userid);

		users_root = add_to_ktree(users_root, item, cmp_users);
		userid_root = add_to_ktree(userid_root, item, cmp_userid);
		k_add_head(users_store, item);
	}
	K_WUNLOCK(users_free);

	return ok;
}

static K_ITEM *users_add(PGconn *conn, char *username, char *emailaddress,
			char *passwordhash, char *by, char *code, char *inet,
			tv_t *cd, K_TREE *trf_root)
{
	ExecStatusType rescode;
	bool conned = false;
	PGresult *res;
	K_ITEM *item;
	USERS *row;
	char *ins;
	char tohash[64];
	uint64_t hash;
	__maybe_unused uint64_t tmp;
	bool ok = false;
	char *params[8 + HISTORYDATECOUNT];
	int n, par = 0;

	LOGDEBUG("%s(): add", __func__);

	K_WLOCK(users_free);
	item = k_unlink_head(users_free);
	K_WUNLOCK(users_free);

	DATA_USERS(row, item);

	row->userid = nextid(conn, "userid", (int64_t)(666 + (random() % 334)),
				cd, by, code, inet);
	if (row->userid == 0)
		goto unitem;

	// TODO: pre-check the username exists? (to save finding out via a DB error)

	STRNCPY(row->username, username);
	row->status[0] = '\0';
	STRNCPY(row->emailaddress, emailaddress);

	snprintf(tohash, sizeof(tohash), "%s&#%s", username, emailaddress);
	HASH_BER(tohash, strlen(tohash), 1, hash, tmp);
	__bin2hex(row->secondaryuserid, (void *)(&hash), sizeof(hash));

	make_salt(row);
	if (passwordhash == EMPTY) {
		// Make it impossible to login for a BTC Address username
		row->passwordhash[0] = '\0';
	} else {
		password_hash(row->username, passwordhash, row->salt,
			      row->passwordhash, sizeof(row->passwordhash));
	}

	HISTORYDATEINIT(row, cd, by, code, inet);
	HISTORYDATETRANSFER(trf_root, row);

	// copy createdate
	row->joineddate.tv_sec = row->createdate.tv_sec;
	row->joineddate.tv_usec = row->createdate.tv_usec;

	par = 0;
	params[par++] = bigint_to_buf(row->userid, NULL, 0);
	params[par++] = str_to_buf(row->username, NULL, 0);
	params[par++] = str_to_buf(row->status, NULL, 0);
	params[par++] = str_to_buf(row->emailaddress, NULL, 0);
	params[par++] = tv_to_buf(&(row->joineddate), NULL, 0);
	params[par++] = str_to_buf(row->passwordhash, NULL, 0);
	params[par++] = str_to_buf(row->secondaryuserid, NULL, 0);
	params[par++] = str_to_buf(row->salt, NULL, 0);
	HISTORYDATEPARAMS(params, par, row);
	PARCHK(par, params);

	ins = "insert into users "
		"(userid,username,status,emailaddress,joineddate,passwordhash,"
		"secondaryuserid,salt"
		HISTORYDATECONTROL ") values (" PQPARAM13 ")";

	if (!conn) {
		conn = dbconnect();
		conned = true;
	}

	res = PQexecParams(conn, ins, par, NULL, (const char **)params, NULL, NULL, 0, CKPQ_WRITE);
	rescode = PQresultStatus(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Insert", rescode, conn);
		goto unparam;
	}

	ok = true;
unparam:
	PQclear(res);
	if (conned)
		PQfinish(conn);
	for (n = 0; n < par; n++)
		free(params[n]);
unitem:
	K_WLOCK(users_free);
	if (!ok)
		k_add_head(users_free, item);
	else {
		users_root = add_to_ktree(users_root, item, cmp_users);
		userid_root = add_to_ktree(userid_root, item, cmp_userid);
		k_add_head(users_store, item);
	}
	K_WUNLOCK(users_free);

	if (ok)
		return item;
	else
		return NULL;
}

static bool users_fill(PGconn *conn)
{
	ExecStatusType rescode;
	PGresult *res;
	K_ITEM *item;
	int n, i;
	USERS *row;
	char *field;
	char *sel;
	int fields = 8;
	bool ok;

	LOGDEBUG("%s(): select", __func__);

	sel = "select "
		"userid,username,status,emailaddress,joineddate,"
		"passwordhash,secondaryuserid,salt"
		HISTORYDATECONTROL
		" from users";
	res = PQexec(conn, sel, CKPQ_READ);
	rescode = PQresultStatus(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Select", rescode, conn);
		PQclear(res);
		return false;
	}

	n = PQnfields(res);
	if (n != (fields + HISTORYDATECOUNT)) {
		LOGERR("%s(): Invalid field count - should be %d, but is %d",
			__func__, fields + HISTORYDATECOUNT, n);
		PQclear(res);
		return false;
	}

	n = PQntuples(res);
	LOGDEBUG("%s(): tree build count %d", __func__, n);
	ok = true;
	K_WLOCK(users_free);
	for (i = 0; i < n; i++) {
		item = k_unlink_head(users_free);
		DATA_USERS(row, item);

		if (everyone_die) {
			ok = false;
			break;
		}

		PQ_GET_FLD(res, i, "userid", field, ok);
		if (!ok)
			break;
		TXT_TO_BIGINT("userid", field, row->userid);

		PQ_GET_FLD(res, i, "username", field, ok);
		if (!ok)
			break;
		TXT_TO_STR("username", field, row->username);

		PQ_GET_FLD(res, i, "status", field, ok);
		if (!ok)
			break;
		TXT_TO_STR("status", field, row->status);

		PQ_GET_FLD(res, i, "emailaddress", field, ok);
		if (!ok)
			break;
		TXT_TO_STR("emailaddress", field, row->emailaddress);

		PQ_GET_FLD(res, i, "joineddate", field, ok);
		if (!ok)
			break;
		TXT_TO_TV("joineddate", field, row->joineddate);

		PQ_GET_FLD(res, i, "passwordhash", field, ok);
		if (!ok)
			break;
		TXT_TO_STR("passwordhash", field, row->passwordhash);

		PQ_GET_FLD(res, i, "secondaryuserid", field, ok);
		if (!ok)
			break;
		TXT_TO_STR("secondaryuserid", field, row->secondaryuserid);

		PQ_GET_FLD(res, i, "salt", field, ok);
		if (!ok)
			break;
		TXT_TO_STR("salt", field, row->salt);

		HISTORYDATEFLDS(res, i, row, ok);
		if (!ok)
			break;

		users_root = add_to_ktree(users_root, item, cmp_users);
		userid_root = add_to_ktree(userid_root, item, cmp_userid);
		k_add_head(users_store, item);
	}
	if (!ok)
		k_add_head(users_free, item);

	K_WUNLOCK(users_free);
	PQclear(res);

	if (ok) {
		LOGDEBUG("%s(): built", __func__);
		LOGWARNING("%s(): loaded %d users records", __func__, n);
	}

	return ok;
}

void users_reload()
{
	PGconn *conn = dbconnect();

	K_WLOCK(users_free);
	users_root = free_ktree(users_root, NULL);
	userid_root = free_ktree(userid_root, NULL);
	k_list_transfer_to_head(users_store, users_free);
	K_WUNLOCK(users_free);

	users_fill(conn);

	PQfinish(conn);
}

// default tree order by userid asc,attname asc,expirydate desc
static cmp_t cmp_useratts(K_ITEM *a, K_ITEM *b)
{
	USERATTS *ua, *ub;
	DATA_USERATTS(ua, a);
	DATA_USERATTS(ub, b);
	cmp_t c = CMP_BIGINT(ua->userid, ub->userid);
	if (c == 0) {
		c = CMP_STR(ua->attname, ub->attname);
		if (c == 0)
			c = CMP_TV(ub->expirydate, ua->expirydate);
	}
	return c;
}

// Must be R or W locked before call
static K_ITEM *find_useratts(int64_t userid, char *attname)
{
	USERATTS useratts;
	K_TREE_CTX ctx[1];
	K_ITEM look;

	useratts.userid = userid;
	STRNCPY(useratts.attname, attname);
	useratts.expirydate.tv_sec = default_expiry.tv_sec;
	useratts.expirydate.tv_usec = default_expiry.tv_usec;

	INIT_USERATTS(&look);
	look.data = (void *)(&useratts);
	return find_in_ktree(useratts_root, &look, cmp_useratts, ctx);
}

static bool useratts_item_add(PGconn *conn, K_ITEM *ua_item, tv_t *cd, bool begun)
{
	ExecStatusType rescode;
	bool conned = false;
	K_TREE_CTX ctx[1];
	PGresult *res;
	K_ITEM *old_item;
	USERATTS *old_useratts, *useratts;
	char *upd, *ins;
	bool ok = false;
	char *params[9 + HISTORYDATECOUNT];
	int n, par = 0;

	LOGDEBUG("%s(): add", __func__);

	DATA_USERATTS(useratts, ua_item);

	K_RLOCK(useratts_free);
	old_item = find_useratts(useratts->userid, useratts->attname);
	K_RUNLOCK(useratts_free);
	DATA_USERATTS_NULL(old_useratts, old_item);

	/* N.B. the values of the old ua_item record, if it exists,
	 * are completely ignored i.e. you must provide all values required */

	if (!conn) {
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
			goto unparam;
		}
	}

	if (old_item) {
		upd = "update useratts set expirydate=$1 where userid=$2 and "
			"attname=$3 and expirydate=$4";
		par = 0;
		params[par++] = tv_to_buf(cd, NULL, 0);
		params[par++] = bigint_to_buf(old_useratts->userid, NULL, 0);
		params[par++] = str_to_buf(old_useratts->attname, NULL, 0);
		params[par++] = tv_to_buf((tv_t *)&default_expiry, NULL, 0);
		PARCHKVAL(par, 4, params);

		res = PQexecParams(conn, upd, par, NULL, (const char **)params, NULL, NULL, 0, CKPQ_WRITE);
		rescode = PQresultStatus(res);
		PQclear(res);
		if (!PGOK(rescode)) {
			PGLOGERR("Update", rescode, conn);
			goto unparam;
		}

		for (n = 0; n < par; n++)
			free(params[n]);
	}

	par = 0;
	params[par++] = bigint_to_buf(useratts->userid, NULL, 0);
	params[par++] = str_to_buf(useratts->attname, NULL, 0);
	params[par++] = str_to_buf(useratts->status, NULL, 0);
	params[par++] = str_to_buf(useratts->attstr, NULL, 0);
	params[par++] = str_to_buf(useratts->attstr2, NULL, 0);
	params[par++] = bigint_to_buf(useratts->attnum, NULL, 0);
	params[par++] = bigint_to_buf(useratts->attnum2, NULL, 0);
	params[par++] = tv_to_buf(&(useratts->attdate), NULL, 0);
	params[par++] = tv_to_buf(&(useratts->attdate2), NULL, 0);
	HISTORYDATEPARAMS(params, par, useratts);
	PARCHK(par, params);

	ins = "insert into useratts "
		"(userid,attname,status,attstr,attstr2,attnum,attnum2,"
		"attdate,attdate2"
		HISTORYDATECONTROL ") values (" PQPARAM14 ")";

	res = PQexecParams(conn, ins, par, NULL, (const char **)params, NULL, NULL, 0, CKPQ_WRITE);
	rescode = PQresultStatus(res);
	PQclear(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Insert", rescode, conn);
		goto rollback;
	}

	ok = true;
rollback:
	if (!begun) {
		if (ok)
			res = PQexec(conn, "Commit", CKPQ_WRITE);
		else
			res = PQexec(conn, "Rollback", CKPQ_WRITE);

		PQclear(res);
	}
unparam:
	if (conned)
		PQfinish(conn);
	for (n = 0; n < par; n++)
		free(params[n]);

	K_WLOCK(useratts_free);
	if (ok) {
		// Update it
		if (old_item) {
			useratts_root = remove_from_ktree(useratts_root, old_item, cmp_useratts, ctx);
			copy_tv(&(old_useratts->expirydate), cd);
			useratts_root = add_to_ktree(useratts_root, old_item, cmp_useratts);
		}
		useratts_root = add_to_ktree(useratts_root, ua_item, cmp_useratts);
		k_add_head(useratts_store, ua_item);
	}
	K_WUNLOCK(useratts_free);

	return ok;
}

static __maybe_unused K_ITEM *useratts_add(PGconn *conn, char *username, char *attname,
				char *status, char *attstr, char *attstr2,
				char *attnum, char *attnum2,  char *attdate,
				char *attdate2, char *by, char *code,
				char *inet, tv_t *cd, K_TREE *trf_root,
				bool begun)
{
	K_ITEM *item, *u_item;
	USERATTS *row;
	USERS *users;
	bool ok = false;

	LOGDEBUG("%s(): add", __func__);

	K_WLOCK(useratts_free);
	item = k_unlink_head(useratts_free);
	K_WUNLOCK(useratts_free);
	DATA_USERATTS(row, item);

	K_RLOCK(users_free);
	u_item = find_users(username);
	K_RUNLOCK(users_free);
	if (!u_item)
		goto unitem;
	DATA_USERS(users, u_item);

	row->userid = users->userid;
	STRNCPY(row->attname, attname);
	if (status == NULL)
		row->status[0] = '\0';
	else
		STRNCPY(row->status, status);
	if (attstr == NULL)
		row->attstr[0] = '\0';
	else
		STRNCPY(row->attstr, attstr);
	if (attstr2 == NULL)
		row->attstr2[0] = '\0';
	else
		STRNCPY(row->attstr2, attstr2);
	if (attnum == NULL || attnum[0] == '\0')
		row->attnum = 0;
	else
		TXT_TO_BIGINT("attnum", attnum, row->attnum);
	if (attnum2 == NULL || attnum2[0] == '\0')
		row->attnum2 = 0;
	else
		TXT_TO_BIGINT("attnum2", attnum2, row->attnum2);
	if (attdate == NULL || attdate[0] == '\0')
		row->attdate.tv_sec = row->attdate.tv_usec = 0L;
	else
		TXT_TO_TV("attdate", attdate, row->attdate);
	if (attdate2 == NULL || attdate2[0] == '\0')
		row->attdate2.tv_sec = row->attdate2.tv_usec = 0L;
	else
		TXT_TO_TV("attdate2", attdate2, row->attdate2);

	HISTORYDATEINIT(row, cd, by, code, inet);
	HISTORYDATETRANSFER(trf_root, row);

	ok = useratts_item_add(conn, item, cd, begun);
unitem:
	if (!ok) {
		K_WLOCK(useratts_free);
		k_add_head(useratts_free, item);
		K_WUNLOCK(useratts_free);
	}

	if (ok)
		return item;
	else
		return NULL;
}

static bool useratts_item_expire(PGconn *conn, K_ITEM *ua_item, tv_t *cd)
{
	ExecStatusType rescode;
	bool conned = false;
	K_TREE_CTX ctx[1];
	PGresult *res;
	K_ITEM *item;
	USERATTS *useratts;
	char *upd;
	bool ok = false;
	char *params[4 + HISTORYDATECOUNT];
	int n, par = 0;

	LOGDEBUG("%s(): add", __func__);

	DATA_USERATTS(useratts, ua_item);

	/* This is pointless if ua_item is part of the tree, however,
	 * it allows for if ua_item isn't already part of the tree */
	K_RLOCK(useratts_free);
	item = find_useratts(useratts->userid, useratts->attname);
	K_RUNLOCK(useratts_free);

	if (item) {
		DATA_USERATTS(useratts, item);

		if (!conn) {
			conn = dbconnect();
			conned = true;
		}

		upd = "update useratts set expirydate=$1 where userid=$2 and "
			"attname=$3 and expirydate=$4";
		par = 0;
		params[par++] = tv_to_buf(cd, NULL, 0);
		params[par++] = bigint_to_buf(useratts->userid, NULL, 0);
		params[par++] = str_to_buf(useratts->attname, NULL, 0);
		params[par++] = tv_to_buf((tv_t *)&default_expiry, NULL, 0);
		PARCHKVAL(par, 4, params);

		res = PQexecParams(conn, upd, par, NULL, (const char **)params, NULL, NULL, 0, CKPQ_WRITE);
		rescode = PQresultStatus(res);
		if (!PGOK(rescode)) {
			PGLOGERR("Update", rescode, conn);
			goto unparam;
		}
	}
	ok = true;
unparam:
	if (par) {
		PQclear(res);
		if (conned)
			PQfinish(conn);
		for (n = 0; n < par; n++)
			free(params[n]);
	}

	K_WLOCK(useratts_free);
	if (ok && item) {
		useratts_root = remove_from_ktree(useratts_root, item, cmp_useratts, ctx);
		copy_tv(&(useratts->expirydate), cd);
		useratts_root = add_to_ktree(useratts_root, item, cmp_useratts);
	}
	K_WUNLOCK(useratts_free);

	return ok;
}

static bool useratts_fill(PGconn *conn)
{
	ExecStatusType rescode;
	PGresult *res;
	K_ITEM *item;
	int n, i;
	USERATTS *row;
	char *field;
	char *sel;
	int fields = 9;
	bool ok;

	LOGDEBUG("%s(): select", __func__);

	sel = "select "
		"userid,attname,status,attstr,attstr2,attnum,attnum2"
		",attdate,attdate2"
		HISTORYDATECONTROL
		" from useratts";
	res = PQexec(conn, sel, CKPQ_READ);
	rescode = PQresultStatus(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Select", rescode, conn);
		PQclear(res);
		return false;
	}

	n = PQnfields(res);
	if (n != (fields + HISTORYDATECOUNT)) {
		LOGERR("%s(): Invalid field count - should be %d, but is %d",
			__func__, fields + HISTORYDATECOUNT, n);
		PQclear(res);
		return false;
	}

	n = PQntuples(res);
	LOGDEBUG("%s(): tree build count %d", __func__, n);
	ok = true;
	K_WLOCK(useratts_free);
	for (i = 0; i < n; i++) {
		item = k_unlink_head(useratts_free);
		DATA_USERATTS(row, item);

		if (everyone_die) {
			ok = false;
			break;
		}

		PQ_GET_FLD(res, i, "userid", field, ok);
		if (!ok)
			break;
		TXT_TO_BIGINT("userid", field, row->userid);

		PQ_GET_FLD(res, i, "attname", field, ok);
		if (!ok)
			break;
		TXT_TO_STR("attname", field, row->attname);

		PQ_GET_FLD(res, i, "status", field, ok);
		if (!ok)
			break;
		TXT_TO_STR("status", field, row->status);

		PQ_GET_FLD(res, i, "attstr", field, ok);
		if (!ok)
			break;
		TXT_TO_STR("attstr", field, row->attstr);

		PQ_GET_FLD(res, i, "attstr2", field, ok);
		if (!ok)
			break;
		TXT_TO_STR("attstr2", field, row->attstr2);

		PQ_GET_FLD(res, i, "attnum", field, ok);
		if (!ok)
			break;
		TXT_TO_BIGINT("attnum", field, row->attnum);

		PQ_GET_FLD(res, i, "attnum2", field, ok);
		if (!ok)
			break;
		TXT_TO_BIGINT("attnum2", field, row->attnum2);

		PQ_GET_FLD(res, i, "attdate", field, ok);
		if (!ok)
			break;
		TXT_TO_TV("attdate", field, row->attdate);

		PQ_GET_FLD(res, i, "attdate2", field, ok);
		if (!ok)
			break;
		TXT_TO_TV("attdate2", field, row->attdate2);

		HISTORYDATEFLDS(res, i, row, ok);
		if (!ok)
			break;

		useratts_root = add_to_ktree(useratts_root, item, cmp_useratts);
		k_add_head(useratts_store, item);
	}
	if (!ok)
		k_add_head(useratts_free, item);

	K_WUNLOCK(useratts_free);
	PQclear(res);

	if (ok) {
		LOGDEBUG("%s(): built", __func__);
		LOGWARNING("%s(): loaded %d useratts records", __func__, n);
	}

	return ok;
}

void useratts_reload()
{
	PGconn *conn = dbconnect();

	K_WLOCK(useratts_free);
	useratts_root = free_ktree(useratts_root, NULL);
	k_list_transfer_to_head(useratts_store, useratts_free);
	K_WUNLOCK(useratts_free);

	useratts_fill(conn);

	PQfinish(conn);
}

// order by userid asc,workername asc,expirydate desc
static cmp_t cmp_workers(K_ITEM *a, K_ITEM *b)
{
	WORKERS *wa, *wb;
	DATA_WORKERS(wa, a);
	DATA_WORKERS(wb, b);
	cmp_t c = CMP_BIGINT(wa->userid, wb->userid);
	if (c == 0) {
		c = CMP_STR(wa->workername, wb->workername);
		if (c == 0)
			c = CMP_TV(wb->expirydate, wa->expirydate);
	}
	return c;
}

static K_ITEM *find_workers(int64_t userid, char *workername)
{
	WORKERS workers;
	K_TREE_CTX ctx[1];
	K_ITEM look;

	workers.userid = userid;
	STRNCPY(workers.workername, workername);
	workers.expirydate.tv_sec = default_expiry.tv_sec;
	workers.expirydate.tv_usec = default_expiry.tv_usec;

	INIT_WORKERS(&look);
	look.data = (void *)(&workers);
	return find_in_ktree(workers_root, &look, cmp_workers, ctx);
}

static K_ITEM *workers_add(PGconn *conn, int64_t userid, char *workername,
			   char *difficultydefault, char *idlenotificationenabled,
			   char *idlenotificationtime, char *by,
			   char *code, char *inet, tv_t *cd, K_TREE *trf_root)
{
	ExecStatusType rescode;
	bool conned = false;
	PGresult *res;
	K_ITEM *item, *ret = NULL;
	WORKERS *row;
	char *ins;
	char *params[6 + HISTORYDATECOUNT];
	int n, par = 0;
	int32_t diffdef;
	int32_t nottime;

	LOGDEBUG("%s(): add", __func__);

	K_WLOCK(workers_free);
	item = k_unlink_head(workers_free);
	K_WUNLOCK(workers_free);

	DATA_WORKERS(row, item);

	if (conn == NULL) {
		conn = dbconnect();
		conned = true;
	}

	row->workerid = nextid(conn, "workerid", (int64_t)1, cd, by, code, inet);
	if (row->workerid == 0)
		goto unitem;

	row->userid = userid;
	STRNCPY(row->workername, workername);
	if (difficultydefault && *difficultydefault) {
		diffdef = atoi(difficultydefault);
		if (diffdef < DIFFICULTYDEFAULT_MIN)
			diffdef = DIFFICULTYDEFAULT_MIN;
		if (diffdef > DIFFICULTYDEFAULT_MAX)
			diffdef = DIFFICULTYDEFAULT_MAX;
		row->difficultydefault = diffdef;
	} else
		row->difficultydefault = DIFFICULTYDEFAULT_DEF;

	row->idlenotificationenabled[1] = '\0';
	if (idlenotificationenabled && *idlenotificationenabled) {
		if (tolower(*idlenotificationenabled) == IDLENOTIFICATIONENABLED[0])
			row->idlenotificationenabled[0] = IDLENOTIFICATIONENABLED[0];
		else
			row->idlenotificationenabled[0] = IDLENOTIFICATIONDISABLED[0];
	} else
		row->idlenotificationenabled[0] = IDLENOTIFICATIONENABLED_DEF[0];

	if (idlenotificationtime && *idlenotificationtime) {
		nottime = atoi(idlenotificationtime);
		if (nottime < DIFFICULTYDEFAULT_MIN) {
			row->idlenotificationenabled[0] = IDLENOTIFICATIONDISABLED[0];
			nottime = DIFFICULTYDEFAULT_MIN;
		} else if (nottime > IDLENOTIFICATIONTIME_MAX)
			nottime = row->idlenotificationtime;
		row->idlenotificationtime = nottime;
	} else
		row->idlenotificationtime = IDLENOTIFICATIONTIME_DEF;

	HISTORYDATEINIT(row, cd, by, code, inet);
	HISTORYDATETRANSFER(trf_root, row);

	par = 0;
	params[par++] = bigint_to_buf(row->workerid, NULL, 0);
	params[par++] = bigint_to_buf(row->userid, NULL, 0);
	params[par++] = str_to_buf(row->workername, NULL, 0);
	params[par++] = int_to_buf(row->difficultydefault, NULL, 0);
	params[par++] = str_to_buf(row->idlenotificationenabled, NULL, 0);
	params[par++] = int_to_buf(row->idlenotificationtime, NULL, 0);
	HISTORYDATEPARAMS(params, par, row);
	PARCHK(par, params);

	ins = "insert into workers "
		"(workerid,userid,workername,difficultydefault,"
		"idlenotificationenabled,idlenotificationtime"
		HISTORYDATECONTROL ") values (" PQPARAM11 ")";

	res = PQexecParams(conn, ins, par, NULL, (const char **)params, NULL, NULL, 0, CKPQ_WRITE);
	rescode = PQresultStatus(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Insert", rescode, conn);
		goto unparam;
	}

	ret = item;
unparam:
	PQclear(res);
	for (n = 0; n < par; n++)
		free(params[n]);
unitem:
	if (conned)
		PQfinish(conn);
	K_WLOCK(workers_free);
	if (!ret)
		k_add_head(workers_free, item);
	else {
		workers_root = add_to_ktree(workers_root, item, cmp_workers);
		k_add_head(workers_store, item);
		// Ensure there is a matching workerstatus
		find_create_workerstatus(userid, workername,
					 __FILE__, __func__, __LINE__);
	}
	K_WUNLOCK(workers_free);

	return ret;
}

static bool workers_update(PGconn *conn, K_ITEM *item, char *difficultydefault,
			   char *idlenotificationenabled, char *idlenotificationtime,
			   char *by, char *code, char *inet, tv_t *cd, K_TREE *trf_root)
{
	ExecStatusType rescode;
	bool conned = false;
	PGresult *res;
	WORKERS *row;
	char *upd, *ins;
	bool ok = false;
	char *params[6 + HISTORYDATECOUNT];
	int n, par = 0;
	int32_t diffdef;
	char idlenot;
	int32_t nottime;

	LOGDEBUG("%s(): update", __func__);

	DATA_WORKERS(row, item);

	if (difficultydefault && *difficultydefault) {
		diffdef = atoi(difficultydefault);
		if (diffdef < DIFFICULTYDEFAULT_MIN)
			diffdef = row->difficultydefault;
		if (diffdef > DIFFICULTYDEFAULT_MAX)
			diffdef = row->difficultydefault;
	} else
		diffdef = row->difficultydefault;

	if (idlenotificationenabled && *idlenotificationenabled) {
		if (tolower(*idlenotificationenabled) == IDLENOTIFICATIONENABLED[0])
			idlenot = IDLENOTIFICATIONENABLED[0];
		else
			idlenot = IDLENOTIFICATIONDISABLED[0];
	} else
		idlenot = row->idlenotificationenabled[0];

	if (idlenotificationtime && *idlenotificationtime) {
		nottime = atoi(idlenotificationtime);
		if (nottime < IDLENOTIFICATIONTIME_MIN)
			nottime = row->idlenotificationtime;
		if (nottime > IDLENOTIFICATIONTIME_MAX)
			nottime = row->idlenotificationtime;
	} else
		nottime = row->idlenotificationtime;

	HISTORYDATEINIT(row, cd, by, code, inet);
	HISTORYDATETRANSFER(trf_root, row);

	if (diffdef == row->difficultydefault &&
	    idlenot == row->idlenotificationenabled[0] &&
	    nottime == row->idlenotificationtime) {
		ok = true;
		goto early;
	}

	upd = "update workers set expirydate=$1 where workerid=$2 and expirydate=$3";
	par = 0;
	params[par++] = tv_to_buf(cd, NULL, 0);
	params[par++] = bigint_to_buf(row->workerid, NULL, 0);
	params[par++] = tv_to_buf((tv_t *)&default_expiry, NULL, 0);
	PARCHKVAL(par, 3, params);

	if (conn == NULL) {
		conn = dbconnect();
		conned = true;
	}

	res = PQexec(conn, "Begin", CKPQ_WRITE);
	rescode = PQresultStatus(res);
	PQclear(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Begin", rescode, conn);
		goto unparam;
	}

	res = PQexecParams(conn, upd, par, NULL, (const char **)params, NULL, NULL, 0, CKPQ_WRITE);
	rescode = PQresultStatus(res);
	PQclear(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Update", rescode, conn);
		goto rollback;
	}

	for (n = 0; n < par; n++)
		free(params[n]);

	ins = "insert into workers "
		"(workerid,userid,workername,difficultydefault,"
		"idlenotificationenabled,idlenotificationtime"
		HISTORYDATECONTROL ") values (" PQPARAM11 ")";

	row->difficultydefault = diffdef;
	row->idlenotificationenabled[0] = idlenot;
	row->idlenotificationenabled[1] = '\0';
	row->idlenotificationtime = nottime;

	par = 0;
	params[par++] = bigint_to_buf(row->workerid, NULL, 0);
	params[par++] = bigint_to_buf(row->userid, NULL, 0);
	params[par++] = str_to_buf(row->workername, NULL, 0);
	params[par++] = int_to_buf(row->difficultydefault, NULL, 0);
	params[par++] = str_to_buf(row->idlenotificationenabled, NULL, 0);
	params[par++] = int_to_buf(row->idlenotificationtime, NULL, 0);
	HISTORYDATEPARAMS(params, par, row);
	PARCHK(par, params);

	res = PQexecParams(conn, ins, par, NULL, (const char **)params, NULL, NULL, 0, CKPQ_WRITE);
	rescode = PQresultStatus(res);
	PQclear(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Insert", rescode, conn);
		goto rollback;
	}

	ok = true;
rollback:
	if (ok)
		res = PQexec(conn, "Commit", CKPQ_WRITE);
	else
		res = PQexec(conn, "Rollback", CKPQ_WRITE);

	PQclear(res);
unparam:
	if (conned)
		PQfinish(conn);
	for (n = 0; n < par; n++)
		free(params[n]);
early:
	return ok;
}

static K_ITEM *new_worker(PGconn *conn, bool update, int64_t userid, char *workername,
			  char *diffdef, char *idlenotificationenabled,
			  char *idlenotificationtime, char *by,
			  char *code, char *inet, tv_t *cd, K_TREE *trf_root)
{
	K_ITEM *item;

	item = find_workers(userid, workername);
	if (item) {
		if (!confirm_sharesummary && update) {
			workers_update(conn, item, diffdef, idlenotificationenabled,
				       idlenotificationtime, by, code, inet, cd,
					trf_root);
		}
	} else {
		if (confirm_sharesummary) {
			// Shouldn't be possible since the sharesummary is already aged
			LOGERR("%s() %"PRId64"/%s workername not found during confirm",
				__func__, userid, workername);
			return NULL;
		}

		// TODO: limit how many?
		item = workers_add(conn, userid, workername, diffdef,
				   idlenotificationenabled, idlenotificationtime,
				   by, code, inet, cd, trf_root);
	}
	return item;
}

static K_ITEM *new_default_worker(PGconn *conn, bool update, int64_t userid, char *workername,
			  char *by, char *code, char *inet, tv_t *cd, K_TREE *trf_root)
{
	return new_worker(conn, update, userid, workername, DIFFICULTYDEFAULT_DEF_STR,
			  IDLENOTIFICATIONENABLED_DEF, IDLENOTIFICATIONTIME_DEF_STR,
			  by, code, inet, cd, trf_root);
}

/* unused
static K_ITEM *new_worker_find_user(PGconn *conn, bool update, char *username,
				    char *workername, char *diffdef,
				    char *idlenotificationenabled,
				    char *idlenotificationtime,
				    char *by, char *code, char *inet,
				    tv_t *cd, K_TREE *trf_root)
{
	K_ITEM *item;
	USERS *users;

	K_RLOCK(users_free);
	item = find_users(username);
	K_RUNLOCK(users_free);
	if (!item)
		return NULL;

	DATA_USERS(users, item);
	return new_worker(conn, update, users->userid, workername, diffdef,
			  idlenotificationenabled, idlenotificationtime,
			  by, code, inet, cd, trf_root);
}
*/

static bool workers_fill(PGconn *conn)
{
	ExecStatusType rescode;
	PGresult *res;
	K_ITEM *item;
	int n, i;
	WORKERS *row;
	char *field;
	char *sel;
	int fields = 6;
	bool ok;

	LOGDEBUG("%s(): select", __func__);

	sel = "select "
		"userid,workername,difficultydefault,"
		"idlenotificationenabled,idlenotificationtime"
		HISTORYDATECONTROL
		",workerid from workers";
	res = PQexec(conn, sel, CKPQ_READ);
	rescode = PQresultStatus(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Select", rescode, conn);
		PQclear(res);
		return false;
	}

	n = PQnfields(res);
	if (n != (fields + HISTORYDATECOUNT)) {
		LOGERR("%s(): Invalid field count - should be %d, but is %d",
			__func__, fields + HISTORYDATECOUNT, n);
		PQclear(res);
		return false;
	}

	n = PQntuples(res);
	LOGDEBUG("%s(): tree build count %d", __func__, n);
	ok = true;
	K_WLOCK(workers_free);
	for (i = 0; i < n; i++) {
		item = k_unlink_head(workers_free);
		DATA_WORKERS(row, item);

		if (everyone_die) {
			ok = false;
			break;
		}

		PQ_GET_FLD(res, i, "userid", field, ok);
		if (!ok)
			break;
		TXT_TO_BIGINT("userid", field, row->userid);

		PQ_GET_FLD(res, i, "workername", field, ok);
		if (!ok)
			break;
		TXT_TO_STR("workername", field, row->workername);

		PQ_GET_FLD(res, i, "difficultydefault", field, ok);
		if (!ok)
			break;
		TXT_TO_INT("difficultydefault", field, row->difficultydefault);

		PQ_GET_FLD(res, i, "idlenotificationenabled", field, ok);
		if (!ok)
			break;
		TXT_TO_STR("idlenotificationenabled", field, row->idlenotificationenabled);

		PQ_GET_FLD(res, i, "idlenotificationtime", field, ok);
		if (!ok)
			break;
		TXT_TO_INT("idlenotificationtime", field, row->idlenotificationtime);

		HISTORYDATEFLDS(res, i, row, ok);
		if (!ok)
			break;

		PQ_GET_FLD(res, i, "workerid", field, ok);
		if (!ok)
			break;
		TXT_TO_BIGINT("workerid", field, row->workerid);

		workers_root = add_to_ktree(workers_root, item, cmp_workers);
		k_add_head(workers_store, item);

		/* Make sure a workerstatus exists for each worker
		 * This is to ensure that code can use the workerstatus tree
		 *  to reference other tables and not miss workers in the
		 *  other tables */
		find_create_workerstatus(row->userid, row->workername,
					 __FILE__, __func__, __LINE__);
	}
	if (!ok)
		k_add_head(workers_free, item);

	K_WUNLOCK(workers_free);
	PQclear(res);

	if (ok) {
		LOGDEBUG("%s(): built", __func__);
		LOGWARNING("%s(): loaded %d workers records", __func__, n);
	}

	return ok;
}

void workers_reload()
{
	PGconn *conn = dbconnect();

	K_WLOCK(workers_free);
	workers_root = free_ktree(workers_root, NULL);
	k_list_transfer_to_head(workers_store, workers_free);
	K_WUNLOCK(workers_free);

	workers_fill(conn);

	PQfinish(conn);
}

// order by userid asc,expirydate desc,payaddress asc
static cmp_t cmp_paymentaddresses(K_ITEM *a, K_ITEM *b)
{
	PAYMENTADDRESSES *pa, *pb;
	DATA_PAYMENTADDRESSES(pa, a);
	DATA_PAYMENTADDRESSES(pb, b);
	cmp_t c = CMP_BIGINT(pa->userid, pb->userid);
	if (c == 0) {
		c = CMP_TV(pb->expirydate, pa->expirydate);
		if (c == 0)
			c = CMP_STR(pa->payaddress, pb->payaddress);
	}
	return c;
}

static K_ITEM *find_paymentaddresses(int64_t userid)
{
	PAYMENTADDRESSES paymentaddresses, *pa;
	K_TREE_CTX ctx[1];
	K_ITEM look, *item;

	paymentaddresses.userid = userid;
	paymentaddresses.payaddress[0] = '\0';
	paymentaddresses.expirydate.tv_sec = DATE_S_EOT;

	INIT_PAYMENTADDRESSES(&look);
	look.data = (void *)(&paymentaddresses);
	item = find_after_in_ktree(paymentaddresses_root, &look, cmp_paymentaddresses, ctx);
	if (item) {
		DATA_PAYMENTADDRESSES(pa, item);
		if (pa->userid == userid && CURRENT(&(pa->expirydate)))
			return item;
		else
			return NULL;
	} else
		return NULL;
}

// Whatever the current paymentaddresses are, replace them with this one
static K_ITEM *paymentaddresses_set(PGconn *conn, int64_t userid, char *payaddress,
					char *by, char *code, char *inet, tv_t *cd,
					K_TREE *trf_root)
{
	ExecStatusType rescode;
	bool conned = false;
	PGresult *res;
	K_TREE_CTX ctx[1], ctx2[1];
	K_ITEM *item, *old, *this, look;
	PAYMENTADDRESSES *row, pa, *thispa;
	char *upd, *ins;
	bool ok = false;
	char *params[4 + HISTORYDATECOUNT];
	int n, par = 0;

	LOGDEBUG("%s(): add", __func__);

	K_WLOCK(paymentaddresses_free);
	item = k_unlink_head(paymentaddresses_free);
	K_WUNLOCK(paymentaddresses_free);

	DATA_PAYMENTADDRESSES(row, item);

	row->paymentaddressid = nextid(conn, "paymentaddressid", 1,
					cd, by, code, inet);
	if (row->paymentaddressid == 0)
		goto unitem;

	row->userid = userid;
	STRNCPY(row->payaddress, payaddress);
	row->payratio = 1000000;

	HISTORYDATEINIT(row, cd, by, code, inet);
	HISTORYDATETRANSFER(trf_root, row);

	upd = "update paymentaddresses set expirydate=$1 where userid=$2 and expirydate=$3";
	par = 0;
	params[par++] = tv_to_buf(cd, NULL, 0);
	params[par++] = bigint_to_buf(row->userid, NULL, 0);
	params[par++] = tv_to_buf((tv_t *)&default_expiry, NULL, 0);
	PARCHKVAL(par, 3, params);

	if (conn == NULL) {
		conn = dbconnect();
		conned = true;
	}

	res = PQexec(conn, "Begin", CKPQ_WRITE);
	rescode = PQresultStatus(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Begin", rescode, conn);
		goto unparam;
	}
	PQclear(res);

	res = PQexecParams(conn, upd, par, NULL, (const char **)params, NULL, NULL, 0, CKPQ_WRITE);
	rescode = PQresultStatus(res);
	PQclear(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Update", rescode, conn);
		goto rollback;
	}

	for (n = 0; n < par; n++)
		free(params[n]);

	ins = "insert into paymentaddresses "
		"(paymentaddressid,userid,payaddress,payratio"
		HISTORYDATECONTROL ") values (" PQPARAM9 ")";

	par = 0;
	params[par++] = bigint_to_buf(row->paymentaddressid, NULL, 0);
	params[par++] = bigint_to_buf(row->userid, NULL, 0);
	params[par++] = str_to_buf(row->payaddress, NULL, 0);
	params[par++] = int_to_buf(row->payratio, NULL, 0);
	HISTORYDATEPARAMS(params, par, row);
	PARCHK(par, params);

	res = PQexecParams(conn, ins, par, NULL, (const char **)params, NULL, NULL, 0, CKPQ_WRITE);
	rescode = PQresultStatus(res);
	PQclear(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Insert", rescode, conn);
		goto rollback;
	}

	ok = true;
rollback:
	if (ok)
		res = PQexec(conn, "Commit", CKPQ_WRITE);
	else
		res = PQexec(conn, "Rollback", CKPQ_WRITE);

	PQclear(res);
unparam:
	if (conned)
		PQfinish(conn);
	for (n = 0; n < par; n++)
		free(params[n]);
unitem:
	K_WLOCK(paymentaddresses_free);
	if (!ok)
		k_add_head(paymentaddresses_free, item);
	else {
		// Remove from ram, old (unneeded) records
		pa.userid = userid;
		pa.expirydate.tv_sec = 0L;
		pa.payaddress[0] = '\0';
		INIT_PAYMENTADDRESSES(&look);
		look.data = (void *)(&pa);
		old = find_after_in_ktree(paymentaddresses_root, &look,
					  cmp_paymentaddresses, ctx);
		while (old) {
			this = old;
			DATA_PAYMENTADDRESSES(thispa, this);
			if (thispa->userid != userid)
				break;
			old = next_in_ktree(ctx);
			paymentaddresses_root = remove_from_ktree(paymentaddresses_root, this,
								  cmp_paymentaddresses, ctx2);
			k_add_head(paymentaddresses_free, this);
		}
		paymentaddresses_root = add_to_ktree(paymentaddresses_root, item,
						     cmp_paymentaddresses);
		k_add_head(paymentaddresses_store, item);
	}
	K_WUNLOCK(paymentaddresses_free);

	if (ok)
		return item;
	else
		return NULL;
}

static bool paymentaddresses_fill(PGconn *conn)
{
	ExecStatusType rescode;
	PGresult *res;
	K_ITEM *item;
	PAYMENTADDRESSES *row;
	char *params[1];
	int n, i, par = 0;
	char *field;
	char *sel;
	int fields = 4;
	bool ok;

	LOGDEBUG("%s(): select", __func__);

	sel = "select "
		"paymentaddressid,userid,payaddress,payratio"
		HISTORYDATECONTROL
		" from paymentaddresses where expirydate=$1";
	par = 0;
	params[par++] = tv_to_buf((tv_t *)(&default_expiry), NULL, 0);
	PARCHK(par, params);
	res = PQexecParams(conn, sel, par, NULL, (const char **)params, NULL, NULL, 0, CKPQ_READ);
	rescode = PQresultStatus(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Select", rescode, conn);
		PQclear(res);
		return false;
	}

	n = PQnfields(res);
	if (n != (fields + HISTORYDATECOUNT)) {
		LOGERR("%s(): Invalid field count - should be %d, but is %d",
			__func__, fields + HISTORYDATECOUNT, n);
		PQclear(res);
		return false;
	}

	n = PQntuples(res);
	LOGDEBUG("%s(): tree build count %d", __func__, n);
	ok = true;
	K_WLOCK(paymentaddresses_free);
	for (i = 0; i < n; i++) {
		item = k_unlink_head(paymentaddresses_free);
		DATA_PAYMENTADDRESSES(row, item);

		if (everyone_die) {
			ok = false;
			break;
		}

		PQ_GET_FLD(res, i, "paymentaddressid", field, ok);
		if (!ok)
			break;
		TXT_TO_BIGINT("paymentaddressid", field, row->paymentaddressid);

		PQ_GET_FLD(res, i, "userid", field, ok);
		if (!ok)
			break;
		TXT_TO_BIGINT("userid", field, row->userid);

		PQ_GET_FLD(res, i, "payaddress", field, ok);
		if (!ok)
			break;
		TXT_TO_STR("payaddress", field, row->payaddress);

		PQ_GET_FLD(res, i, "payratio", field, ok);
		if (!ok)
			break;
		TXT_TO_INT("payratio", field, row->payratio);

		HISTORYDATEFLDS(res, i, row, ok);
		if (!ok)
			break;

		paymentaddresses_root = add_to_ktree(paymentaddresses_root, item, cmp_paymentaddresses);
		k_add_head(paymentaddresses_store, item);
	}
	if (!ok)
		k_add_head(paymentaddresses_free, item);

	K_WUNLOCK(paymentaddresses_free);
	PQclear(res);

	if (ok) {
		LOGDEBUG("%s(): built", __func__);
		LOGWARNING("%s(): loaded %d paymentaddresses records", __func__, n);
	}

	return ok;
}

// order by userid asc,paydate asc,payaddress asc,expirydate desc
static cmp_t cmp_payments(K_ITEM *a, K_ITEM *b)
{
	PAYMENTS *pa, *pb;
	DATA_PAYMENTS(pa, a);
	DATA_PAYMENTS(pb, b);
	cmp_t c = CMP_BIGINT(pa->userid, pb->userid);
	if (c == 0) {
		c = CMP_TV(pa->paydate, pb->paydate);
		if (c == 0) {
			c = CMP_STR(pa->payaddress, pb->payaddress);
			if (c == 0)
				c = CMP_TV(pb->expirydate, pa->expirydate);
		}
	}
	return c;
}

static bool payments_fill(PGconn *conn)
{
	ExecStatusType rescode;
	PGresult *res;
	K_ITEM *item;
	PAYMENTS *row;
	char *params[1];
	int n, i, par = 0;
	char *field;
	char *sel;
	int fields = 8;
	bool ok;

	LOGDEBUG("%s(): select", __func__);

	// TODO: handle selecting a subset, eg 20 per web page (in blocklist also)
	sel = "select "
		"userid,paydate,payaddress,originaltxn,amount,committxn,commitblockhash"
		HISTORYDATECONTROL
		",paymentid from payments where expirydate=$1";
	par = 0;
	params[par++] = tv_to_buf((tv_t *)(&default_expiry), NULL, 0);
	PARCHK(par, params);
	res = PQexecParams(conn, sel, par, NULL, (const char **)params, NULL, NULL, 0, CKPQ_READ);
	rescode = PQresultStatus(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Select", rescode, conn);
		PQclear(res);
		return false;
	}

	n = PQnfields(res);
	if (n != (fields + HISTORYDATECOUNT)) {
		LOGERR("%s(): Invalid field count - should be %d, but is %d",
			__func__, fields + HISTORYDATECOUNT, n);
		PQclear(res);
		return false;
	}

	n = PQntuples(res);
	LOGDEBUG("%s(): tree build count %d", __func__, n);
	ok = true;
	K_WLOCK(payments_free);
	for (i = 0; i < n; i++) {
		item = k_unlink_head(payments_free);
		DATA_PAYMENTS(row, item);

		if (everyone_die) {
			ok = false;
			break;
		}

		PQ_GET_FLD(res, i, "userid", field, ok);
		if (!ok)
			break;
		TXT_TO_BIGINT("userid", field, row->userid);

		PQ_GET_FLD(res, i, "paydate", field, ok);
		if (!ok)
			break;
		TXT_TO_TV("paydate", field, row->paydate);

		PQ_GET_FLD(res, i, "payaddress", field, ok);
		if (!ok)
			break;
		TXT_TO_STR("payaddress", field, row->payaddress);

		PQ_GET_FLD(res, i, "originaltxn", field, ok);
		if (!ok)
			break;
		TXT_TO_STR("originaltxn", field, row->originaltxn);

		PQ_GET_FLD(res, i, "amount", field, ok);
		if (!ok)
			break;
		TXT_TO_BIGINT("amount", field, row->amount);

		PQ_GET_FLD(res, i, "committxn", field, ok);
		if (!ok)
			break;
		TXT_TO_STR("committxn", field, row->committxn);

		PQ_GET_FLD(res, i, "commitblockhash", field, ok);
		if (!ok)
			break;
		TXT_TO_STR("commitblockhash", field, row->commitblockhash);

		HISTORYDATEFLDS(res, i, row, ok);
		if (!ok)
			break;

		PQ_GET_FLD(res, i, "paymentid", field, ok);
		if (!ok)
			break;
		TXT_TO_BIGINT("paymentid", field, row->paymentid);

		payments_root = add_to_ktree(payments_root, item, cmp_payments);
		k_add_head(payments_store, item);
	}
	if (!ok)
		k_add_head(payments_free, item);

	K_WUNLOCK(payments_free);
	PQclear(res);

	if (ok) {
		LOGDEBUG("%s(): built", __func__);
		LOGWARNING("%s(): loaded %d payments records", __func__, n);
	}

	return ok;
}

void payments_reload()
{
	PGconn *conn = dbconnect();

	K_WLOCK(payments_free);
	payments_root = free_ktree(payments_root, NULL);
	k_list_transfer_to_head(payments_store, payments_free);
	K_WUNLOCK(payments_free);

	payments_fill(conn);

	PQfinish(conn);
}

// order by optionname asc,activationdate asc,activationheight asc,expirydate desc
static cmp_t cmp_optioncontrol(K_ITEM *a, K_ITEM *b)
{
	OPTIONCONTROL *oca, *ocb;
	DATA_OPTIONCONTROL(oca, a);
	DATA_OPTIONCONTROL(ocb, b);
	cmp_t c = CMP_STR(oca->optionname, ocb->optionname);
	if (c == 0) {
		c = CMP_TV(oca->activationdate, ocb->activationdate);
		if (c == 0) {
			c = CMP_INT(oca->activationheight, ocb->activationheight);
			if (c == 0)
				c = CMP_TV(ocb->expirydate, oca->expirydate);
		}
	}
	return c;
}

// Must be R or W locked before call
static K_ITEM *find_optioncontrol(char *optionname, tv_t *now)
{
	OPTIONCONTROL optioncontrol, *oc, *ocbest;
	K_TREE_CTX ctx[1];
	K_ITEM look, *item, *best;

	/* Step through all records having optionaname and check:
	 * 1) activationdate is <= now
	 *  and
	 * 2) height <= current
	 * Remember the active record with the newest activationdate
	 * If two records have the same activation date, then
	 *  remember the active record with the highest height
	 * In optioncontrol_add(), when not specified,
	 *  the default activation date is DATE_BEGIN
	 *  and the default height is 1 (OPTIONCONTROL_HEIGHT)
	 * Thus if records have both values set, then
	 *  activationdate will determine the newests record
	 * To have activationheight decide selection,
	 *  create all records with only activationheight and then
	 *  activationdate will all be the default value and not
	 *  decide the outcome */
	STRNCPY(optioncontrol.optionname, optionname);
	optioncontrol.activationdate.tv_sec = 0L;
	optioncontrol.activationdate.tv_usec = 0L;
	optioncontrol.activationheight = OPTIONCONTROL_HEIGHT - 1;
	optioncontrol.expirydate.tv_sec = default_expiry.tv_sec;
	optioncontrol.expirydate.tv_usec = default_expiry.tv_usec;

	INIT_OPTIONCONTROL(&look);
	look.data = (void *)(&optioncontrol);
	item = find_after_in_ktree(optioncontrol_root, &look, cmp_optioncontrol, ctx);
	ocbest = NULL;
	best = NULL;
	while (item) {
		DATA_OPTIONCONTROL(oc, item);
		// Ordered first by optionname
		if (strcmp(oc->optionname, optionname) != 0)
			break;

		// Is oc active?
		if (CURRENT(&(oc->expirydate)) &&
		    oc->activationheight <= pool.height &&
		    tv_newer_eq(&(oc->activationdate), now)) {
			// Is oc newer than ocbest?
			if (!ocbest ||
			    tv_newer(&(ocbest->activationdate), &(oc->activationdate)) ||
			    (tv_equal(&(ocbest->activationdate), &(oc->activationdate)) &&
			     ocbest->activationheight < oc->activationheight)) {
				ocbest = oc;
				best = item;
			}
		}
		item = next_in_ktree(ctx);
	}
	return best;
}

static K_ITEM *optioncontrol_item_add(PGconn *conn, K_ITEM *oc_item, tv_t *cd, bool begun)
{
	ExecStatusType rescode;
	bool conned = false;
	K_TREE_CTX ctx[1];
	PGresult *res;
	K_ITEM *old_item, look;
	OPTIONCONTROL *row;
	char *upd, *ins;
	bool ok = false;
	char *params[4 + HISTORYDATECOUNT];
	int n, par = 0;

	LOGDEBUG("%s(): add", __func__);

	DATA_OPTIONCONTROL(row, oc_item);

	INIT_OPTIONCONTROL(&look);
	look.data = (void *)row;
	K_RLOCK(optioncontrol_free);
	old_item = find_in_ktree(optioncontrol_root, &look, cmp_optioncontrol, ctx);
	K_RUNLOCK(optioncontrol_free);

	if (!conn) {
		conn = dbconnect();
		conned = true;
	}

	if (!begun) {
		res = PQexec(conn, "Begin", CKPQ_WRITE);
		rescode = PQresultStatus(res);
		PQclear(res);
		if (!PGOK(rescode)) {
			PGLOGERR("Begin", rescode, conn);
			goto nostart;
		}
	}

	if (old_item) {
		upd = "update optioncontrol "
			"set expirydate=$1 where optionname=$2 and "
			"activationdate=$3 and activationheight=$4 and "
			"expirydate=$5";

		par = 0;
		params[par++] = tv_to_buf(cd, NULL, 0);
		params[par++] = str_to_buf(row->optionname, NULL, 0);
		params[par++] = tv_to_buf(&(row->activationdate), NULL, 0);
		params[par++] = int_to_buf(row->activationheight, NULL, 0);
		params[par++] = tv_to_buf((tv_t *)&default_expiry, NULL, 0);
		PARCHKVAL(par, 5, params);

		res = PQexecParams(conn, upd, par, NULL, (const char **)params, NULL, NULL, 0, CKPQ_WRITE);
		rescode = PQresultStatus(res);
		PQclear(res);
		if (!PGOK(rescode)) {
			PGLOGERR("Update", rescode, conn);
			goto rollback;
		}

		for (n = 0; n < par; n++)
			free(params[n]);
	}

	par = 0;
	params[par++] = str_to_buf(row->optionname, NULL, 0);
	params[par++] = str_to_buf(row->optionvalue, NULL, 0);
	params[par++] = tv_to_buf(&(row->activationdate), NULL, 0);
	params[par++] = int_to_buf(row->activationheight, NULL, 0);
	HISTORYDATEPARAMS(params, par, row);
	PARCHK(par, params);

	ins = "insert into optioncontrol "
		"(optionname,optionvalue,activationdate,activationheight"
		HISTORYDATECONTROL ") values (" PQPARAM9 ")";

	res = PQexecParams(conn, ins, par, NULL, (const char **)params, NULL, NULL, 0, CKPQ_WRITE);
	rescode = PQresultStatus(res);
	PQclear(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Insert", rescode, conn);
		goto rollback;
	}

	ok = true;
rollback:
	if (!begun) {
		if (ok)
			res = PQexec(conn, "Commit", CKPQ_WRITE);
		else
			res = PQexec(conn, "Rollback", CKPQ_WRITE);

		PQclear(res);
	}
nostart:
	if (conned)
		PQfinish(conn);
	for (n = 0; n < par; n++)
		free(params[n]);

	K_WLOCK(optioncontrol_free);
	if (!ok)
		k_add_head(optioncontrol_free, oc_item);
	else {
		// Discard it
		if (old_item) {
			optioncontrol_root = remove_from_ktree(optioncontrol_root, old_item,
							       cmp_optioncontrol, ctx);
			k_add_head(optioncontrol_free, old_item);
		}
		optioncontrol_root = add_to_ktree(optioncontrol_root, oc_item, cmp_optioncontrol);
		k_add_head(optioncontrol_store, oc_item);
	}
	K_WUNLOCK(optioncontrol_free);

	if (ok)
		return oc_item;
	else
		return NULL;
}

static __maybe_unused K_ITEM *optioncontrol_add(PGconn *conn, char *optionname, char *optionvalue,
				 char *activationdate, char *activationheight,
				 char *by, char *code, char *inet, tv_t *cd,
				 K_TREE *trf_root, bool begun)
{
	K_ITEM *item;
	OPTIONCONTROL *row;
	bool ok = false;

	LOGDEBUG("%s(): add", __func__);

	K_WLOCK(optioncontrol_free);
	item = k_unlink_head(optioncontrol_free);
	K_WUNLOCK(optioncontrol_free);

	DATA_OPTIONCONTROL(row, item);

	STRNCPY(row->optionname, optionname);
	row->optionvalue = strdup(optionvalue);
	if (!(row->optionvalue))
		quithere(1, "malloc (%d) OOM", (int)strlen(optionvalue));
	if (activationdate && *activationdate) {
		TXT_TO_CTV("activationdate", activationdate,
			   row->activationdate);
	} else
		copy_tv(&(row->activationdate), &date_begin);
	if (activationheight && *activationheight) {
		TXT_TO_INT("activationheight", activationheight,
			   row->activationheight);
	} else
		row->activationheight = 1;

	HISTORYDATEINIT(row, cd, by, code, inet);
	HISTORYDATETRANSFER(trf_root, row);

	ok = optioncontrol_item_add(conn, item, cd, begun);

	if (!ok) {
		free(row->optionvalue);
		K_WLOCK(optioncontrol_free);
		k_add_head(optioncontrol_free, item);
		K_WUNLOCK(optioncontrol_free);
	}

	if (ok)
		return item;
	else
		return NULL;
}

static bool optioncontrol_fill(PGconn *conn)
{
	ExecStatusType rescode;
	PGresult *res;
	K_ITEM *item;
	OPTIONCONTROL *row;
	char *params[1];
	int n, i, par = 0;
	char *field;
	char *sel;
	int fields = 4;
	bool ok;

	LOGDEBUG("%s(): select", __func__);

	// No need to keep old versions in ram for now ...
	sel = "select "
		"optionname,optionvalue,activationdate,activationheight"
		HISTORYDATECONTROL
		" from optioncontrol where expirydate=$1";
	par = 0;
	params[par++] = tv_to_buf((tv_t *)(&default_expiry), NULL, 0);
	PARCHK(par, params);
	res = PQexecParams(conn, sel, par, NULL, (const char **)params, NULL, NULL, 0, CKPQ_READ);
	rescode = PQresultStatus(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Select", rescode, conn);
		PQclear(res);
		return false;
	}

	n = PQnfields(res);
	if (n != (fields + HISTORYDATECOUNT)) {
		LOGERR("%s(): Invalid field count - should be %d, but is %d",
			__func__, fields + HISTORYDATECOUNT, n);
		PQclear(res);
		return false;
	}

	n = PQntuples(res);
	LOGDEBUG("%s(): tree build count %d", __func__, n);
	ok = true;
	K_WLOCK(optioncontrol_free);
	for (i = 0; i < n; i++) {
		item = k_unlink_head(optioncontrol_free);
		DATA_OPTIONCONTROL(row, item);

		if (everyone_die) {
			ok = false;
			break;
		}

		PQ_GET_FLD(res, i, "optionname", field, ok);
		if (!ok)
			break;
		TXT_TO_STR("optionname", field, row->optionname);

		PQ_GET_FLD(res, i, "optionvalue", field, ok);
		if (!ok)
			break;
		TXT_TO_BLOB("optionvalue", field, row->optionvalue);

		PQ_GET_FLD(res, i, "activationdate", field, ok);
		if (!ok)
			break;
		TXT_TO_TV("activationdate", field, row->activationdate);

		PQ_GET_FLD(res, i, "activationheight", field, ok);
		if (!ok)
			break;
		TXT_TO_INT("activationheight", field, row->activationheight);

		HISTORYDATEFLDS(res, i, row, ok);
		if (!ok)
			break;

		optioncontrol_root = add_to_ktree(optioncontrol_root, item, cmp_optioncontrol);
		k_add_head(optioncontrol_store, item);
	}
	if (!ok)
		k_add_head(optioncontrol_free, item);

	K_WUNLOCK(optioncontrol_free);
	PQclear(res);

	if (ok) {
		LOGDEBUG("%s(): built", __func__);
		LOGWARNING("%s(): loaded %d optioncontrol records", __func__, n);
	}

	return ok;
}

// order by workinfoid asc,expirydate asc
static cmp_t cmp_workinfo(K_ITEM *a, K_ITEM *b)
{
	WORKINFO *wa, *wb;
	DATA_WORKINFO(wa, a);
	DATA_WORKINFO(wb, b);
	cmp_t c = CMP_BIGINT(wa->workinfoid, wb->workinfoid);
	if (c == 0)
		c = CMP_TV(wa->expirydate, wb->expirydate);
	return c;
}

inline int32_t _coinbase1height(char *coinbase1, WHERE_FFL_ARGS)
{
	int32_t height = 0;
	uchar *cb1;
	int siz;

	cb1 = ((uchar *)coinbase1) + 84;
	siz = ((hex2bin_tbl[*cb1]) << 4) + (hex2bin_tbl[*(cb1+1)]);

	// limit to 4 for int32_t and since ... that should last a while :)
	if (siz < 1 || siz > 4) {
		LOGERR("%s(): Invalid coinbase1 block height size (%d)"
			" require: 1..4 (cb1 %s)" WHERE_FFL,
			__func__, siz, coinbase1, WHERE_FFL_PASS);
		return height;
	}

	siz *= 2;
	while (siz-- > 0) {
		height <<= 4;
		height += (int32_t)hex2bin_tbl[*(cb1+(siz^1)+2)];
	}

	return height;
}

static cmp_t _cmp_height(char *coinbase1a, char *coinbase1b, WHERE_FFL_ARGS)
{
	return CMP_INT(_coinbase1height(coinbase1a, WHERE_FFL_PASS),
		       _coinbase1height(coinbase1b, WHERE_FFL_PASS));
}

// order by height asc,createdate asc
static cmp_t cmp_workinfo_height(K_ITEM *a, K_ITEM *b)
{
	WORKINFO *wa, *wb;
	DATA_WORKINFO(wa, a);
	DATA_WORKINFO(wb, b);
	cmp_t c = cmp_height(wa->coinbase1, wb->coinbase1);
	if (c == 0)
		c = CMP_TV(wa->createdate, wb->createdate);
	return c;
}

static K_ITEM *find_workinfo(int64_t workinfoid)
{
	WORKINFO workinfo;
	K_TREE_CTX ctx[1];
	K_ITEM look, *item;

	workinfo.workinfoid = workinfoid;
	workinfo.expirydate.tv_sec = default_expiry.tv_sec;
	workinfo.expirydate.tv_usec = default_expiry.tv_usec;

	INIT_WORKINFO(&look);
	look.data = (void *)(&workinfo);
	K_RLOCK(workinfo_free);
	item = find_in_ktree(workinfo_root, &look, cmp_workinfo, ctx);
	K_RUNLOCK(workinfo_free);
	return item;
}

static int64_t workinfo_add(PGconn *conn, char *workinfoidstr, char *poolinstance,
				char *transactiontree, char *merklehash, char *prevhash,
				char *coinbase1, char *coinbase2, char *version,
				char *bits, char *ntime, char *reward, char *by,
				char *code, char *inet, tv_t *cd, bool igndup,
				K_TREE *trf_root)
{
	ExecStatusType rescode;
	bool conned = false;
	K_TREE_CTX ctx[1];
	PGresult *res;
	K_ITEM *item;
	char cd_buf[DATE_BUFSIZ];
	char ndiffbin[TXT_SML+1];
	int64_t workinfoid = -1;
	WORKINFO *row;
	char *ins;
	char *params[11 + HISTORYDATECOUNT];
	int n, par = 0;

	LOGDEBUG("%s(): add", __func__);

	K_WLOCK(workinfo_free);
	item = k_unlink_head(workinfo_free);
	K_WUNLOCK(workinfo_free);

	DATA_WORKINFO(row, item);

	TXT_TO_BIGINT("workinfoid", workinfoidstr, row->workinfoid);
	STRNCPY(row->poolinstance, poolinstance);
	row->transactiontree = strdup(transactiontree);
	if (!(row->transactiontree))
		quithere(1, "malloc (%d) OOM", (int)strlen(transactiontree));
	row->merklehash = strdup(merklehash);
	if (!(row->merklehash))
		quithere(1, "malloc (%d) OOM", (int)strlen(merklehash));
	STRNCPY(row->prevhash, prevhash);
	STRNCPY(row->coinbase1, coinbase1);
	STRNCPY(row->coinbase2, coinbase2);
	STRNCPY(row->version, version);
	STRNCPY(row->bits, bits);
	STRNCPY(row->ntime, ntime);
	TXT_TO_BIGINT("reward", reward, row->reward);

	HISTORYDATEINIT(row, cd, by, code, inet);
	HISTORYDATETRANSFER(trf_root, row);

	K_WLOCK(workinfo_free);
	if (find_in_ktree(workinfo_root, item, cmp_workinfo, ctx)) {
		free(row->transactiontree);
		free(row->merklehash);
		workinfoid = row->workinfoid;
		k_add_head(workinfo_free, item);
		K_WUNLOCK(workinfo_free);

		if (!igndup) {
			tv_to_buf(cd, cd_buf, sizeof(cd_buf));
			LOGERR("%s(): Duplicate workinfo ignored %s/%s/%s",
				__func__, workinfoidstr, poolinstance, cd_buf);
		}

		return workinfoid;
	}
	K_WUNLOCK(workinfo_free);

	if (!confirm_sharesummary) {
		par = 0;
		params[par++] = bigint_to_buf(row->workinfoid, NULL, 0);
		params[par++] = str_to_buf(row->poolinstance, NULL, 0);
		params[par++] = str_to_buf(row->transactiontree, NULL, 0);
		params[par++] = str_to_buf(row->merklehash, NULL, 0);
		params[par++] = str_to_buf(row->prevhash, NULL, 0);
		params[par++] = str_to_buf(row->coinbase1, NULL, 0);
		params[par++] = str_to_buf(row->coinbase2, NULL, 0);
		params[par++] = str_to_buf(row->version, NULL, 0);
		params[par++] = str_to_buf(row->bits, NULL, 0);
		params[par++] = str_to_buf(row->ntime, NULL, 0);
		params[par++] = bigint_to_buf(row->reward, NULL, 0);
		HISTORYDATEPARAMS(params, par, row);
		PARCHK(par, params);

		ins = "insert into workinfo "
			"(workinfoid,poolinstance,transactiontree,merklehash,"
			"prevhash,coinbase1,coinbase2,version,bits,ntime,reward"
			HISTORYDATECONTROL ") values (" PQPARAM16 ")";

		if (!conn) {
			conn = dbconnect();
			conned = true;
		}

		res = PQexecParams(conn, ins, par, NULL, (const char **)params, NULL, NULL, 0, CKPQ_WRITE);
		rescode = PQresultStatus(res);
		if (!PGOK(rescode)) {
			PGLOGERR("Insert", rescode, conn);
			goto unparam;
		}
	}

	workinfoid = row->workinfoid;

unparam:
	if (par) {
		PQclear(res);
		if (conned)
			PQfinish(conn);
		for (n = 0; n < par; n++)
			free(params[n]);
	}

	K_WLOCK(workinfo_free);
	if (workinfoid == -1) {
		free(row->transactiontree);
		free(row->merklehash);
		k_add_head(workinfo_free, item);
	} else {
		if (row->transactiontree && *(row->transactiontree)) {
			// Not currently needed in RAM
			free(row->transactiontree);
			row->transactiontree = strdup(EMPTY);
		}

		hex2bin(ndiffbin, row->bits, 4);
		current_ndiff = diff_from_nbits(ndiffbin);

		workinfo_root = add_to_ktree(workinfo_root, item, cmp_workinfo);
		k_add_head(workinfo_store, item);

		// Remember the bc = 'cd' when the height changes
		if (workinfo_current) {
			WORKINFO *wic;
			DATA_WORKINFO(wic, workinfo_current);
			if (cmp_height(wic->coinbase1, row->coinbase1) != 0)
				copy_tv(&last_bc, cd);
		}

		workinfo_current = item;
	}
	K_WUNLOCK(workinfo_free);

	return workinfoid;
}

#define sharesummary_update(_conn, _s_row, _e_row, _ss_item, _by, _code, _inet, _cd) \
		_sharesummary_update(_conn, _s_row, _e_row, _ss_item, _by, _code, _inet, _cd, \
					WHERE_FFL_HERE)

static bool _sharesummary_update(PGconn *conn, SHARES *s_row, SHAREERRORS *e_row, K_ITEM *ss_item,
				char *by, char *code, char *inet, tv_t *cd, WHERE_FFL_ARGS);
static cmp_t cmp_sharesummary_workinfoid(K_ITEM *a, K_ITEM *b);
static cmp_t cmp_shares(K_ITEM *a, K_ITEM *b);

static bool workinfo_age(PGconn *conn, int64_t workinfoid, char *poolinstance,
			 char *by, char *code, char *inet, tv_t *cd,
			 tv_t *ss_first, tv_t *ss_last, int64_t *ss_count,
			 int64_t *s_count, int64_t *s_diff)
{
	K_ITEM *wi_item, ss_look, *ss_item, s_look, *s_item, *tmp_item;
	K_TREE_CTX ss_ctx[1], s_ctx[1], tmp_ctx[1];
	char cd_buf[DATE_BUFSIZ];
	int64_t ss_tot, ss_already, ss_failed, shares_tot, shares_dumped;
	SHARESUMMARY looksharesummary, *sharesummary;
	WORKINFO *workinfo;
	SHARES lookshares, *shares;
	bool ok = false, conned = false, skipupdate;
	char error[1024];

	LOGDEBUG("%s(): age", __func__);

	ss_first->tv_sec = ss_first->tv_usec =
	ss_last->tv_sec = ss_last->tv_usec = 0;
	*ss_count = *s_count = *s_diff = 0;

	wi_item = find_workinfo(workinfoid);
	if (!wi_item) {
		tv_to_buf(cd, cd_buf, sizeof(cd_buf));
		LOGERR("%s() %"PRId64"/%s/%ld,%ld %.19s no workinfo! Age discarded!",
			__func__, workinfoid, poolinstance,
			cd->tv_sec, cd->tv_usec, cd_buf);
		goto bye;
	}

	DATA_WORKINFO(workinfo, wi_item);
	if (strcmp(poolinstance, workinfo->poolinstance) != 0) {
		tv_to_buf(cd, cd_buf, sizeof(cd_buf));
		LOGERR("%s() %"PRId64"/%s/%ld,%ld %.19s Poolinstance changed "
			"(from %s)! Age discarded!",
			__func__, workinfoid, poolinstance,
			cd->tv_sec, cd->tv_usec, cd_buf,
			workinfo->poolinstance);
		goto bye;
	}

	INIT_SHARESUMMARY(&ss_look);
	INIT_SHARES(&s_look);

	// Find the first matching sharesummary
	looksharesummary.workinfoid = workinfoid;
	looksharesummary.userid = -1;
	looksharesummary.workername[0] = '\0';

	ok = true;
	ss_tot = ss_already = ss_failed = shares_tot = shares_dumped = 0;
	ss_look.data = (void *)(&looksharesummary);
	K_RLOCK(sharesummary_free);
	ss_item = find_after_in_ktree(sharesummary_workinfoid_root, &ss_look, cmp_sharesummary_workinfoid, ss_ctx);
	K_RUNLOCK(sharesummary_free);
	DATA_SHARESUMMARY_NULL(sharesummary, ss_item);
	while (ss_item && sharesummary->workinfoid == workinfoid) {
		ss_tot++;
		error[0] = '\0';
		skipupdate = false;
		/* Reloading during a confirm will not have any old data
		 * so finding an aged sharesummary here is an error */
		if (reloading) {
			if (sharesummary->complete[0] == SUMMARY_COMPLETE) {
				ss_already++;
				skipupdate = true;
				if (confirm_sharesummary) {
					LOGERR("%s(): Duplicate %s found during confirm %"PRId64"/%s/%"PRId64,
						__func__, __func__,
						sharesummary->userid,
						sharesummary->workername,
						sharesummary->workinfoid);
				}
			}
		}

		if (!skipupdate) {
			if (conn == NULL && !confirm_sharesummary) {
				conn = dbconnect();
				conned = true;
			}

			if (!sharesummary_update(conn, NULL, NULL, ss_item, by, code, inet, cd)) {
				ss_failed++;
				LOGERR("%s(): Failed to age share summary %"PRId64"/%s/%"PRId64,
					__func__, sharesummary->userid,
					sharesummary->workername,
					sharesummary->workinfoid);
				ok = false;
			} else {
				(*ss_count)++;
				*s_count += sharesummary->sharecount;
				*s_diff += sharesummary->diffacc;
				if (ss_first->tv_sec == 0 ||
				    !tv_newer(ss_first, &(sharesummary->firstshare)))
					copy_tv(ss_first, &(sharesummary->firstshare));
				if (tv_newer(ss_last, &(sharesummary->lastshare)))
					copy_tv(ss_last, &(sharesummary->lastshare));
			}
		}

		// Discard the shares either way
		lookshares.workinfoid = workinfoid;
		lookshares.userid = sharesummary->userid;
		strcpy(lookshares.workername, sharesummary->workername);
		lookshares.createdate.tv_sec = 0;
		lookshares.createdate.tv_usec = 0;

		s_look.data = (void *)(&lookshares);
		K_WLOCK(shares_free);
		s_item = find_after_in_ktree(shares_root, &s_look, cmp_shares, s_ctx);
		while (s_item) {
			DATA_SHARES(shares, s_item);
			if (shares->workinfoid != workinfoid ||
			    shares->userid != lookshares.userid ||
			    strcmp(shares->workername, lookshares.workername) != 0)
				break;

			shares_tot++;
			tmp_item = next_in_ktree(s_ctx);
			shares_root = remove_from_ktree(shares_root, s_item, cmp_shares, tmp_ctx);
			k_unlink_item(shares_store, s_item);
			if (reloading && skipupdate)
				shares_dumped++;
			if (reloading && skipupdate && !error[0]) {
				snprintf(error, sizeof(error),
					 "reload found aged shares: %"PRId64"/%"PRId64"/%s",
					 shares->workinfoid,
					 shares->userid,
					 shares->workername);
			}
			k_add_head(shares_free, s_item);
			s_item = tmp_item;
		}
		K_WUNLOCK(shares_free);
		K_RLOCK(sharesummary_free);
		ss_item = next_in_ktree(ss_ctx);
		K_RUNLOCK(sharesummary_free);
		DATA_SHARESUMMARY_NULL(sharesummary, ss_item);

		if (error[0])
			LOGERR("%s(): %s", __func__, error);
	}

	if (conned)
		PQfinish(conn);

	if (ss_already || ss_failed || shares_dumped) {
		/* If all were already aged, and no shares
		 * then we don't want a message */
		if (!(ss_already == ss_tot && shares_tot == 0)) {
			LOGERR("%s(): Summary aging of %"PRId64"/%s sstotal=%"PRId64
				" already=%"PRId64" failed=%"PRId64
				", sharestotal=%"PRId64" dumped=%"PRId64,
				__func__, workinfoid, poolinstance, ss_tot,
				ss_already, ss_failed, shares_tot,
				shares_dumped);
		}
	}
bye:
	return ok;
}

static void auto_age_older(PGconn *conn, int64_t workinfoid, char *poolinstance,
				char *by, char *code, char *inet, tv_t *cd)
{
	static int64_t last_attempted_id = -1;
	static int64_t prev_found = 0;
	static int repeat;

	char min_buf[DATE_BUFSIZ], max_buf[DATE_BUFSIZ];
	int64_t ss_count_tot, s_count_tot, s_diff_tot;
	int64_t ss_count, s_count, s_diff;
	tv_t ss_first_min, ss_last_max;
	tv_t ss_first, ss_last;
	int32_t wid_count;
	SHARESUMMARY looksharesummary, *sharesummary;
	K_TREE_CTX ctx[1];
	K_ITEM look, *ss_item;
	int64_t age_id, do_id, to_id;
	bool ok, found;

	LOGDEBUG("%s(): workinfoid=%"PRId64" prev=%"PRId64, __func__, workinfoid, prev_found);

	age_id = prev_found;

	// Find the oldest 'unaged' sharesummary < workinfoid and >= prev_found
	looksharesummary.workinfoid = prev_found;
	looksharesummary.userid = -1;
	looksharesummary.workername[0] = '\0';
	INIT_SHARESUMMARY(&look);
	look.data = (void *)(&looksharesummary);

	K_RLOCK(sharesummary_free);
	ss_item = find_after_in_ktree(sharesummary_workinfoid_root, &look,
				      cmp_sharesummary_workinfoid, ctx);
	DATA_SHARESUMMARY_NULL(sharesummary, ss_item);

	ss_first_min.tv_sec = ss_first_min.tv_usec =
	ss_last_max.tv_sec = ss_last_max.tv_usec = 0;
	ss_count_tot = s_count_tot = s_diff_tot = 0;

	found = false;
	while (ss_item && sharesummary->workinfoid < workinfoid) {
		if (sharesummary->complete[0] == SUMMARY_NEW) {
			age_id = sharesummary->workinfoid;
			prev_found = age_id;
			found = true;
			break;
		}
		ss_item = next_in_ktree(ctx);
		DATA_SHARESUMMARY_NULL(sharesummary, ss_item);
	}
	K_RUNLOCK(sharesummary_free);

	LOGDEBUG("%s(): age_id=%"PRId64" found=%d", __func__, age_id, found);
	// Don't repeat searching old items to avoid accessing their ram
	if (!found)
		prev_found = workinfoid;
	else {
		/* Process all the consecutive sharesummaries that's aren't aged
		 * This way we find each oldest 'batch' of sharesummaries that have
		 *  been missed and can report the range of data that was aged,
		 *  which would normally just be an approx 10min set of workinfoids
		 *  from the last time ckpool stopped
		 * Each next group of unaged sharesummaries following this, will be
		 *  picked up by each next aging */
		wid_count = 0;
		do_id = age_id;
		to_id = 0;
		do {
			ok = workinfo_age(conn, do_id, poolinstance,
						by, code, inet, cd,
						&ss_first, &ss_last,
						&ss_count, &s_count, &s_diff);

			ss_count_tot += ss_count;
			s_count_tot += s_count;
			s_diff_tot += s_diff;
			if (ss_first_min.tv_sec == 0 || !tv_newer(&ss_first_min, &ss_first))
				copy_tv(&ss_first_min, &ss_first);
			if (tv_newer(&ss_last_max, &ss_last))
				copy_tv(&ss_last_max, &ss_last);

			if (!ok)
				break;

			to_id = do_id;
			wid_count++;
			K_RLOCK(sharesummary_free);
			while (ss_item && sharesummary->workinfoid == to_id) {
				ss_item = next_in_ktree(ctx);
				DATA_SHARESUMMARY_NULL(sharesummary, ss_item);
			}
			K_RUNLOCK(sharesummary_free);

			if (ss_item) {
				do_id = sharesummary->workinfoid;
				if (do_id >= workinfoid)
					break;
				if (sharesummary->complete[0] != SUMMARY_NEW)
					break;
			}
		} while (ss_item);
		if (to_id == 0) {
			if (last_attempted_id != age_id || ++repeat >= 10) {
				// Approx once every 5min since workinfo defaults to ~30s
				LOGWARNING("%s() Auto-age failed to age %"PRId64,
					   __func__, age_id);
				last_attempted_id = age_id;
				repeat = 0;
			}
		} else {
			char idrange[64];
			char sharerange[256];
			if (to_id != age_id) {
				snprintf(idrange, sizeof(idrange),
					 "from %"PRId64" to %"PRId64,
					 age_id, to_id);
			} else {
				snprintf(idrange, sizeof(idrange),
					 "%"PRId64, age_id);
			}
			tv_to_buf(&ss_first_min, min_buf, sizeof(min_buf));
			if (tv_equal(&ss_first_min, &ss_last_max)) {
				snprintf(sharerange, sizeof(sharerange),
					 "share date %s", min_buf);
			} else {
				tv_to_buf(&ss_last_max, max_buf, sizeof(max_buf));
				snprintf(sharerange, sizeof(sharerange),
					 "share dates %s to %s",
					 min_buf, max_buf);
			}
			LOGWARNING("%s() Auto-aged %"PRId64"(%"PRId64") "
				   "share%s %d sharesummar%s %d workinfoid%s "
				   "%s %s",
				   __func__,
				   s_count_tot, s_diff_tot,
				   (s_count_tot == 1) ? "" : "s",
				   ss_count_tot,
				   (ss_count_tot == 1) ? "y" : "ies",
				   wid_count,
				   (wid_count == 1) ? "" : "s",
				   idrange, sharerange);
		}
	}
}

static bool workinfo_fill(PGconn *conn)
{
	ExecStatusType rescode;
	PGresult *res;
	K_ITEM *item;
	WORKINFO *row;
	char *params[1];
	int n, i, par = 0;
	char *field;
	char *sel;
	int fields = 10;
	bool ok;

	LOGDEBUG("%s(): select", __func__);

	// TODO: select the data based on sharesummary since old data isn't needed
	//  however, the ageing rules for workinfo will decide that also
	//  keep the last block + current? Rules will depend on payout scheme also
	sel = "select "
//		"workinfoid,poolinstance,transactiontree,merklehash,prevhash,"
		"workinfoid,poolinstance,merklehash,prevhash,"
		"coinbase1,coinbase2,version,bits,ntime,reward"
		HISTORYDATECONTROL
		" from workinfo where expirydate=$1";
	par = 0;
	params[par++] = tv_to_buf((tv_t *)(&default_expiry), NULL, 0);
	PARCHK(par, params);
	res = PQexecParams(conn, sel, par, NULL, (const char **)params, NULL, NULL, 0, CKPQ_READ);
	rescode = PQresultStatus(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Select", rescode, conn);
		PQclear(res);
		return false;
	}

	n = PQnfields(res);
	if (n != (fields + HISTORYDATECOUNT)) {
		LOGERR("%s(): Invalid field count - should be %d, but is %d",
			__func__, fields + HISTORYDATECOUNT, n);
		PQclear(res);
		return false;
	}

	n = PQntuples(res);
	LOGDEBUG("%s(): tree build count %d", __func__, n);
	ok = true;
	K_WLOCK(workinfo_free);
	for (i = 0; i < n; i++) {
		item = k_unlink_head(workinfo_free);
		DATA_WORKINFO(row, item);

		if (everyone_die) {
			ok = false;
			break;
		}

		PQ_GET_FLD(res, i, "workinfoid", field, ok);
		if (!ok)
			break;
		TXT_TO_BIGINT("workinfoid", field, row->workinfoid);

		PQ_GET_FLD(res, i, "poolinstance", field, ok);
		if (!ok)
			break;
		TXT_TO_STR("poolinstance", field, row->poolinstance);

/* Not currently needed in RAM
		PQ_GET_FLD(res, i, "transactiontree", field, ok);
		if (!ok)
			break;
		TXT_TO_BLOB("transactiontree", field, row->transactiontree);
*/
		row->transactiontree = strdup(EMPTY);

		PQ_GET_FLD(res, i, "merklehash", field, ok);
		if (!ok)
			break;
		TXT_TO_BLOB("merklehash", field, row->merklehash);

		PQ_GET_FLD(res, i, "prevhash", field, ok);
		if (!ok)
			break;
		TXT_TO_STR("prevhash", field, row->prevhash);

		PQ_GET_FLD(res, i, "coinbase1", field, ok);
		if (!ok)
			break;
		TXT_TO_STR("coinbase1", field, row->coinbase1);

		PQ_GET_FLD(res, i, "coinbase2", field, ok);
		if (!ok)
			break;
		TXT_TO_STR("coinbase2", field, row->coinbase2);

		PQ_GET_FLD(res, i, "version", field, ok);
		if (!ok)
			break;
		TXT_TO_STR("version", field, row->version);

		PQ_GET_FLD(res, i, "bits", field, ok);
		if (!ok)
			break;
		TXT_TO_STR("bits", field, row->bits);

		PQ_GET_FLD(res, i, "ntime", field, ok);
		if (!ok)
			break;
		TXT_TO_STR("ntime", field, row->ntime);

		PQ_GET_FLD(res, i, "reward", field, ok);
		if (!ok)
			break;
		TXT_TO_BIGINT("reward", field, row->reward);

		HISTORYDATEFLDS(res, i, row, ok);
		if (!ok)
			break;

		workinfo_root = add_to_ktree(workinfo_root, item, cmp_workinfo);
		if (!confirm_sharesummary)
			workinfo_height_root = add_to_ktree(workinfo_height_root, item, cmp_workinfo_height);
		k_add_head(workinfo_store, item);

		if (tv_newer(&(dbstatus.newest_createdate_workinfo), &(row->createdate)))
			copy_tv(&(dbstatus.newest_createdate_workinfo), &(row->createdate));

		tick();
	}
	if (!ok)
		k_add_head(workinfo_free, item);

	K_WUNLOCK(workinfo_free);
	PQclear(res);

	if (ok) {
		LOGDEBUG("%s(): built", __func__);
		LOGWARNING("%s(): loaded %d workinfo records", __func__, n);
	}

	return ok;
}

void workinfo_reload()
{
	// TODO: ??? a bad idea?
/*
	PGconn *conn = dbconnect();

	K_WLOCK(workinfo_free);
	workinfo_root = free_ktree(workinfo_root, ???); free transactiontree and merklehash
	k_list_transfer_to_head(workinfo_store, workinfo_free);
	K_WUNLOCK(workinfo_free);

	workinfo_fill(conn);

	PQfinish(conn);
*/
}

// order by workinfoid asc,userid asc,workername asc,createdate asc,nonce asc,expirydate desc
static cmp_t cmp_shares(K_ITEM *a, K_ITEM *b)
{
	SHARES *sa, *sb;
	DATA_SHARES(sa, a);
	DATA_SHARES(sb, b);
	cmp_t c = CMP_BIGINT(sa->workinfoid, sb->workinfoid);
	if (c == 0) {
		c = CMP_BIGINT(sa->userid, sb->userid);
		if (c == 0) {
			c = CMP_STR(sa->workername, sb->workername);
			if (c == 0) {
				c = CMP_TV(sa->createdate, sb->createdate);
				if (c == 0) {
					c = CMP_STR(sa->nonce, sb->nonce);
					if (c == 0) {
						c = CMP_TV(sb->expirydate,
							   sa->expirydate);
					}
				}
			}
		}
	}
	return c;
}

static void zero_sharesummary(SHARESUMMARY *row, tv_t *cd, double diff)
{
	row->diffacc = row->diffsta = row->diffdup = row->diffhi =
	row->diffrej = row->shareacc = row->sharesta = row->sharedup =
	row->sharehi = row->sharerej = 0.0;
	row->sharecount = row->errorcount = row->countlastupdate = 0;
	row->reset = false;
	row->firstshare.tv_sec = cd->tv_sec;
	row->firstshare.tv_usec = cd->tv_usec;
	row->lastshare.tv_sec = row->firstshare.tv_sec;
	row->lastshare.tv_usec = row->firstshare.tv_usec;
	row->lastdiffacc = diff;
	row->complete[0] = SUMMARY_NEW;
	row->complete[1] = '\0';
}

static K_ITEM *find_sharesummary(int64_t userid, char *workername, int64_t workinfoid);

// Memory (and log file) only
static bool shares_add(PGconn *conn, char *workinfoid, char *username, char *workername,
			char *clientid, char *errn, char *enonce1, char *nonce2,
			char *nonce, char *diff, char *sdiff, char *secondaryuserid,
			char *by, char *code, char *inet, tv_t *cd, K_TREE *trf_root)
{
	K_ITEM *s_item, *u_item, *wi_item, *w_item, *ss_item;
	char cd_buf[DATE_BUFSIZ];
	SHARESUMMARY *sharesummary;
	SHARES *shares;
	USERS *users;
	bool ok = false;

	LOGDEBUG("%s(): add", __func__);

	K_WLOCK(shares_free);
	s_item = k_unlink_head(shares_free);
	K_WUNLOCK(shares_free);

	DATA_SHARES(shares, s_item);

	K_RLOCK(users_free);
	u_item = find_users(username);
	K_RUNLOCK(users_free);
	if (!u_item) {
		tv_to_buf(cd, cd_buf, sizeof(cd_buf));
		LOGERR("%s() %s/%ld,%ld %.19s no user! Share discarded!",
			__func__, username,
			cd->tv_sec, cd->tv_usec, cd_buf);
		goto unitem;
	}
	DATA_USERS(users, u_item);

	shares->userid = users->userid;

	TXT_TO_BIGINT("workinfoid", workinfoid, shares->workinfoid);
	STRNCPY(shares->workername, workername);
	TXT_TO_INT("clientid", clientid, shares->clientid);
	TXT_TO_INT("errn", errn, shares->errn);
	STRNCPY(shares->enonce1, enonce1);
	STRNCPY(shares->nonce2, nonce2);
	STRNCPY(shares->nonce, nonce);
	TXT_TO_DOUBLE("diff", diff, shares->diff);
	TXT_TO_DOUBLE("sdiff", sdiff, shares->sdiff);
	STRNCPY(shares->secondaryuserid, secondaryuserid);

	if (!(*secondaryuserid)) {
		STRNCPY(shares->secondaryuserid, users->secondaryuserid);
		if (!tv_newer(&missing_secuser_min, cd) ||
		    !tv_newer(cd, &missing_secuser_max)) {
			tv_to_buf(cd, cd_buf, sizeof(cd_buf));
			LOGERR("%s() %s/%ld,%ld %.19s missing secondaryuserid! "
				"Share corrected",
				__func__, username,
				cd->tv_sec, cd->tv_usec, cd_buf);
		}
	}

	HISTORYDATEINIT(shares, cd, by, code, inet);
	HISTORYDATETRANSFER(trf_root, shares);

	wi_item = find_workinfo(shares->workinfoid);
	if (!wi_item) {
		tv_to_buf(cd, cd_buf, sizeof(cd_buf));
		LOGERR("%s() %"PRId64"/%s/%ld,%ld %.19s no workinfo! Share discarded!",
			__func__, shares->workinfoid, workername,
			cd->tv_sec, cd->tv_usec, cd_buf);
		goto unitem;
	}

	w_item = new_default_worker(conn, false, shares->userid, shares->workername,
					by, code, inet, cd, trf_root);
	if (!w_item)
		goto unitem;

	if (reloading && !confirm_sharesummary) {
		ss_item = find_sharesummary(shares->userid, shares->workername, shares->workinfoid);
		if (ss_item) {
			DATA_SHARESUMMARY(sharesummary, ss_item);
			if (sharesummary->complete[0] != SUMMARY_NEW) {
				K_WLOCK(shares_free);
				k_add_head(shares_free, s_item);
				K_WUNLOCK(shares_free);
				return true;
			}

			if (!sharesummary->reset) {
				zero_sharesummary(sharesummary, cd, shares->diff);
				sharesummary->reset = true;
			}
		}
	}

	if (!confirm_sharesummary)
		workerstatus_update(NULL, shares, NULL);

	sharesummary_update(conn, shares, NULL, NULL, by, code, inet, cd);

	ok = true;
unitem:
	K_WLOCK(shares_free);
	if (!ok)
		k_add_head(shares_free, s_item);
	else {
		shares_root = add_to_ktree(shares_root, s_item, cmp_shares);
		k_add_head(shares_store, s_item);
	}
	K_WUNLOCK(shares_free);

	return ok;
}

static bool shares_fill()
{
	return true;
}

// order by workinfoid asc,userid asc,createdate asc,nonce asc,expirydate desc
static cmp_t cmp_shareerrors(K_ITEM *a, K_ITEM *b)
{
	SHAREERRORS *sa, *sb;
	DATA_SHAREERRORS(sa, a);
	DATA_SHAREERRORS(sb, b);
	cmp_t c = CMP_BIGINT(sa->workinfoid, sb->workinfoid);
	if (c == 0) {
		c = CMP_BIGINT(sa->userid, sb->userid);
		if (c == 0) {
			c = CMP_TV(sa->createdate, sb->createdate);
			if (c == 0)
				c = CMP_TV(sb->expirydate, sa->expirydate);
		}
	}
	return c;
}

// Memory (and log file) only
// TODO: handle shareerrors that appear after a workinfoid is aged or doesn't exist?
static bool shareerrors_add(PGconn *conn, char *workinfoid, char *username,
				char *workername, char *clientid, char *errn,
				char *error, char *secondaryuserid, char *by,
				char *code, char *inet, tv_t *cd, K_TREE *trf_root)
{
	K_ITEM *s_item, *u_item, *wi_item, *w_item, *ss_item;
	char cd_buf[DATE_BUFSIZ];
	SHARESUMMARY *sharesummary;
	SHAREERRORS *shareerrors;
	USERS *users;
	bool ok = false;

	LOGDEBUG("%s(): add", __func__);

	K_WLOCK(shareerrors_free);
	s_item = k_unlink_head(shareerrors_free);
	K_WUNLOCK(shareerrors_free);

	DATA_SHAREERRORS(shareerrors, s_item);

	K_RLOCK(users_free);
	u_item = find_users(username);
	K_RUNLOCK(users_free);
	if (!u_item) {
		tv_to_buf(cd, cd_buf, sizeof(cd_buf));
		LOGERR("%s() %s/%ld,%ld %.19s no user! Shareerror discarded!",
			__func__, username,
			cd->tv_sec, cd->tv_usec, cd_buf);
		goto unitem;
	}
	DATA_USERS(users, u_item);

	shareerrors->userid = users->userid;

	TXT_TO_BIGINT("workinfoid", workinfoid, shareerrors->workinfoid);
	STRNCPY(shareerrors->workername, workername);
	TXT_TO_INT("clientid", clientid, shareerrors->clientid);
	TXT_TO_INT("errn", errn, shareerrors->errn);
	STRNCPY(shareerrors->error, error);
	STRNCPY(shareerrors->secondaryuserid, secondaryuserid);

	if (!(*secondaryuserid)) {
		STRNCPY(shareerrors->secondaryuserid, users->secondaryuserid);
		if (!tv_newer(&missing_secuser_min, cd) ||
		    !tv_newer(cd, &missing_secuser_max)) {
			tv_to_buf(cd, cd_buf, sizeof(cd_buf));
			LOGERR("%s() %s/%ld,%ld %.19s missing secondaryuserid! "
				"Sharerror corrected",
				__func__, username,
				cd->tv_sec, cd->tv_usec, cd_buf);
		}
	}

	HISTORYDATEINIT(shareerrors, cd, by, code, inet);
	HISTORYDATETRANSFER(trf_root, shareerrors);

	wi_item = find_workinfo(shareerrors->workinfoid);
	if (!wi_item) {
		tv_to_buf(cd, cd_buf, sizeof(cd_buf));
		LOGERR("%s() %"PRId64"/%s/%ld,%ld %.19s no workinfo! Shareerror discarded!",
			__func__, shareerrors->workinfoid, workername,
			cd->tv_sec, cd->tv_usec, cd_buf);
		goto unitem;
	}

	w_item = new_default_worker(NULL, false, shareerrors->userid, shareerrors->workername,
					by, code, inet, cd, trf_root);
	if (!w_item)
		goto unitem;

	if (reloading && !confirm_sharesummary) {
		ss_item = find_sharesummary(shareerrors->userid, shareerrors->workername, shareerrors->workinfoid);
		if (ss_item) {
			DATA_SHARESUMMARY(sharesummary, ss_item);
			if (sharesummary->complete[0] != SUMMARY_NEW) {
				K_WLOCK(shareerrors_free);
				k_add_head(shareerrors_free, s_item);
				K_WUNLOCK(shareerrors_free);
				return true;
			}

			if (!sharesummary->reset) {
				zero_sharesummary(sharesummary, cd, 0.0);
				sharesummary->reset = true;
			}
		}
	}

	sharesummary_update(conn, NULL, shareerrors, NULL, by, code, inet, cd);

	ok = true;
unitem:
	K_WLOCK(shareerrors_free);
	if (!ok)
		k_add_head(shareerrors_free, s_item);
	else {
		shareerrors_root = add_to_ktree(shareerrors_root, s_item, cmp_shareerrors);
		k_add_head(shareerrors_store, s_item);
	}
	K_WUNLOCK(shareerrors_free);

	return ok;
}

static bool shareerrors_fill()
{
	return true;
}

static void dsp_sharesummary(K_ITEM *item, FILE *stream)
{
	char createdate_buf[DATE_BUFSIZ];
	SHARESUMMARY *s;

	if (!item)
		fprintf(stream, "%s() called with (null) item\n", __func__);
	else {
		DATA_SHARESUMMARY(s, item);

		tv_to_buf(&(s->createdate), createdate_buf, sizeof(createdate_buf));
		fprintf(stream, " uid=%"PRId64" wn='%s' wid=%"PRId64" "
				"da=%f ds=%f ss=%f c='%s' cd=%s\n",
				s->userid, s->workername, s->workinfoid,
				s->diffacc, s->diffsta, s->sharesta,
				s->complete, createdate_buf);
	}
}

// default tree order by userid asc,workername asc,workinfoid asc for reporting
static cmp_t cmp_sharesummary(K_ITEM *a, K_ITEM *b)
{
	SHARESUMMARY *sa, *sb;
	DATA_SHARESUMMARY(sa, a);
	DATA_SHARESUMMARY(sb, b);
	cmp_t c = CMP_BIGINT(sa->userid, sb->userid);
	if (c == 0) {
		c = CMP_STR(sa->workername, sb->workername);
		if (c == 0)
			c = CMP_BIGINT(sa->workinfoid, sb->workinfoid);
	}
	return c;
}

// order by workinfoid asc,userid asc,workername asc for flagging complete
static cmp_t cmp_sharesummary_workinfoid(K_ITEM *a, K_ITEM *b)
{
	SHARESUMMARY *sa, *sb;
	DATA_SHARESUMMARY(sa, a);
	DATA_SHARESUMMARY(sb, b);
	cmp_t c = CMP_BIGINT(sa->workinfoid, sb->workinfoid);
	if (c == 0) {
		c = CMP_BIGINT(sa->userid, sb->userid);
		if (c == 0)
			c = CMP_STR(sa->workername, sb->workername);
	}
	return c;
}

static K_ITEM *find_sharesummary(int64_t userid, char *workername, int64_t workinfoid)
{
	SHARESUMMARY sharesummary;
	K_TREE_CTX ctx[1];
	K_ITEM look;

	sharesummary.userid = userid;
	STRNCPY(sharesummary.workername, workername);
	sharesummary.workinfoid = workinfoid;

	INIT_SHARESUMMARY(&look);
	look.data = (void *)(&sharesummary);
	return find_in_ktree(sharesummary_root, &look, cmp_sharesummary, ctx);
}

static bool _sharesummary_update(PGconn *conn, SHARES *s_row, SHAREERRORS *e_row, K_ITEM *ss_item,
				char *by, char *code, char *inet, tv_t *cd, WHERE_FFL_ARGS)
{
	ExecStatusType rescode;
	PGresult *res = NULL;
	SHARESUMMARY *row;
	K_ITEM *item;
	char *ins, *upd;
	bool ok = false, new;
	char *params[19 + MODIFYDATECOUNT];
	int n, par = 0;
	int64_t userid, workinfoid;
	char *workername;
	tv_t *sharecreatedate;
	bool must_update = false, conned = false;
	double diff = 0;

	LOGDEBUG("%s(): update", __func__);

	if (ss_item) {
		if (s_row || e_row) {
			quithere(1, "ERR: only one of s_row, e_row and "
				    "ss_item allowed" WHERE_FFL,
				    WHERE_FFL_PASS);
		}
		new = false;
		item = ss_item;
		DATA_SHARESUMMARY(row, item);
		must_update = true;
		row->complete[0] = SUMMARY_COMPLETE;
		row->complete[1] = '\0';
	} else {
		if (s_row) {
			if (e_row) {
				quithere(1, "ERR: only one of s_row, e_row "
					    "(and ss_item) allowed" WHERE_FFL,
					    WHERE_FFL_PASS);
			}
			userid = s_row->userid;
			workername = s_row->workername;
			workinfoid = s_row->workinfoid;
			diff = s_row->diff;
			sharecreatedate = &(s_row->createdate);
		} else {
			if (!e_row) {
				quithere(1, "ERR: all s_row, e_row and "
					    "ss_item are NULL" WHERE_FFL,
					    WHERE_FFL_PASS);
			}
			userid = e_row->userid;
			workername = e_row->workername;
			workinfoid = e_row->workinfoid;
			sharecreatedate = &(e_row->createdate);
		}

		K_RLOCK(sharesummary_free);
		item = find_sharesummary(userid, workername, workinfoid);
		K_RUNLOCK(sharesummary_free);
		if (item) {
			new = false;
			DATA_SHARESUMMARY(row, item);
		} else {
			new = true;
			K_WLOCK(sharesummary_free);
			item = k_unlink_head(sharesummary_free);
			K_WUNLOCK(sharesummary_free);
			DATA_SHARESUMMARY(row, item);
			row->userid = userid;
			STRNCPY(row->workername, workername);
			row->workinfoid = workinfoid;
			zero_sharesummary(row, sharecreatedate, diff);
			row->inserted = false;
			row->saveaged = false;
		}

		if (e_row)
			row->errorcount += 1;
		else {
			row->sharecount += 1;
			switch (s_row->errn) {
				case SE_NONE:
					row->diffacc += s_row->diff;
					row->shareacc++;
					break;
				case SE_STALE:
					row->diffsta += s_row->diff;
					row->sharesta++;
					break;
				case SE_DUPE:
					row->diffdup += s_row->diff;
					row->sharedup++;
					break;
				case SE_HIGH_DIFF:
					row->diffhi += s_row->diff;
					row->sharehi++;
					break;
				default:
					row->diffrej += s_row->diff;
					row->sharerej++;
					break;
			}
		}

		if (!new) {
			double td;
			td = tvdiff(sharecreatedate, &(row->firstshare));
			// don't LOGERR '=' in case shares come from ckpool with the same timestamp
			if (td < 0.0) {
				char *tmp1, *tmp2;
				LOGERR("%s(): %s createdate (%s) is < summary firstshare (%s)",
					__func__, s_row ? "shares" : "shareerrors",
					(tmp1 = ctv_to_buf(sharecreatedate, NULL, 0)),
					(tmp2 = ctv_to_buf(&(row->firstshare), NULL, 0)));
				free(tmp2);
				free(tmp1);
				row->firstshare.tv_sec = sharecreatedate->tv_sec;
				row->firstshare.tv_usec = sharecreatedate->tv_usec;
				// Don't change lastdiffacc
			}
			td = tvdiff(sharecreatedate, &(row->lastshare));
			// don't LOGERR '=' in case shares come from ckpool with the same timestamp
			if (td >= 0.0) {
				row->lastshare.tv_sec = sharecreatedate->tv_sec;
				row->lastshare.tv_usec = sharecreatedate->tv_usec;
				row->lastdiffacc = diff;
			} else {
				char *tmp1, *tmp2;
				LOGERR("%s(): %s createdate (%s) is < summary lastshare (%s)",
					__func__, s_row ? "shares" : "shareerrors",
					(tmp1 = ctv_to_buf(sharecreatedate, NULL, 0)),
					(tmp2 = ctv_to_buf(&(row->lastshare), NULL, 0)));
				free(tmp2);
				free(tmp1);
			}
			if (row->complete[0] != SUMMARY_NEW) {
				LOGDEBUG("%s(): updating sharesummary not '%c' %"PRId64"/%s/%"PRId64"/%s",
					__func__, SUMMARY_NEW, row->userid, row->workername,
					row->workinfoid, row->complete);
			}
		}
	}

	// During startup, don't save 'new' sharesummaries, to reduce DB I/O
	if (!startup_complete && row->complete[0] == SUMMARY_NEW)
		goto startupskip;

	if (conn == NULL && !confirm_sharesummary) {
		conn = dbconnect();
		conned = true;
	}

	if (new || !(row->inserted)) {
		MODIFYDATEINIT(row, cd, by, code, inet);

		if (!confirm_sharesummary) {
			par = 0;
			params[par++] = bigint_to_buf(row->userid, NULL, 0);
			params[par++] = str_to_buf(row->workername, NULL, 0);
			params[par++] = bigint_to_buf(row->workinfoid, NULL, 0);
			params[par++] = double_to_buf(row->diffacc, NULL, 0);
			params[par++] = double_to_buf(row->diffsta, NULL, 0);
			params[par++] = double_to_buf(row->diffdup, NULL, 0);
			params[par++] = double_to_buf(row->diffhi, NULL, 0);
			params[par++] = double_to_buf(row->diffrej, NULL, 0);
			params[par++] = double_to_buf(row->shareacc, NULL, 0);
			params[par++] = double_to_buf(row->sharesta, NULL, 0);
			params[par++] = double_to_buf(row->sharedup, NULL, 0);
			params[par++] = double_to_buf(row->sharehi, NULL, 0);
			params[par++] = double_to_buf(row->sharerej, NULL, 0);
			params[par++] = bigint_to_buf(row->sharecount, NULL, 0);
			params[par++] = bigint_to_buf(row->errorcount, NULL, 0);
			params[par++] = tv_to_buf(&(row->firstshare), NULL, 0);
			params[par++] = tv_to_buf(&(row->lastshare), NULL, 0);
			params[par++] = double_to_buf(row->lastdiffacc, NULL, 0);
			params[par++] = str_to_buf(row->complete, NULL, 0);
			MODIFYDATEPARAMS(params, par, row);
			PARCHK(par, params);

			ins = "insert into sharesummary "
				"(userid,workername,workinfoid,diffacc,diffsta,diffdup,diffhi,"
				"diffrej,shareacc,sharesta,sharedup,sharehi,sharerej,"
				"sharecount,errorcount,firstshare,lastshare,"
				"lastdiffacc,complete"
				MODIFYDATECONTROL ") values (" PQPARAM27 ")";

			res = PQexecParams(conn, ins, par, NULL, (const char **)params, NULL, NULL, 0, CKPQ_WRITE);
			rescode = PQresultStatus(res);
			if (!PGOK(rescode)) {
				PGLOGERR("Insert", rescode, conn);
				goto unparam;
			}
		}

		row->countlastupdate = row->sharecount + row->errorcount;
		row->inserted = true;
		if (row->complete[0] == SUMMARY_COMPLETE)
			row->saveaged = true;
	} else {
		bool stats_update = false;

		MODIFYUPDATE(row, cd, by, code, inet);

		if ((row->countlastupdate + SHARESUMMARY_UPDATE_EVERY) <
		    (row->sharecount + row->errorcount))
			stats_update = true;

		if (must_update && row->countlastupdate < (row->sharecount + row->errorcount))
			stats_update = true;

		if (stats_update) {
			if (!confirm_sharesummary) {
				par = 0;
				params[par++] = bigint_to_buf(row->userid, NULL, 0);
				params[par++] = str_to_buf(row->workername, NULL, 0);
				params[par++] = bigint_to_buf(row->workinfoid, NULL, 0);
				params[par++] = double_to_buf(row->diffacc, NULL, 0);
				params[par++] = double_to_buf(row->diffsta, NULL, 0);
				params[par++] = double_to_buf(row->diffdup, NULL, 0);
				params[par++] = double_to_buf(row->diffhi, NULL, 0);
				params[par++] = double_to_buf(row->diffrej, NULL, 0);
				params[par++] = double_to_buf(row->shareacc, NULL, 0);
				params[par++] = double_to_buf(row->sharesta, NULL, 0);
				params[par++] = double_to_buf(row->sharedup, NULL, 0);
				params[par++] = double_to_buf(row->sharehi, NULL, 0);
				params[par++] = double_to_buf(row->sharerej, NULL, 0);
				params[par++] = tv_to_buf(&(row->firstshare), NULL, 0);
				params[par++] = tv_to_buf(&(row->lastshare), NULL, 0);
				params[par++] = bigint_to_buf(row->sharecount, NULL, 0);
				params[par++] = bigint_to_buf(row->errorcount, NULL, 0);
				params[par++] = double_to_buf(row->lastdiffacc, NULL, 0);
				params[par++] = str_to_buf(row->complete, NULL, 0);
				MODIFYUPDATEPARAMS(params, par, row);
				PARCHKVAL(par, 23, params);

				upd = "update sharesummary "
					"set diffacc=$4,diffsta=$5,diffdup=$6,diffhi=$7,diffrej=$8,"
					"shareacc=$9,sharesta=$10,sharedup=$11,sharehi=$12,"
					"sharerej=$13,firstshare=$14,lastshare=$15,"
					"sharecount=$16,errorcount=$17,lastdiffacc=$18,complete=$19"
					",modifydate=$20,modifyby=$21,modifycode=$22,modifyinet=$23 "
					"where userid=$1 and workername=$2 and workinfoid=$3";

				res = PQexecParams(conn, upd, par, NULL, (const char **)params, NULL, NULL, 0, CKPQ_WRITE);
				rescode = PQresultStatus(res);
				if (!PGOK(rescode)) {
					PGLOGERR("Update", rescode, conn);
					goto unparam;
				}
			}
			row->countlastupdate = row->sharecount + row->errorcount;
			if (row->complete[0] == SUMMARY_COMPLETE)
				row->saveaged = true;
		} else {
			if (!must_update) {
				ok = true;
				goto late;
			} else {
				if (!confirm_sharesummary) {
					par = 0;
					params[par++] = bigint_to_buf(row->userid, NULL, 0);
					params[par++] = str_to_buf(row->workername, NULL, 0);
					params[par++] = bigint_to_buf(row->workinfoid, NULL, 0);
					params[par++] = str_to_buf(row->complete, NULL, 0);
					MODIFYUPDATEPARAMS(params, par, row);
					PARCHKVAL(par, 8, params);

					upd = "update sharesummary "
						"set complete=$4,modifydate=$5,modifyby=$6,modifycode=$7,modifyinet=$8 "
						"where userid=$1 and workername=$2 and workinfoid=$3";

					res = PQexecParams(conn, upd, par, NULL, (const char **)params, NULL, NULL, 0, CKPQ_WRITE);
					rescode = PQresultStatus(res);
					if (!PGOK(rescode)) {
						PGLOGERR("MustUpdate", rescode, conn);
						goto unparam;
					}
				}
				row->countlastupdate = row->sharecount + row->errorcount;
				if (row->complete[0] == SUMMARY_COMPLETE)
					row->saveaged = true;
			}
		}
	}
startupskip:
	ok = true;
unparam:
	if (par) {
		PQclear(res);
		for (n = 0; n < par; n++)
			free(params[n]);
	}
late:
	if (conned)
		PQfinish(conn);

	// We keep the new item no matter what 'ok' is, since it will be inserted later
	K_WLOCK(sharesummary_free);
	if (new) {
		sharesummary_root = add_to_ktree(sharesummary_root, item, cmp_sharesummary);
		sharesummary_workinfoid_root = add_to_ktree(sharesummary_workinfoid_root,
							    item,
							    cmp_sharesummary_workinfoid);
		k_add_head(sharesummary_store, item);
	}
	K_WUNLOCK(sharesummary_free);

	return ok;
}

static bool sharesummary_fill(PGconn *conn)
{
	ExecStatusType rescode;
	PGresult *res;
	K_ITEM *item;
	int n, i;
	SHARESUMMARY *row;
	char *field;
	char *sel;
	int fields = 19;
	bool ok;

	LOGDEBUG("%s(): select", __func__);

	// TODO: limit how far back
	sel = "select "
		"userid,workername,workinfoid,diffacc,diffsta,diffdup,diffhi,"
		"diffrej,shareacc,sharesta,sharedup,sharehi,sharerej,"
		"sharecount,errorcount,firstshare,lastshare,"
		"lastdiffacc,complete"
		MODIFYDATECONTROL
		" from sharesummary";
	res = PQexec(conn, sel, CKPQ_READ);
	rescode = PQresultStatus(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Select", rescode, conn);
		PQclear(res);
		return false;
	}

	n = PQnfields(res);
	if (n != (fields + MODIFYDATECOUNT)) {
		LOGERR("%s(): Invalid field count - should be %d, but is %d",
			__func__, fields + MODIFYDATECOUNT, n);
		PQclear(res);
		return false;
	}

	n = PQntuples(res);
	LOGDEBUG("%s(): tree build count %d", __func__, n);
	ok = true;
	for (i = 0; i < n; i++) {
		item = k_unlink_head(sharesummary_free);
		DATA_SHARESUMMARY(row, item);

		if (everyone_die) {
			ok = false;
			break;
		}

		row->inserted = true;

		PQ_GET_FLD(res, i, "userid", field, ok);
		if (!ok)
			break;
		TXT_TO_BIGINT("userid", field, row->userid);

		PQ_GET_FLD(res, i, "workername", field, ok);
		if (!ok)
			break;
		TXT_TO_STR("workername", field, row->workername);

		PQ_GET_FLD(res, i, "workinfoid", field, ok);
		if (!ok)
			break;
		TXT_TO_BIGINT("workinfoid", field, row->workinfoid);

		PQ_GET_FLD(res, i, "diffacc", field, ok);
		if (!ok)
			break;
		TXT_TO_DOUBLE("diffacc", field, row->diffacc);

		PQ_GET_FLD(res, i, "diffsta", field, ok);
		if (!ok)
			break;
		TXT_TO_DOUBLE("diffsta", field, row->diffsta);

		PQ_GET_FLD(res, i, "diffdup", field, ok);
		if (!ok)
			break;
		TXT_TO_DOUBLE("diffdup", field, row->diffdup);

		PQ_GET_FLD(res, i, "diffhi", field, ok);
		if (!ok)
			break;
		TXT_TO_DOUBLE("diffhi", field, row->diffhi);

		PQ_GET_FLD(res, i, "diffrej", field, ok);
		if (!ok)
			break;
		TXT_TO_DOUBLE("diffrej", field, row->diffrej);

		PQ_GET_FLD(res, i, "shareacc", field, ok);
		if (!ok)
			break;
		TXT_TO_DOUBLE("shareacc", field, row->shareacc);

		PQ_GET_FLD(res, i, "sharesta", field, ok);
		if (!ok)
			break;
		TXT_TO_DOUBLE("sharesta", field, row->sharesta);

		PQ_GET_FLD(res, i, "sharedup", field, ok);
		if (!ok)
			break;
		TXT_TO_DOUBLE("sharedup", field, row->sharedup);

		PQ_GET_FLD(res, i, "sharehi", field, ok);
		if (!ok)
			break;
		TXT_TO_DOUBLE("sharehi", field, row->sharehi);

		PQ_GET_FLD(res, i, "sharerej", field, ok);
		if (!ok)
			break;
		TXT_TO_DOUBLE("sharerej", field, row->sharerej);

		PQ_GET_FLD(res, i, "sharecount", field, ok);
		if (!ok)
			break;
		TXT_TO_BIGINT("sharecount", field, row->sharecount);

		PQ_GET_FLD(res, i, "errorcount", field, ok);
		if (!ok)
			break;
		TXT_TO_BIGINT("errorcount", field, row->errorcount);

		row->countlastupdate = row->sharecount + row->errorcount;

		PQ_GET_FLD(res, i, "firstshare", field, ok);
		if (!ok)
			break;
		TXT_TO_TV("firstshare", field, row->firstshare);

		PQ_GET_FLD(res, i, "lastshare", field, ok);
		if (!ok)
			break;
		TXT_TO_TV("lastshare", field, row->lastshare);

		PQ_GET_FLD(res, i, "lastdiffacc", field, ok);
		if (!ok)
			break;
		TXT_TO_DOUBLE("lastdiffacc", field, row->lastdiffacc);

		PQ_GET_FLD(res, i, "complete", field, ok);
		if (!ok)
			break;
		TXT_TO_STR("complete", field, row->complete);

		MODIFYDATEFLDS(res, i, row, ok);
		if (!ok)
			break;

		sharesummary_root = add_to_ktree(sharesummary_root, item, cmp_sharesummary);
		sharesummary_workinfoid_root = add_to_ktree(sharesummary_workinfoid_root, item, cmp_sharesummary_workinfoid);
		k_add_head(sharesummary_store, item);

		// A share summary is currently only shares in a single workinfo, at all 3 levels n,a,y
		if (tolower(row->complete[0]) == SUMMARY_NEW) {
			if (dbstatus.oldest_sharesummary_firstshare_n.tv_sec == 0 ||
			    !tv_newer(&(dbstatus.oldest_sharesummary_firstshare_n), &(row->firstshare))) {
				copy_tv(&(dbstatus.oldest_sharesummary_firstshare_n), &(row->firstshare));
				dbstatus.oldest_workinfoid_n = row->workinfoid;
			}
		} else {
			if (tv_newer(&(dbstatus.newest_sharesummary_firstshare_ay), &(row->firstshare)))
				copy_tv(&(dbstatus.newest_sharesummary_firstshare_ay), &(row->firstshare));
			if (tolower(row->complete[0]) == SUMMARY_COMPLETE) {
				if (dbstatus.oldest_sharesummary_firstshare_a.tv_sec == 0 ||
				    !tv_newer(&(dbstatus.oldest_sharesummary_firstshare_a), &(row->firstshare))) {
					copy_tv(&(dbstatus.oldest_sharesummary_firstshare_a), &(row->firstshare));
					dbstatus.oldest_workinfoid_a = row->workinfoid;
				}
				if (tv_newer(&(dbstatus.newest_sharesummary_firstshare_a), &(row->firstshare))) {
					copy_tv(&(dbstatus.newest_sharesummary_firstshare_a), &(row->firstshare));
					dbstatus.newest_workinfoid_a = row->workinfoid;
				}
			} else /* SUMMARY_CONFIRM */ {
				if (tv_newer(&(dbstatus.newest_sharesummary_firstshare_y), &(row->firstshare))) {
					copy_tv(&(dbstatus.newest_sharesummary_firstshare_y), &(row->firstshare));
					dbstatus.newest_workinfoid_y = row->workinfoid;
				}
			}
		}

		tick();
	}
	if (!ok)
		k_add_head(sharesummary_free, item);

	PQclear(res);

	if (ok) {
		LOGDEBUG("%s(): built", __func__);
		LOGWARNING("%s(): loaded %d sharesummary records", __func__, n);
	}

	return ok;
}

void sharesummary_reload()
{
	PGconn *conn = dbconnect();

	sharesummary_root = free_ktree(sharesummary_root, NULL);
	sharesummary_workinfoid_root = free_ktree(sharesummary_workinfoid_root, NULL);
	k_list_transfer_to_head(sharesummary_store, sharesummary_free);

	sharesummary_fill(conn);

	PQfinish(conn);
}

// TODO: do this better ... :)
static void dsp_hash(char *hash, char *buf, size_t siz)
{
	char *ptr;

	ptr = hash + strlen(hash) - (siz - 1) - 8;
	if (ptr < hash)
		ptr = hash;
	STRNCPYSIZ(buf, ptr, siz);
}

static void dsp_blocks(K_ITEM *item, FILE *stream)
{
	char createdate_buf[DATE_BUFSIZ], expirydate_buf[DATE_BUFSIZ];
	BLOCKS *b = NULL;
	char hash_dsp[16+1];

	if (!item)
		fprintf(stream, "%s() called with (null) item\n", __func__);
	else {
		DATA_BLOCKS(b, item);

		dsp_hash(b->blockhash, hash_dsp, sizeof(hash_dsp));
		tv_to_buf(&(b->createdate), createdate_buf, sizeof(createdate_buf));
		tv_to_buf(&(b->expirydate), expirydate_buf, sizeof(expirydate_buf));
		fprintf(stream, " hi=%d hash='%.16s' conf=%s uid=%"PRId64
				" w='%s' sconf=%s cd=%s ed=%s\n",
				b->height, hash_dsp, b->confirmed, b->userid,
				b->workername, b->statsconfirmed,
				createdate_buf, expirydate_buf);
	}
}

// order by height asc,blockhash asc,expirydate desc
static cmp_t cmp_blocks(K_ITEM *a, K_ITEM *b)
{
	BLOCKS *ba, *bb;
	DATA_BLOCKS(ba, a);
	DATA_BLOCKS(bb, b);
	cmp_t c = CMP_INT(ba->height, bb->height);
	if (c == 0) {
		c = CMP_STR(ba->blockhash, bb->blockhash);
		if (c == 0)
			c = CMP_TV(bb->expirydate, ba->expirydate);
	}
	return c;
}

/* TODO: and make sure all block searches use these
 * or add new ones as required here */

// Must be R or W locked before call - gets current status (default_expiry)
static K_ITEM *find_blocks(int32_t height, char *blockhash)
{
	BLOCKS blocks;
	K_TREE_CTX ctx[1];
	K_ITEM look;

	blocks.height = height;
	STRNCPY(blocks.blockhash, blockhash);
	blocks.expirydate.tv_sec = default_expiry.tv_sec;
	blocks.expirydate.tv_usec = default_expiry.tv_usec;

	INIT_BLOCKS(&look);
	look.data = (void *)(&blocks);
	return find_in_ktree(blocks_root, &look, cmp_blocks, ctx);
}

// Must be R or W locked before call
static K_ITEM *find_prev_blocks(int32_t height)
{
	BLOCKS lookblocks, *blocks;
	K_TREE_CTX ctx[1];
	K_ITEM look, *b_item;

	/* TODO: For self orphaned (if that ever happens)
	 * this will find based on blockhash order if it has two,
	 * not NEW, blocks, which might not find the right one */
	lookblocks.height = height;
	lookblocks.blockhash[0] = '\0';
	lookblocks.expirydate.tv_sec = 0L;
	lookblocks.expirydate.tv_usec = 0L;

	INIT_BLOCKS(&look);
	look.data = (void *)(&lookblocks);
	b_item = find_before_in_ktree(blocks_root, &look, cmp_blocks, ctx);
	while (b_item) {
		DATA_BLOCKS(blocks, b_item);
		if (blocks->confirmed[0] != BLOCKS_NEW &&
		    CURRENT(&(blocks->expirydate)))
			return b_item;
		b_item = prev_in_ktree(ctx);
	}
	return NULL;
}

static const char *blocks_confirmed(char *confirmed)
{
	switch (confirmed[0]) {
		case BLOCKS_NEW:
			return blocks_new;
		case BLOCKS_CONFIRM:
			return blocks_confirm;
		case BLOCKS_42:
			return blocks_42;
		case BLOCKS_ORPHAN:
			return blocks_orphan;
	}
	return blocks_unknown;
}

static bool blocks_stats(PGconn *conn, int32_t height, char *blockhash,
			 double diffacc, double diffinv, double shareacc,
			 double shareinv, int64_t elapsed,
			 char *by, char *code, char *inet, tv_t *cd)
{
	ExecStatusType rescode;
	bool conned = false;
	PGresult *res = NULL;
	K_TREE_CTX ctx[1];
	K_ITEM *b_item, *old_b_item;
	BLOCKS *row, *oldblocks;
	char hash_dsp[16+1];
	char *upd, *ins;
	char *params[8 + HISTORYDATECOUNT];
	bool ok = false, update_old = false;
	int n, par = 0;

	LOGDEBUG("%s(): confirm", __func__);

	dsp_hash(blockhash, hash_dsp, sizeof(hash_dsp));

	K_RLOCK(blocks_free);
	old_b_item = find_blocks(height, blockhash);
	K_RUNLOCK(blocks_free);

	if (!old_b_item) {
		LOGERR("%s(): Non-existent Block: %d/...%s",
			__func__, height, hash_dsp);
		return false;
	}

	DATA_BLOCKS(oldblocks, old_b_item);

	K_WLOCK(blocks_free);
	b_item = k_unlink_head(blocks_free);
	K_WUNLOCK(blocks_free);

	DATA_BLOCKS(row, b_item);
	memcpy(row, oldblocks, sizeof(*row));
	row->diffacc = diffacc;
	row->diffinv = diffinv;
	row->shareacc = shareacc;
	row->shareinv = shareinv;
	row->elapsed = elapsed;
	row->statsconfirmed[0] = BLOCKS_STATSCONFIRMED;
	row->statsconfirmed[1] = '\0';
	HISTORYDATEINIT(row, cd, by, code, inet);

	upd = "update blocks set expirydate=$1 where blockhash=$2 and expirydate=$3";
	par = 0;
	params[par++] = tv_to_buf(cd, NULL, 0);
	params[par++] = str_to_buf(row->blockhash, NULL, 0);
	params[par++] = tv_to_buf((tv_t *)&default_expiry, NULL, 0);
	PARCHKVAL(par, 3, params);

	if (conn == NULL) {
		conn = dbconnect();
		conned = true;
	}

	res = PQexec(conn, "Begin", CKPQ_WRITE);
	rescode = PQresultStatus(res);
	PQclear(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Begin", rescode, conn);
		goto unparam;
	}

	res = PQexecParams(conn, upd, par, NULL, (const char **)params, NULL, NULL, 0, CKPQ_WRITE);
	rescode = PQresultStatus(res);
	PQclear(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Update", rescode, conn);
		goto rollback;
	}

	update_old = true;

	for (n = 0; n < par; n++)
		free(params[n]);

	par = 0;
	params[par++] = str_to_buf(row->blockhash, NULL, 0);
	params[par++] = tv_to_buf(cd, NULL, 0);
	params[par++] = double_to_buf(row->diffacc, NULL, 0);
	params[par++] = double_to_buf(row->diffinv, NULL, 0);
	params[par++] = double_to_buf(row->shareacc, NULL, 0);
	params[par++] = double_to_buf(row->shareinv, NULL, 0);
	params[par++] = bigint_to_buf(row->elapsed, NULL, 0);
	params[par++] = str_to_buf(row->statsconfirmed, NULL, 0);
	HISTORYDATEPARAMS(params, par, row);
	PARCHKVAL(par, 8 + HISTORYDATECOUNT, params); // 13 as per ins

	ins = "insert into blocks "
		"(height,blockhash,workinfoid,userid,workername,"
		"clientid,enonce1,nonce2,nonce,reward,confirmed,"
		"diffacc,diffinv,shareacc,shareinv,elapsed,"
		"statsconfirmed"
		HISTORYDATECONTROL ") select "
		"height,blockhash,workinfoid,userid,workername,"
		"clientid,enonce1,nonce2,nonce,reward,confirmed,"
		"$3,$4,$5,$6,$7,$8,"
		"$9,$10,$11,$12,$13 from blocks where "
		"blockhash=$1 and expirydate=$2";

	res = PQexecParams(conn, ins, par, NULL, (const char **)params, NULL, NULL, 0, CKPQ_WRITE);
	rescode = PQresultStatus(res);
	PQclear(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Insert", rescode, conn);
		goto rollback;
	}

	ok = true;
rollback:
	if (ok)
		res = PQexec(conn, "Commit", CKPQ_WRITE);
	else
		res = PQexec(conn, "Rollback", CKPQ_WRITE);

	PQclear(res);
unparam:
	for (n = 0; n < par; n++)
		free(params[n]);

	if (conned)
		PQfinish(conn);

	K_WLOCK(blocks_free);
	if (!ok)
		k_add_head(blocks_free, b_item);
	else {
		if (update_old) {
			blocks_root = remove_from_ktree(blocks_root, old_b_item, cmp_blocks, ctx);
			copy_tv(&(oldblocks->expirydate), cd);
			blocks_root = add_to_ktree(blocks_root, old_b_item, cmp_blocks);
		}
		blocks_root = add_to_ktree(blocks_root, b_item, cmp_blocks);
		k_add_head(blocks_store, b_item);
	}
	K_WUNLOCK(blocks_free);

	return ok;
}

static bool blocks_add(PGconn *conn, char *height, char *blockhash,
			char *confirmed, char *workinfoid, char *username,
			char *workername, char *clientid, char *enonce1,
			char *nonce2, char *nonce, char *reward,
			char *by, char *code, char *inet, tv_t *cd,
			bool igndup, char *id, K_TREE *trf_root)
{
	ExecStatusType rescode;
	bool conned = false;
	PGresult *res = NULL;
	K_TREE_CTX ctx[1];
	K_ITEM *b_item, *u_item, *old_b_item;
	char cd_buf[DATE_BUFSIZ];
	char hash_dsp[16+1];
	BLOCKS *row, *oldblocks;
	USERS *users;
	char *upd, *ins;
	char *params[17 + HISTORYDATECOUNT];
	bool ok = false, update_old = false;
	int n, par = 0;
	char want = '?';

	LOGDEBUG("%s(): add", __func__);

	K_WLOCK(blocks_free);
	b_item = k_unlink_head(blocks_free);
	K_WUNLOCK(blocks_free);

	DATA_BLOCKS(row, b_item);

	TXT_TO_INT("height", height, row->height);
	STRNCPY(row->blockhash, blockhash);

	dsp_hash(blockhash, hash_dsp, sizeof(hash_dsp));

	K_RLOCK(blocks_free);
	old_b_item = find_blocks(row->height, blockhash);
	K_RUNLOCK(blocks_free);
	DATA_BLOCKS_NULL(oldblocks, old_b_item);

	switch (confirmed[0]) {
		case BLOCKS_NEW:
			// None should exist - so must be a duplicate
			if (old_b_item) {
				K_WLOCK(blocks_free);
				k_add_head(blocks_free, b_item);
				K_WUNLOCK(blocks_free);
				if (!igndup) {
					tv_to_buf(cd, cd_buf, sizeof(cd_buf));
					LOGERR("%s(): Duplicate (%s) blocks ignored, Status: "
						"%s, Block: %s/...%s/%s",
						__func__,
						blocks_confirmed(oldblocks->confirmed),
						blocks_confirmed(confirmed),
						height, hash_dsp, cd_buf);
				}
				return true;
			}

			K_RLOCK(users_free);
			u_item = find_users(username);
			K_RUNLOCK(users_free);
			if (!u_item)
				row->userid = KANO;
			else {
				DATA_USERS(users, u_item);
				row->userid = users->userid;
			}

			STRNCPY(row->confirmed, confirmed);
			TXT_TO_BIGINT("workinfoid", workinfoid, row->workinfoid);
			STRNCPY(row->workername, workername);
			TXT_TO_INT("clientid", clientid, row->clientid);
			STRNCPY(row->enonce1, enonce1);
			STRNCPY(row->nonce2, nonce2);
			STRNCPY(row->nonce, nonce);
			TXT_TO_BIGINT("reward", reward, row->reward);
			// Specify them
			row->diffacc = 0;
			row->diffinv = 0;
			row->shareacc = 0;
			row->shareinv = 0;
			row->elapsed = 0;
			STRNCPY(row->statsconfirmed, BLOCKS_STATSPENDING_STR);

			HISTORYDATEINIT(row, cd, by, code, inet);
			HISTORYDATETRANSFER(trf_root, row);

			par = 0;
			params[par++] = int_to_buf(row->height, NULL, 0);
			params[par++] = str_to_buf(row->blockhash, NULL, 0);
			params[par++] = bigint_to_buf(row->workinfoid, NULL, 0);
			params[par++] = bigint_to_buf(row->userid, NULL, 0);
			params[par++] = str_to_buf(row->workername, NULL, 0);
			params[par++] = int_to_buf(row->clientid, NULL, 0);
			params[par++] = str_to_buf(row->enonce1, NULL, 0);
			params[par++] = str_to_buf(row->nonce2, NULL, 0);
			params[par++] = str_to_buf(row->nonce, NULL, 0);
			params[par++] = bigint_to_buf(row->reward, NULL, 0);
			params[par++] = str_to_buf(row->confirmed, NULL, 0);
			params[par++] = double_to_buf(row->diffacc, NULL, 0);
			params[par++] = double_to_buf(row->diffinv, NULL, 0);
			params[par++] = double_to_buf(row->shareacc, NULL, 0);
			params[par++] = double_to_buf(row->shareinv, NULL, 0);
			params[par++] = bigint_to_buf(row->elapsed, NULL, 0);
			params[par++] = str_to_buf(row->statsconfirmed, NULL, 0);
			HISTORYDATEPARAMS(params, par, row);
			PARCHK(par, params);

			ins = "insert into blocks "
				"(height,blockhash,workinfoid,userid,workername,"
				"clientid,enonce1,nonce2,nonce,reward,confirmed,"
				"diffacc,diffinv,shareacc,shareinv,elapsed,"
				"statsconfirmed"
				HISTORYDATECONTROL ") values (" PQPARAM22 ")";

			if (conn == NULL) {
				conn = dbconnect();
				conned = true;
			}

			res = PQexecParams(conn, ins, par, NULL, (const char **)params, NULL, NULL, 0, CKPQ_WRITE);
			rescode = PQresultStatus(res);
			PQclear(res);
			if (!PGOK(rescode)) {
				PGLOGERR("Insert", rescode, conn);
				goto unparam;
			}
			// We didn't use a Begin
			ok = true;
			goto unparam;
			break;
		case BLOCKS_ORPHAN:
		case BLOCKS_42:
			// These shouldn't be possible until startup completes
			if (!startup_complete) {
				tv_to_buf(cd, cd_buf, sizeof(cd_buf));
				LOGERR("%s(): Status: %s invalid during startup. "
					"Ignored: Block: %s/...%s/%s",
					__func__,
					blocks_confirmed(confirmed),
					height, hash_dsp, cd_buf);
				goto flail;
			}
			want = BLOCKS_CONFIRM;
		case BLOCKS_CONFIRM:
			if (!old_b_item) {
				tv_to_buf(cd, cd_buf, sizeof(cd_buf));
				LOGERR("%s(): Can't %s a non-existent Block: %s/...%s/%s",
					__func__, blocks_confirmed(confirmed),
					height, hash_dsp, cd_buf);
				goto flail;
			}
			if (confirmed[0] == BLOCKS_CONFIRM)
				want = BLOCKS_NEW;
			if (oldblocks->confirmed[0] != want) {
				// No mismatch messages during startup
				if (startup_complete) {
					tv_to_buf(cd, cd_buf, sizeof(cd_buf));
					LOGERR("%s(): New Status: %s requires Status: %c. "
						"Ignored: Status: %s, Block: %s/...%s/%s",
						__func__,
						blocks_confirmed(confirmed), want,
						blocks_confirmed(oldblocks->confirmed),
						height, hash_dsp, cd_buf);
				}
				goto flail;
			}

			upd = "update blocks set expirydate=$1 where blockhash=$2 and expirydate=$3";
			par = 0;
			params[par++] = tv_to_buf(cd, NULL, 0);
			params[par++] = str_to_buf(row->blockhash, NULL, 0);
			params[par++] = tv_to_buf((tv_t *)&default_expiry, NULL, 0);
			PARCHKVAL(par, 3, params);

			if (conn == NULL) {
				conn = dbconnect();
				conned = true;
			}

			// New is mostly a copy of the old
			memcpy(row, oldblocks, sizeof(*row));
			STRNCPY(row->confirmed, confirmed);
			if (confirmed[0] == BLOCKS_CONFIRM) {
				row->diffacc = pool.diffacc;
				row->diffinv = pool.diffinv;
				row->shareacc = pool.shareacc;
				row->shareinv = pool.shareinv;
			}

			HISTORYDATEINIT(row, cd, by, code, inet);
			HISTORYDATETRANSFER(trf_root, row);

			res = PQexec(conn, "Begin", CKPQ_WRITE);
			rescode = PQresultStatus(res);
			PQclear(res);
			if (!PGOK(rescode)) {
				PGLOGERR("Begin", rescode, conn);
				goto unparam;
			}

			res = PQexecParams(conn, upd, par, NULL, (const char **)params, NULL, NULL, 0, CKPQ_WRITE);
			rescode = PQresultStatus(res);
			PQclear(res);
			if (!PGOK(rescode)) {
				PGLOGERR("Update", rescode, conn);
				goto rollback;
			}

			for (n = 0; n < par; n++)
				free(params[n]);

			par = 0;
			params[par++] = str_to_buf(row->blockhash, NULL, 0);
			params[par++] = tv_to_buf(cd, NULL, 0);
			params[par++] = str_to_buf(row->confirmed, NULL, 0);

			if (confirmed[0] == BLOCKS_CONFIRM) {
				params[par++] = double_to_buf(row->diffacc, NULL, 0);
				params[par++] = double_to_buf(row->diffinv, NULL, 0);
				params[par++] = double_to_buf(row->shareacc, NULL, 0);
				params[par++] = double_to_buf(row->shareinv, NULL, 0);
				HISTORYDATEPARAMS(params, par, row);
				PARCHKVAL(par, 7 + HISTORYDATECOUNT, params); // 12 as per ins

				ins = "insert into blocks "
					"(height,blockhash,workinfoid,userid,workername,"
					"clientid,enonce1,nonce2,nonce,reward,confirmed,"
					"diffacc,diffinv,shareacc,shareinv,elapsed,"
					"statsconfirmed"
					HISTORYDATECONTROL ") select "
					"height,blockhash,workinfoid,userid,workername,"
					"clientid,enonce1,nonce2,nonce,reward,"
					"$3,$4,$5,$6,$7,elapsed,statsconfirmed,"
					"$8,$9,$10,$11,$12 from blocks where "
					"blockhash=$1 and expirydate=$2";
			} else {
				HISTORYDATEPARAMS(params, par, row);
				PARCHKVAL(par, 3 + HISTORYDATECOUNT, params); // 8 as per ins

				ins = "insert into blocks "
					"(height,blockhash,workinfoid,userid,workername,"
					"clientid,enonce1,nonce2,nonce,reward,confirmed,"
					"diffacc,diffinv,shareacc,shareinv,elapsed,"
					"statsconfirmed"
					HISTORYDATECONTROL ") select "
					"height,blockhash,workinfoid,userid,workername,"
					"clientid,enonce1,nonce2,nonce,reward,"
					"$3,diffacc,diffinv,shareacc,shareinv,elapsed,"
					"statsconfirmed,"
					"$4,$5,$6,$7,$8 from blocks where "
					"blockhash=$1 and expirydate=$2";
			}

			res = PQexecParams(conn, ins, par, NULL, (const char **)params, NULL, NULL, 0, CKPQ_WRITE);
			rescode = PQresultStatus(res);
			PQclear(res);
			if (!PGOK(rescode)) {
				PGLOGERR("Insert", rescode, conn);
				goto rollback;
			}

			update_old = true;
			break;
		default:
			LOGERR("%s(): %s.failed.invalid confirm='%s'",
			       __func__, id, confirmed);
			goto flail;
	}

	ok = true;
rollback:
	if (ok)
		res = PQexec(conn, "Commit", CKPQ_WRITE);
	else
		res = PQexec(conn, "Rollback", CKPQ_WRITE);

	PQclear(res);
unparam:
	for (n = 0; n < par; n++)
		free(params[n]);
flail:
	if (conned)
		PQfinish(conn);

	K_WLOCK(blocks_free);
	if (!ok)
		k_add_head(blocks_free, b_item);
	else {
		if (update_old) {
			blocks_root = remove_from_ktree(blocks_root, old_b_item, cmp_blocks, ctx);
			copy_tv(&(oldblocks->expirydate), cd);
			blocks_root = add_to_ktree(blocks_root, old_b_item, cmp_blocks);
		}
		blocks_root = add_to_ktree(blocks_root, b_item, cmp_blocks);
		k_add_head(blocks_store, b_item);
	}
	K_WUNLOCK(blocks_free);

	if (ok) {
		char pct[16] = "?";
		char est[16] = "";
		K_ITEM *w_item;
		char tmp[256];
		bool blk;

		switch (confirmed[0]) {
			case BLOCKS_NEW:
				blk = true;
				tv_to_buf(&(row->createdate), cd_buf, sizeof(cd_buf));
				snprintf(tmp, sizeof(tmp), " UTC:%s", cd_buf);
				break;
			case BLOCKS_CONFIRM:
				blk = true;
				w_item = find_workinfo(row->workinfoid);
				if (w_item) {
					char wdiffbin[TXT_SML+1];
					double wdiff;
					WORKINFO *workinfo;
					DATA_WORKINFO(workinfo, w_item);
					hex2bin(wdiffbin, workinfo->bits, 4);
					wdiff = diff_from_nbits(wdiffbin);
					if (wdiff > 0.0) {
						snprintf(pct, sizeof(pct), "%.2f",
							 100.0 * pool.diffacc / wdiff);
					}
				}
				if (pool.diffacc >= 1000.0) {
					suffix_string(pool.diffacc, est, sizeof(est)-1, 0);
					strcat(est, " ");
				}
				tv_to_buf(&(row->createdate), cd_buf, sizeof(cd_buf));
				snprintf(tmp, sizeof(tmp),
					 " Reward: %f, Worker: %s, ShareEst: %.1f %s%s%% UTC:%s",
					 BTC_TO_D(row->reward),
					 row->workername,
					 pool.diffacc, est, pct, cd_buf);
				if (pool.workinfoid < row->workinfoid) {
					pool.workinfoid = row->workinfoid;
					pool.height = row->height;
					zero_on_new_block();
				}
				break;
			case BLOCKS_ORPHAN:
			case BLOCKS_42:
			default:
				blk = false;
				tmp[0] = '\0';
				break;
		}

		LOGWARNING("%s(): %sStatus: %s, Block: %s/...%s%s",
			   __func__, blk ? "BLOCK! " : "",
			   blocks_confirmed(confirmed),
			   height, hash_dsp, tmp);
	}

	return ok;
}

static bool blocks_fill(PGconn *conn)
{
	ExecStatusType rescode;
	PGresult *res;
	K_ITEM *item;
	int n, i;
	BLOCKS *row;
	char *field;
	char *sel;
	int fields = 17;
	bool ok;

	LOGDEBUG("%s(): select", __func__);

	sel = "select "
		"height,blockhash,workinfoid,userid,workername,"
		"clientid,enonce1,nonce2,nonce,reward,confirmed,"
		"diffacc,diffinv,shareacc,shareinv,elapsed,statsconfirmed"
		HISTORYDATECONTROL
		" from blocks";
	res = PQexec(conn, sel, CKPQ_READ);
	rescode = PQresultStatus(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Select", rescode, conn);
		PQclear(res);
		return false;
	}

	n = PQnfields(res);
	if (n != (fields + HISTORYDATECOUNT)) {
		LOGERR("%s(): Invalid field count - should be %d, but is %d",
			__func__, fields + HISTORYDATECOUNT, n);
		PQclear(res);
		return false;
	}

	n = PQntuples(res);
	LOGDEBUG("%s(): tree build count %d", __func__, n);
	ok = true;
	for (i = 0; i < n; i++) {
		item = k_unlink_head(blocks_free);
		DATA_BLOCKS(row, item);

		if (everyone_die) {
			ok = false;
			break;
		}

		PQ_GET_FLD(res, i, "height", field, ok);
		if (!ok)
			break;
		TXT_TO_INT("height", field, row->height);

		PQ_GET_FLD(res, i, "blockhash", field, ok);
		if (!ok)
			break;
		TXT_TO_STR("blockhash", field, row->blockhash);

		PQ_GET_FLD(res, i, "workinfoid", field, ok);
		if (!ok)
			break;
		TXT_TO_BIGINT("workinfoid", field, row->workinfoid);

		PQ_GET_FLD(res, i, "userid", field, ok);
		if (!ok)
			break;
		TXT_TO_BIGINT("userid", field, row->userid);

		PQ_GET_FLD(res, i, "workername", field, ok);
		if (!ok)
			break;
		TXT_TO_STR("workername", field, row->workername);

		PQ_GET_FLD(res, i, "clientid", field, ok);
		if (!ok)
			break;
		TXT_TO_INT("clientid", field, row->clientid);

		PQ_GET_FLD(res, i, "enonce1", field, ok);
		if (!ok)
			break;
		TXT_TO_STR("enonce1", field, row->enonce1);

		PQ_GET_FLD(res, i, "nonce2", field, ok);
		if (!ok)
			break;
		TXT_TO_STR("nonce2", field, row->nonce2);

		PQ_GET_FLD(res, i, "nonce", field, ok);
		if (!ok)
			break;
		TXT_TO_STR("nonce", field, row->nonce);

		PQ_GET_FLD(res, i, "reward", field, ok);
		if (!ok)
			break;
		TXT_TO_BIGINT("reward", field, row->reward);

		PQ_GET_FLD(res, i, "confirmed", field, ok);
		if (!ok)
			break;
		TXT_TO_STR("confirmed", field, row->confirmed);

		PQ_GET_FLD(res, i, "diffacc", field, ok);
		if (!ok)
			break;
		TXT_TO_DOUBLE("diffacc", field, row->diffacc);

		PQ_GET_FLD(res, i, "diffinv", field, ok);
		if (!ok)
			break;
		TXT_TO_DOUBLE("diffinv", field, row->diffinv);

		PQ_GET_FLD(res, i, "shareacc", field, ok);
		if (!ok)
			break;
		TXT_TO_DOUBLE("shareacc", field, row->shareacc);

		PQ_GET_FLD(res, i, "shareinv", field, ok);
		if (!ok)
			break;
		TXT_TO_DOUBLE("shareinv", field, row->shareinv);

		PQ_GET_FLD(res, i, "elapsed", field, ok);
		if (!ok)
			break;
		TXT_TO_BIGINT("elapsed", field, row->elapsed);

		PQ_GET_FLD(res, i, "statsconfirmed", field, ok);
		if (!ok)
			break;
		TXT_TO_STR("statsconfirmed", field, row->statsconfirmed);

		HISTORYDATEFLDS(res, i, row, ok);
		if (!ok)
			break;

		blocks_root = add_to_ktree(blocks_root, item, cmp_blocks);
		k_add_head(blocks_store, item);

		if (tv_newer(&(dbstatus.newest_createdate_blocks), &(row->createdate)))
			copy_tv(&(dbstatus.newest_createdate_blocks), &(row->createdate));

		if (pool.workinfoid < row->workinfoid) {
			pool.workinfoid = row->workinfoid;
			pool.height = row->height;
		}
	}
	if (!ok)
		k_add_head(blocks_free, item);

	PQclear(res);

	if (ok) {
		LOGDEBUG("%s(): built", __func__);
		LOGWARNING("%s(): loaded %d blocks records", __func__, n);
	}

	return ok;
}

void blocks_reload()
{
	PGconn *conn = dbconnect();

	blocks_root = free_ktree(blocks_root, NULL);
	k_list_transfer_to_head(blocks_store, blocks_free);

	blocks_fill(conn);

	PQfinish(conn);
}

/* order by height asc,userid asc,expirydate asc
 * i.e. only one payout amount per block per user */
static cmp_t cmp_miningpayouts(K_ITEM *a, K_ITEM *b)
{
	MININGPAYOUTS *ma, *mb;
	DATA_MININGPAYOUTS(ma, a);
	DATA_MININGPAYOUTS(mb, b);
	cmp_t c = CMP_INT(ma->height, mb->height);
	if (c == 0) {
		c = CMP_BIGINT(ma->userid, mb->userid);
		if (c == 0)
			c = CMP_TV(ma->expirydate, mb->expirydate);
	}
	return c;
}

__maybe_unused static bool miningpayouts_add(PGconn *conn, char *username, char *height,
			      char *blockhash, char *amount, char *by,
			      char *code, char *inet, tv_t *cd, K_TREE *trf_root)
{
	ExecStatusType rescode;
	bool conned = false;
	PGresult *res;
	K_ITEM *m_item, *u_item;
	bool ok = false;
	MININGPAYOUTS *row;
	USERS *users;
	char *ins;
	char *params[5 + HISTORYDATECOUNT];
	int n, par = 0;

	LOGDEBUG("%s(): add", __func__);

	K_WLOCK(miningpayouts_free);
	m_item = k_unlink_head(miningpayouts_free);
	K_WUNLOCK(miningpayouts_free);

	DATA_MININGPAYOUTS(row, m_item);

	if (conn == NULL) {
		conn = dbconnect();
		conned = true;
	}

	row->miningpayoutid = nextid(conn, "miningpayoutid", (int64_t)1, cd, by, code, inet);
	if (row->miningpayoutid == 0)
		goto unitem;

	K_RLOCK(users_free);
	u_item = find_users(username);
	K_RUNLOCK(users_free);
	if (!u_item)
		goto unitem;
	DATA_USERS(users, u_item);

	row->userid = users->userid;
	TXT_TO_INT("height", height, row->height);
	STRNCPY(row->blockhash, blockhash);
	TXT_TO_BIGINT("amount", amount, row->amount);

	HISTORYDATEINIT(row, cd, by, code, inet);
	HISTORYDATETRANSFER(trf_root, row);

	par = 0;
	params[par++] = bigint_to_buf(row->miningpayoutid, NULL, 0);
	params[par++] = bigint_to_buf(row->userid, NULL, 0);
	params[par++] = int_to_buf(row->height, NULL, 0);
	params[par++] = str_to_buf(row->blockhash, NULL, 0);
	params[par++] = bigint_to_buf(row->amount, NULL, 0);
	HISTORYDATEPARAMS(params, par, row);
	PARCHK(par, params);

	ins = "insert into miningpayouts "
		"(miningpayoutid,userid,height,blockhash,amount"
		HISTORYDATECONTROL ") values (" PQPARAM10 ")";

	res = PQexecParams(conn, ins, par, NULL, (const char **)params, NULL, NULL, 0, CKPQ_WRITE);
	rescode = PQresultStatus(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Insert", rescode, conn);
		goto unparam;
	}

	ok = true;

unparam:
	PQclear(res);
	for (n = 0; n < par; n++)
		free(params[n]);
unitem:
	if (conned)
		PQfinish(conn);
	K_WLOCK(miningpayouts_free);
	if (!ok)
		k_add_head(miningpayouts_free, m_item);
	else {
		miningpayouts_root = add_to_ktree(miningpayouts_root, m_item, cmp_miningpayouts);
		k_add_head(miningpayouts_store, m_item);
	}
	K_WUNLOCK(miningpayouts_free);

	return ok;
}

static bool miningpayouts_fill(PGconn *conn)
{
	ExecStatusType rescode;
	PGresult *res;
	K_ITEM *item;
	MININGPAYOUTS *row;
	char *params[1];
	int n, i, par = 0;
	char *field;
	char *sel;
	int fields = 5;
	bool ok;

	LOGDEBUG("%s(): select", __func__);

	sel = "select "
		"miningpayoutid,userid,height,blockhash,amount"
		HISTORYDATECONTROL
		" from miningpayouts where expirydate=$1";
	par = 0;
	params[par++] = tv_to_buf((tv_t *)(&default_expiry), NULL, 0);
	PARCHK(par, params);
	res = PQexecParams(conn, sel, par, NULL, (const char **)params, NULL, NULL, 0, CKPQ_READ);
	rescode = PQresultStatus(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Select", rescode, conn);
		PQclear(res);
		return false;
	}

	n = PQnfields(res);
	if (n != (fields + HISTORYDATECOUNT)) {
		LOGERR("%s(): Invalid field count - should be %d, but is %d",
			__func__, fields + HISTORYDATECOUNT, n);
		PQclear(res);
		return false;
	}

	n = PQntuples(res);
	LOGDEBUG("%s(): tree build count %d", __func__, n);
	ok = true;
	K_WLOCK(miningpayouts_free);
	for (i = 0; i < n; i++) {
		item = k_unlink_head(miningpayouts_free);
		DATA_MININGPAYOUTS(row, item);

		if (everyone_die) {
			ok = false;
			break;
		}

		PQ_GET_FLD(res, i, "miningpayoutid", field, ok);
		if (!ok)
			break;
		TXT_TO_BIGINT("miningpayoutid", field, row->miningpayoutid);

		PQ_GET_FLD(res, i, "userid", field, ok);
		if (!ok)
			break;
		TXT_TO_BIGINT("userid", field, row->userid);

		PQ_GET_FLD(res, i, "height", field, ok);
		if (!ok)
			break;
		TXT_TO_INT("height", field, row->height);

		PQ_GET_FLD(res, i, "blockhash", field, ok);
		if (!ok)
			break;
		TXT_TO_STR("blockhash", field, row->blockhash);

		PQ_GET_FLD(res, i, "amount", field, ok);
		if (!ok)
			break;
		TXT_TO_BIGINT("amount", field, row->amount);

		HISTORYDATEFLDS(res, i, row, ok);
		if (!ok)
			break;

		miningpayouts_root = add_to_ktree(miningpayouts_root, item, cmp_miningpayouts);
		k_add_head(miningpayouts_store, item);

		tick();
	}
	if (!ok)
		k_add_head(miningpayouts_free, item);

	K_WUNLOCK(miningpayouts_free);
	PQclear(res);

	if (ok) {
		LOGDEBUG("%s(): built", __func__);
		LOGWARNING("%s(): loaded %d miningpayout records", __func__, n);
	}

	return ok;
}

void miningpayouts_reload()
{
	PGconn *conn = dbconnect();

	K_WLOCK(miningpayouts_free);
	miningpayouts_root = free_ktree(miningpayouts_root, NULL);
	k_list_transfer_to_head(miningpayouts_store, miningpayouts_free);
	K_WUNLOCK(miningpayouts_free);

	miningpayouts_fill(conn);

	PQfinish(conn);
}

// order by userid asc,createdate asc,authid asc,expirydate desc
static cmp_t cmp_auths(K_ITEM *a, K_ITEM *b)
{
	AUTHS *aa, *ab;
	DATA_AUTHS(aa, a);
	DATA_AUTHS(ab, b);
	cmp_t c = CMP_BIGINT(aa->userid, ab->userid);
	if (c == 0) {
		c = CMP_TV(aa->createdate, ab->createdate);
		if (c == 0) {
			c = CMP_BIGINT(aa->authid, ab->authid);
			if (c == 0)
				c = CMP_TV(ab->expirydate, aa->expirydate);
		}
	}
	return c;
}

static char *auths_add(PGconn *conn, char *poolinstance, char *username,
			char *workername, char *clientid, char *enonce1,
			char *useragent, char *preauth, char *by, char *code,
			char *inet, tv_t *cd, bool igndup, K_TREE *trf_root,
			bool addressuser)
{
	ExecStatusType rescode;
	bool conned = false;
	PGresult *res;
	K_TREE_CTX ctx[1];
	K_ITEM *a_item, *u_item;
	char cd_buf[DATE_BUFSIZ];
	USERS *users;
	AUTHS *row;
	char *ins;
	char *secuserid = NULL;
	char *params[8 + HISTORYDATECOUNT];
	int n, par = 0;

	LOGDEBUG("%s(): add", __func__);

	K_WLOCK(auths_free);
	a_item = k_unlink_head(auths_free);
	K_WUNLOCK(auths_free);

	DATA_AUTHS(row, a_item);

	K_RLOCK(users_free);
	u_item = find_users(username);
	K_RUNLOCK(users_free);
	if (!u_item) {
		if (addressuser) {
			if (conn == NULL) {
				conn = dbconnect();
				conned = true;
			}
			u_item = users_add(conn, username, EMPTY, EMPTY,
					   by, code, inet, cd, trf_root);
		}
		if (!u_item)
			goto unitem;
	}
	DATA_USERS(users, u_item);

	STRNCPY(row->poolinstance, poolinstance);
	row->userid = users->userid;
	// since update=false, a dup will be ok and do nothing when igndup=true
	new_worker(conn, false, row->userid, workername, DIFFICULTYDEFAULT_DEF_STR,
		   IDLENOTIFICATIONENABLED_DEF, IDLENOTIFICATIONTIME_DEF_STR,
		   by, code, inet, cd, trf_root);
	STRNCPY(row->workername, workername);
	TXT_TO_INT("clientid", clientid, row->clientid);
	STRNCPY(row->enonce1, enonce1);
	STRNCPY(row->useragent, useragent);
	STRNCPY(row->preauth, preauth);

	HISTORYDATEINIT(row, cd, by, code, inet);
	HISTORYDATETRANSFER(trf_root, row);

	K_WLOCK(auths_free);
	if (find_in_ktree(auths_root, a_item, cmp_auths, ctx)) {
		k_add_head(auths_free, a_item);
		K_WUNLOCK(auths_free);

		if (conned)
			PQfinish(conn);

		if (!igndup) {
			tv_to_buf(cd, cd_buf, sizeof(cd_buf));
			LOGERR("%s(): Duplicate auths ignored %s/%s/%s",
				__func__, poolinstance, workername, cd_buf);
		}

		return users->secondaryuserid;
	}
	K_WUNLOCK(auths_free);

	// Update even if DB fails
	workerstatus_update(row, NULL, NULL);

	if (conn == NULL) {
		conn = dbconnect();
		conned = true;
	}

	row->authid = nextid(conn, "authid", (int64_t)1, cd, by, code, inet);
	if (row->authid == 0)
		goto unitem;

	par = 0;
	params[par++] = bigint_to_buf(row->authid, NULL, 0);
	params[par++] = str_to_buf(row->poolinstance, NULL, 0);
	params[par++] = bigint_to_buf(row->userid, NULL, 0);
	params[par++] = str_to_buf(row->workername, NULL, 0);
	params[par++] = int_to_buf(row->clientid, NULL, 0);
	params[par++] = str_to_buf(row->enonce1, NULL, 0);
	params[par++] = str_to_buf(row->useragent, NULL, 0);
	params[par++] = str_to_buf(row->preauth, NULL, 0);
	HISTORYDATEPARAMS(params, par, row);
	PARCHK(par, params);

	ins = "insert into auths "
		"(authid,poolinstance,userid,workername,clientid,enonce1,useragent,preauth"
		HISTORYDATECONTROL ") values (" PQPARAM13 ")";

	res = PQexecParams(conn, ins, par, NULL, (const char **)params, NULL, NULL, 0, CKPQ_WRITE);
	rescode = PQresultStatus(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Insert", rescode, conn);
		goto unparam;
	}

	secuserid = users->secondaryuserid;

unparam:
	PQclear(res);
	for (n = 0; n < par; n++)
		free(params[n]);
unitem:
	if (conned)
		PQfinish(conn);
	K_WLOCK(auths_free);
	if (!secuserid)
		k_add_head(auths_free, a_item);
	else {
		auths_root = add_to_ktree(auths_root, a_item, cmp_auths);
		k_add_head(auths_store, a_item);
	}
	K_WUNLOCK(auths_free);

	return secuserid;
}

static bool auths_fill(PGconn *conn)
{
	ExecStatusType rescode;
	PGresult *res;
	K_ITEM *item;
	AUTHS *row;
	char *params[1];
	int n, i, par = 0;
	char *field;
	char *sel;
	int fields = 7;
	bool ok;

	LOGDEBUG("%s(): select", __func__);

	// TODO: add/update a (single) fake auth every ~10min or 10min after the last one?
	sel = "select "
		"authid,userid,workername,clientid,enonce1,useragent,preauth"
		HISTORYDATECONTROL
		" from auths where expirydate=$1";
	par = 0;
	params[par++] = tv_to_buf((tv_t *)(&default_expiry), NULL, 0);
	PARCHK(par, params);
	res = PQexecParams(conn, sel, par, NULL, (const char **)params, NULL, NULL, 0, CKPQ_READ);
	rescode = PQresultStatus(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Select", rescode, conn);
		PQclear(res);
		return false;
	}

	n = PQnfields(res);
	if (n != (fields + HISTORYDATECOUNT)) {
		LOGERR("%s(): Invalid field count - should be %d, but is %d",
			__func__, fields + HISTORYDATECOUNT, n);
		PQclear(res);
		return false;
	}

	n = PQntuples(res);
	LOGDEBUG("%s(): tree build count %d", __func__, n);
	ok = true;
	K_WLOCK(auths_free);
	for (i = 0; i < n; i++) {
		item = k_unlink_head(auths_free);
		DATA_AUTHS(row, item);

		if (everyone_die) {
			ok = false;
			break;
		}

		PQ_GET_FLD(res, i, "authid", field, ok);
		if (!ok)
			break;
		TXT_TO_BIGINT("authid", field, row->authid);

		PQ_GET_FLD(res, i, "userid", field, ok);
		if (!ok)
			break;
		TXT_TO_BIGINT("userid", field, row->userid);

		PQ_GET_FLD(res, i, "workername", field, ok);
		if (!ok)
			break;
		TXT_TO_STR("workername", field, row->workername);

		PQ_GET_FLD(res, i, "clientid", field, ok);
		if (!ok)
			break;
		TXT_TO_INT("clientid", field, row->clientid);

		PQ_GET_FLD(res, i, "enonce1", field, ok);
		if (!ok)
			break;
		TXT_TO_STR("enonce1", field, row->enonce1);

		PQ_GET_FLD(res, i, "useragent", field, ok);
		if (!ok)
			break;
		TXT_TO_STR("useragent", field, row->useragent);

		PQ_GET_FLD(res, i, "preauth", field, ok);
		if (!ok)
			break;
		TXT_TO_STR("preauth", field, row->preauth);

		HISTORYDATEFLDS(res, i, row, ok);
		if (!ok)
			break;

		auths_root = add_to_ktree(auths_root, item, cmp_auths);
		k_add_head(auths_store, item);
		workerstatus_update(row, NULL, NULL);

		if (tv_newer(&(dbstatus.newest_createdate_auths), &(row->createdate)))
			copy_tv(&(dbstatus.newest_createdate_auths), &(row->createdate));

		tick();
	}
	if (!ok)
		k_add_head(auths_free, item);

	K_WUNLOCK(auths_free);
	PQclear(res);

	if (ok) {
		LOGDEBUG("%s(): built", __func__);
		LOGWARNING("%s(): loaded %d auth records", __func__, n);
	}

	return ok;
}

void auths_reload()
{
	PGconn *conn = dbconnect();

	K_WLOCK(auths_free);
	auths_root = free_ktree(auths_root, NULL);
	k_list_transfer_to_head(auths_store, auths_free);
	K_WUNLOCK(auths_free);

	auths_fill(conn);

	PQfinish(conn);
}

// order by poolinstance asc,createdate asc
static cmp_t cmp_poolstats(K_ITEM *a, K_ITEM *b)
{
	POOLSTATS *pa, *pb;
	DATA_POOLSTATS(pa, a);
	DATA_POOLSTATS(pb, b);
	cmp_t c = CMP_STR(pa->poolinstance, pb->poolinstance);
	if (c == 0)
		c = CMP_TV(pa->createdate, pb->createdate);
	return c;
}

static bool poolstats_add(PGconn *conn, bool store, char *poolinstance,
				char *elapsed, char *users, char *workers,
				char *hashrate, char *hashrate5m,
				char *hashrate1hr, char *hashrate24hr,
				char *by, char *code, char *inet, tv_t *cd,
				bool igndup, K_TREE *trf_root)
{
	ExecStatusType rescode;
	bool conned = false;
	PGresult *res;
	K_TREE_CTX ctx[1];
	K_ITEM *p_item;
	POOLSTATS *row;
	char *ins;
	char *params[8 + SIMPLEDATECOUNT];
	int n, par = 0;
	bool ok = false;

	LOGDEBUG("%s(): add", __func__);

	K_WLOCK(poolstats_free);
	p_item = k_unlink_head(poolstats_free);
	K_WUNLOCK(poolstats_free);

	DATA_POOLSTATS(row, p_item);

	row->stored = false;

	STRNCPY(row->poolinstance, poolinstance);
	TXT_TO_BIGINT("elapsed", elapsed, row->elapsed);
	TXT_TO_INT("users", users, row->users);
	TXT_TO_INT("workers", workers, row->workers);
	TXT_TO_DOUBLE("hashrate", hashrate, row->hashrate);
	TXT_TO_DOUBLE("hashrate5m", hashrate5m, row->hashrate5m);
	TXT_TO_DOUBLE("hashrate1hr", hashrate1hr, row->hashrate1hr);
	TXT_TO_DOUBLE("hashrate24hr", hashrate24hr, row->hashrate24hr);

	SIMPLEDATEINIT(row, cd, by, code, inet);
	SIMPLEDATETRANSFER(trf_root, row);

	if (igndup && find_in_ktree(poolstats_root, p_item, cmp_poolstats, ctx)) {
		K_WLOCK(poolstats_free);
		k_add_head(poolstats_free, p_item);
		K_WUNLOCK(poolstats_free);
		return true;
	}

	if (store) {
		par = 0;
		params[par++] = str_to_buf(row->poolinstance, NULL, 0);
		params[par++] = bigint_to_buf(row->elapsed, NULL, 0);
		params[par++] = int_to_buf(row->users, NULL, 0);
		params[par++] = int_to_buf(row->workers, NULL, 0);
		params[par++] = bigint_to_buf(row->hashrate, NULL, 0);
		params[par++] = bigint_to_buf(row->hashrate5m, NULL, 0);
		params[par++] = bigint_to_buf(row->hashrate1hr, NULL, 0);
		params[par++] = bigint_to_buf(row->hashrate24hr, NULL, 0);
		SIMPLEDATEPARAMS(params, par, row);
		PARCHK(par, params);

		ins = "insert into poolstats "
			"(poolinstance,elapsed,users,workers,hashrate,"
			"hashrate5m,hashrate1hr,hashrate24hr"
			SIMPLEDATECONTROL ") values (" PQPARAM12 ")";

		if (!conn) {
			conn = dbconnect();
			conned = true;
		}

		res = PQexecParams(conn, ins, par, NULL, (const char **)params, NULL, NULL, 0, CKPQ_WRITE);
		rescode = PQresultStatus(res);
		if (!PGOK(rescode)) {
			PGLOGERR("Insert", rescode, conn);
			goto unparam;
		}

		row->stored = true;
	}

	ok = true;
unparam:
	if (store) {
		PQclear(res);
		if (conned)
			PQfinish(conn);
		for (n = 0; n < par; n++)
			free(params[n]);
	}

	K_WLOCK(poolstats_free);
	if (!ok)
		k_add_head(poolstats_free, p_item);
	else {
		poolstats_root = add_to_ktree(poolstats_root, p_item, cmp_poolstats);
		k_add_head(poolstats_store, p_item);
	}
	K_WUNLOCK(poolstats_free);

	return ok;
}

// TODO: data selection - only require ?
static bool poolstats_fill(PGconn *conn)
{
	ExecStatusType rescode;
	PGresult *res;
	K_ITEM *item;
	int n, i;
	POOLSTATS *row;
	char *field;
	char *sel;
	int fields = 8;
	bool ok;

	LOGDEBUG("%s(): select", __func__);

	sel = "select "
		"poolinstance,elapsed,users,workers,hashrate,hashrate5m,"
		"hashrate1hr,hashrate24hr"
		SIMPLEDATECONTROL
		" from poolstats";
	res = PQexec(conn, sel, CKPQ_READ);
	rescode = PQresultStatus(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Select", rescode, conn);
		PQclear(res);
		return false;
	}

	n = PQnfields(res);
	if (n != (fields + SIMPLEDATECOUNT)) {
		LOGERR("%s(): Invalid field count - should be %d, but is %d",
			__func__, fields + SIMPLEDATECOUNT, n);
		PQclear(res);
		return false;
	}

	n = PQntuples(res);
	LOGDEBUG("%s(): tree build count %d", __func__, n);
	ok = true;
	K_WLOCK(poolstats_free);
	for (i = 0; i < n; i++) {
		item = k_unlink_head(poolstats_free);
		DATA_POOLSTATS(row, item);

		if (everyone_die) {
			ok = false;
			break;
		}

		row->stored = true;

		PQ_GET_FLD(res, i, "poolinstance", field, ok);
		if (!ok)
			break;
		TXT_TO_STR("poolinstance", field, row->poolinstance);

		PQ_GET_FLD(res, i, "elapsed", field, ok);
		if (!ok)
			break;
		TXT_TO_BIGINT("elapsed", field, row->elapsed);

		PQ_GET_FLD(res, i, "users", field, ok);
		if (!ok)
			break;
		TXT_TO_INT("users", field, row->users);

		PQ_GET_FLD(res, i, "workers", field, ok);
		if (!ok)
			break;
		TXT_TO_INT("workers", field, row->workers);

		PQ_GET_FLD(res, i, "hashrate", field, ok);
		if (!ok)
			break;
		TXT_TO_DOUBLE("hashrate", field, row->hashrate);

		PQ_GET_FLD(res, i, "hashrate5m", field, ok);
		if (!ok)
			break;
		TXT_TO_DOUBLE("hashrate5m", field, row->hashrate5m);

		PQ_GET_FLD(res, i, "hashrate1hr", field, ok);
		if (!ok)
			break;
		TXT_TO_DOUBLE("hashrate1hr", field, row->hashrate1hr);

		PQ_GET_FLD(res, i, "hashrate24hr", field, ok);
		if (!ok)
			break;
		TXT_TO_DOUBLE("hashrate24hr", field, row->hashrate24hr);

		SIMPLEDATEFLDS(res, i, row, ok);
		if (!ok)
			break;

		poolstats_root = add_to_ktree(poolstats_root, item, cmp_poolstats);
		k_add_head(poolstats_store, item);

		if (tv_newer(&(dbstatus.newest_createdate_poolstats), &(row->createdate)))
			copy_tv(&(dbstatus.newest_createdate_poolstats), &(row->createdate));

		tick();
	}
	if (!ok)
		k_add_head(poolstats_free, item);

	K_WUNLOCK(poolstats_free);
	PQclear(res);

	if (ok) {
		LOGDEBUG("%s(): built", __func__);
		LOGWARNING("%s(): loaded %d poolstats records", __func__, n);
	}

	return ok;
}

void poolstats_reload()
{
	PGconn *conn = dbconnect();

	K_WLOCK(poolstats_free);
	poolstats_root = free_ktree(poolstats_root, NULL);
	k_list_transfer_to_head(poolstats_store, poolstats_free);
	K_WUNLOCK(poolstats_free);

	poolstats_fill(conn);

	PQfinish(conn);
}

static void dsp_userstats(K_ITEM *item, FILE *stream)
{
	char statsdate_buf[DATE_BUFSIZ], createdate_buf[DATE_BUFSIZ];
	USERSTATS *u = NULL;

	if (!item)
		fprintf(stream, "%s() called with (null) item\n", __func__);
	else {
		DATA_USERSTATS(u, item);
		tv_to_buf(&(u->statsdate), statsdate_buf, sizeof(statsdate_buf));
		tv_to_buf(&(u->createdate), createdate_buf, sizeof(createdate_buf));
		fprintf(stream, " pi='%s' uid=%"PRId64" w='%s' e=%"PRId64" Hs=%f "
				"Hs5m=%f Hs1hr=%f Hs24hr=%f sl=%s sc=%d sd=%s cd=%s\n",
				u->poolinstance, u->userid, u->workername,
				u->elapsed, u->hashrate, u->hashrate5m,
				u->hashrate1hr, u->hashrate24hr, u->summarylevel,
				u->summarycount, statsdate_buf, createdate_buf);
	}
}

/* order by userid asc,statsdate asc,poolinstance asc,workername asc
   as per required for userstats homepage summarisation */
static cmp_t cmp_userstats(K_ITEM *a, K_ITEM *b)
{
	USERSTATS *ua, *ub;
	DATA_USERSTATS(ua, a);
	DATA_USERSTATS(ub, b);
	cmp_t c = CMP_BIGINT(ua->userid, ub->userid);
	if (c == 0) {
		c = CMP_TV(ua->statsdate, ub->statsdate);
		if (c == 0) {
			c = CMP_STR(ua->poolinstance, ub->poolinstance);
			if (c == 0)
				c = CMP_STR(ua->workername, ub->workername);
		}
	}
	return c;
}

/* order by userid asc,workername asc
   temporary tree for summing userstats when sending user homepage info */
static cmp_t cmp_userstats_workername(K_ITEM *a, K_ITEM *b)
{
	USERSTATS *ua, *ub;
	DATA_USERSTATS(ua, a);
	DATA_USERSTATS(ub, b);
	cmp_t c = CMP_BIGINT(ua->userid, ub->userid);
	if (c == 0)
		c = CMP_STR(ua->workername, ub->workername);
	return c;
}

/* order by statsdate,userid asc,statsdate asc,workername asc,poolinstance asc
   as per required for DB summarisation */
static cmp_t cmp_userstats_statsdate(K_ITEM *a, K_ITEM *b)
{
	USERSTATS *ua, *ub;
	DATA_USERSTATS(ua, a);
	DATA_USERSTATS(ub, b);
	cmp_t c = CMP_TV(ua->statsdate, ub->statsdate);
	if (c == 0) {
		c = CMP_BIGINT(ua->userid, ub->userid);
		if (c == 0) {
			c = CMP_STR(ua->workername, ub->workername);
			if (c == 0)
				c = CMP_STR(ua->poolinstance, ub->poolinstance);
		}
	}
	return c;
}

/* order by userid asc,workername asc,statsdate asc,poolinstance asc
   built during data load to update workerstatus at the end of the load
   and used during reload to discard stats already in the DB */
static cmp_t cmp_userstats_workerstatus(K_ITEM *a, K_ITEM *b)
{
	USERSTATS *ua, *ub;
	DATA_USERSTATS(ua, a);
	DATA_USERSTATS(ub, b);
	cmp_t c = CMP_BIGINT(ua->userid, ub->userid);
	if (c == 0) {
		c = CMP_STR(ua->workername, ub->workername);
		if (c == 0) {
			c = CMP_TV(ua->statsdate, ub->statsdate);
			if (c == 0)
				c = CMP_STR(ua->poolinstance, ub->poolinstance);
		}
	}
	return c;
}

static bool userstats_add_db(PGconn *conn, USERSTATS *row)
{
	ExecStatusType rescode;
	bool conned = false;
	PGresult *res;
	char *ins;
	bool ok = false;
	char *params[10 + SIMPLEDATECOUNT];
	int n, par = 0;

	LOGDEBUG("%s(): store", __func__);

	par = 0;
	params[par++] = bigint_to_buf(row->userid, NULL, 0);
	params[par++] = str_to_buf(row->workername, NULL, 0);
	params[par++] = bigint_to_buf(row->elapsed, NULL, 0);
	params[par++] = double_to_buf(row->hashrate, NULL, 0);
	params[par++] = double_to_buf(row->hashrate5m, NULL, 0);
	params[par++] = double_to_buf(row->hashrate1hr, NULL, 0);
	params[par++] = double_to_buf(row->hashrate24hr, NULL, 0);
	params[par++] = str_to_buf(row->summarylevel, NULL, 0);
	params[par++] = int_to_buf(row->summarycount, NULL, 0);
	params[par++] = tv_to_buf(&(row->statsdate), NULL, 0);
	SIMPLEDATEPARAMS(params, par, row);
	PARCHK(par, params);

	ins = "insert into userstats "
		"(userid,workername,elapsed,hashrate,hashrate5m,hashrate1hr,"
		"hashrate24hr,summarylevel,summarycount,statsdate"
		SIMPLEDATECONTROL ") values (" PQPARAM14 ")";

	if (conn == NULL) {
		conn = dbconnect();
		conned = true;
	}

	res = PQexecParams(conn, ins, par, NULL, (const char **)params, NULL, NULL, 0, CKPQ_WRITE);
	rescode = PQresultStatus(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Insert", rescode, conn);
		goto unparam;
	}

	ok = true;
unparam:
	PQclear(res);
	if (conned)
		PQfinish(conn);
	for (n = 0; n < par; n++)
		free(params[n]);

	return ok;
}

static bool userstats_add(char *poolinstance, char *elapsed, char *username,
			  char *workername, char *hashrate, char *hashrate5m,
			  char *hashrate1hr, char *hashrate24hr, bool idle,
			  bool eos, char *by, char *code, char *inet, tv_t *cd,
			  K_TREE *trf_root)
{
	K_ITEM *us_item, *u_item, *us_match, *us_next, look;
	tv_t eosdate;
	USERSTATS *row, cmp, *match, *next;
	USERS *users;
	K_TREE_CTX ctx[1];

	LOGDEBUG("%s(): add", __func__);

	K_WLOCK(userstats_free);
	us_item = k_unlink_head(userstats_free);
	K_WUNLOCK(userstats_free);

	DATA_USERSTATS(row, us_item);

	STRNCPY(row->poolinstance, poolinstance);
	TXT_TO_BIGINT("elapsed", elapsed, row->elapsed);
	K_RLOCK(users_free);
	u_item = find_users(username);
	K_RUNLOCK(users_free);
	if (!u_item)
		return false;
	DATA_USERS(users, u_item);
	row->userid = users->userid;
	TXT_TO_STR("workername", workername, row->workername);
	TXT_TO_DOUBLE("hashrate", hashrate, row->hashrate);
	TXT_TO_DOUBLE("hashrate5m", hashrate5m, row->hashrate5m);
	TXT_TO_DOUBLE("hashrate1hr", hashrate1hr, row->hashrate1hr);
	TXT_TO_DOUBLE("hashrate24hr", hashrate24hr, row->hashrate24hr);
	row->idle = idle;
	row->summarylevel[0] = SUMMARY_NONE;
	row->summarylevel[1] = '\0';
	row->summarycount = 1;
	SIMPLEDATEINIT(row, cd, by, code, inet);
	SIMPLEDATETRANSFER(trf_root, row);
	copy_tv(&(row->statsdate), &(row->createdate));

	if (eos) {
		// Save it for end processing
		eosdate.tv_sec = row->createdate.tv_sec;
		eosdate.tv_usec = row->createdate.tv_usec;
	}

	// confirm_summaries() doesn't call this
	if (reloading) {
		memcpy(&cmp, row, sizeof(cmp));
		INIT_USERSTATS(&look);
		look.data = (void *)(&cmp);
		// Just zero it to ensure the DB record is after it, not equal to it
		cmp.statsdate.tv_usec = 0;
		/* If there is a matching user+worker DB record summarising this row,
		 * or a matching user+worker DB record next after this row, discard it */
		us_match = find_after_in_ktree(userstats_workerstatus_root, &look,
						cmp_userstats_workerstatus, ctx);
		DATA_USERSTATS_NULL(match, us_match);
		if (us_match &&
		    match->userid == row->userid &&
		    strcmp(match->workername, row->workername) == 0 &&
		    match->summarylevel[0] != SUMMARY_NONE) {
			K_WLOCK(userstats_free);
			k_add_head(userstats_free, us_item);
			K_WUNLOCK(userstats_free);

			/* If this was an eos record and eos_store has data,
			 * it means we need to process the eos_store */
			if (eos && userstats_eos_store->count > 0)
				goto advancetogo;

			return true;
		}
	}

	workerstatus_update(NULL, NULL, row);

	/* group at full key: userid,createdate,poolinstance,workername
	   i.e. ignore instance and group together down at workername */
	us_match = userstats_eos_store->head;
	while (us_match && cmp_userstats(us_item, us_match) != 0.0)
		us_match = us_match->next;

	if (us_match) {
		DATA_USERSTATS(match, us_match);
		match->hashrate += row->hashrate;
		match->hashrate5m += row->hashrate5m;
		match->hashrate1hr += row->hashrate1hr;
		match->hashrate24hr += row->hashrate24hr;
		// Minimum elapsed of the data set
		if (match->elapsed > row->elapsed)
			match->elapsed = row->elapsed;
		// Unused
		K_WLOCK(userstats_free);
		k_add_head(userstats_free, us_item);
		K_WUNLOCK(userstats_free);
	} else {
		// New worker
		K_WLOCK(userstats_free);
		k_add_head(userstats_eos_store, us_item);
		K_WUNLOCK(userstats_free);
	}

	if (eos) {
advancetogo:
		K_WLOCK(userstats_free);
		us_next = userstats_eos_store->head;
		while (us_next) {
			DATA_USERSTATS(next, us_next);
			if (tvdiff(&(next->createdate), &eosdate) != 0.0) {
				char date_buf[DATE_BUFSIZ];
				LOGERR("userstats != eos '%s' discarded: %s/%"PRId64"/%s",
				       tv_to_buf(&eosdate, date_buf, DATE_BUFSIZ),
				       next->poolinstance,
				       next->userid,
				       next->workername);
				us_next = us_next->next;
			} else {
				us_match = us_next;
				us_next = us_match->next;
				k_unlink_item(userstats_eos_store, us_match);
				userstats_root = add_to_ktree(userstats_root, us_match,
								cmp_userstats);
				userstats_statsdate_root = add_to_ktree(userstats_statsdate_root, us_match,
									cmp_userstats_statsdate);
				if (!startup_complete) {
					userstats_workerstatus_root = add_to_ktree(userstats_workerstatus_root, us_match,
										   cmp_userstats_workerstatus);
				}
				k_add_head(userstats_store, us_match);
			}
		}
		// Discard them
		if (userstats_eos_store->count > 0)
			k_list_transfer_to_head(userstats_eos_store, userstats_free);
		K_WUNLOCK(userstats_free);
	}

	return true;
}

static bool userstats_starttimeband(USERSTATS *row, tv_t *statsdate)
{
	char buf[DATE_BUFSIZ+1];

	copy_tv(statsdate, &(row->statsdate));
	// Start of this timeband
	switch (row->summarylevel[0]) {
		case SUMMARY_DB:
			statsdate->tv_sec -= statsdate->tv_sec % USERSTATS_DB_S;
			statsdate->tv_usec = 0;
			break;
		case SUMMARY_FULL:
			statsdate->tv_sec -= statsdate->tv_sec % USERSTATS_DB_DS;
			statsdate->tv_usec = 0;
			break;
		default:
			tv_to_buf(statsdate, buf, sizeof(buf));
			// Bad userstats are not fatal
			LOGERR("Unknown userstats summarylevel 0x%02x '%c' "
				"userid %"PRId64" workername %s statsdate %s",
				row->summarylevel[0], row->summarylevel[0],
				row->userid, row->workername, buf);
			return false;
	}
	return true;
}

// TODO: data selection - only require ?
static bool userstats_fill(PGconn *conn)
{
	ExecStatusType rescode;
	PGresult *res;
	K_ITEM *item;
	int n, i;
	USERSTATS *row;
	tv_t statsdate;
	char *field;
	char *sel;
	int fields = 10;
	bool ok;

	LOGDEBUG("%s(): select", __func__);

	sel = "select "
		"userid,workername,elapsed,hashrate,hashrate5m,hashrate1hr,"
		"hashrate24hr,summarylevel,summarycount,statsdate"
		SIMPLEDATECONTROL
		" from userstats";
	res = PQexec(conn, sel, CKPQ_READ);
	rescode = PQresultStatus(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Select", rescode, conn);
		PQclear(res);
		return false;
	}

	n = PQnfields(res);
	if (n != (fields + SIMPLEDATECOUNT)) {
		LOGERR("%s(): Invalid field count - should be %d, but is %d",
			__func__, fields + SIMPLEDATECOUNT, n);
		PQclear(res);
		return false;
	}

	n = PQntuples(res);
	LOGDEBUG("%s(): tree build count %d", __func__, n);
	ok = true;
	K_WLOCK(userstats_free);
	for (i = 0; i < n; i++) {
		item = k_unlink_head(userstats_free);
		DATA_USERSTATS(row, item);

		if (everyone_die) {
			ok = false;
			break;
		}

		// Not a DB field
		row->poolinstance[0] = '\0';

		PQ_GET_FLD(res, i, "userid", field, ok);
		if (!ok)
			break;
		TXT_TO_BIGINT("userid", field, row->userid);

		PQ_GET_FLD(res, i, "workername", field, ok);
		if (!ok)
			break;
		TXT_TO_STR("workername", field, row->workername);

		PQ_GET_FLD(res, i, "elapsed", field, ok);
		if (!ok)
			break;
		TXT_TO_BIGINT("elapsed", field, row->elapsed);

		PQ_GET_FLD(res, i, "hashrate", field, ok);
		if (!ok)
			break;
		TXT_TO_DOUBLE("hashrate", field, row->hashrate);

		PQ_GET_FLD(res, i, "hashrate5m", field, ok);
		if (!ok)
			break;
		TXT_TO_DOUBLE("hashrate5m", field, row->hashrate5m);

		PQ_GET_FLD(res, i, "hashrate1hr", field, ok);
		if (!ok)
			break;
		TXT_TO_DOUBLE("hashrate1hr", field, row->hashrate1hr);

		PQ_GET_FLD(res, i, "hashrate24hr", field, ok);
		if (!ok)
			break;
		TXT_TO_DOUBLE("hashrate24hr", field, row->hashrate24hr);

		PQ_GET_FLD(res, i, "summarylevel", field, ok);
		if (!ok)
			break;
		TXT_TO_STR("summarylevel", field, row->summarylevel);

		PQ_GET_FLD(res, i, "summarycount", field, ok);
		if (!ok)
			break;
		TXT_TO_INT("summarycount", field, row->summarycount);

		PQ_GET_FLD(res, i, "statsdate", field, ok);
		if (!ok)
			break;
		TXT_TO_TV("statsdate", field, row->statsdate);

		// From DB - 1hr means it must have been idle > 10m
		if (row->hashrate5m == 0.0 && row->hashrate1hr == 0.0)
			row->idle = true;
		else
			row->idle = false;

		SIMPLEDATEFLDS(res, i, row, ok);
		if (!ok)
			break;

		userstats_root = add_to_ktree(userstats_root, item, cmp_userstats);
		userstats_statsdate_root = add_to_ktree(userstats_statsdate_root, item,
							cmp_userstats_statsdate);
		userstats_workerstatus_root = add_to_ktree(userstats_workerstatus_root, item,
							   cmp_userstats_workerstatus);
		k_add_head(userstats_store, item);

		workerstatus_update(NULL, NULL, row);
		if (userstats_starttimeband(row, &statsdate)) {
			if (tv_newer(&(dbstatus.newest_starttimeband_userstats), &statsdate))
				copy_tv(&(dbstatus.newest_starttimeband_userstats), &statsdate);
		}

		tick();
	}
	if (!ok)
		k_add_head(userstats_free, item);

	K_WUNLOCK(userstats_free);
	PQclear(res);

	if (ok) {
		LOGDEBUG("%s(): built", __func__);
		LOGWARNING("%s(): loaded %d userstats records", __func__, n);
	}

	return ok;
}

void userstats_reload()
{
	PGconn *conn = dbconnect();

	K_WLOCK(userstats_free);
	userstats_root = free_ktree(userstats_root, NULL);
	userstats_statsdate_root = free_ktree(userstats_statsdate_root, NULL);
	k_list_transfer_to_head(userstats_store, userstats_free);
	K_WUNLOCK(userstats_free);

	userstats_fill(conn);

	PQfinish(conn);
}

static bool check_db_version(PGconn *conn)
{
	ExecStatusType rescode;
	PGresult *res;
	char *field;
	char *sel;
	char *pgv;
	int fields = 3;
	bool ok;
	int n;

	LOGDEBUG("%s(): select", __func__);

	sel = "select version() as pgv,* from version;";
	res = PQexec(conn, sel, CKPQ_READ);
	rescode = PQresultStatus(res);
	if (!PGOK(rescode)) {
		PGLOGEMERG("Select", rescode, conn);
		PQclear(res);
		return false;
	}

	n = PQnfields(res);
	if (n != fields) {
		LOGEMERG("%s(): Invalid field count - should be %d, but is %d",
			__func__, fields, n);
		PQclear(res);
		return false;
	}

	n = PQntuples(res);
	if (n != 1) {
		LOGEMERG("%s(): Invalid record count - should be %d, but is %d",
			__func__, 1, n);
		PQclear(res);
		return false;
	}

	ok = true;
	PQ_GET_FLD(res, 0, "vlock", field, ok);
	if (!ok) {
		LOGEMERG("%s(): Missing field vlock", __func__);
		PQclear(res);
		return false;
	}

	if (strcmp(field, DB_VLOCK)) {
		LOGEMERG("%s(): incorrect vlock '%s' - should be '%s'",
			__func__, field, DB_VLOCK);
		PQclear(res);
		return false;
	}

	ok = true;
	PQ_GET_FLD(res, 0, "version", field, ok);
	if (!ok) {
		LOGEMERG("%s(): Missing field version", __func__);
		PQclear(res);
		return false;
	}

	if (strcmp(field, DB_VERSION)) {
		LOGEMERG("%s(): incorrect version '%s' - should be '%s'",
			__func__, field, DB_VERSION);
		PQclear(res);
		return false;
	}

	PQ_GET_FLD(res, 0, "pgv", field, ok);
	if (ok)
		pgv = strdup(field);
	else
		pgv = strdup("Failed to get postgresql version information");

	PQclear(res);

	LOGWARNING("%s(): DB version (%s) correct (CKDB V%s)",
		   __func__, DB_VERSION, CKDB_VERSION);
	LOGWARNING("%s(): %s", __func__, pgv);

	free(pgv);

	return true;
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
	if (!confirm_sharesummary)
		ok = auths_fill(conn);

matane:

	PQfinish(conn);
	return ok;
}

static bool getdata2()
{
	PGconn *conn = dbconnect();
	bool ok = true;

	if (!(ok = blocks_fill(conn)) || everyone_die)
		goto sukamudai;
	if (!confirm_sharesummary) {
		if (!(ok = paymentaddresses_fill(conn)) || everyone_die)
			goto sukamudai;
		if (!(ok = payments_fill(conn)) || everyone_die)
			goto sukamudai;
	}
	if (!(ok = workinfo_fill(conn)) || everyone_die)
		goto sukamudai;
	if (!(ok = shares_fill()) || everyone_die)
		goto sukamudai;
	if (!(ok = shareerrors_fill()) || everyone_die)
		goto sukamudai;
	if (!(ok = sharesummary_fill(conn)) || everyone_die)
		goto sukamudai;
	if (!confirm_sharesummary) {
		if (!(ok = useratts_fill(conn)) || everyone_die)
			goto sukamudai;
		if (!(ok = poolstats_fill(conn)) || everyone_die)
			goto sukamudai;
		ok = userstats_fill(conn);
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
	tv_to_buf(&(dbstatus.newest_createdate_auths), buf, sizeof(buf));
	LOGWARNING("%s(): %s newest DB auths", __func__, buf);
	tv_to_buf(&(dbstatus.newest_createdate_poolstats), buf, sizeof(buf));
	LOGWARNING("%s(): %s newest DB poolstats", __func__, buf);
	tv_to_buf(&(dbstatus.newest_starttimeband_userstats), buf, sizeof(buf));
	LOGWARNING("%s(): %s newest DB userstats start timeband", __func__, buf);
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
	if (!tv_newer(&start, &(dbstatus.newest_createdate_auths))) {
		copy_tv(&start, &(dbstatus.newest_createdate_auths));
		reason = "auths";
	}
	if (!tv_newer(&start, &(dbstatus.newest_createdate_poolstats))) {
		copy_tv(&start, &(dbstatus.newest_createdate_poolstats));
		reason = "poolstats";
	}
	if (!tv_newer(&start, &(dbstatus.newest_starttimeband_userstats))) {
		copy_tv(&start, &(dbstatus.newest_starttimeband_userstats));
		reason = "userstats";
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

/* TODO:
static PGconn *dbquit(PGconn *conn)
{
	if (conn != NULL)
		PQfinish(conn);
	return NULL;
}
*/

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

	payments_free = k_new_list("Payments", sizeof(PAYMENTS),
					ALLOC_PAYMENTS, LIMIT_PAYMENTS, true);
	payments_store = k_new_store(payments_free);
	payments_root = new_ktree();

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
	userstats_summ = k_new_store(userstats_free);
	userstats_root = new_ktree();
	userstats_statsdate_root = new_ktree();
	userstats_workerstatus_root = new_ktree();
	userstats_free->dsp_func = dsp_userstats;

	workerstatus_free = k_new_list("WorkerStatus", sizeof(WORKERSTATUS),
					ALLOC_WORKERSTATUS, LIMIT_WORKERSTATUS, true);
	workerstatus_store = k_new_store(workerstatus_free);
	workerstatus_root = new_ktree();
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

	db_auths_complete = true;
	cksem_post(&socketer_sem);

	if (!getdata2() || everyone_die)
		return false;

	db_load_complete = true;

	if (!reload() || everyone_die)
		return false;

	set_block_share_counters();

	if (everyone_die)
		return false;

	workerstatus_ready();

	userstats_workerstatus_root = free_ktree(userstats_workerstatus_root, NULL);

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
	bool ok = false;
	char *oldhash;

	LOGDEBUG("%s(): cmd '%s'", __func__, cmd);

	i_username = require_name(trf_root, "username", 3, (char *)userpatt, reply, siz);
	if (!i_username)
		return strdup(reply);

	i_oldhash = optional_name(trf_root, "oldhash", 64, (char *)hashpatt);
	if (i_oldhash)
		oldhash = transfer_data(i_oldhash);
	else
		oldhash = EMPTY;

	i_newhash = require_name(trf_root, "newhash", 64, (char *)hashpatt, reply, siz);
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
					    by, code, inet, now, trf_root);
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
						64, (char *)hashpatt);
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
			i_email = optional_name(trf_root, "email", 1, (char *)mailpatt);
			if (i_email)
				email = transfer_data(i_email);
			else
				email = NULL;
			i_address = optional_name(trf_root, "address", 1, NULL);
			if (i_address)
				address = transfer_data(i_address);
			else
				address = NULL;
			if ((email == NULL || *email == '\0') &&
			    (address == NULL || *address == '\0')) {
				reason = "Missing/Invalid value";
				goto struckout;
			}

//			if (address && *address)
//				TODO: validate it

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

	i_elapsed = optional_name(trf_root, "elapsed", 1, NULL);
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

	i_elapsed = optional_name(trf_root, "elapsed", 1, NULL);
	if (!i_elapsed)
		i_elapsed = &userstats_elapsed;

	i_username = require_name(trf_root, "username", 1, NULL, reply, siz);
	if (!i_username)
		return strdup(reply);

	i_workername = optional_name(trf_root, "workername", 1, NULL);
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

	i_idle = optional_name(trf_root, "idle", 1, NULL);
	if (!i_idle)
		i_idle = &userstats_idle;

	idle = (strcasecmp(transfer_data(i_idle), TRUE_STR) == 0);

	i_eos = optional_name(trf_root, "eos", 1, NULL);
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
	K_ITEM *i_idname, *i_idvalue, *look;
	IDCONTROL *row;
	char *params[2 + MODIFYDATECOUNT];
	int n, par = 0;
	bool ok = false;
	ExecStatusType rescode;
	bool conned = false;
	PGresult *res;
	char *ins;

	LOGDEBUG("%s(): cmd '%s'", __func__, cmd);

	i_idname = require_name(trf_root, "idname", 3, (char *)idpatt, reply, siz);
	if (!i_idname)
		return strdup(reply);

	i_idvalue = require_name(trf_root, "idvalue", 1, (char *)intpatt, reply, siz);
	if (!i_idvalue)
		return strdup(reply);

	K_WLOCK(idcontrol_free);
	look = k_unlink_head(idcontrol_free);
	K_WUNLOCK(idcontrol_free);

	DATA_IDCONTROL(row, look);

	STRNCPY(row->idname, transfer_data(i_idname));
	TXT_TO_BIGINT("idvalue", transfer_data(i_idvalue), row->lastid);
	MODIFYDATEINIT(row, now, by, code, inet);

	par = 0;
	params[par++] = str_to_buf(row->idname, NULL, 0);
	params[par++] = bigint_to_buf(row->lastid, NULL, 0);
	MODIFYDATEPARAMS(params, par, row);
	PARCHK(par, params);

	ins = "insert into idcontrol "
		"(idname,lastid" MODIFYDATECONTROL ") values (" PQPARAM10 ")";

	if (!conn) {
		conn = dbconnect();
		conned = true;
	}

	res = PQexecParams(conn, ins, par, NULL, (const char **)params, NULL, NULL, 0, CKPQ_WRITE);
	rescode = PQresultStatus(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Insert", rescode, conn);
		goto foil;
	}

	ok = true;
foil:
	PQclear(res);
	if (conned)
		PQfinish(conn);
	for (n = 0; n < par; n++)
		free(params[n]);

	K_WLOCK(idcontrol_free);
	k_add_head(idcontrol_free, look);
	K_WUNLOCK(idcontrol_free);

	if (!ok) {
		LOGERR("%s() %s.failed.DBE", __func__, id);
		return strdup("failed.DBE");
	}
	LOGDEBUG("%s.ok.added %s %"PRId64, id, transfer_data(i_idname), row->lastid);
	snprintf(reply, siz, "ok.added %s %"PRId64,
				transfer_data(i_idname), row->lastid);
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

	i_stats = optional_name(trf_root, "stats", 1, NULL);
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
				int64_t w_elapsed;
				tv_t w_lastshare;
				double w_lastdiff, w_diffacc, w_diffinv;
				double w_diffsta, w_diffdup;
				double w_diffhi, w_diffrej;
				double w_shareacc, w_shareinv;
				double w_sharesta, w_sharedup;
				double w_sharehi, w_sharerej;

				w_hashrate5m = w_hashrate1hr = 0.0;
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
		 stats ? ",w_hashrate5m,w_hashrate1hr,w_elapsed,w_lastshare,"
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

		i_secondaryuserid = optional_name(trf_root, "secondaryuserid", 1, NULL);
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

		i_secondaryuserid = optional_name(trf_root, "secondaryuserid", 1, NULL);
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
	char *secuserid;

	LOGDEBUG("%s(): cmd '%s'", __func__, cmd);

	i_poolinstance = optional_name(trf_root, "poolinstance", 1, NULL);
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

	i_preauth = optional_name(trf_root, "preauth", 1, NULL);
	if (!i_preauth)
		i_preauth = &auth_preauth;

	secuserid = auths_add(conn, transfer_data(i_poolinstance),
				    transfer_data(i_username),
				    transfer_data(i_workername),
				    transfer_data(i_clientid),
				    transfer_data(i_enonce1),
				    transfer_data(i_useragent),
				    transfer_data(i_preauth),
				    by, code, inet, cd, igndup, trf_root, false);

	if (!secuserid) {
		LOGDEBUG("%s() %s.failed.DBE", __func__, id);
		return strdup("failed.DBE");
	}

	LOGDEBUG("%s.ok.auth added for %s", id, secuserid);
	snprintf(reply, siz, "ok.%s", secuserid);
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
	char *secuserid;

	LOGDEBUG("%s(): cmd '%s'", __func__, cmd);

	i_poolinstance = optional_name(trf_root, "poolinstance", 1, NULL);
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

	secuserid = auths_add(conn, transfer_data(i_poolinstance),
				    transfer_data(i_username),
				    transfer_data(i_workername),
				    transfer_data(i_clientid),
				    transfer_data(i_enonce1),
				    transfer_data(i_useragent),
				    transfer_data(i_preauth),
				    by, code, inet, cd, igndup, trf_root, true);

	if (!secuserid) {
		LOGDEBUG("%s() %s.failed.DBE", __func__, id);
		return strdup("failed.DBE");
	}

	LOGDEBUG("%s.ok.auth added for %s", id, secuserid);
	snprintf(reply, siz, "ok.%s", secuserid);
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

static char *cmd_homepage(__maybe_unused PGconn *conn, char *cmd, char *id,
			  __maybe_unused tv_t *now, __maybe_unused char *by,
			  __maybe_unused char *code, __maybe_unused char *inet,
			  __maybe_unused tv_t *notcd, K_TREE *trf_root)
{
	K_ITEM *i_username, *u_item, *b_item, *p_item, *us_item, look;
	double u_hashrate5m, u_hashrate1hr;
	char reply[1024], tmp[1024], *buf;
	USERSTATS lookuserstats, *userstats;
	POOLSTATS *poolstats;
	BLOCKS *blocks;
	USERS *users;
	int64_t u_elapsed;
	K_TREE_CTX ctx[1], w_ctx[1];
	size_t len, off;
	bool has_uhr;

	LOGDEBUG("%s(): cmd '%s'", __func__, cmd);

	i_username = optional_name(trf_root, "username", 1, NULL);

	APPEND_REALLOC_INIT(buf, off, len);
	APPEND_REALLOC(buf, off, len, "ok.");
	if (last_bc.tv_sec) {
		tvs_to_buf(&last_bc, reply, sizeof(reply));
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
		tvs_to_buf(&(blocks->createdate), reply, sizeof(reply));
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
		int_to_buf(poolstats->users, reply, sizeof(reply));
		snprintf(tmp, sizeof(tmp), "users=%s%c", reply, FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);

		int_to_buf(poolstats->workers, reply, sizeof(reply));
		snprintf(tmp, sizeof(tmp), "workers=%s%c", reply, FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);

		double_to_buf(poolstats->hashrate5m, reply, sizeof(reply));
		snprintf(tmp, sizeof(tmp), "p_hashrate5m=%s%c", reply, FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);

		double_to_buf(poolstats->hashrate1hr, reply, sizeof(reply));
		snprintf(tmp, sizeof(tmp), "p_hashrate1hr=%s%c", reply, FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);

		bigint_to_buf(poolstats->elapsed, reply, sizeof(reply));
		snprintf(tmp, sizeof(tmp), "p_elapsed=%s%c", reply, FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);
	} else {
		snprintf(tmp, sizeof(tmp), "users=?%cworkers=?%cp_hashrate5m=?%c"
					   "p_hashrate1hr=?%cp_elapsed=?%c",
					   FLDSEP, FLDSEP, FLDSEP, FLDSEP, FLDSEP);
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
		double_to_buf(u_hashrate5m, reply, sizeof(reply));
		snprintf(tmp, sizeof(tmp), "u_hashrate5m=%s%c", reply, FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);

		double_to_buf(u_hashrate1hr, reply, sizeof(reply));
		snprintf(tmp, sizeof(tmp), "u_hashrate1hr=%s%c", reply, FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);

		bigint_to_buf(u_elapsed, reply, sizeof(reply));
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

	i_difftimes = optional_name(trf_root, "diff_times", 1, NULL);
	if (i_difftimes)
		TXT_TO_DOUBLE("diff_times", transfer_data(i_difftimes), diff_times);

	i_diffadd = optional_name(trf_root, "diff_add", 1, NULL);
	if (i_diffadd)
		TXT_TO_DOUBLE("diff_add", transfer_data(i_diffadd), diff_add);

	i_allowaged = optional_name(trf_root, "allow_aged", 1, NULL);
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

	dsp_ktree(sharesummary_free, sharesummary_root, transfer_data(i_file), NULL);

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
	uint64_t ram, tot = 0;
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
	snprintf(tmp, sizeof(tmp), \
		 "name:%d=" #_obj "%cinitial:%d=%d%callocated:%d=%d%c" \
		 "store:%d=%d%ctrees:%d=%d%cram:%d=%"PRIu64"%c" \
		 "cull:%d=%d%c", \
		 rows, FLDSEP, \
		 rows, klist->allocate, FLDSEP, \
		 rows, klist->total, FLDSEP, \
		 rows, klist->total - klist->count, FLDSEP, \
		 rows, _trees, FLDSEP, \
		 rows, ram, FLDSEP, \
		 rows, klist->cull_count, FLDSEP); \
	APPEND_REALLOC(buf, off, len, tmp); \
	tot += ram; \
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
 */
static struct CMDS {
	enum cmd_values cmd_val;
	char *cmd_str;
	bool noid; // doesn't require an id
	bool createdate; // requires a createdate
	char *(*func)(PGconn *, char *, char *, tv_t *, char *, char *,
			char *, tv_t *, K_TREE *);
	char *access;
} cmds[] = {
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
	{ CMD_ADDUSER,	"adduser",	false,	false,	cmd_adduser,	ACCESS_WEB },
	{ CMD_NEWPASS,	"newpass",	false,	false,	cmd_newpass,	ACCESS_WEB },
	{ CMD_CHKPASS,	"chkpass",	false,	false,	cmd_chkpass,	ACCESS_WEB },
	{ CMD_USERSET,	"usersettings",	false,	false,	cmd_userset,	ACCESS_WEB },
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

static enum cmd_values breakdown(K_TREE **trf_root, K_STORE **trf_store,
				 char *buf, int *which_cmds, char *cmd,
				 char *id, tv_t *cd)
{
	char reply[1024] = "";
	TRANSFER *transfer;
	K_TREE_CTX ctx[1];
	K_ITEM *item;
	char *cmdptr, *idptr, *next, *eq;
	char *data = NULL;
	bool noid = false;

	*trf_root = NULL;
	*trf_store = NULL;
	*which_cmds = CMD_UNSET;
	*cmd = *id = '\0';
	cd->tv_sec = 0;
	cd->tv_usec = 0;

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
	for (*which_cmds = 0; cmds[*which_cmds].cmd_val != CMD_END; (*which_cmds)++) {
		if (strcasecmp(cmd, cmds[*which_cmds].cmd_str) == 0)
			break;
	}

	if (cmds[*which_cmds].cmd_val == CMD_END) {
		LOGERR("Listener received unknown command: '%s'", buf);
		free(cmdptr);
		return CMD_REPLY;
	}

	if (noid) {
		if (cmds[*which_cmds].noid) {
			*id = '\0';
			free(cmdptr);
			return cmds[*which_cmds].cmd_val;
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
		json_t *json_data;
		json_error_t err_val;
		void *json_iter;
		const char *json_key, *json_str;
		json_t *json_value;
		int json_typ;
		size_t siz;
		bool ok;

		next += JSON_TRANSFER_LEN;
		json_data = json_loads(next, JSON_DISABLE_EOF_CHECK, &err_val);
		if (!json_data) {
			/* This REALLY shouldn't ever get an error since the input
			 * is a json generated string
			 * If that happens then dump lots of information */
			char *text = safe_text(next);
			LOGERR("Json decode error from command: '%s' "
				"json_err=(%d:%d:%d)%s:%s input='%s'",
				cmd, err_val.line, err_val.column,
				err_val.position, err_val.source,
				err_val.text, text);
			free(text);
			free(cmdptr);
			return CMD_REPLY;
		}
		json_iter = json_object_iter(json_data);
		K_WLOCK(transfer_free);
		while (json_iter) {
			json_key = json_object_iter_key(json_iter);
			json_value = json_object_iter_value(json_iter);
			item = k_unlink_head(transfer_free);
			DATA_TRANSFER(transfer, item);
			ok = true;
			json_typ = json_typeof(json_value);
			switch (json_typ) {
			 case JSON_STRING:
				json_str = json_string_value(json_value);
				siz = strlen(json_str);
				if (siz >= sizeof(transfer->svalue))
					transfer->mvalue = strdup(json_str);
				else {
					STRNCPY(transfer->svalue, json_str);
					transfer->mvalue = transfer->svalue;
				}
				break;
			 case JSON_REAL:
				snprintf(transfer->svalue,
					 sizeof(transfer->svalue),
					 "%f", json_real_value(json_value));
				transfer->mvalue = transfer->svalue;
				break;
			 case JSON_INTEGER:
				snprintf(transfer->svalue,
					 sizeof(transfer->svalue),
					 "%"PRId64,
					 (int64_t)json_integer_value(json_value));
				transfer->mvalue = transfer->svalue;
				break;
			 case JSON_TRUE:
			 case JSON_FALSE:
				snprintf(transfer->svalue,
					 sizeof(transfer->svalue),
					 "%s", (json_typ == JSON_TRUE) ?
							TRUE_STR : FALSE_STR);
				transfer->mvalue = transfer->svalue;
				break;
			 case JSON_ARRAY:
				{
					/* only one level array of strings for now (merkletree)
					 * ignore other data */
					size_t i, len, off, count = json_array_size(json_value);
					json_t *json_element;
					bool first = true;

					APPEND_REALLOC_INIT(transfer->mvalue, off, len);
					for (i = 0; i < count; i++) {
						json_element = json_array_get(json_value, i);
						if (json_is_string(json_element)) {
							json_str = json_string_value(json_element);
							siz = strlen(json_str);
							if (first)
								first = false;
							else {
								APPEND_REALLOC(transfer->mvalue,
										off, len, " ");
							}
							APPEND_REALLOC(transfer->mvalue,
									off, len, json_str);
						} else
							LOGERR("%s() unhandled json type %d in array %s"
							       " in cmd %s", __func__,
							       json_typ, json_key, cmd);
					}
				}
				break;
			 default:
				LOGERR("%s() unhandled json type %d in cmd %s",
				       __func__, json_typ, cmd);
				ok = false;
				break;
			}

			if (ok)
				STRNCPY(transfer->name, json_key);
			if (!ok || find_in_ktree(*trf_root, item, cmp_transfer, ctx)) {
				if (transfer->mvalue != transfer->svalue)
					free(transfer->mvalue);
				k_add_head(transfer_free, item);
			} else {
				*trf_root = add_to_ktree(*trf_root, item, cmp_transfer);
				k_add_head(*trf_store, item);
			}
			json_iter = json_object_iter_next(json_data, json_iter);
		}
		K_WUNLOCK(transfer_free);
		json_decref(json_data);
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
					free(transfer->mvalue);
				k_add_head(transfer_free, item);
			} else {
				*trf_root = add_to_ktree(*trf_root, item, cmp_transfer);
				k_add_head(*trf_store, item);
			}
		}
		K_WUNLOCK(transfer_free);
	}
	if (cmds[*which_cmds].createdate) {
		item = require_name(*trf_root, "createdate", 10, NULL, reply, sizeof(reply));
		if (!item)
			return CMD_REPLY;

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
	return cmds[*which_cmds].cmd_val;
}

static void summarise_blocks()
{
	K_ITEM *b_item, *b_prev, *wi_item, ss_look, *ss_item;
	K_TREE_CTX ctx[1], ss_ctx[1];
	double diffacc, diffinv, shareacc, shareinv;
	tv_t now, elapsed_start, elapsed_finish;
	int64_t elapsed, wi_start, wi_finish;
	BLOCKS *blocks, *prev_blocks;
	WORKINFO *prev_workinfo;
	SHARESUMMARY looksharesummary, *sharesummary;
	int32_t hi, prev_hi;
	bool ok;

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
		wi_item = find_workinfo(wi_start);
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
	looksharesummary.workername[0] = '\0';
	INIT_SHARESUMMARY(&ss_look);
	ss_look.data = (void *)(&looksharesummary);
	K_RLOCK(sharesummary_free);
	ss_item = find_before_in_ktree(sharesummary_workinfoid_root, &ss_look,
					cmp_sharesummary_workinfoid, ss_ctx);

	if (!ss_item) {
		K_RUNLOCK(sharesummary_free);
		// This will repeat each call here until fixed ...
		LOGERR("%s() block %d, prev %d no sharesummaries "
			"on or before %"PRId64,
			__func__, blocks->height,
			prev_hi, wi_finish);
		return;
	}
	DATA_SHARESUMMARY(sharesummary, ss_item);
	while (ss_item && sharesummary->workinfoid > wi_start) {
		if (sharesummary->complete[0] == SUMMARY_NEW) {
			// Not aged yet
			K_RUNLOCK(sharesummary_free);
			return;
		}
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
	K_RUNLOCK(sharesummary_free);

	elapsed = (int64_t)(tvdiff(&elapsed_finish, &elapsed_start) + 0.5);
	ok = blocks_stats(NULL, blocks->height, blocks->blockhash,
			  diffacc, diffinv, shareacc, shareinv, elapsed,
			  by_default, (char *)__func__, inet_default, &now);

	if (ok) {
		LOGWARNING("%s() block %d, stats confirmed "
			   "%0.f/%.0f/%.0f/%.0f/%"PRId64,
			   __func__, blocks->height,
			   diffacc, diffinv, shareacc, shareinv, elapsed);
	} else {
		LOGERR("%s() block %d, failed to confirm stats",
			__func__, blocks->height);
	}
}

static void summarise_poolstats()
{
// TODO
}

// TODO: daily
// TODO: consider limiting how much/how long this processes each time
static void summarise_userstats()
{
	K_TREE_CTX ctx[1], ctx2[1];
	K_ITEM *first, *last, *new, *next, *tmp;
	USERSTATS *userstats, *us_first, *us_last, *us_next;
	double statrange, factor;
	bool locked, upgrade;
	tv_t now, process, when;
	PGconn *conn = NULL;
	int count;
	char error[1024];
	char tvbuf1[DATE_BUFSIZ], tvbuf2[DATE_BUFSIZ];

	upgrade = false;
	locked = false;
	while (1764) {
		error[0] = '\0';
		setnow(&now);
		upgrade = false;
		locked = true;
		K_ILOCK(userstats_free);

		// confirm_summaries() doesn't call this
		if (!reloading)
			copy_tv(&process, &now);
		else {
			// During reload, base the check date on the newest statsdate
			last = last_in_ktree(userstats_statsdate_root, ctx);
			if (!last)
				break;

			DATA_USERSTATS(us_last, last);
			copy_tv(&process, &us_last->statsdate);
		}

		first = first_in_ktree(userstats_statsdate_root, ctx);
		DATA_USERSTATS_NULL(us_first, first);
		// Oldest non DB stat
		// TODO: make the index start with summarylevel? so can find faster
		while (first && us_first->summarylevel[0] != SUMMARY_NONE) {
			first = next_in_ktree(ctx);
			DATA_USERSTATS_NULL(us_first, first);
		}

		if (!first)
			break;

		statrange = tvdiff(&process, &(us_first->statsdate));
		// Is there data ready for summarising?
		if (statrange <= USERSTATS_AGE)
			break;

		copy_tv(&when,  &(us_first->statsdate));
		/* Convert when to the start of the timeframe after the one it is in
		 * assume timeval ignores leapseconds ... */
		when.tv_sec = when.tv_sec - (when.tv_sec % USERSTATS_DB_S) + USERSTATS_DB_S;
		when.tv_usec = 0;

		// Is the whole timerange up to before 'when' ready for summarising?
		statrange = tvdiff(&process, &when);
		if (statrange < USERSTATS_AGE)
			break;

		next = next_in_ktree(ctx);

		upgrade = true;
		K_ULOCK(userstats_free);
		new = k_unlink_head(userstats_free);
		DATA_USERSTATS(userstats, new);
		memcpy(userstats, us_first, sizeof(USERSTATS));

		userstats_root = remove_from_ktree(userstats_root, first, cmp_userstats, ctx2);
		userstats_statsdate_root = remove_from_ktree(userstats_statsdate_root, first,
							     cmp_userstats_statsdate, ctx2);
		k_unlink_item(userstats_store, first);
		k_add_head(userstats_summ, first);

		count = 1;
		while (next) {
			DATA_USERSTATS(us_next, next);
			statrange = tvdiff(&when, &(us_next->statsdate));
			if (statrange <= 0)
				break;

			tmp = next_in_ktree(ctx);

			if (us_next->summarylevel[0] == SUMMARY_NONE &&
			    us_next->userid == userstats->userid &&
			    strcmp(us_next->workername, userstats->workername) == 0) {
				count++;
				userstats->hashrate += us_next->hashrate;
				userstats->hashrate5m += us_next->hashrate5m;
				userstats->hashrate1hr += us_next->hashrate1hr;
				userstats->hashrate24hr += us_next->hashrate24hr;
				if (userstats->elapsed > us_next->elapsed)
					userstats->elapsed = us_next->elapsed;
				userstats->summarycount += us_next->summarycount;

				userstats_root = remove_from_ktree(userstats_root, next, cmp_userstats, ctx2);
				userstats_statsdate_root = remove_from_ktree(userstats_statsdate_root, next,
									     cmp_userstats_statsdate, ctx2);
				k_unlink_item(userstats_store, next);
				k_add_head(userstats_summ, next);
			}
			next = tmp;
		}

		// Can temporarily release the lock since all our data is now not part of the lock
		if (upgrade)
			K_WUNLOCK(userstats_free);
		else
			K_IUNLOCK(userstats_free);
		upgrade = false;
		locked = false;

		if (userstats->hashrate5m > 0.0 || userstats->hashrate1hr > 0.0)
			userstats->idle = false;
		else
			userstats->idle = true;

		userstats->summarylevel[0] = SUMMARY_DB;
		userstats->summarylevel[1] = '\0';

		// Expect 6 per poolinstance
		factor = (double)count / 6.0;
		userstats->hashrate *= factor;
		userstats->hashrate5m *= factor;
		userstats->hashrate1hr *= factor;
		userstats->hashrate24hr *= factor;

		copy_tv(&(userstats->statsdate), &when);
		// Stats to the end of this timeframe
		userstats->statsdate.tv_sec -= 1;
		userstats->statsdate.tv_usec = 999999;

		// This is simply when it was written, so 'now' is fine
		SIMPLEDATEDEFAULT(userstats, &now);

		if (!conn)
			conn = dbconnect();

		if (!userstats_add_db(conn, userstats)) {
			/* This should only happen if a restart finds data
			   that wasn't found during the reload but is in
			   the same timeframe as DB data
			   i.e. it shouldn't happen, but keep the summary anyway */
			when.tv_sec -= USERSTATS_DB_S;
			tv_to_buf(&when, tvbuf1, sizeof(tvbuf1));
			tv_to_buf(&(userstats->statsdate), tvbuf2, sizeof(tvbuf2));
			snprintf(error, sizeof(error),
				 "Userid %"PRId64" Worker %s, %d userstats record%s "
				 "discarded from %s to %s",
				 userstats->userid,
				 userstats->workername,
				 count, (count == 1 ? "" : "s"),
				 tvbuf1, tvbuf2);
		}

		// The flags are not needed
		//upgrade = true;
		//locked = true;
		K_WLOCK(userstats_free);
		k_list_transfer_to_tail(userstats_summ, userstats_free);
		k_add_head(userstats_store, new);
		userstats_root = add_to_ktree(userstats_root, new, cmp_userstats);
		userstats_statsdate_root = add_to_ktree(userstats_statsdate_root, new,
							cmp_userstats_statsdate);

		K_WUNLOCK(userstats_free);
		//locked = false;
		//upgrade = false;

		if (error[0])
			LOGERR(error);
	}

	if (locked) {
		if (upgrade)
			K_WUNLOCK(userstats_free);
		else
			K_IUNLOCK(userstats_free);
	}

	if (conn)
		PQfinish(conn);
}

static void *summariser(__maybe_unused void *arg)
{
	pthread_detach(pthread_self());

	rename_proc("db_summariser");

	while (!everyone_die && !db_load_complete)
		cksleep_ms(42);

	while (!everyone_die) {
		sleep(5);
		if (!everyone_die)
			summarise_blocks();

		sleep(4);
		if (!everyone_die)
			summarise_poolstats();

		sleep(4);
		if (!everyone_die)
			summarise_userstats();
	}

	return NULL;
}

static void *logger(__maybe_unused void *arg)
{
	K_ITEM *lq_item;
	LOGQUEUE *lq;
	char buf[128];
	tv_t now;

	pthread_detach(pthread_self());

	snprintf(buf, sizeof(buf), "db%s_logger", dbcode);
	rename_proc(buf);

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
			free(lq->msg);

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
	setnow(&now);
	snprintf(buf, sizeof(buf), "logstopping.%d.%ld,%ld",
				   logqueue_store->count,
				   now.tv_sec, now.tv_usec);
	LOGFILE(buf);
	while((lq_item = k_unlink_head(logqueue_store))) {
		DATA_LOGQUEUE(lq, lq_item);
		LOGFILE(lq->msg);
	}
	K_WUNLOCK(logqueue_free);

	setnow(&now);
	snprintf(buf, sizeof(buf), "logstop.%ld,%ld",
				   now.tv_sec, now.tv_usec);
	LOGFILE(buf);

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
	char *last_newid = NULL, *reply_newid = NULL;
	char *last_setatts = NULL, *reply_setatts = NULL;
	char *last_setopts = NULL, *reply_setopts = NULL;
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
	bool dup, want_first;
	int loglevel, oldloglevel;

	pthread_detach(pthread_self());

	rename_proc("db_socketer");

	while (!everyone_die && !db_auths_complete)
		cksem_mswait(&socketer_sem, 420);

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
			} else if (last_setatts && strcmp(last_setatts, buf) == 0) {
				reply_last = reply_setatts;
				dup = true;
			} else if (last_setopts && strcmp(last_setopts, buf) == 0) {
				reply_last = reply_setopts;
				dup = true;
			} else if (last_web && strcmp(last_web, buf) == 0) {
				reply_last = reply_web;
				dup = true;
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
				LOGWARNING("Duplicate '%s' message received", duptype);
			} else {
				LOGQUE(buf);
				cmdnum = breakdown(&trf_root, &trf_store, buf, &which_cmds, cmd, id, &cd);
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
					// Always process immediately:
					case CMD_AUTH:
					case CMD_ADDRAUTH:
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
					case CMD_GETATTS:
					case CMD_SETATTS:
					case CMD_EXPATTS:
					case CMD_GETOPTS:
					case CMD_SETOPTS:
					case CMD_BLOCKLIST:
					case CMD_NEWID:
					case CMD_STATS:
						ans = cmds[which_cmds].func(NULL, cmd, id, &now,
									    by_default,
									    (char *)__func__,
									    inet_default,
									    &cd, trf_root);
						siz = strlen(ans) + strlen(id) + 32;
						rep = malloc(siz);
						snprintf(rep, siz, "%s.%ld.%s", id, now.tv_sec, ans);
						send_unix_msg(sockd, rep);
						free(ans);
						ans = NULL;
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
							case CMD_NEWID:
								STORELASTREPLY(newid);
								break;
							case CMD_SETATTS:
								STORELASTREPLY(setatts);
								break;
							case CMD_SETOPTS:
								STORELASTREPLY(setopts);
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
					case CMD_DSP:
					case CMD_BLOCKSTATUS:
						if (!startup_complete) {
							snprintf(reply, sizeof(reply),
								 "%s.%ld.loading.%s",
								 id, now.tv_sec, cmd);
							send_unix_msg(sockd, reply);
						} else {
							ans = cmds[which_cmds].func(NULL, cmd, id, &now,
										    by_default,
										    (char *)__func__,
										    inet_default,
										    &cd, trf_root);
							siz = strlen(ans) + strlen(id) + 32;
							rep = malloc(siz);
							snprintf(rep, siz, "%s.%ld.%s", id, now.tv_sec, ans);
							send_unix_msg(sockd, rep);
							free(ans);
							ans = NULL;
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
					// Always queue (ok.queued)
					case CMD_SHARELOG:
					case CMD_POOLSTAT:
					case CMD_USERSTAT:
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
					free(transfer->mvalue);
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
		cmdnum = breakdown(&trf_root, &trf_store, buf, &which_cmds, cmd, id, &cd);
		switch (cmdnum) {
			// Ignore
			case CMD_REPLY:
				break;
			// Shouldn't be there
			case CMD_SHUTDOWN:
			case CMD_PING:
			case CMD_VERSION:
			case CMD_LOGLEVEL:
			// Non pool commands, shouldn't be there
			case CMD_ADDUSER:
			case CMD_NEWPASS:
			case CMD_CHKPASS:
			case CMD_USERSET:
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
				LOGERR("%s() Message line %"PRIu64" '%s' - invalid - ignored",
					__func__, count, cmd);
				break;
			case CMD_AUTH:
			case CMD_ADDRAUTH:
			case CMD_POOLSTAT:
			case CMD_USERSTAT:
			case CMD_BLOCK:
				if (confirm_sharesummary)
					break;
			case CMD_SHARELOG:
				ans = cmds[which_cmds].func(conn, cmd, id, &now,
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
					free(transfer->mvalue);
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
	bool finished = false, matched = false, ret = true;
	char *filename = NULL;
	uint64_t count, total;
	tv_t now;
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
	fp = fopen(filename, "re");
	if (!fp)
		quithere(1, "Failed to open '%s'", filename);

	setnow(&now);
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

		while (!everyone_die && !matched && fgets_unlocked(reload_buf, MAX_READ, fp))
			matched = reload_line(conn, filename, ++count, reload_buf);

		if (ferror(fp)) {
			int err = errno;
			quithere(1, "Read failed on %s (%d) '%s'",
				    filename, err, strerror(err));
		}

		LOGWARNING("%s(): %sread %"PRIu64" line%s from %s",
			   __func__,
			   everyone_die ? "Shutdown, aborting - " : "",
			   count, count == 1 ? "" : "s",
			   filename);
		total += count;
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
		fp = fopen(filename, "re");
		if (!fp) {
			missingfirst = strdup(filename);
			free(filename);
			filename = NULL;
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
				fp = fopen(filename, "re");
				if (fp)
					break;
				errno = 0;
				if (missing_count++ > 1)
					free(missinglast);
				missinglast = strdup(filename);
				free(filename);
				filename = NULL;
			}
			if (missing_count == 1)
				LOGWARNING("%s(): skipped %s", __func__, missingfirst+rflen);
			else {
				LOGWARNING("%s(): skipped %d files from %s to %s",
					   __func__, missing_count, missingfirst+rflen, missinglast+rflen);
				free(missinglast);
				missinglast = NULL;
			}
			free(missingfirst);
			missingfirst = NULL;
		}
	}

	PQfinish(conn);

	snprintf(reload_buf, MAX_READ, "reload.%s.%"PRIu64, run, total);
	LOGQUE(reload_buf);
	LOGWARNING("%s(): read %d file%s, total %"PRIu64" line%s",
		   __func__,
		   processing, processing == 1 ? "" : "s",
		   total, total == 1 ? "" : "s");

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

	free(reload_buf);
	reload_buf = NULL;

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
		ans = cmds[workqueue->which_cmds].func(conn, workqueue->cmd, workqueue->id,
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
			free(transfer->mvalue);
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
	K_ITEM *wq_item;
	time_t now;
	int wqcount, wqgot;

	logqueue_free = k_new_list("LogQueue", sizeof(LOGQUEUE),
					ALLOC_LOGQUEUE, LIMIT_LOGQUEUE, true);
	logqueue_store = k_new_store(logqueue_free);

	create_pthread(&log_pt, logger, NULL);

	create_pthread(&sock_pt, socketer, arg);

	create_pthread(&summ_pt, summariser, NULL);

	rename_proc("db_listener");

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

		/* Don't keep a connection for more than ~10s or ~1000 items
		 *  but always have a connection open */
		if ((time(NULL) - now) > 10 || wqgot > 1000) {
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
			pthread_cond_timedwait(&wq_waitcond, &wq_waitlock, &abs);
			mutex_unlock(&wq_waitlock);
		}
	}

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
	looksharesummary.workername[0] = '\0';
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
			   __func__, buf);
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
						   __func__, buf);
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
		start.tv_sec = start.tv_usec = 0;
		LOGWARNING("%s() no start workinfo found ... using time 0", __func__);
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
	{ "dbprefix",		required_argument,	0,	'b' },
	{ "config",		required_argument,	0,	'c' },
	{ "dbname",		required_argument,	0,	'd' },
	{ "help",		no_argument,		0,	'h' },
	{ "killold",		no_argument,		0,	'k' },
	{ "loglevel",		required_argument,	0,	'l' },
	{ "name",		required_argument,	0,	'n' },
	{ "dbpass",		required_argument,	0,	'p' },
	{ "ckpool-logdir",	required_argument,	0,	'r' },
	{ "logdir",		required_argument,	0,	'R' },
	{ "sockdir",		required_argument,	0,	's' },
	{ "dbuser",		required_argument,	0,	'u' },
	{ "version",		no_argument,		0,	'v' },
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

	while ((c = getopt_long(argc, argv, "c:d:hkl:n:p:r:R:s:u:vyY:", long_options, &i)) != -1) {
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
			case 'r':
				restorefrom = strdup(optarg);
				break;
			case 'R':
				ckp.logdir = strdup(optarg);
				break;
			case 's':
				ckp.socket_dir = strdup(optarg);
				break;
			case 'u':
				db_user = strdup(optarg);
				kill = optarg;
				while (*kill)
					*(kill++) = ' ';
				break;
			case 'v':
				exit(0);
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

	if (confirm_sharesummary) {
		// TODO: add a system lock to stop running 2 at once?
		confirm_summaries();
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

	clean_up(&ckp);

	return 0;
}
