/*
 * Copyright 1995-2014 Andrew Smith
 * Copyright 2014 Con Kolivas
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#ifndef CKDB_H
#define CKDB_H

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
#define CKDB_VERSION DB_VERSION"-0.402"

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

extern char *EMPTY;

extern const char *userpatt;
extern const char *mailpatt;
extern const char *idpatt;
extern const char *intpatt;
extern const char *hashpatt;
extern const char *addrpatt;

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
extern LOADSTATUS dbstatus;

// So cmd_getopts works on a new empty pool
#define START_POOL_HEIGHT 2

// Share stats since last block
typedef struct poolstatus {
	int64_t workinfoid; // Last block
	int32_t height;
	int64_t reward;
	double diffacc;
	double diffinv; // Non-acc
	double shareacc;
	double shareinv; // Non-acc
	double best_sdiff; // TODO (maybe)
} POOLSTATUS;
extern POOLSTATUS pool;

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

#define MAXID 0x7fffffffffffffffLL

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

// 6-Jun-6666 06:06:06+00
#define DEFAULT_EXPIRY 148204965966L
// 1-Jun-6666 00:00:00+00
#define COMPARE_EXPIRY 148204512000L

extern const tv_t default_expiry;

// No actual need to test tv_usec
#define CURRENT(_tv) (((_tv)->tv_sec == DEFAULT_EXPIRY) ? true : false)

// 31-Dec-9999 23:59:59+00
#define DATE_S_EOT 253402300799L
#define DATE_uS_EOT 0L
extern const tv_t date_eot;

// All data will be after: 2-Jan-2014 00:00:00+00
#define DATE_BEGIN 1388620800L
extern const tv_t date_begin;

#define BTC_TO_D(_amt) ((double)((_amt) / 100000000.0))

// argv -y - don't run in ckdb mode, just confirm sharesummaries
extern bool confirm_sharesummary;

extern int64_t confirm_first_workinfoid;
extern int64_t confirm_last_workinfoid;

/* Stop the reload 11min after the 'last' workinfoid+1 appears
 * ckpool uses 10min - but add 1min to be sure */
#define WORKINFO_AGE 660

// DB users,workers,auth load is complete
extern bool db_auths_complete;
// DB load is complete
extern bool db_load_complete;
// Different input data handling
extern bool reloading;
// Data load is complete
extern bool startup_complete;
// Tell everyone to die
extern bool everyone_die;

#define JSON_TRANSFER "json="
#define JSON_TRANSFER_LEN (sizeof(JSON_TRANSFER)-1)

// Methods for sharelog (common function for all)
#define STR_WORKINFO "workinfo"
#define STR_SHARES "shares"
#define STR_SHAREERRORS "shareerror"
#define STR_AGEWORKINFO "ageworkinfo"

extern char *by_default;
extern char *inet_default;

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
	CMD_HEARTBEAT,
	CMD_NEWPASS,
	CMD_CHKPASS,
	CMD_USERSET,
	CMD_WORKERSET,
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

// ***
// *** ckdb.c
// ***

// CCLs are every ...
#define ROLL_S 3600

#define LOGQUE(_msg) log_queue_message(_msg)
#define LOGFILE(_msg) rotating_log_nolock(_msg)
#define LOGDUP "dup."

// ***
// *** klists/ktrees ***
// ***

#define HISTORYDATECONTROL ",createdate,createby,createcode,createinet,expirydate"
#define HISTORYDATECOUNT 5
#define HISTORYDATECONTROLFIELDS \
	tv_t createdate; \
	char createby[TXT_SML+1]; \
	char createcode[TXT_MED+1]; \
	char createinet[TXT_MED+1]; \
	tv_t expirydate

#define HISTORYDATEINIT(_row, _cd, _by, _code, _inet) do { \
		_row->createdate.tv_sec = (_cd)->tv_sec; \
		_row->createdate.tv_usec = (_cd)->tv_usec; \
		STRNCPY(_row->createby, _by); \
		STRNCPY(_row->createcode, _code); \
		STRNCPY(_row->createinet, _inet); \
		_row->expirydate.tv_sec = default_expiry.tv_sec; \
		_row->expirydate.tv_usec = default_expiry.tv_usec; \
	} while (0)

/* Override _row defaults if transfer fields are present
 * We don't care about the reply so it can be small */
#define HISTORYDATETRANSFER(_root, _row) do { \
		char __reply[16]; \
		size_t __siz = sizeof(__reply); \
		K_ITEM *__item; \
		TRANSFER *__transfer; \
		__item = optional_name(_root, "createby", 1, NULL, __reply, __siz); \
		if (__item) { \
			DATA_TRANSFER(__transfer, __item); \
			STRNCPY(_row->createby, __transfer->mvalue); \
		} \
		__item = optional_name(_root, "createcode", 1, NULL, __reply, __siz); \
		if (__item) { \
			DATA_TRANSFER(__transfer, __item); \
			STRNCPY(_row->createcode, __transfer->mvalue); \
		} \
		__item = optional_name(_root, "createinet", 1, NULL, __reply, __siz); \
		if (__item) { \
			DATA_TRANSFER(__transfer, __item); \
			STRNCPY(_row->createinet, __transfer->mvalue); \
		} \
	} while (0)

#define MODIFYDATECONTROL ",createdate,createby,createcode,createinet" \
			  ",modifydate,modifyby,modifycode,modifyinet"
#define MODIFYDATECOUNT 8
#define MODIFYUPDATECOUNT 4
#define MODIFYDATECONTROLFIELDS \
	tv_t createdate; \
	char createby[TXT_SML+1]; \
	char createcode[TXT_MED+1]; \
	char createinet[TXT_MED+1]; \
	tv_t modifydate; \
	char modifyby[TXT_SML+1]; \
	char modifycode[TXT_MED+1]; \
	char modifyinet[TXT_MED+1]

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

#define SIMPLEDATECONTROL ",createdate,createby,createcode,createinet"
#define SIMPLEDATECOUNT 4
#define SIMPLEDATECONTROLFIELDS \
	tv_t createdate; \
	char createby[TXT_SML+1]; \
	char createcode[TXT_MED+1]; \
	char createinet[TXT_MED+1]

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

/* Override _row defaults if transfer fields are present
 * We don't care about the reply so it can be small */
#define SIMPLEDATETRANSFER(_root, _row) do { \
		char __reply[16]; \
		size_t __siz = sizeof(__reply); \
		K_ITEM *__item; \
		TRANSFER *__transfer; \
		__item = optional_name(_root, "createby", 1, NULL, __reply, __siz); \
		if (__item) { \
			DATA_TRANSFER(__transfer, __item); \
			STRNCPY(_row->createby, __transfer->mvalue); \
		} \
		__item = optional_name(_root, "createcode", 1, NULL, __reply, __siz); \
		if (__item) { \
			DATA_TRANSFER(__transfer, __item); \
			STRNCPY(_row->createcode, __transfer->mvalue); \
		} \
		__item = optional_name(_root, "createinet", 1, NULL, __reply, __siz); \
		if (__item) { \
			DATA_TRANSFER(__transfer, __item); \
			STRNCPY(_row->createinet, __transfer->mvalue); \
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

extern K_LIST *logqueue_free;
extern K_STORE *logqueue_store;

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

extern K_LIST *workqueue_free;
extern K_STORE *workqueue_store;
extern pthread_mutex_t wq_waitlock;
extern pthread_cond_t wq_waitcond;

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

extern K_LIST *transfer_free;

#define transfer_data(_item) _transfer_data(_item, WHERE_FFL_HERE)

extern const char Transfer[];

extern K_ITEM auth_poolinstance;
extern K_ITEM auth_preauth;
extern K_ITEM poolstats_elapsed;
extern K_ITEM userstats_elapsed;
extern K_ITEM userstats_workername;
extern K_ITEM userstats_idle;
extern K_ITEM userstats_eos;
extern K_ITEM shares_secondaryuserid;
extern K_ITEM shareerrors_secondaryuserid;
extern tv_t missing_secuser_min;
extern tv_t missing_secuser_max;

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

extern K_TREE *users_root;
extern K_TREE *userid_root;
extern K_LIST *users_free;
extern K_STORE *users_store;

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

extern K_TREE *useratts_root;
extern K_LIST *useratts_free;
extern K_STORE *useratts_store;

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

extern K_TREE *workers_root;
extern K_LIST *workers_free;
extern K_STORE *workers_store;

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

extern K_TREE *paymentaddresses_root;
extern K_LIST *paymentaddresses_free;
extern K_STORE *paymentaddresses_store;

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

extern K_TREE *payments_root;
extern K_LIST *payments_free;
extern K_STORE *payments_store;

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

extern K_TREE *accountbalance_root;
extern K_LIST *accountbalance_free;
extern K_STORE *accountbalance_store;

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

extern K_TREE *accountadjustment_root;
extern K_LIST *accountadjustment_free;
extern K_STORE *accountadjustment_store;
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
//extern K_TREE *idcontrol_root;
extern K_LIST *idcontrol_free;
extern K_STORE *idcontrol_store;

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

extern K_TREE *optioncontrol_root;
extern K_LIST *optioncontrol_free;
extern K_STORE *optioncontrol_store;

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

extern K_TREE *workinfo_root;
// created during data load then destroyed since not needed later
extern K_TREE *workinfo_height_root;
extern K_LIST *workinfo_free;
extern K_STORE *workinfo_store;
// one in the current block
extern K_ITEM *workinfo_current;
// first workinfo of current block
extern tv_t last_bc;
// current network diff
extern double current_ndiff;

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

extern K_TREE *shares_root;
extern K_LIST *shares_free;
extern K_STORE *shares_store;

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

extern K_TREE *shareerrors_root;
extern K_LIST *shareerrors_free;
extern K_STORE *shareerrors_store;

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

extern K_TREE *sharesummary_root;
extern K_TREE *sharesummary_workinfoid_root;
extern K_LIST *sharesummary_free;
extern K_STORE *sharesummary_store;

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

extern const char *blocks_new;
extern const char *blocks_confirm;
extern const char *blocks_42;
extern const char *blocks_orphan;
extern const char *blocks_unknown;

#define KANO -27972

extern K_TREE *blocks_root;
extern K_LIST *blocks_free;
extern K_STORE *blocks_store;

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

extern K_TREE *miningpayouts_root;
extern K_LIST *miningpayouts_free;
extern K_STORE *miningpayouts_store;

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

extern K_TREE *eventlog_root;
extern K_LIST *eventlog_free;
extern K_STORE *eventlog_store;
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

extern K_TREE *auths_root;
extern K_LIST *auths_free;
extern K_STORE *auths_store;

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

extern K_TREE *poolstats_root;
extern K_LIST *poolstats_free;
extern K_STORE *poolstats_store;

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

extern K_TREE *userstats_root;
extern K_TREE *userstats_statsdate_root; // ordered by statsdate first
extern K_TREE *userstats_workerstatus_root; // during data load
extern K_LIST *userstats_free;
extern K_STORE *userstats_store;
// Awaiting EOS
extern K_STORE *userstats_eos_store;
// Temporary while summarising
extern K_STORE *userstats_summ;

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

extern K_TREE *workerstatus_root;
extern K_LIST *workerstatus_free;
extern K_STORE *workerstatus_store;

extern void logmsg(int loglevel, const char *fmt, ...);
extern void tick();
extern PGconn *dbconnect();

// ***
// *** ckdb_data.c ***
// ***

extern char *safe_text(char *txt);

extern void _txt_to_data(enum data_type typ, char *nam, char *fld, void *data, size_t siz, WHERE_FFL_ARGS);

#define txt_to_str(_nam, _fld, _data, _siz) _txt_to_str(_nam, _fld, _data, _siz, WHERE_FFL_HERE)
#define txt_to_bigint(_nam, _fld, _data, _siz) _txt_to_bigint(_nam, _fld, _data, _siz, WHERE_FFL_HERE)
#define txt_to_int(_nam, _fld, _data, _siz) _txt_to_int(_nam, _fld, _data, _siz, WHERE_FFL_HERE)
#define txt_to_tv(_nam, _fld, _data, _siz) _txt_to_tv(_nam, _fld, _data, _siz, WHERE_FFL_HERE)
#define txt_to_ctv(_nam, _fld, _data, _siz) _txt_to_ctv(_nam, _fld, _data, _siz, WHERE_FFL_HERE)
#define txt_to_blob(_nam, _fld, _data) _txt_to_blob(_nam, _fld, _data, WHERE_FFL_HERE)
#define txt_to_double(_nam, _fld, _data, _siz) _txt_to_double(_nam, _fld, _data, _siz, WHERE_FFL_HERE)

// N.B. STRNCPY* macros truncate, whereas this aborts ckdb if src > trg
extern void _txt_to_str(char *nam, char *fld, char data[], size_t siz, WHERE_FFL_ARGS);
extern void _txt_to_bigint(char *nam, char *fld, int64_t *data, size_t siz, WHERE_FFL_ARGS);
extern void _txt_to_int(char *nam, char *fld, int32_t *data, size_t siz, WHERE_FFL_ARGS);
extern void _txt_to_tv(char *nam, char *fld, tv_t *data, size_t siz, WHERE_FFL_ARGS);
// Convert msg S,nS to tv_t
extern void _txt_to_ctv(char *nam, char *fld, tv_t *data, size_t siz, WHERE_FFL_ARGS);
extern void _txt_to_blob(char *nam, char *fld, char **data, WHERE_FFL_ARGS);
extern void _txt_to_double(char *nam, char *fld, double *data, size_t siz, WHERE_FFL_ARGS);

extern char *_data_to_buf(enum data_type typ, void *data, char *buf, size_t siz, WHERE_FFL_ARGS);

#define str_to_buf(_data, _buf, _siz) _str_to_buf(_data, _buf, _siz, WHERE_FFL_HERE)
#define bigint_to_buf(_data, _buf, _siz) _bigint_to_buf(_data, _buf, _siz, WHERE_FFL_HERE)
#define int_to_buf(_data, _buf, _siz) _int_to_buf(_data, _buf, _siz, WHERE_FFL_HERE)
#define tv_to_buf(_data, _buf, _siz) _tv_to_buf(_data, _buf, _siz, WHERE_FFL_HERE)
#define ctv_to_buf(_data, _buf, _siz) _ctv_to_buf(_data, _buf, _siz, WHERE_FFL_HERE)
#define tvs_to_buf(_data, _buf, _siz) _tvs_to_buf(_data, _buf, _siz, WHERE_FFL_HERE)
//#define blob_to_buf(_data, _buf, _siz) _blob_to_buf(_data, _buf, _siz, WHERE_FFL_HERE)
#define double_to_buf(_data, _buf, _siz) _double_to_buf(_data, _buf, _siz, WHERE_FFL_HERE)

extern char *_str_to_buf(char data[], char *buf, size_t siz, WHERE_FFL_ARGS);
extern char *_bigint_to_buf(int64_t data, char *buf, size_t siz, WHERE_FFL_ARGS);
extern char *_int_to_buf(int32_t data, char *buf, size_t siz, WHERE_FFL_ARGS);
extern char *_tv_to_buf(tv_t *data, char *buf, size_t siz, WHERE_FFL_ARGS);
// Convert tv to S,uS
extern char *_ctv_to_buf(tv_t *data, char *buf, size_t siz, WHERE_FFL_ARGS);
// Convert tv to seconds (ignore uS)
extern char *_tvs_to_buf(tv_t *data, char *buf, size_t siz, WHERE_FFL_ARGS);
/* unused yet
extern char *_blob_to_buf(char *data, char *buf, size_t siz, WHERE_FFL_ARGS);
*/
extern char *_double_to_buf(double data, char *buf, size_t siz, WHERE_FFL_ARGS);

extern char *_transfer_data(K_ITEM *item, WHERE_FFL_ARGS);
extern void dsp_transfer(K_ITEM *item, FILE *stream);
extern cmp_t cmp_transfer(K_ITEM *a, K_ITEM *b);
extern K_ITEM *find_transfer(K_TREE *trf_root, char *name);
#define optional_name(_root, _name, _len, _patt, _reply, _siz) \
		_optional_name(_root, _name, _len, _patt, _reply, _siz, \
				WHERE_FFL_HERE)
extern K_ITEM *_optional_name(K_TREE *trf_root, char *name, int len, char *patt,
				char *reply, size_t siz, WHERE_FFL_ARGS);
#define require_name(_root, _name, _len, _patt, _reply, _siz) \
		_require_name(_root, _name, _len, _patt, _reply, \
				_siz, WHERE_FFL_HERE)
extern K_ITEM *_require_name(K_TREE *trf_root, char *name, int len, char *patt,
				char *reply, size_t siz, WHERE_FFL_ARGS);
extern cmp_t cmp_workerstatus(K_ITEM *a, K_ITEM *b);
extern K_ITEM *get_workerstatus(int64_t userid, char *workername);
#define find_create_workerstatus(_u, _w, _file, _func, _line) \
	_find_create_workerstatus(_u, _w, true, _file, _func, _line, WHERE_FFL_HERE)
#define find_workerstatus(_u, _w, _file, _func, _line) \
	 _find_create_workerstatus(_u, _w, false, _file, _func, _line, WHERE_FFL_HERE)

extern K_ITEM *_find_create_workerstatus(int64_t userid, char *workername,
					 bool create, const char *file2,
					 const char *func2, const int line2,
					 WHERE_FFL_ARGS);
extern void workerstatus_ready();
#define workerstatus_update(_auths, _shares, _userstats) \
	_workerstatus_update(_auths, _shares, _userstats, WHERE_FFL_HERE)
extern void _workerstatus_update(AUTHS *auths, SHARES *shares,
				 USERSTATS *userstats, WHERE_FFL_ARGS);
extern cmp_t cmp_users(K_ITEM *a, K_ITEM *b);
extern cmp_t cmp_userid(K_ITEM *a, K_ITEM *b);
extern K_ITEM *find_users(char *username);
extern K_ITEM *find_userid(int64_t userid);
extern void make_salt(USERS *users);
extern void password_hash(char *username, char *passwordhash, char *salt, char *result, size_t siz);
extern bool check_hash(USERS *users, char *passwordhash);
extern cmp_t cmp_useratts(K_ITEM *a, K_ITEM *b);
extern K_ITEM *find_useratts(int64_t userid, char *attname);
extern cmp_t cmp_workers(K_ITEM *a, K_ITEM *b);
extern K_ITEM *find_workers(int64_t userid, char *workername);
extern K_ITEM *new_worker(PGconn *conn, bool update, int64_t userid, char *workername,
			  char *diffdef, char *idlenotificationenabled,
			  char *idlenotificationtime, char *by,
			  char *code, char *inet, tv_t *cd, K_TREE *trf_root);
extern K_ITEM *new_default_worker(PGconn *conn, bool update, int64_t userid, char *workername,
				  char *by, char *code, char *inet, tv_t *cd, K_TREE *trf_root);
extern cmp_t cmp_paymentaddresses(K_ITEM *a, K_ITEM *b);
extern K_ITEM *find_paymentaddresses(int64_t userid);
extern cmp_t cmp_payments(K_ITEM *a, K_ITEM *b);
extern cmp_t cmp_optioncontrol(K_ITEM *a, K_ITEM *b);
extern K_ITEM *find_optioncontrol(char *optionname, tv_t *now);
extern cmp_t cmp_workinfo(K_ITEM *a, K_ITEM *b);
#define coinbase1height(_cb1) _coinbase1height(_cb1, WHERE_FFL_HERE)
extern int32_t _coinbase1height(char *coinbase1, WHERE_FFL_ARGS);
#define cmp_height(_cb1a, _cb1b) _cmp_height(_cb1a, _cb1b, WHERE_FFL_HERE)
extern cmp_t _cmp_height(char *coinbase1a, char *coinbase1b, WHERE_FFL_ARGS);
extern cmp_t cmp_workinfo_height(K_ITEM *a, K_ITEM *b);
extern K_ITEM *find_workinfo(int64_t workinfoid);
extern bool workinfo_age(PGconn *conn, int64_t workinfoid, char *poolinstance,
			 char *by, char *code, char *inet, tv_t *cd,
			 tv_t *ss_first, tv_t *ss_last, int64_t *ss_count,
			 int64_t *s_count, int64_t *s_diff);
extern cmp_t cmp_shares(K_ITEM *a, K_ITEM *b);
extern cmp_t cmp_shareerrors(K_ITEM *a, K_ITEM *b);
extern void dsp_sharesummary(K_ITEM *item, FILE *stream);
extern cmp_t cmp_sharesummary(K_ITEM *a, K_ITEM *b);
extern cmp_t cmp_sharesummary_workinfoid(K_ITEM *a, K_ITEM *b);
extern void zero_sharesummary(SHARESUMMARY *row, tv_t *cd, double diff);
extern K_ITEM *find_sharesummary(int64_t userid, char *workername, int64_t workinfoid);
extern void auto_age_older(PGconn *conn, int64_t workinfoid, char *poolinstance,
			   char *by, char *code, char *inet, tv_t *cd);
extern void dsp_hash(char *hash, char *buf, size_t siz);
extern void dsp_blocks(K_ITEM *item, FILE *stream);
extern cmp_t cmp_blocks(K_ITEM *a, K_ITEM *b);
extern K_ITEM *find_blocks(int32_t height, char *blockhash);
extern K_ITEM *find_prev_blocks(int32_t height);
extern const char *blocks_confirmed(char *confirmed);
extern void zero_on_new_block();
extern void set_block_share_counters();
extern cmp_t cmp_miningpayouts(K_ITEM *a, K_ITEM *b);
extern cmp_t cmp_auths(K_ITEM *a, K_ITEM *b);
extern cmp_t cmp_poolstats(K_ITEM *a, K_ITEM *b);
extern void dsp_userstats(K_ITEM *item, FILE *stream);
extern cmp_t cmp_userstats(K_ITEM *a, K_ITEM *b);
extern cmp_t cmp_userstats_workername(K_ITEM *a, K_ITEM *b);
extern cmp_t cmp_userstats_statsdate(K_ITEM *a, K_ITEM *b);
extern cmp_t cmp_userstats_workerstatus(K_ITEM *a, K_ITEM *b);
extern bool userstats_starttimeband(USERSTATS *row, tv_t *statsdate);

// ***
// *** PostgreSQL functions ckdb_dbio.c
// ***

/* These PG/PQ defines need to exist outside ckdb_dbio.c
 * since external functions can choose to run a single transaction
 * over a set of dbio functions */
#define PGOK(_res) ((_res) == PGRES_COMMAND_OK || \
			(_res) == PGRES_TUPLES_OK || \
			(_res) == PGRES_EMPTY_QUERY)

#define CKPQ_READ true
#define CKPQ_WRITE false

#define CKPQexec(_conn, _qry, _isread) _CKPQexec(_conn, _qry, _isread, WHERE_FFL_HERE)
extern PGresult *_CKPQexec(PGconn *conn, const char *qry, bool isread, WHERE_FFL_ARGS);
#define CKPQexecParams(_conn, _qry, _p1, _p2, _p3, _p4, _p5, _p6, _isread) \
			_CKPQexecParams(_conn, _qry, _p1, _p2, _p3, _p4, _p5, _p6, \
			_isread, WHERE_FFL_HERE)
extern PGresult *_CKPQexecParams(PGconn *conn, const char *qry,
				 int nParams,
				 const Oid *paramTypes,
				 const char *const * paramValues,
				 const int *paramLengths,
				 const int *paramFormats,
				 int resultFormat,
				 bool isread, WHERE_FFL_ARGS);

// Force use CKPQ... for PQ functions in use
#define PQexec CKPQexec
#define PQexecParams CKPQexecParams

#define PGLOG(__LOG, __str, __rescode, __conn) do { \
		char *__buf = pqerrmsg(__conn); \
		__LOG("%s(): %s failed (%d) '%s'", __func__, \
			__str, (int)rescode, __buf); \
		free(__buf); \
	} while (0)

#define PGLOGERR(_str, _rescode, _conn) PGLOG(LOGERR, _str, _rescode, _conn)
#define PGLOGEMERG(_str, _rescode, _conn) PGLOG(LOGEMERG, _str, _rescode, _conn)

extern char *pqerrmsg(PGconn *conn);

extern int64_t nextid(PGconn *conn, char *idname, int64_t increment,
			tv_t *cd, char *by, char *code, char *inet);
extern bool users_pass_email(PGconn *conn, K_ITEM *u_item, char *oldhash,
			     char *newhash, char *email, char *by, char *code,
			     char *inet, tv_t *cd, K_TREE *trf_root);
extern K_ITEM *users_add(PGconn *conn, char *username, char *emailaddress,
			char *passwordhash, char *by, char *code, char *inet,
			tv_t *cd, K_TREE *trf_root);
extern bool users_fill(PGconn *conn);
extern bool useratts_item_add(PGconn *conn, K_ITEM *ua_item, tv_t *cd, bool begun);
extern K_ITEM *useratts_add(PGconn *conn, char *username, char *attname,
				char *status, char *attstr, char *attstr2,
				char *attnum, char *attnum2,  char *attdate,
				char *attdate2, char *by, char *code,
				char *inet, tv_t *cd, K_TREE *trf_root,
				bool begun);
extern bool useratts_item_expire(PGconn *conn, K_ITEM *ua_item, tv_t *cd);
extern bool useratts_fill(PGconn *conn);
extern K_ITEM *workers_add(PGconn *conn, int64_t userid, char *workername,
			   char *difficultydefault, char *idlenotificationenabled,
			   char *idlenotificationtime, char *by,
			   char *code, char *inet, tv_t *cd, K_TREE *trf_root);
extern bool workers_update(PGconn *conn, K_ITEM *item, char *difficultydefault,
			   char *idlenotificationenabled,
			   char *idlenotificationtime, char *by, char *code,
			   char *inet, tv_t *cd, K_TREE *trf_root, bool check);
extern bool workers_fill(PGconn *conn);
extern K_ITEM *paymentaddresses_set(PGconn *conn, int64_t userid, char *payaddress,
					char *by, char *code, char *inet, tv_t *cd,
					K_TREE *trf_root);
extern bool paymentaddresses_fill(PGconn *conn);
extern bool payments_fill(PGconn *conn);
extern bool idcontrol_add(PGconn *conn, char *idname, char *idvalue, char *by,
			  char *code, char *inet, tv_t *cd, K_TREE *trf_root);
extern K_ITEM *optioncontrol_item_add(PGconn *conn, K_ITEM *oc_item, tv_t *cd, bool begun);
extern K_ITEM *optioncontrol_add(PGconn *conn, char *optionname, char *optionvalue,
				 char *activationdate, char *activationheight,
				 char *by, char *code, char *inet, tv_t *cd,
				 K_TREE *trf_root, bool begun);
extern bool optioncontrol_fill(PGconn *conn);
extern int64_t workinfo_add(PGconn *conn, char *workinfoidstr, char *poolinstance,
				char *transactiontree, char *merklehash, char *prevhash,
				char *coinbase1, char *coinbase2, char *version,
				char *bits, char *ntime, char *reward, char *by,
				char *code, char *inet, tv_t *cd, bool igndup,
				K_TREE *trf_root);
extern bool workinfo_fill(PGconn *conn);
extern bool shares_add(PGconn *conn, char *workinfoid, char *username, char *workername,
			char *clientid, char *errn, char *enonce1, char *nonce2,
			char *nonce, char *diff, char *sdiff, char *secondaryuserid,
			char *by, char *code, char *inet, tv_t *cd, K_TREE *trf_root);
extern bool shareerrors_add(PGconn *conn, char *workinfoid, char *username,
				char *workername, char *clientid, char *errn,
				char *error, char *secondaryuserid, char *by,
				char *code, char *inet, tv_t *cd, K_TREE *trf_root);
#define sharesummary_update(_conn, _s_row, _e_row, _ss_item, _by, _code, _inet, _cd) \
		_sharesummary_update(_conn, _s_row, _e_row, _ss_item, _by, _code, _inet, _cd, \
					WHERE_FFL_HERE)
extern bool _sharesummary_update(PGconn *conn, SHARES *s_row, SHAREERRORS *e_row, K_ITEM *ss_item,
				char *by, char *code, char *inet, tv_t *cd, WHERE_FFL_ARGS);
extern bool sharesummary_fill(PGconn *conn);
extern bool blocks_stats(PGconn *conn, int32_t height, char *blockhash,
			 double diffacc, double diffinv, double shareacc,
			 double shareinv, int64_t elapsed,
			 char *by, char *code, char *inet, tv_t *cd);
extern bool blocks_add(PGconn *conn, char *height, char *blockhash,
			char *confirmed, char *workinfoid, char *username,
			char *workername, char *clientid, char *enonce1,
			char *nonce2, char *nonce, char *reward,
			char *by, char *code, char *inet, tv_t *cd,
			bool igndup, char *id, K_TREE *trf_root);
extern bool blocks_fill(PGconn *conn);
extern bool miningpayouts_add(PGconn *conn, char *username, char *height,
			      char *blockhash, char *amount, char *by,
			      char *code, char *inet, tv_t *cd, K_TREE *trf_root);
extern bool miningpayouts_fill(PGconn *conn);
extern char *auths_add(PGconn *conn, char *poolinstance, char *username,
			char *workername, char *clientid, char *enonce1,
			char *useragent, char *preauth, char *by, char *code,
			char *inet, tv_t *cd, bool igndup, K_TREE *trf_root,
			bool addressuser);
extern bool auths_fill(PGconn *conn);
extern bool poolstats_add(PGconn *conn, bool store, char *poolinstance,
				char *elapsed, char *users, char *workers,
				char *hashrate, char *hashrate5m,
				char *hashrate1hr, char *hashrate24hr,
				char *by, char *code, char *inet, tv_t *cd,
				bool igndup, K_TREE *trf_root);
extern bool poolstats_fill(PGconn *conn);
extern bool userstats_add_db(PGconn *conn, USERSTATS *row);
extern bool userstats_add(char *poolinstance, char *elapsed, char *username,
			  char *workername, char *hashrate, char *hashrate5m,
			  char *hashrate1hr, char *hashrate24hr, bool idle,
			  bool eos, char *by, char *code, char *inet, tv_t *cd,
			  K_TREE *trf_root);
extern bool userstats_fill(PGconn *conn);
extern bool check_db_version(PGconn *conn);

// ***
// *** ckdb_cmd.c
// ***

struct CMDS {
	enum cmd_values cmd_val;
	char *cmd_str;
	bool noid; // doesn't require an id
	bool createdate; // requires a createdate
	char *(*func)(PGconn *, char *, char *, tv_t *, char *, char *,
			char *, tv_t *, K_TREE *);
	char *access;
};

extern struct CMDS ckdb_cmds[];

#endif
