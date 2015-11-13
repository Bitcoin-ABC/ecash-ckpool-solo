/*
 * Copyright 1995-2015 Andrew Smith
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#include "ckdb.h"
#include <math.h>

// Data free functions (added here as needed)

void free_msgline_data(K_ITEM *item, bool t_lock, bool t_cull)
{
	K_ITEM *t_item = NULL;
	TRANSFER *transfer;
	MSGLINE *msgline;

	DATA_MSGLINE(msgline, item);
	if (msgline->trf_root)
		free_ktree(msgline->trf_root, NULL);
	if (msgline->trf_store) {
		t_item = msgline->trf_store->head;
		while (t_item) {
			DATA_TRANSFER(transfer, t_item);
			if (transfer->mvalue != transfer->svalue)
				FREENULL(transfer->mvalue);
			t_item = t_item->next;
		}
		if (t_lock)
			K_WLOCK(transfer_free);
		k_list_transfer_to_head(msgline->trf_store, transfer_free);
		if (t_cull) {
			if (transfer_free->count == transfer_free->total &&
			    transfer_free->total >= ALLOC_TRANSFER * CULL_TRANSFER)
				k_cull_list(transfer_free);
		}
		if (t_lock)
			K_WUNLOCK(transfer_free);
		msgline->trf_store = k_free_store(msgline->trf_store);
	}
	FREENULL(msgline->msg);
}

void free_users_data(K_ITEM *item)
{
	USERS *users;

	DATA_USERS(users, item);
	LIST_MEM_SUB(users_free, users->userdata);
	FREENULL(users->userdata);
}

void free_workinfo_data(K_ITEM *item)
{
	WORKINFO *workinfo;

	DATA_WORKINFO(workinfo, item);
	LIST_MEM_SUB(workinfo_free, workinfo->transactiontree);
	FREENULL(workinfo->transactiontree);
	LIST_MEM_SUB(workinfo_free, workinfo->merklehash);
	FREENULL(workinfo->merklehash);
}

void free_payouts_data(K_ITEM *item)
{
	PAYOUTS *payouts;

	DATA_PAYOUTS(payouts, item);
	LIST_MEM_SUB(payouts_free, payouts->stats);
	FREENULL(payouts->stats);
}

void free_sharesummary_data(K_ITEM *item)
{
	SHARESUMMARY *sharesummary;

	DATA_SHARESUMMARY(sharesummary, item);
	LIST_MEM_SUB(sharesummary_free, sharesummary->workername);
	FREENULL(sharesummary->workername);
	SET_CREATEBY(sharesummary_free, sharesummary->createby, EMPTY);
	SET_CREATECODE(sharesummary_free, sharesummary->createcode, EMPTY);
	SET_CREATEINET(sharesummary_free, sharesummary->createinet, EMPTY);
	SET_MODIFYBY(sharesummary_free, sharesummary->modifyby, EMPTY);
	SET_MODIFYCODE(sharesummary_free, sharesummary->modifycode, EMPTY);
	SET_MODIFYINET(sharesummary_free, sharesummary->modifyinet, EMPTY);
}

void free_optioncontrol_data(K_ITEM *item)
{
	OPTIONCONTROL *optioncontrol;

	DATA_OPTIONCONTROL(optioncontrol, item);
	LIST_MEM_SUB(optioncontrol_free, optioncontrol->optionvalue);
	FREENULL(optioncontrol->optionvalue);
}

void free_markersummary_data(K_ITEM *item)
{
	MARKERSUMMARY *markersummary;

	DATA_MARKERSUMMARY(markersummary, item);
	LIST_MEM_SUB(markersummary_free, markersummary->workername);
	FREENULL(markersummary->workername);
	SET_CREATEBY(markersummary_free, markersummary->createby, EMPTY);
	SET_CREATECODE(markersummary_free, markersummary->createcode, EMPTY);
	SET_CREATEINET(markersummary_free, markersummary->createinet, EMPTY);
	SET_MODIFYBY(markersummary_free, markersummary->modifyby, EMPTY);
	SET_MODIFYCODE(markersummary_free, markersummary->modifycode, EMPTY);
	SET_MODIFYINET(markersummary_free, markersummary->modifyinet, EMPTY);
}

void free_workmarkers_data(K_ITEM *item)
{
	WORKMARKERS *workmarkers;

	DATA_WORKMARKERS(workmarkers, item);
	LIST_MEM_SUB(workmarkers_free, workmarkers->poolinstance);
	FREENULL(workmarkers->poolinstance);
	LIST_MEM_SUB(workmarkers_free, workmarkers->description);
	FREENULL(workmarkers->description);
}

void free_marks_data(K_ITEM *item)
{
	MARKS *marks;

	DATA_MARKS(marks, item);
	LIST_MEM_SUB(marks_free, marks->poolinstance);
	FREENULL(marks->poolinstance);
	LIST_MEM_SUB(marks_free, marks->description);
	FREENULL(marks->description);
	LIST_MEM_SUB(marks_free, marks->extra);
	FREENULL(marks->extra);
}

void _free_seqset_data(K_ITEM *item, bool lock)
{
	K_STORE *reload_lost;
	SEQSET *seqset;
	int i;

	DATA_SEQSET(seqset, item);
	if (seqset->seqstt) {
		for (i = 0; i < SEQ_MAX; i++) {
			reload_lost = seqset->seqdata[i].reload_lost;
			if (reload_lost) {
				if (lock)
					K_WLOCK(seqtrans_free);
				k_list_transfer_to_head(reload_lost, seqtrans_free);
				if (lock)
					K_WUNLOCK(seqtrans_free);
				k_free_store(reload_lost);
				seqset->seqdata[i].reload_lost = NULL;
			}
			FREENULL(seqset->seqdata[i].entry);
		}
		seqset->seqstt = 0;
	}
}

/* Data copy functions (added here as needed)
   All pointers need to initialised since DUP_POINTER will free them */

void copy_users(USERS *newu, USERS *oldu)
{
	memcpy(newu, oldu, sizeof(*newu));
	newu->userdata = NULL;
	DUP_POINTER(users_free, newu->userdata, oldu->userdata);
}

// Clear text printable version of txt up to first '\0'
char *_safe_text(char *txt, bool shownull)
{
	unsigned char *ptr = (unsigned char *)txt;
	size_t len;
	char *ret, *buf;

	if (!txt) {
		buf = strdup("(Null)");
		if (!buf)
			quithere(1, "strdup OOM");
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
	if (shownull)
		strcpy(buf, "0x00");
	else
		*buf = '\0';

	return ret;
}

#define TRIM_IGNORE(ch) ((ch) == '_' || (ch) == '.' || (ch) == '-' || isspace(ch))

void username_trim(USERS *users)
{
	char *front, *trail;

	front = users->username;
	while (*front && TRIM_IGNORE(*front))
		front++;

	STRNCPY(users->usertrim, front);

	front = users->usertrim;
	trail = front + strlen(front) - 1;
	while (trail >= front) {
		if (TRIM_IGNORE(*trail))
			*(trail--) = '\0';
		else
			break;
	}

	while (trail >= front) {
		*trail = tolower(*trail);
		trail--;
	}
}

/* Is the trimmed username like an address?
 * False positive is OK (i.e. 'like')
 * Before checking, it is trimmed to avoid web display confusion
 * Length check is done before trimming - this may give a false
 *  positive on any username with lots of trim characters ... which is OK */
bool like_address(char *username)
{
	char *tmp, *front, *trail;
	size_t len;
	regex_t re;
	int ret;

	len = strlen(username);
	if (len < ADDR_USER_CHECK)
		return false;

	tmp = strdup(username);
	front = tmp;
	while (*front && TRIM_IGNORE(*front))
		front++;

	trail = front + strlen(front) - 1;
	while (trail >= front) {
		if (TRIM_IGNORE(*trail))
			*(trail--) = '\0';
		else
			break;
	}

	if (regcomp(&re, addrpatt, REG_NOSUB) != 0) {
		LOGEMERG("%s(): failed to compile addrpatt '%s'",
			 __func__, addrpatt);
		free(tmp);
		// This will disable adding any new usernames ...
		return true;
	}

	ret = regexec(&re, front, (size_t)0, NULL, 0);
	regfree(&re);

	if (ret == 0) {
		free(tmp);
		return true;
	}

	free(tmp);
	return false;
}

void _txt_to_data(enum data_type typ, char *nam, char *fld, void *data, size_t siz, WHERE_FFL_ARGS)
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
			DATE_ZERO((tv_t *)data);
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
			// free() allows NULL
			free(*((char **)data));
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

// N.B. STRNCPY* macros truncate, whereas this aborts ckdb if src > trg
void _txt_to_str(char *nam, char *fld, char data[], size_t siz, WHERE_FFL_ARGS)
{
	_txt_to_data(TYPE_STR, nam, fld, (void *)data, siz, WHERE_FFL_PASS);
}

void _txt_to_bigint(char *nam, char *fld, int64_t *data, size_t siz, WHERE_FFL_ARGS)
{
	_txt_to_data(TYPE_BIGINT, nam, fld, (void *)data, siz, WHERE_FFL_PASS);
}

void _txt_to_int(char *nam, char *fld, int32_t *data, size_t siz, WHERE_FFL_ARGS)
{
	_txt_to_data(TYPE_INT, nam, fld, (void *)data, siz, WHERE_FFL_PASS);
}

void _txt_to_tv(char *nam, char *fld, tv_t *data, size_t siz, WHERE_FFL_ARGS)
{
	_txt_to_data(TYPE_TV, nam, fld, (void *)data, siz, WHERE_FFL_PASS);
}

// Convert msg S,nS to tv_t
void _txt_to_ctv(char *nam, char *fld, tv_t *data, size_t siz, WHERE_FFL_ARGS)
{
	_txt_to_data(TYPE_CTV, nam, fld, (void *)data, siz, WHERE_FFL_PASS);
}

void _txt_to_blob(char *nam, char *fld, char **data, WHERE_FFL_ARGS)
{
	_txt_to_data(TYPE_BLOB, nam, fld, (void *)data, 0, WHERE_FFL_PASS);
}

void _txt_to_double(char *nam, char *fld, double *data, size_t siz, WHERE_FFL_ARGS)
{
	_txt_to_data(TYPE_DOUBLE, nam, fld, (void *)data, siz, WHERE_FFL_PASS);
}

char *_data_to_buf(enum data_type typ, void *data, char *buf, size_t siz, WHERE_FFL_ARGS)
{
	struct tm tm;
	double d;

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
			case TYPE_BTV:
			case TYPE_T:
			case TYPE_BT:
				siz = DATE_BUFSIZ;
				break;
			case TYPE_CTV:
			case TYPE_FTV:
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
		case TYPE_BTV:
			gmtime_r(&(((tv_t *)data)->tv_sec), &tm);
			snprintf(buf, siz, "%02d %02d:%02d:%02d",
					   tm.tm_mday,
					   tm.tm_hour,
					   tm.tm_min,
					   tm.tm_sec);
			break;
		case TYPE_CTV:
			snprintf(buf, siz, "%ld,%ld",
					   (((tv_t *)data)->tv_sec),
					   (((tv_t *)data)->tv_usec));
			break;
		case TYPE_FTV:
			d = (double)(((tv_t *)data)->tv_sec) +
			    (double)(((tv_t *)data)->tv_usec) / 1000000.0;
			snprintf(buf, siz, "%.6f", d);
			break;
		case TYPE_TVS:
			snprintf(buf, siz, "%ld", (((tv_t *)data)->tv_sec));
			break;
		case TYPE_DOUBLE:
			snprintf(buf, siz, "%f", *((double *)data));
			break;
		case TYPE_T:
			gmtime_r((time_t *)data, &tm);
			snprintf(buf, siz, "%d-%02d-%02d %02d:%02d:%02d+00",
					   tm.tm_year + 1900,
					   tm.tm_mon + 1,
					   tm.tm_mday,
					   tm.tm_hour,
					   tm.tm_min,
					   tm.tm_sec);
			break;
		case TYPE_BT:
			gmtime_r((time_t *)data, &tm);
			snprintf(buf, siz, "%d-%02d %02d:%02d:%02d",
					   tm.tm_mon + 1,
					   tm.tm_mday,
					   tm.tm_hour,
					   tm.tm_min,
					   tm.tm_sec);
			break;
	}

	return buf;
}

char *_str_to_buf(char data[], char *buf, size_t siz, WHERE_FFL_ARGS)
{
	return _data_to_buf(TYPE_STR, (void *)data, buf, siz, WHERE_FFL_PASS);
}

char *_bigint_to_buf(int64_t data, char *buf, size_t siz, WHERE_FFL_ARGS)
{
	return _data_to_buf(TYPE_BIGINT, (void *)(&data), buf, siz, WHERE_FFL_PASS);
}

char *_int_to_buf(int32_t data, char *buf, size_t siz, WHERE_FFL_ARGS)
{
	return _data_to_buf(TYPE_INT, (void *)(&data), buf, siz, WHERE_FFL_PASS);
}

char *_tv_to_buf(tv_t *data, char *buf, size_t siz, WHERE_FFL_ARGS)
{
	return _data_to_buf(TYPE_TV, (void *)data, buf, siz, WHERE_FFL_PASS);
}

// Convert tv to S,uS
char *_ctv_to_buf(tv_t *data, char *buf, size_t siz, WHERE_FFL_ARGS)
{
	return _data_to_buf(TYPE_CTV, (void *)data, buf, siz, WHERE_FFL_PASS);
}

// Convert tv to S.uS
char *_ftv_to_buf(tv_t *data, char *buf, size_t siz, WHERE_FFL_ARGS)
{
	return _data_to_buf(TYPE_FTV, (void *)data, buf, siz, WHERE_FFL_PASS);
}

// Convert tv to seconds (ignore uS)
char *_tvs_to_buf(tv_t *data, char *buf, size_t siz, WHERE_FFL_ARGS)
{
	return _data_to_buf(TYPE_TVS, (void *)data, buf, siz, WHERE_FFL_PASS);
}

// Convert tv to (brief) DD HH:MM:SS
char *_btv_to_buf(tv_t *data, char *buf, size_t siz, WHERE_FFL_ARGS)
{
	return _data_to_buf(TYPE_BTV, (void *)data, buf, siz, WHERE_FFL_PASS);
}

/* unused yet
char *_blob_to_buf(char *data, char *buf, size_t siz, WHERE_FFL_ARGS)
{
	return _data_to_buf(TYPE_BLOB, (void *)data, buf, siz, WHERE_FFL_PASS);
}
*/

char *_double_to_buf(double data, char *buf, size_t siz, WHERE_FFL_ARGS)
{
	return _data_to_buf(TYPE_DOUBLE, (void *)(&data), buf, siz, WHERE_FFL_PASS);
}

char *_t_to_buf(time_t *data, char *buf, size_t siz, WHERE_FFL_ARGS)
{
	return _data_to_buf(TYPE_T, (void *)data, buf, siz, WHERE_FFL_PASS);
}

char *_bt_to_buf(time_t *data, char *buf, size_t siz, WHERE_FFL_ARGS)
{
	return _data_to_buf(TYPE_BT, (void *)data, buf, siz, WHERE_FFL_PASS);
}

char *_btu64_to_buf(uint64_t *data, char *buf, size_t siz, WHERE_FFL_ARGS)
{
	time_t t = *data;
	return _data_to_buf(TYPE_BT, (void *)&t, buf, siz, WHERE_FFL_PASS);
}

// For mutiple variable function calls that need the data
char *_transfer_data(K_ITEM *item, WHERE_FFL_ARGS)
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

void dsp_transfer(K_ITEM *item, FILE *stream)
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
cmp_t cmp_transfer(K_ITEM *a, K_ITEM *b)
{
	TRANSFER *ta, *tb;
	DATA_TRANSFER(ta, a);
	DATA_TRANSFER(tb, b);
	return CMP_STR(ta->name, tb->name);
}

K_ITEM *find_transfer(K_TREE *trf_root, char *name)
{
	TRANSFER transfer;
	K_TREE_CTX ctx[1];
	K_ITEM look;

	STRNCPY(transfer.name, name);
	INIT_TRANSFER(&look);
	look.data = (void *)(&transfer);
	return find_in_ktree(trf_root, &look, ctx);
}

K_ITEM *_optional_name(K_TREE *trf_root, char *name, int len, char *patt,
			char *reply, size_t siz, WHERE_FFL_ARGS)
{
	TRANSFER *trf;
	K_ITEM *item;
	char *mvalue;
	regex_t re;
	size_t dlen;
	int ret;

	reply[0] = '\0';

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
			LOGERR("%s(): field '%s' NULL (%d:%d) from %s():%d",
				__func__, name, (int)dlen, len, func, line);
		} else
			snprintf(reply, siz, "failed.short %s", name);
		return NULL;
	}

	if (patt) {
		if (regcomp(&re, patt, REG_NOSUB) != 0) {
			snprintf(reply, siz, "failed.REG %s", name);
			return NULL;
		}

		ret = regexec(&re, mvalue, (size_t)0, NULL, 0);
		regfree(&re);

		if (ret != 0) {
			snprintf(reply, siz, "failed.invalid %s", name);
			return NULL;
		}
	}

	return item;
}

K_ITEM *_require_name(K_TREE *trf_root, char *name, int len, char *patt,
			char *reply, size_t siz, WHERE_FFL_ARGS)
{
	TRANSFER *trf;
	K_ITEM *item;
	char *mvalue;
	regex_t re;
	size_t dlen;
	int ret;

	reply[0] = '\0';

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
			snprintf(reply, siz, "failed.REG %s", name);
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

// order by userid asc,workername asc
cmp_t cmp_workerstatus(K_ITEM *a, K_ITEM *b)
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
K_ITEM *get_workerstatus(bool lock, int64_t userid, char *workername)
{
	WORKERSTATUS workerstatus;
	K_TREE_CTX ctx[1];
	K_ITEM look, *find;

	workerstatus.userid = userid;
	STRNCPY(workerstatus.workername, workername);

	INIT_WORKERSTATUS(&look);
	look.data = (void *)(&workerstatus);
	if (lock)
		K_RLOCK(workerstatus_free);
	find = find_in_ktree(workerstatus_root, &look, ctx);
	if (lock)
		K_RUNLOCK(workerstatus_free);
	return find;
}

/* Worker loading/creation calls this with create = true
 * All others with create = false since the workerstatus should exist
 * If it is missing, it will check for and create the worker if needed
 *  and create a new workerstatus and return it
 * This has 2 sets of file/func/line to allow 2 levels of traceback
 *  to see why it happened
 */
K_ITEM *_find_create_workerstatus(bool lock, int64_t userid, char *workername,
				  bool create, const char *file2,
				  const char *func2, const int line2,
				  WHERE_FFL_ARGS)
{
	WORKERSTATUS *row;
	K_ITEM *ws_item, *w_item = NULL;
	bool ws_err = false, w_err = false;
	tv_t now;

	ws_item = get_workerstatus(lock, userid, workername);
	if (!ws_item) {
		if (!create) {
			ws_err = true;

			w_item = find_workers(userid, workername);
			if (!w_item) {
				w_err = true;
				setnow(&now);
				w_item = workers_add(NULL, lock, userid,
						     workername,
						     NULL, NULL, NULL,
						     by_default,
						     (char *)__func__,
						     (char *)inet_default,
						     &now, NULL);
			}
		}

		if (lock)
			K_WLOCK(workerstatus_free);
		ws_item = k_unlink_head(workerstatus_free);

		DATA_WORKERSTATUS(row, ws_item);

		bzero(row, sizeof(*row));
		row->userid = userid;
		STRNCPY(row->workername, workername);

		add_to_ktree(workerstatus_root, ws_item);
		k_add_head(workerstatus_store, ws_item);
		if (lock)
			K_WUNLOCK(workerstatus_free);

		if (ws_err) {
			LOGNOTICE("%s(): CREATED Missing workerstatus"
				  " %"PRId64"/%s"
				  WHERE_FFL WHERE_FFL,
				  __func__, userid, workername,
				  file2, func2, line2, WHERE_FFL_PASS);
			if (w_err) {
				int sta = LOG_ERR;
				if (w_item)
					sta = LOG_NOTICE;
				LOGMSG(sta,
					"%s(): %s Missing worker %"PRId64"/%s",
					__func__,
					w_item ? "CREATED" : "FAILED TO CREATE",
					userid, workername);
			}
		}
	}
	return ws_item;
}

// workerstatus must be locked
static void zero_on_idle(tv_t *when, WORKERSTATUS *workerstatus)
{
	copy_tv(&(workerstatus->active_start), when);
	workerstatus->active_diffacc = workerstatus->active_diffinv =
	workerstatus->active_diffsta = workerstatus->active_diffdup =
	workerstatus->active_diffhi = workerstatus->active_diffrej =
	workerstatus->active_shareacc = workerstatus->active_shareinv =
	workerstatus->active_sharesta = workerstatus->active_sharedup =
	workerstatus->active_sharehi = workerstatus->active_sharerej = 0.0;
}

void zero_all_active(tv_t *when)
{
	WORKERSTATUS *workerstatus;
	K_TREE_CTX ws_ctx[1];
	K_ITEM *ws_item;

	K_WLOCK(workerstatus_free);
	ws_item = first_in_ktree(workerstatus_root, ws_ctx);
	while (ws_item) {
		DATA_WORKERSTATUS(workerstatus, ws_item);
		zero_on_idle(when, workerstatus);
		ws_item = next_in_ktree(ws_ctx);
	}

	K_WUNLOCK(workerstatus_free);
}

/* All data is loaded, now update workerstatus fields
   TODO: combine set_block_share_counters() with this? */
void workerstatus_ready()
{
	K_TREE_CTX ws_ctx[1];
	K_ITEM *ws_item, *ms_item, *ss_item;
	WORKERSTATUS *workerstatus;
	MARKERSUMMARY *markersummary;
	SHARESUMMARY *sharesummary;

	LOGWARNING("%s(): Updating workerstatus...", __func__);

	ws_item = first_in_ktree(workerstatus_root, ws_ctx);
	while (ws_item) {
		DATA_WORKERSTATUS(workerstatus, ws_item);

		// This is the last share datestamp
		ms_item = find_markersummary_userid(workerstatus->userid,
						    workerstatus->workername,
						    NULL);
		if (ms_item) {
			DATA_MARKERSUMMARY(markersummary, ms_item);
			if (tv_newer(&(workerstatus->last_share),
				     &(markersummary->lastshare))) {
				copy_tv(&(workerstatus->last_share),
					&(markersummary->lastshare));
			}
			if (tv_newer(&(workerstatus->last_share_acc),
				     &(markersummary->lastshareacc))) {
				copy_tv(&(workerstatus->last_share_acc),
					&(markersummary->lastshareacc));
				workerstatus->last_diff_acc =
					markersummary->lastdiffacc;
			}
		}

		ss_item = find_last_sharesummary(workerstatus->userid,
						 workerstatus->workername);
		if (ss_item) {
			DATA_SHARESUMMARY(sharesummary, ss_item);
			if (tv_newer(&(workerstatus->last_share),
				     &(sharesummary->lastshare))) {
				copy_tv(&(workerstatus->last_share),
					&(sharesummary->lastshare));
			}
			if (tv_newer(&(workerstatus->last_share_acc),
				     &(sharesummary->lastshareacc))) {
				copy_tv(&(workerstatus->last_share_acc),
					&(sharesummary->lastshareacc));
				workerstatus->last_diff_acc =
					sharesummary->lastdiffacc;
			}
		}

		ws_item = next_in_ktree(ws_ctx);
	}

	LOGWARNING("%s(): Update workerstatus complete", __func__);
}

void _workerstatus_update(AUTHS *auths, SHARES *shares,
				USERSTATS *userstats, WHERE_FFL_ARGS)
{
	WORKERSTATUS *row;
	K_ITEM *item;

	if (auths) {
		item = find_workerstatus(true, auths->userid, auths->workername,
					 file, func, line);
		if (item) {
			DATA_WORKERSTATUS(row, item);
			K_WLOCK(workerstatus_free);
			if (tv_newer(&(row->last_auth), &(auths->createdate)))
				copy_tv(&(row->last_auth), &(auths->createdate));
			if (row->active_start.tv_sec == 0)
				copy_tv(&(row->active_start), &(auths->createdate));
			K_WUNLOCK(workerstatus_free);
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
		item = find_workerstatus(true, shares->userid,
					 shares->workername,
					 file, func, line);
		if (item) {
			DATA_WORKERSTATUS(row, item);
			K_WLOCK(workerstatus_free);
			if (tv_newer(&(row->last_share), &(shares->createdate)))
				copy_tv(&(row->last_share), &(shares->createdate));
			if (row->active_start.tv_sec == 0)
				copy_tv(&(row->active_start), &(shares->createdate));
			switch (shares->errn) {
				case SE_NONE:
					row->block_diffacc += shares->diff;
					row->block_shareacc++;
					row->active_diffacc += shares->diff;
					row->active_shareacc++;
					if (tv_newer(&(row->last_share_acc),
						     &(shares->createdate))) {
						copy_tv(&(row->last_share_acc),
							&(shares->createdate));
						row->last_diff_acc = shares->diff;
					}
					break;
				case SE_STALE:
					row->block_diffinv += shares->diff;
					row->block_shareinv++;
					row->block_diffsta += shares->diff;
					row->block_sharesta++;
					row->active_diffinv += shares->diff;
					row->active_shareinv++;
					row->active_diffsta += shares->diff;
					row->active_sharesta++;
					break;
				case SE_DUPE:
					row->block_diffinv += shares->diff;
					row->block_shareinv++;
					row->block_diffdup += shares->diff;
					row->block_sharedup++;
					row->active_diffinv += shares->diff;
					row->active_shareinv++;
					row->active_diffdup += shares->diff;
					row->active_sharedup++;
					break;
				case SE_HIGH_DIFF:
					row->block_diffinv += shares->diff;
					row->block_shareinv++;
					row->block_diffhi += shares->diff;
					row->block_sharehi++;
					row->active_diffinv += shares->diff;
					row->active_shareinv++;
					row->active_diffhi += shares->diff;
					row->active_sharehi++;
					break;
				default:
					row->block_diffinv += shares->diff;
					row->block_shareinv++;
					row->block_diffrej += shares->diff;
					row->block_sharerej++;
					row->active_diffinv += shares->diff;
					row->active_shareinv++;
					row->active_diffrej += shares->diff;
					row->active_sharerej++;
					break;
			}
			K_WUNLOCK(workerstatus_free);
		}
	}

	if (startup_complete && userstats) {
		item = find_workerstatus(true, userstats->userid,
					 userstats->workername,
					 file, func, line);
		if (item) {
			DATA_WORKERSTATUS(row, item);
			K_WLOCK(workerstatus_free);
			if (userstats->idle) {
				if (tv_newer(&(row->last_idle), &(userstats->statsdate))) {
					copy_tv(&(row->last_idle), &(userstats->statsdate));
					zero_on_idle(&(userstats->statsdate), row);
				}
			} else {
				if (tv_newer(&(row->last_stats), &(userstats->statsdate)))
					copy_tv(&(row->last_stats), &(userstats->statsdate));
			}
			K_WUNLOCK(workerstatus_free);
		}
	}
}

// default tree order by username asc,expirydate desc
cmp_t cmp_users(K_ITEM *a, K_ITEM *b)
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
cmp_t cmp_userid(K_ITEM *a, K_ITEM *b)
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
K_ITEM *find_users(char *username)
{
	USERS users;
	K_TREE_CTX ctx[1];
	K_ITEM look;

	STRNCPY(users.username, username);
	users.expirydate.tv_sec = default_expiry.tv_sec;
	users.expirydate.tv_usec = default_expiry.tv_usec;

	INIT_USERS(&look);
	look.data = (void *)(&users);
	return find_in_ktree(users_root, &look, ctx);
}

// Must be R or W locked before call
K_ITEM *find_userid(int64_t userid)
{
	USERS users;
	K_TREE_CTX ctx[1];
	K_ITEM look;

	users.userid = userid;
	users.expirydate.tv_sec = default_expiry.tv_sec;
	users.expirydate.tv_usec = default_expiry.tv_usec;

	INIT_USERS(&look);
	look.data = (void *)(&users);
	return find_in_ktree(userid_root, &look, ctx);
}

// TODO: endian? (to avoid being all zeros?)
void make_salt(USERS *users)
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

void password_hash(char *username, char *passwordhash, char *salt, char *result, size_t siz)
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

bool check_hash(USERS *users, char *passwordhash)
{
	char hex[SHA256SIZHEX+1];

	if (*(users->salt)) {
		password_hash(users->username, passwordhash, users->salt, hex, sizeof(hex));
		return (strcasecmp(hex, users->passwordhash) == 0);
	} else
		return (strcasecmp(passwordhash, users->passwordhash) == 0);
}

static void users_checkfor(USERS *users, char *name, int64_t bits)
{
	char *ptr;

	ptr = strstr(users->userdata, name);
	if (ptr) {
		size_t len = strlen(name);
		if ((ptr == users->userdata || *(ptr-1) == DATABITS_SEP) &&
		    *(ptr+len) == '=') {
			users->databits |= bits;
		}
	}
}

void users_databits(USERS *users)
{
	users->databits = 0;
	if (users->userdata && *(users->userdata))
	{
		users_checkfor(users, USER_TOTPAUTH_NAME, USER_TOTPAUTH);
		users_checkfor(users, USER_TEST2FA_NAME, USER_TEST2FA);
	}
}

// Returns the hex text string (and length) in a malloced buffer
char *_users_userdata_get_hex(USERS *users, char *name, int64_t bit,
			      size_t *hexlen, WHERE_FFL_ARGS)
{
	char *ptr, *tmp, *end, *st = NULL, *val = NULL;

	*hexlen = 0;
	if (users->userdata && (users->databits & bit)) {
		ptr = strstr(users->userdata, name);
		// Should always be true
		if (!ptr) {
			LOGEMERG("%s() users userdata/databits mismatch for "
				 "%s/%"PRId64 WHERE_FFL,
				 __func__,
				 st = safe_text_nonull(users->username),
				 users->databits, WHERE_FFL_PASS);
			FREENULL(st);
		} else {
			tmp = ptr + strlen(name) + 1;
			if ((ptr == users->userdata || *(ptr-1) == DATABITS_SEP) &&
			    *(tmp-1) == '=') {
				end = strchr(tmp, DATABITS_SEP);
				if (end)
					*hexlen = end - tmp;
				else
					*hexlen = strlen(tmp);
				val = malloc(*hexlen + 1);
				if (!val)
					quithere(1, "malloc OOM");
				memcpy(val, tmp, *hexlen);
				val[*hexlen] = '\0';
			}
		}
	}
	return val;
}

// Returns binary malloced string (and length) or NULL if not found
unsigned char *_users_userdata_get_bin(USERS *users, char *name, int64_t bit,
				       size_t *binlen, WHERE_FFL_ARGS)
{
	unsigned char *val = NULL;
	size_t hexlen;
	char *hex;

	*binlen = 0;
	hex = _users_userdata_get_hex(users, name, bit, &hexlen,
				      WHERE_FFL_PASS);
	if (hex) {
		/* avoid calling malloc twice, hex is 2x required
		 *  and overlap is OK with _hex2bin code */
		hexlen >>= 1;
		if (hex2bin(hex, hex, hexlen)) {
			val = (unsigned char *)hex;
			*binlen = hexlen;
		} else
			FREENULL(hex);
	}
	return val;
}

/* WARNING - users->userdata and users->databits are updated */
void _users_userdata_del(USERS *users, char *name, int64_t bit, WHERE_FFL_ARGS)
{
	char *ptr, *tmp, *st = NULL, *end;

	if (users->userdata && (users->databits & bit)) {
		ptr = strstr(users->userdata, name);
		// Should always be true
		if (!ptr) {
			LOGEMERG("%s() users userdata/databits mismatch for "
				 "%s/%"PRId64 WHERE_FFL,
				 __func__,
				 st = safe_text_nonull(users->username),
				 users->databits, WHERE_FFL_PASS);
			FREENULL(st);
		} else {
			tmp = ptr + strlen(name) + 1;
			if ((ptr == users->userdata || *(ptr-1) == DATABITS_SEP) &&
			    *(tmp-1) == '=') {
				// overwrite the memory since it will be smaller
				end = strchr(tmp, DATABITS_SEP);
				if (!end) {
					// chop off the end
					if (ptr == users->userdata) {
						// now empty
						*ptr = '\0';
					} else {
						// remove from DATABITS_SEP
						*(ptr-1) = '\0';
					}
				} else {
					// overlap
					memmove(ptr, end+1, strlen(end+1)+1);
				}
				users->databits &= ~bit;
			}
		}
	}
}

/* hex should be null terminated hex text
 * WARNING - users->userdata and users->databits are updated */
void _users_userdata_add_hex(USERS *users, char *name, int64_t bit, char *hex,
			     WHERE_FFL_ARGS)
{
	char *ptr;

	if (users->userdata && (users->databits & bit)) {
		// TODO: if it's the same size or smaller, don't reallocate
		_users_userdata_del(users, name, bit, WHERE_FFL_PASS);
	}

	if (users->userdata == EMPTY)
		users->userdata = NULL;
	else if (users->userdata && !(*(users->userdata)))
		FREENULL(users->userdata);

	if (users->userdata) {
		size_t len = strlen(users->userdata) + 1 +
				strlen(name) + 1 + strlen(hex) + 1;
		ptr = malloc(len);
		if (!(ptr))
			quithere(1, "malloc OOM");
		snprintf(ptr, len,
			 "%s%c%s=%s",
			 users->userdata, DATABITS_SEP, name, hex);
		FREENULL(users->userdata);
		users->userdata = ptr;
	} else {
		size_t len = strlen(name) + 1 + strlen(hex) + 1;
		users->userdata = malloc(len);
		if (!(users->userdata))
			quithere(1, "malloc OOM");
		snprintf(users->userdata, len, "%s=%s", name, hex);
	}
	users->databits |= bit;
}

/* value is considered binary data of length len
 * WARNING - users->userdata and users->databits are updated */
void _users_userdata_add_bin(USERS *users, char *name, int64_t bit,
			     unsigned char *bin, size_t len, WHERE_FFL_ARGS)
{
	char *hex = bin2hex((const void *)bin, len);
	_users_userdata_add_hex(users, name, bit, hex, WHERE_FFL_PASS);
	FREENULL(hex);
}

// default tree order by userid asc,attname asc,expirydate desc
cmp_t cmp_useratts(K_ITEM *a, K_ITEM *b)
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
K_ITEM *find_useratts(int64_t userid, char *attname)
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
	return find_in_ktree(useratts_root, &look, ctx);
}

// order by userid asc,workername asc,expirydate desc
cmp_t cmp_workers(K_ITEM *a, K_ITEM *b)
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

K_ITEM *find_workers(int64_t userid, char *workername)
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
	return find_in_ktree(workers_root, &look, ctx);
}

K_ITEM *first_workers(int64_t userid, K_TREE_CTX *ctx)
{
	WORKERS workers;
	K_TREE_CTX ctx0[1];
	K_ITEM look;

	if (ctx == NULL)
		ctx = ctx0;

	workers.userid = userid;
	workers.workername[0] = '\0';
	DATE_ZERO(&(workers.expirydate));

	INIT_WORKERS(&look);
	look.data = (void *)(&workers);
	// Caller needs to check userid/expirydate if the result != NULL
	return find_after_in_ktree(workers_root, &look, ctx);
}

K_ITEM *new_worker(PGconn *conn, bool update, int64_t userid, char *workername,
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
				       trf_root, true);
		}
	} else {
		if (confirm_sharesummary) {
			// Shouldn't be possible since the sharesummary is already aged
			LOGERR("%s() %"PRId64"/%s workername not found during confirm",
				__func__, userid, workername);
			return NULL;
		}

		// TODO: limit how many?
		item = workers_add(conn, true, userid, workername, diffdef,
				   idlenotificationenabled, idlenotificationtime,
				   by, code, inet, cd, trf_root);
	}
	return item;
}

K_ITEM *new_default_worker(PGconn *conn, bool update, int64_t userid, char *workername,
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

void dsp_paymentaddresses(K_ITEM *item, FILE *stream)
{
	char expirydate_buf[DATE_BUFSIZ], createdate_buf[DATE_BUFSIZ];
	PAYMENTADDRESSES *pa;

	if (!item)
		fprintf(stream, "%s() called with (null) item\n", __func__);
	else {
		DATA_PAYMENTADDRESSES(pa, item);
		tv_to_buf(&(pa->expirydate), expirydate_buf, sizeof(expirydate_buf));
		tv_to_buf(&(pa->createdate), createdate_buf, sizeof(createdate_buf));
		fprintf(stream, " id=%"PRId64" userid=%"PRId64" addr='%s' "
				"ratio=%"PRId32" exp=%s cd=%s\n",
				pa->paymentaddressid, pa->userid,
				pa->payaddress, pa->payratio,
				expirydate_buf, createdate_buf);
	}
}

// order by expirydate asc,userid asc,payaddress asc
cmp_t cmp_paymentaddresses(K_ITEM *a, K_ITEM *b)
{
	PAYMENTADDRESSES *pa, *pb;
	DATA_PAYMENTADDRESSES(pa, a);
	DATA_PAYMENTADDRESSES(pb, b);
	cmp_t c = CMP_TV(pa->expirydate, pb->expirydate);
	if (c == 0) {
		c = CMP_BIGINT(pa->userid, pb->userid);
		if (c == 0)
			c = CMP_STR(pa->payaddress, pb->payaddress);
	}
	return c;
}

// order by userid asc,createdate asc,payaddress asc
cmp_t cmp_payaddr_create(K_ITEM *a, K_ITEM *b)
{
	PAYMENTADDRESSES *pa, *pb;
	DATA_PAYMENTADDRESSES(pa, a);
	DATA_PAYMENTADDRESSES(pb, b);
	cmp_t c = CMP_BIGINT(pa->userid, pb->userid);
	if (c == 0) {
		c = CMP_TV(pa->createdate, pb->createdate);
		if (c == 0)
			c = CMP_STR(pa->payaddress, pb->payaddress);
	}
	return c;
}

/* Find the last CURRENT paymentaddresses for the given userid
 * N.B. there can be more than one
 *  any more will be prev_in_ktree(ctx): CURRENT and userid matches */
K_ITEM *find_paymentaddresses(int64_t userid, K_TREE_CTX *ctx)
{
	PAYMENTADDRESSES paymentaddresses, *pa;
	K_ITEM look, *item;

	paymentaddresses.expirydate.tv_sec = default_expiry.tv_sec;
	paymentaddresses.expirydate.tv_usec = default_expiry.tv_usec;
	paymentaddresses.userid = userid+1;
	paymentaddresses.payaddress[0] = '\0';

	INIT_PAYMENTADDRESSES(&look);
	look.data = (void *)(&paymentaddresses);
	item = find_before_in_ktree(paymentaddresses_root, &look, ctx);
	if (item) {
		DATA_PAYMENTADDRESSES(pa, item);
		if (pa->userid == userid && CURRENT(&(pa->expirydate)))
			return item;
		else
			return NULL;
	} else
		return NULL;
}

/* Find the first paymentaddresses for the given userid
 *  sorted by userid+createdate+... */
K_ITEM *find_paymentaddresses_create(int64_t userid, K_TREE_CTX *ctx)
{
	PAYMENTADDRESSES paymentaddresses, *pa;
	K_ITEM look, *item;

	paymentaddresses.userid = userid;
	DATE_ZERO(&(paymentaddresses.createdate));
	paymentaddresses.payaddress[0] = '\0';

	INIT_PAYMENTADDRESSES(&look);
	look.data = (void *)(&paymentaddresses);
	item = find_after_in_ktree(paymentaddresses_create_root, &look, ctx);
	if (item) {
		DATA_PAYMENTADDRESSES(pa, item);
		if (pa->userid == userid)
			return item;
		else
			return NULL;
	} else
		return NULL;
}

K_ITEM *find_one_payaddress(int64_t userid, char *payaddress, K_TREE_CTX *ctx)
{
	PAYMENTADDRESSES paymentaddresses;
	K_ITEM look;

	paymentaddresses.expirydate.tv_sec = default_expiry.tv_sec;
	paymentaddresses.expirydate.tv_usec = default_expiry.tv_usec;
	paymentaddresses.userid = userid;
	STRNCPY(paymentaddresses.payaddress, payaddress);

	INIT_PAYMENTADDRESSES(&look);
	look.data = (void *)(&paymentaddresses);
	return find_in_ktree(paymentaddresses_root, &look, ctx);
}

/* This will match any user that has the payaddress
 * This avoids the bitcoind delay of rechecking an address
 *  that has EVER been seen before
 * However, also, cmd_userset() that uses it, effectively ensures
 *  that 2 standard users, that mine to a username rather than
 *  a bitcoin address, cannot ever use the same bitcoin address
 * N.B. this is faster than a bitcoind check, but still slow
 *  It needs a tree based on payaddress to speed it up
 * N.B.2 paymentadresses_root doesn't contain addrauth usernames */
K_ITEM *find_any_payaddress(char *payaddress)
{
	PAYMENTADDRESSES *pa;
	K_TREE_CTX ctx[1];
	K_ITEM *item;

	item = first_in_ktree(paymentaddresses_root, ctx);
	while (item) {
		DATA_PAYMENTADDRESSES(pa, item);
		if (strcmp(pa->payaddress, payaddress) == 0)
			return item;
		item = next_in_ktree(ctx);
	}
	return NULL;
}

// order by userid asc,payoutid asc,subname asc,expirydate desc
cmp_t cmp_payments(K_ITEM *a, K_ITEM *b)
{
	PAYMENTS *pa, *pb;
	DATA_PAYMENTS(pa, a);
	DATA_PAYMENTS(pb, b);
	cmp_t c = CMP_BIGINT(pa->userid, pb->userid);
	if (c == 0) {
		c = CMP_BIGINT(pa->payoutid, pb->payoutid);
		if (c == 0) {
			c = CMP_STR(pa->subname, pb->subname);
			if (c == 0)
				c = CMP_TV(pb->expirydate, pa->expirydate);
		}
	}
	return c;
}

K_ITEM *find_payments(int64_t payoutid, int64_t userid, char *subname)
{
	PAYMENTS payments;
	K_TREE_CTX ctx[1];
	K_ITEM look;

	payments.payoutid = payoutid;
	payments.userid = userid;
	STRNCPY(payments.subname, subname);
	payments.expirydate.tv_sec = default_expiry.tv_sec;
	payments.expirydate.tv_usec = default_expiry.tv_usec;

	INIT_PAYMENTS(&look);
	look.data = (void *)(&payments);
	return find_in_ktree(payments_root, &look, ctx);
}

K_ITEM *find_first_payments(int64_t userid, K_TREE_CTX *ctx)
{
	PAYMENTS payments;
	K_TREE_CTX ctx0[1];
	K_ITEM look, *item;

	if (ctx == NULL)
		ctx = ctx0;

	bzero(&payments, sizeof(payments));
	payments.userid = userid;

	INIT_PAYMENTS(&look);
	look.data = (void *)(&payments);
	// userid needs to be checked if item returned != NULL
	item = find_after_in_ktree(payments_root, &look, ctx);
	return item;
}

K_ITEM *find_first_paypayid(int64_t userid, int64_t payoutid, K_TREE_CTX *ctx)
{
	PAYMENTS payments;
	K_TREE_CTX ctx0[1];
	K_ITEM look, *item;

	if (ctx == NULL)
		ctx = ctx0;

	payments.userid = userid;
	payments.payoutid = payoutid;
	payments.subname[0] = '\0';

	INIT_PAYMENTS(&look);
	look.data = (void *)(&payments);
	// userid+payoutid needs to be checked if item returned != NULL
	item = find_after_in_ktree(payments_root, &look, ctx);
	return item;
}

// order by userid asc
cmp_t cmp_accountbalance(K_ITEM *a, K_ITEM *b)
{
	PAYMENTS *aba, *abb;
	DATA_PAYMENTS(aba, a);
	DATA_PAYMENTS(abb, b);
	return CMP_BIGINT(aba->userid, abb->userid);
}

K_ITEM *find_accountbalance(int64_t userid)
{
	ACCOUNTBALANCE accountbalance;
	K_TREE_CTX ctx[1];
	K_ITEM look, *item;

	accountbalance.userid = userid;

	INIT_ACCOUNTBALANCE(&look);
	look.data = (void *)(&accountbalance);
	K_RLOCK(accountbalance_free);
	item = find_in_ktree(accountbalance_root, &look, ctx);
	K_RUNLOCK(accountbalance_free);
	return item;
}

// order by optionname asc,activationdate asc,activationheight asc,expirydate desc
cmp_t cmp_optioncontrol(K_ITEM *a, K_ITEM *b)
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

#define reward_override_name(_height, _buf, _siz) \
	_reward_override_name(_height, _buf, _siz, WHERE_FFL_HERE)
static bool _reward_override_name(int32_t height, char *buf, size_t siz,
				  WHERE_FFL_ARGS)
{
	char tmp[128];
	size_t len;

	snprintf(tmp, sizeof(tmp), REWARDOVERRIDE"_%"PRId32, height);

	// Code bug - detect and notify truncation coz that would be bad :P
	len = strlen(tmp) + 1;
	if (len > siz) {
		LOGEMERG("%s(): Invalid size %d passed - required %d" WHERE_FFL,
			 __func__, (int)siz, (int)len, WHERE_FFL_PASS);
		return false;
	}

	strcpy(buf, tmp);
	return true;
}

// Must be R or W locked before call
K_ITEM *find_optioncontrol(char *optionname, const tv_t *now, int32_t height)
{
	OPTIONCONTROL optioncontrol, *oc, *ocbest;
	K_TREE_CTX ctx[1];
	K_ITEM look, *item, *best;

	/* Step through all records having optionname and check:
	 * 1) activationdate is <= now
	 *  and
	 * 2) height <= specified height (pool.height = current)
	 * The logic being: if 'now' is after the record activation date
	 *  and 'height' is after the record activation height then
	 *  the record is active
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
	DATE_ZERO(&(optioncontrol.activationdate));
	optioncontrol.activationheight = OPTIONCONTROL_HEIGHT - 1;
	optioncontrol.expirydate.tv_sec = default_expiry.tv_sec;
	optioncontrol.expirydate.tv_usec = default_expiry.tv_usec;

	INIT_OPTIONCONTROL(&look);
	look.data = (void *)(&optioncontrol);
	item = find_after_in_ktree(optioncontrol_root, &look, ctx);
	ocbest = NULL;
	best = NULL;
	while (item) {
		DATA_OPTIONCONTROL(oc, item);
		// Ordered first by optionname
		if (strcmp(oc->optionname, optionname) != 0)
			break;

		// Is oc active?
		if (CURRENT(&(oc->expirydate)) &&
		    oc->activationheight <= height &&
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

/*
 * Get a setting value for the given setting name
 * First check if there is a USERATTS attnum value != 0
 * If not, check if there is an OPTIONCONTROL record (can be any value)
 * If not, return the default
 * WARNING OPTIONCONTROL is time dependent,
 *  i.e. ensure now and pool.height are correct (e.g. during a reload)
 */
int64_t user_sys_setting(int64_t userid, char *setting_name,
			 int64_t setting_default, const tv_t *now)
{
	OPTIONCONTROL *optioncontrol;
	K_ITEM *ua_item, *oc_item;
	USERATTS *useratts;

	if (userid != 0) {
		K_RLOCK(useratts_free);
		ua_item = find_useratts(userid, setting_name);
		K_RUNLOCK(useratts_free);
		if (ua_item) {
			DATA_USERATTS(useratts, ua_item);
			if (useratts->attnum != 0)
				return useratts->attnum;
		}
	}

	K_RLOCK(optioncontrol_free);
	oc_item = find_optioncontrol(setting_name, now, pool.height);
	K_RUNLOCK(optioncontrol_free);
	if (oc_item) {
		DATA_OPTIONCONTROL(optioncontrol, oc_item);
		return (int64_t)atol(optioncontrol->optionvalue);
	}

	return setting_default;
}

// order by workinfoid asc,expirydate asc
cmp_t cmp_workinfo(K_ITEM *a, K_ITEM *b)
{
	WORKINFO *wa, *wb;
	DATA_WORKINFO(wa, a);
	DATA_WORKINFO(wb, b);
	cmp_t c = CMP_BIGINT(wa->workinfoid, wb->workinfoid);
	if (c == 0)
		c = CMP_TV(wa->expirydate, wb->expirydate);
	return c;
}

int32_t _coinbase1height(WORKINFO *wi, WHERE_FFL_ARGS)
{
	int32_t height = 0;
	char *st = NULL;
	uchar *cb1;
	size_t len;
	int siz;

	len = strlen(wi->coinbase1);
	if (len < (BLOCKNUM_OFFSET * 2 + 4) || (len & 1)) {
		LOGERR("ERR %s(): Invalid coinbase1 len %d - "
			"should be >= %d and even - wid %"PRId64
			" (cb1 %.10s%s)",
			__func__, (int)len, (BLOCKNUM_OFFSET * 2 + 4),
			wi->workinfoid, st = safe_text_nonull(wi->coinbase1),
			len <= 10 ? "" : "...");
		FREENULL(st);
		return height;
	}

	cb1 = ((uchar *)(wi->coinbase1)) + (BLOCKNUM_OFFSET * 2);
	siz = ((hex2bin_tbl[*cb1]) << 4) + (hex2bin_tbl[*(cb1+1)]);

	// limit to 4 for int32_t and since ... that should last a while :)
	if (siz < 1 || siz > 4) {
		LOGERR("ERR %s(): Invalid coinbase1 block height size (%d)"
			" require: 1..4 - wid %"PRId64" (cb1 %.10s...)"
			WHERE_FFL,
			__func__, siz, wi->workinfoid, wi->coinbase1,
			WHERE_FFL_PASS);
		return height;
	}

	siz *= 2;
	while (siz-- > 0) {
		height <<= 4;
		height += (int32_t)hex2bin_tbl[*(cb1+(siz^1)+2)];
	}

	return height;
}

// order by height asc,createdate asc
cmp_t cmp_workinfo_height(K_ITEM *a, K_ITEM *b)
{
	WORKINFO *wa, *wb;
	DATA_WORKINFO(wa, a);
	DATA_WORKINFO(wb, b);
	cmp_t c = CMP_INT(wa->height, wb->height);
	if (c == 0)
		c = CMP_TV(wa->createdate, wb->createdate);
	return c;
}

K_ITEM *find_workinfo(int64_t workinfoid, K_TREE_CTX *ctx)
{
	WORKINFO workinfo;
	K_TREE_CTX ctx0[1];
	K_ITEM look, *item;

	if (ctx == NULL)
		ctx = ctx0;

	workinfo.workinfoid = workinfoid;
	workinfo.expirydate.tv_sec = default_expiry.tv_sec;
	workinfo.expirydate.tv_usec = default_expiry.tv_usec;

	INIT_WORKINFO(&look);
	look.data = (void *)(&workinfo);
	K_RLOCK(workinfo_free);
	item = find_in_ktree(workinfo_root, &look, ctx);
	K_RUNLOCK(workinfo_free);
	return item;
}

K_ITEM *next_workinfo(int64_t workinfoid, K_TREE_CTX *ctx)
{
	WORKINFO workinfo, *wi;
	K_TREE_CTX ctx0[1];
	K_ITEM look, *item;

	if (ctx == NULL)
		ctx = ctx0;

	workinfo.workinfoid = workinfoid;
	workinfo.expirydate.tv_sec = default_expiry.tv_sec;
	workinfo.expirydate.tv_usec = default_expiry.tv_usec;

	INIT_WORKINFO(&look);
	look.data = (void *)(&workinfo);
	K_RLOCK(workinfo_free);
	item = find_after_in_ktree(workinfo_root, &look, ctx);
	if (item) {
		DATA_WORKINFO(wi, item);
		while (item && !CURRENT(&(wi->expirydate))) {
			item = next_in_ktree(ctx);
			DATA_WORKINFO_NULL(wi, item);
		}
	}
	K_RUNLOCK(workinfo_free);
	return item;
}

// Duplicates during a reload are set to not show messages
bool workinfo_age(int64_t workinfoid, char *poolinstance, char *by, char *code,
		  char *inet, tv_t *cd, tv_t *ss_first, tv_t *ss_last,
		  int64_t *ss_count, int64_t *s_count, int64_t *s_diff)
{
	K_ITEM *wi_item, ss_look, *ss_item, s_look, *s_item;
	K_ITEM *wm_item, *tmp_item;
	K_TREE_CTX ss_ctx[1], s_ctx[1];
	char cd_buf[DATE_BUFSIZ];
	int64_t ss_tot, ss_already, ss_failed, shares_tot, shares_dumped;
	int64_t diff_tot;
	SHARESUMMARY looksharesummary, *sharesummary;
	WORKINFO *workinfo;
	SHARES lookshares, *shares;
	bool ok = false, skipupdate;
	char error[1024];

	LOGDEBUG("%s(): age", __func__);

	DATE_ZERO(ss_first);
	DATE_ZERO(ss_last);
	*ss_count = *s_count = *s_diff = 0;

	wi_item = find_workinfo(workinfoid, NULL);
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

	K_RLOCK(workmarkers_free);
	wm_item = find_workmarkers(workinfoid, false, MARKER_PROCESSED, NULL);
	K_RUNLOCK(workmarkers_free);
	// Should never happen?
	if (wm_item && !reloading) {
		tv_to_buf(cd, cd_buf, sizeof(cd_buf));
		LOGERR("%s() %"PRId64"/%s/%ld,%ld %.19s attempt to age a "
			"workmarker! Age ignored!",
			__func__, workinfoid, poolinstance,
			cd->tv_sec, cd->tv_usec, cd_buf);
		goto bye;
	}

	INIT_SHARESUMMARY(&ss_look);
	INIT_SHARES(&s_look);

	// Find the first matching sharesummary
	looksharesummary.workinfoid = workinfoid;
	looksharesummary.userid = -1;
	looksharesummary.workername = EMPTY;

	ok = true;
	ss_tot = ss_already = ss_failed = shares_tot = shares_dumped =
	diff_tot = 0;
	ss_look.data = (void *)(&looksharesummary);
	K_RLOCK(sharesummary_free);
	ss_item = find_after_in_ktree(sharesummary_workinfoid_root, &ss_look, ss_ctx);
	K_RUNLOCK(sharesummary_free);
	DATA_SHARESUMMARY_NULL(sharesummary, ss_item);
	while (ss_item && sharesummary->workinfoid == workinfoid) {
		ss_tot++;
		error[0] = '\0';
		skipupdate = false;
		/* Reloading during a confirm will not have any old data
		 *  so finding an aged sharesummary here is an error
		 * N.B. this can only happen with (very) old reload files */
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
			if (!sharesummary_age(ss_item, by, code, inet, cd)) {
				ss_failed++;
				LOGERR("%s(): Failed to age sharesummary %"PRId64"/%s/%"PRId64,
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
		DATE_ZERO(&(lookshares.createdate));

		s_look.data = (void *)(&lookshares);
		K_WLOCK(shares_free);
		s_item = find_after_in_ktree(shares_root, &s_look, s_ctx);
		while (s_item) {
			DATA_SHARES(shares, s_item);
			if (shares->workinfoid != workinfoid ||
			    shares->userid != lookshares.userid ||
			    strcmp(shares->workername, lookshares.workername) != 0)
				break;

			shares_tot++;
			if (shares->errn == SE_NONE)
				diff_tot += shares->diff;
			tmp_item = next_in_ktree(s_ctx);
			remove_from_ktree(shares_root, s_item);
			k_unlink_item(shares_store, s_item);
			if (reloading && skipupdate)
				shares_dumped++;
			if (reloading && skipupdate && !error[0]) {
				snprintf(error, sizeof(error),
					 "reload found aged share: %"PRId64
					 "/%"PRId64"/%s/%s%.0f",
					 shares->workinfoid,
					 shares->userid,
					 shares->workername,
					 (shares->errn == SE_NONE) ? "" : "*",
					 shares->diff);
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

	if (ss_already || ss_failed || shares_dumped) {
		/* If all were already aged, and no shares
		 * then we don't want a message */
		if (!(ss_already == ss_tot && shares_tot == 0)) {
			LOGERR("%s(): Summary aging of %"PRId64
				"/%s sstotal=%"PRId64" already=%"PRId64
				" failed=%"PRId64", sharestotal=%"PRId64
				" dumped=%"PRId64", diff=%"PRId64,
				__func__, workinfoid, poolinstance, ss_tot,
				ss_already, ss_failed, shares_tot,
				shares_dumped, diff_tot);
		}
	}
bye:
	return ok;
}

// Block height coinbase reward value
double coinbase_reward(int32_t height)
{
	double value;

	value = REWARD_BASE * pow(0.5, floor((double)height / REWARD_HALVE));

	return(value);
}

// The PPS value of a 1diff share for the given workinfoid
double workinfo_pps(K_ITEM *w_item, int64_t workinfoid, bool lock)
{
	OPTIONCONTROL *optioncontrol;
	K_ITEM *oc_item;
	char oc_name[TXT_SML+1];
	WORKINFO *workinfo;

	// Allow optioncontrol override for a given workinfoid
	snprintf(oc_name, sizeof(oc_name), PPSOVERRIDE"_%"PRId64, workinfoid);
	if (lock)
		K_RLOCK(optioncontrol_free);
	// No time/height control is used, just find the latest record
	oc_item = find_optioncontrol(oc_name, &date_eot, MAX_HEIGHT);
	if (lock)
		K_RUNLOCK(optioncontrol_free);

	// Value is a floating point double of satoshi
	if (oc_item) {
		DATA_OPTIONCONTROL(optioncontrol, oc_item);
		return atof(optioncontrol->optionvalue);
	}

	if (!w_item) {
		LOGERR("%s(): missing workinfo %"PRId64,
			__func__, workinfoid);
		return 0.0;
	}

	DATA_WORKINFO(workinfo, w_item);

	// PPS 1diff is worth coinbase reward divided by difficulty
	return(coinbase_reward(workinfo->height) / workinfo->diff_target);
}

// order by workinfoid asc,userid asc,workername asc,createdate asc,nonce asc,expirydate desc
cmp_t cmp_shares(K_ITEM *a, K_ITEM *b)
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

// order by workinfoid asc,userid asc,createdate asc,nonce asc,expirydate desc
cmp_t cmp_shareerrors(K_ITEM *a, K_ITEM *b)
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

void dsp_sharesummary(K_ITEM *item, FILE *stream)
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
cmp_t cmp_sharesummary(K_ITEM *a, K_ITEM *b)
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
cmp_t cmp_sharesummary_workinfoid(K_ITEM *a, K_ITEM *b)
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

void zero_sharesummary(SHARESUMMARY *row)
{
	row->diffacc = row->diffsta = row->diffdup = row->diffhi =
	row->diffrej = row->shareacc = row->sharesta = row->sharedup =
	row->sharehi = row->sharerej = 0.0;
	row->sharecount = row->errorcount = 0;
	DATE_ZERO(&(row->firstshare));
	DATE_ZERO(&(row->lastshare));
	DATE_ZERO(&(row->firstshareacc));
	DATE_ZERO(&(row->lastshareacc));
	row->lastdiffacc = 0;
	row->complete[0] = SUMMARY_NEW;
	row->complete[1] = '\0';
}

K_ITEM *_find_sharesummary(int64_t userid, char *workername, int64_t workinfoid, bool pool)
{
	SHARESUMMARY sharesummary;
	K_TREE_CTX ctx[1];
	K_ITEM look;

	sharesummary.userid = userid;
	sharesummary.workername = workername;
	sharesummary.workinfoid = workinfoid;

	INIT_SHARESUMMARY(&look);
	look.data = (void *)(&sharesummary);
	if (pool)
		return find_in_ktree(sharesummary_pool_root, &look, ctx);
	else
		return find_in_ktree(sharesummary_root, &look, ctx);
}

K_ITEM *find_last_sharesummary(int64_t userid, char *workername)
{
	SHARESUMMARY look_sharesummary, *sharesummary;
	K_TREE_CTX ctx[1];
	K_ITEM look, *item;

	look_sharesummary.userid = userid;
	look_sharesummary.workername = workername;
	look_sharesummary.workinfoid = MAXID;

	INIT_SHARESUMMARY(&look);
	look.data = (void *)(&look_sharesummary);
	item = find_before_in_ktree(sharesummary_root, &look, ctx);
	if (item) {
		DATA_SHARESUMMARY(sharesummary, item);
		if (sharesummary->userid != userid ||
		    strcmp(sharesummary->workername, workername) != 0)
			item = NULL;
	}
	return item;
}

/* TODO: markersummary checking?
 * However, there should be no issues since the sharesummaries are removed */
void auto_age_older(int64_t workinfoid, char *poolinstance, char *by,
		    char *code, char *inet, tv_t *cd)
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
	looksharesummary.workername = EMPTY;
	INIT_SHARESUMMARY(&look);
	look.data = (void *)(&looksharesummary);

	K_RLOCK(sharesummary_free);
	ss_item = find_after_in_ktree(sharesummary_workinfoid_root, &look, ctx);
	DATA_SHARESUMMARY_NULL(sharesummary, ss_item);

	DATE_ZERO(&ss_first_min);
	DATE_ZERO(&ss_last_max);
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
			ok = workinfo_age(do_id, poolinstance, by, code, inet,
					  cd, &ss_first, &ss_last, &ss_count,
					  &s_count, &s_diff);

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
				   "share%s %"PRId64" sharesummar%s %"PRId32
				   " workinfoid%s %s %s",
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

void _dbhash2btchash(char *hash, char *buf, size_t siz, WHERE_FFL_ARGS)
{
	size_t len;
	int i, j;

	// code bug
	if (siz < (SHA256SIZHEX + 1)) {
		quitfrom(1, file, func, line,
			 "%s() passed buf too small %d (%d)",
			 __func__, (int)siz, SHA256SIZHEX+1);
	}

	len = strlen(hash);
	// code bug - check this before calling
	if (len != SHA256SIZHEX) {
		quitfrom(1, file, func, line,
			 "%s() invalid hash passed - size %d (%d)",
			 __func__, (int)len, SHA256SIZHEX);
	}

	for (i = 0; i < SHA256SIZHEX; i++) {
		j = SHA256SIZHEX - 8 - (i & 0xfff8) + (i % 8);
		buf[i] = hash[j];
	}
	buf[SHA256SIZHEX] = '\0';
}

void _dsp_hash(char *hash, char *buf, size_t siz, WHERE_FFL_ARGS)
{
	char tmp[SHA256SIZHEX+1];
	char *ptr;

	_dbhash2btchash(hash, tmp, sizeof(tmp), file, func, line);
	ptr = tmp;
	while (*ptr && *ptr == '0')
		ptr++;
	ptr -= 4;
	if (ptr < tmp)
		ptr = tmp;
	STRNCPYSIZ(buf, ptr, siz);
}

double _blockhash_diff(char *hash, WHERE_FFL_ARGS)
{
	uchar binhash[SHA256SIZHEX >> 1];
	uchar swap[SHA256SIZHEX >> 1];
	size_t len;

	len = strlen(hash);
	// code bug - check this before calling
	if (len != SHA256SIZHEX) {
		quitfrom(1, file, func, line,
			 "%s() invalid hash passed - size %d (%d)",
			 __func__, (int)len, SHA256SIZHEX);
	}

	hex2bin(binhash, hash, sizeof(binhash));

	flip_32(swap, binhash);

	return diff_from_target(swap);
}

void dsp_blocks(K_ITEM *item, FILE *stream)
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
cmp_t cmp_blocks(K_ITEM *a, K_ITEM *b)
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
K_ITEM *find_blocks(int32_t height, char *blockhash, K_TREE_CTX *ctx)
{
	BLOCKS blocks;
	K_TREE_CTX ctx0[1];
	K_ITEM look;

	if (ctx == NULL)
		ctx = ctx0;

	blocks.height = height;
	STRNCPY(blocks.blockhash, blockhash);
	blocks.expirydate.tv_sec = default_expiry.tv_sec;
	blocks.expirydate.tv_usec = default_expiry.tv_usec;

	INIT_BLOCKS(&look);
	look.data = (void *)(&blocks);
	return find_in_ktree(blocks_root, &look, ctx);
}

// Must be R or W locked before call
K_ITEM *find_prev_blocks(int32_t height, K_TREE_CTX *ctx)
{
	BLOCKS lookblocks, *blocks;
	K_TREE_CTX ctx0[1];
	K_ITEM look, *b_item;

	if (ctx == NULL)
		ctx = ctx0;

	/* TODO: For self orphaned (if that ever happens)
	 * this will find based on blockhash order if it has two,
	 * not NEW, blocks, which might not find the right one */
	lookblocks.height = height;
	lookblocks.blockhash[0] = '\0';
	DATE_ZERO(&(lookblocks.expirydate));

	INIT_BLOCKS(&look);
	look.data = (void *)(&lookblocks);
	b_item = find_before_in_ktree(blocks_root, &look, ctx);
	while (b_item) {
		DATA_BLOCKS(blocks, b_item);
		if (blocks->confirmed[0] != BLOCKS_NEW &&
		    CURRENT(&(blocks->expirydate)))
			return b_item;
		b_item = prev_in_ktree(ctx);
	}
	return NULL;
}

const char *blocks_confirmed(char *confirmed)
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
		case BLOCKS_REJECT:
			return blocks_reject;
	}
	return blocks_unknown;
}

void zero_on_new_block(bool lock)
{
	WORKERSTATUS *workerstatus;
	K_TREE_CTX ctx[1];
	K_ITEM *ws_item;

	if (lock)
		K_WLOCK(workerstatus_free);
	pool.diffacc = pool.diffinv = pool.shareacc =
	pool.shareinv = pool.best_sdiff = 0;
	ws_item = first_in_ktree(workerstatus_root, ctx);
	while (ws_item) {
		DATA_WORKERSTATUS(workerstatus, ws_item);
		workerstatus->block_diffacc = workerstatus->block_diffinv =
		workerstatus->block_diffsta = workerstatus->block_diffdup =
		workerstatus->block_diffhi = workerstatus->block_diffrej =
		workerstatus->block_shareacc = workerstatus->block_shareinv =
		workerstatus->block_sharesta = workerstatus->block_sharedup =
		workerstatus->block_sharehi = workerstatus->block_sharerej = 0.0;
		ws_item = next_in_ktree(ctx);
	}
	if (lock)
		K_WUNLOCK(workerstatus_free);
}

// Currently only used at the end of the startup
void set_block_share_counters()
{
	K_TREE_CTX ctx[1], ctx_ms[1];
	K_ITEM *ss_item, ss_look, *ws_item, *wm_item, *ms_item, ms_look;
	WORKERSTATUS *workerstatus = NULL;
	SHARESUMMARY *sharesummary, looksharesummary;
	WORKMARKERS *workmarkers;
	MARKERSUMMARY *markersummary, lookmarkersummary;

	LOGWARNING("%s(): Updating block sharesummary counters...", __func__);

	INIT_SHARESUMMARY(&ss_look);
	INIT_MARKERSUMMARY(&ms_look);

	zero_on_new_block(false);

	ws_item = NULL;
	/* From the end backwards so we can skip the workinfoid's we don't
	 * want by jumping back to just before the current worker when the
	 * workinfoid goes below the limit */
	ss_item = last_in_ktree(sharesummary_root, ctx);
	while (ss_item) {
		DATA_SHARESUMMARY(sharesummary, ss_item);
		if (sharesummary->workinfoid <= pool.workinfoid) {
			// Skip back to the next worker
			looksharesummary.userid = sharesummary->userid;
			looksharesummary.workername = sharesummary->workername;
			looksharesummary.workinfoid = -1;
			ss_look.data = (void *)(&looksharesummary);
			ss_item = find_before_in_ktree(sharesummary_root,
							&ss_look, ctx);
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
			ws_item = find_workerstatus(false, sharesummary->userid,
						    sharesummary->workername,
						    __FILE__, __func__, __LINE__);
			if (!ws_item) {
				ws_item = find_create_workerstatus(false, sharesummary->userid,
								   sharesummary->workername,
								   __FILE__, __func__, __LINE__);
			}
			DATA_WORKERSTATUS(workerstatus, ws_item);
		}

		pool.diffacc += sharesummary->diffacc;
		pool.diffinv += sharesummary->diffsta + sharesummary->diffdup +
				sharesummary->diffhi + sharesummary->diffrej;
		// Block stats only
		workerstatus->block_diffacc += sharesummary->diffacc;
		workerstatus->block_diffinv += sharesummary->diffsta +
						sharesummary->diffdup +
						sharesummary->diffhi +
						sharesummary->diffrej;
		workerstatus->block_diffsta += sharesummary->diffsta;
		workerstatus->block_diffdup += sharesummary->diffdup;
		workerstatus->block_diffhi += sharesummary->diffhi;
		workerstatus->block_diffrej += sharesummary->diffrej;
		workerstatus->block_shareacc += sharesummary->shareacc;
		workerstatus->block_shareinv += sharesummary->sharesta +
						sharesummary->sharedup +
						sharesummary->sharehi +
						sharesummary->sharerej;
		workerstatus->block_sharesta += sharesummary->sharesta;
		workerstatus->block_sharedup += sharesummary->sharedup;
		workerstatus->block_sharehi += sharesummary->sharehi;
		workerstatus->block_sharerej += sharesummary->sharerej;

		ss_item = prev_in_ktree(ctx);
	}

	LOGWARNING("%s(): Updating block markersummary counters...", __func__);

	// workmarkers after the workinfoid of the last pool block
	// TODO: tune the loop layout if needed
	ws_item = NULL;
	wm_item = last_in_ktree(workmarkers_workinfoid_root, ctx);
	DATA_WORKMARKERS_NULL(workmarkers, wm_item);
	while (wm_item &&
	       CURRENT(&(workmarkers->expirydate)) &&
	       workmarkers->workinfoidend > pool.workinfoid) {

		if (WMPROCESSED(workmarkers->status))
		{
			// Should never be true
			if (workmarkers->workinfoidstart <= pool.workinfoid) {
				LOGEMERG("%s(): ERROR workmarker %"PRId64" has an invalid"
					 " workinfoid range start=%"PRId64" end=%"PRId64
					 " due to pool lastblock=%"PRId32
					 " workinfoid=%"PRId64,
					 __func__, workmarkers->markerid,
					 workmarkers->workinfoidstart,
					 workmarkers->workinfoidend,
					 pool.height, pool.workinfoid);
			}

			lookmarkersummary.markerid = workmarkers->markerid;
			lookmarkersummary.userid = MAXID;
			lookmarkersummary.workername = EMPTY;
			ms_look.data = (void *)(&lookmarkersummary);
			ms_item = find_before_in_ktree(markersummary_root,
							&ms_look, ctx_ms);
			while (ms_item) {
				DATA_MARKERSUMMARY(markersummary, ms_item);
				if (markersummary->markerid != workmarkers->markerid)
					break;

				/* Check for user/workername change for new workerstatus
				 * The tree has user/workername grouped together in order
				 *  so this will only be once per user/workername */
				if (!ws_item ||
				    markersummary->userid != workerstatus->userid ||
				    strcmp(markersummary->workername, workerstatus->workername)) {
					/* This is to trigger a console error if it is missing
					 *  since it should always exist
					 * However, it is simplest to simply create it
					 *  and keep going */
					ws_item = find_workerstatus(false, markersummary->userid,
								    markersummary->workername,
								    __FILE__, __func__, __LINE__);
					if (!ws_item) {
						ws_item = find_create_workerstatus(false, markersummary->userid,
										   markersummary->workername,
										   __FILE__, __func__, __LINE__);
					}
					DATA_WORKERSTATUS(workerstatus, ws_item);
				}

				pool.diffacc += markersummary->diffacc;
				pool.diffinv += markersummary->diffsta + markersummary->diffdup +
						markersummary->diffhi + markersummary->diffrej;
				// Block stats only
				workerstatus->block_diffacc += markersummary->diffacc;
				workerstatus->block_diffinv += markersummary->diffsta +
								markersummary->diffdup +
								markersummary->diffhi +
								markersummary->diffrej;
				workerstatus->block_diffsta += markersummary->diffsta;
				workerstatus->block_diffdup += markersummary->diffdup;
				workerstatus->block_diffhi += markersummary->diffhi;
				workerstatus->block_diffrej += markersummary->diffrej;
				workerstatus->block_shareacc += markersummary->shareacc;
				workerstatus->block_shareinv += markersummary->sharesta +
								markersummary->sharedup +
								markersummary->sharehi +
								markersummary->sharerej;
				workerstatus->block_sharesta += markersummary->sharesta;
				workerstatus->block_sharedup += markersummary->sharedup;
				workerstatus->block_sharehi += markersummary->sharehi;
				workerstatus->block_sharerej += markersummary->sharerej;

				ms_item = prev_in_ktree(ctx_ms);
			}
		}
		wm_item = prev_in_ktree(ctx);
		DATA_WORKMARKERS_NULL(workmarkers, wm_item);
	}

	LOGWARNING("%s(): Update block counters complete", __func__);
}

/* Must be under K_WLOCK(blocks_free) when called
 * Call this before using the block stats and again check (under lock)
 *  the blocks_stats_time didn't change after you finish processing
 * If it has changed, redo the processing from scratch
 * If return is false, then stats aren't available
 * TODO: consider storing the partial calculations in the BLOCKS structure
 *	and only recalc from the last block modified (remembered)
 *	Will be useful with a large block history */
bool check_update_blocks_stats(tv_t *stats)
{
	static int64_t last_missing_workinfoid = 0;
	static tv_t last_message = { 0L, 0L };
	K_TREE_CTX ctx[1];
	K_ITEM *b_item, *w_item;
	WORKINFO *workinfo;
	BLOCKS *blocks;
	double ok, diffacc, netsumm, diffmean, pending, txmean, cr;
	tv_t now;

	/* Wait for startup_complete rather than db_load_complete
	 * This avoids doing a 'long' lock stats update while reloading */
	if (!startup_complete)
		return false;

	if (blocks_stats_rebuild) {
		/* Have to first work out the diffcalc for each block
		 * Orphans count towards the next valid block after the orphan
		 *  so this has to be done in the reverse order of the range
		 *  calculations */
		pending = 0.0;
		b_item = first_in_ktree(blocks_root, ctx);
		while (b_item) {
			DATA_BLOCKS(blocks, b_item);
			if (CURRENT(&(blocks->expirydate))) {
				pending += blocks->diffacc;
				if (blocks->confirmed[0] == BLOCKS_ORPHAN ||
				    blocks->confirmed[0] == BLOCKS_REJECT)
					blocks->diffcalc = 0.0;
				else {
					blocks->diffcalc = pending;
					pending = 0.0;
				}
			}
			b_item = next_in_ktree(ctx);
		}
		ok = diffacc = netsumm = diffmean = 0.0, txmean = 0.0;
		b_item = last_in_ktree(blocks_root, ctx);
		while (b_item) {
			DATA_BLOCKS(blocks, b_item);
			if (CURRENT(&(blocks->expirydate))) {
				if (blocks->netdiff == 0) {
					// Deadlock alert
					K_RLOCK(workinfo_free);
					w_item = find_workinfo(blocks->workinfoid, NULL);
					K_RUNLOCK(workinfo_free);
					if (!w_item) {
						setnow(&now);
						if (blocks->workinfoid != last_missing_workinfoid ||
						    tvdiff(&now, &last_message) >= 15.0) {
							LOGEMERG("%s(): missing block workinfoid %"
								 PRId32"/%"PRId64"/%s",
								 __func__, blocks->height,
								 blocks->workinfoid,
								 blocks->confirmed);
						}
						last_missing_workinfoid = blocks->workinfoid;
						copy_tv(&last_message, &now);
						return false;
					}
					DATA_WORKINFO(workinfo, w_item);
					blocks->netdiff = workinfo->diff_target;
				}
				/* Stats for each blocks are independent of
				 * if they are orphans or not */
				if (blocks->netdiff == 0.0)
					blocks->blockdiffratio = 0.0;
				else
					blocks->blockdiffratio = blocks->diffacc / blocks->netdiff;
				blocks->blockcdf = 1.0 - exp(-1.0 * blocks->blockdiffratio);
				if (blocks->blockdiffratio == 0.0)
					blocks->blockluck = 0.0;
				else
					blocks->blockluck = 1.0 / blocks->blockdiffratio;

				/* Orphans/Rejects are treated as +diffacc but no block
				 *  i.e. they simply add shares to the later block
				 *  and have running stats set to zero */
				if (blocks->confirmed[0] == BLOCKS_ORPHAN ||
				    blocks->confirmed[0] == BLOCKS_REJECT) {
					blocks->diffratio = 0.0;
					blocks->diffmean = 0.0;
					blocks->cdferl = 0.0;
					blocks->luck = 0.0;
					blocks->txmean = 0.0;
				} else {
					ok++;
					diffacc += blocks->diffcalc;
					netsumm += blocks->netdiff;

					if (netsumm == 0.0)
						blocks->diffratio = 0.0;
					else
						blocks->diffratio = diffacc / netsumm;

					diffmean = ((diffmean * (ok - 1)) +
						    (blocks->diffcalc / blocks->netdiff)) / ok;
					blocks->diffmean = diffmean;

					if (diffmean == 0.0) {
						blocks->cdferl = 0.0;
						blocks->luck = 0.0;
					} else {
						blocks->cdferl = gsl_cdf_gamma_P(diffmean, ok, 1.0 / ok);
						blocks->luck = 1.0 / diffmean;
					}

					cr = coinbase_reward(blocks->height);
					txmean = ((txmean * (ok - 1)) +
						    ((double)(blocks->reward) / cr)) / ok;
					blocks->txmean = txmean;
				}
			}
			b_item = prev_in_ktree(ctx);
		}
		setnow(&blocks_stats_time);
		blocks_stats_rebuild = false;
	}
	copy_tv(stats, &blocks_stats_time);
	return true;
}

// Must be under K_WLOCK(blocks_free) when called except during DB load
bool _set_blockcreatedate(int32_t oldest_height, WHERE_FFL_ARGS)
{
	K_TREE_CTX ctx[1];
	BLOCKS *blocks;
	K_ITEM *b_item;
	int32_t height;
	char blockhash[TXT_BIG+1];
	char cd_buf[DATE_BUFSIZ];
	tv_t createdate;
	bool ok = true;

	// No blocks?
	if (blocks_store->count == 0)
		return true;

	height = 0;
	blockhash[0] = '\0';
	DATE_ZERO(&createdate);
	b_item = last_in_ktree(blocks_root, ctx);
	DATA_BLOCKS_NULL(blocks, b_item);
	while (b_item && blocks->height >= oldest_height) {
		// NEW will be first going back
		if (blocks->confirmed[0] == BLOCKS_NEW) {
			height = blocks->height;
			STRNCPY(blockhash, blocks->blockhash);
			copy_tv(&createdate, &(blocks->createdate));
		}
		if (blocks->height != height ||
		    strcmp(blocks->blockhash, blockhash) != 0) {
			// Missing NEW
			tv_to_buf(&(blocks->expirydate), cd_buf, sizeof(cd_buf));
			LOGEMERG("%s() block %"PRId32"/%s/%s/%s has no '"
				 BLOCKS_NEW_STR "' prev was %"PRId32"/%s."
				 WHERE_FFL,
				 __func__,
				 blocks->height, blocks->blockhash,
				 blocks->confirmed, cd_buf,
				 height, blockhash, WHERE_FFL_PASS);
			ok = false;

			height = blocks->height;
			STRNCPY(blockhash, blocks->blockhash);
			// set a useable (incorrect) value
			copy_tv(&createdate, &(blocks->createdate));
		}
		// Always update it
		copy_tv(&(blocks->blockcreatedate), &createdate);

		b_item = prev_in_ktree(ctx);
		DATA_BLOCKS_NULL(blocks, b_item);
	}
	return ok;
}

// Must be under K_WLOCK(blocks_free) when called except during DB load
bool _set_prevcreatedate(int32_t oldest_height, WHERE_FFL_ARGS)
{
	K_ITEM look, *b_item = NULL, *wi_item;
	BLOCKS lookblocks, *blocks = NULL;
	K_TREE_CTX b_ctx[1], wi_ctx[1];
	WORKINFO *workinfo;
	char curr_blockhash[TXT_BIG+1];
	char cd_buf[DATE_BUFSIZ];
	int32_t curr_height;
	tv_t prev_createdate;
	tv_t curr_createdate;
	bool ok = true, currok = false;

	// No blocks?
	if (blocks_store->count == 0)
		return true;

	// Find first 'ok' block before oldest_height
	lookblocks.height = oldest_height;
	lookblocks.blockhash[0] = '\0';
	DATE_ZERO(&(lookblocks.expirydate));

	INIT_BLOCKS(&look);
	look.data = (void *)(&lookblocks);
	b_item = find_before_in_ktree(blocks_root, &look, b_ctx);
	while (b_item) {
		DATA_BLOCKS(blocks, b_item);
		if (CURRENT(&(blocks->expirydate)) &&
		    blocks->confirmed[0] != BLOCKS_ORPHAN &&
		    blocks->confirmed[0] != BLOCKS_REJECT)
			break;
		b_item = prev_in_ktree(b_ctx);
	}

	// Setup prev_createdate
	if (b_item) {
		/* prev_createdate is the ok b_item (before oldest_height)
		 * _set_blockcreatedate() should always be called
		 *  before calling _set_prevcreatedate() */
		copy_tv(&prev_createdate, &(blocks->blockcreatedate));

		/* Move b_item forward to the next block
		 *  since we don't have the prev value for b_item and
		 *  also don't need to update the b_item block */
		curr_height = blocks->height;
		STRNCPY(curr_blockhash, blocks->blockhash);
		while (b_item && blocks->height == curr_height &&
		       strcmp(blocks->blockhash, curr_blockhash) == 0) {
			b_item = next_in_ktree(b_ctx);
			DATA_BLOCKS_NULL(blocks, b_item);
		}
	} else {
		/* There's none before oldest_height, so instead use:
		 *  'Pool Start' = first workinfo createdate */
		K_RLOCK(workinfo_free);
		wi_item = first_in_ktree(workinfo_root, wi_ctx);
		K_RUNLOCK(workinfo_free);
		if (wi_item) {
			DATA_WORKINFO(workinfo, wi_item);
			copy_tv(&prev_createdate, &(workinfo->createdate));
		} else {
			/* Shouldn't be possible since this function is first
			 *  called after workinfo is loaded and the workinfo
			 *  for each block must exist - thus data corruption */
			DATE_ZERO(&prev_createdate);
			LOGEMERG("%s() DB/tree corruption - blocks exist but "
				 "no workinfo exist!"
				 WHERE_FFL,
				 __func__, WHERE_FFL_PASS);
			ok = false;
		}
		b_item = first_in_ktree(blocks_root, b_ctx);
	}

	// curr_* is unset and will be set first time in the while loop
	curr_height = 0;
	curr_blockhash[0] = '\0';
	DATE_ZERO(&curr_createdate);
	currok = false;
	while (b_item) {
		DATA_BLOCKS(blocks, b_item);
		// While the same block, keep setting it
		if (blocks->height == curr_height &&
		    strcmp(blocks->blockhash, curr_blockhash) == 0) {
			copy_tv(&(blocks->prevcreatedate), &prev_createdate);
		} else {
			// Next block - if currok then 'prev' becomes 'curr'
			if (currok)
				copy_tv(&prev_createdate, &curr_createdate);

			// New curr - CURRENT will be first
			if (!CURRENT(&(blocks->expirydate))) {
				tv_to_buf(&(blocks->expirydate), cd_buf,
					  sizeof(cd_buf));
				LOGEMERG("%s() block %"PRId32"/%s/%s/%s first "
					 "record is not CURRENT" WHERE_FFL,
					 __func__,
					 blocks->height, blocks->blockhash,
					 blocks->confirmed, cd_buf,
					 WHERE_FFL_PASS);
				ok = false;
			}

			curr_height = blocks->height;
			STRNCPY(curr_blockhash, blocks->blockhash);
			copy_tv(&curr_createdate, &(blocks->blockcreatedate));

			if (CURRENT(&(blocks->expirydate)) &&
			    blocks->confirmed[0] != BLOCKS_ORPHAN &&
			    blocks->confirmed[0] != BLOCKS_REJECT)
				currok = true;
			else
				currok = false;

			// Set it
			copy_tv(&(blocks->prevcreatedate), &prev_createdate);
		}
		b_item = next_in_ktree(b_ctx);
	}
	return ok;
}

/* order by payoutid asc,userid asc,expirydate asc
 * i.e. only one payout amount per block per user */
cmp_t cmp_miningpayouts(K_ITEM *a, K_ITEM *b)
{
	MININGPAYOUTS *ma, *mb;
	DATA_MININGPAYOUTS(ma, a);
	DATA_MININGPAYOUTS(mb, b);
	cmp_t c = CMP_BIGINT(ma->payoutid, mb->payoutid);
	if (c == 0) {
		c = CMP_BIGINT(ma->userid, mb->userid);
		if (c == 0)
			c = CMP_TV(ma->expirydate, mb->expirydate);
	}
	return c;
}

K_ITEM *find_miningpayouts(int64_t payoutid, int64_t userid)
{
	MININGPAYOUTS miningpayouts;
	K_TREE_CTX ctx[1];
	K_ITEM look;

	miningpayouts.payoutid = payoutid;
	miningpayouts.userid = userid;
	miningpayouts.expirydate.tv_sec = default_expiry.tv_sec;
	miningpayouts.expirydate.tv_usec = default_expiry.tv_usec;

	INIT_MININGPAYOUTS(&look);
	look.data = (void *)(&miningpayouts);
	return find_in_ktree(miningpayouts_root, &look, ctx);
}

K_ITEM *first_miningpayouts(int64_t payoutid, K_TREE_CTX *ctx)
{
	MININGPAYOUTS miningpayouts;
	K_TREE_CTX ctx0[1];
	K_ITEM look;

	if (ctx == NULL)
		ctx = ctx0;

	miningpayouts.payoutid = payoutid;
	miningpayouts.userid = 0;
	DATE_ZERO(&(miningpayouts.expirydate));

	INIT_MININGPAYOUTS(&look);
	look.data = (void *)(&miningpayouts);
	return find_after_in_ktree(miningpayouts_root, &look, ctx);
}

/* Processing payouts uses it's own tree of miningpayouts keyed only on userid
 *  that is stored in the miningpayouts tree/db when the calculations are done
 * cmp_mu() and upd_add_mu() are used for that */

// order by userid asc
cmp_t cmp_mu(K_ITEM *a, K_ITEM *b)
{
	MININGPAYOUTS *ma, *mb;
	DATA_MININGPAYOUTS(ma, a);
	DATA_MININGPAYOUTS(mb, b);
	return CMP_BIGINT(ma->userid, mb->userid);
}

// update the userid record or add a new one if the userid isn't already present
K_TREE *upd_add_mu(K_TREE *mu_root, K_STORE *mu_store, int64_t userid,
		   double diffacc)
{
	MININGPAYOUTS lookminingpayouts, *miningpayouts;
	K_ITEM look, *mu_item;
	K_TREE_CTX ctx[1];

	lookminingpayouts.userid = userid;
	INIT_MININGPAYOUTS(&look);
	look.data = (void *)(&lookminingpayouts);
	// No locking required since it's not a shared tree or store
	mu_item = find_in_ktree(mu_root, &look, ctx);
	if (mu_item) {
		DATA_MININGPAYOUTS(miningpayouts, mu_item);
		miningpayouts->diffacc += diffacc;
	} else {
		K_WLOCK(mu_store);
		mu_item = k_unlink_head(miningpayouts_free);
		DATA_MININGPAYOUTS(miningpayouts, mu_item);
		miningpayouts->userid = userid;
		miningpayouts->diffacc = diffacc;
		add_to_ktree(mu_root, mu_item);
		k_add_head(mu_store, mu_item);
		K_WUNLOCK(mu_store);
	}

	return mu_root;
}

// order by height asc,blockhash asc,expirydate asc
cmp_t cmp_payouts(K_ITEM *a, K_ITEM *b)
{
	PAYOUTS *pa, *pb;
	DATA_PAYOUTS(pa, a);
	DATA_PAYOUTS(pb, b);
	cmp_t c = CMP_INT(pa->height, pb->height);
	if (c == 0) {
		c = CMP_STR(pa->blockhash, pb->blockhash);
		if (c == 0)
			c = CMP_TV(pa->expirydate, pb->expirydate);
	}
	return c;
}

// order by payoutid asc,expirydate asc
cmp_t cmp_payouts_id(K_ITEM *a, K_ITEM *b)
{
	PAYOUTS *pa, *pb;
	DATA_PAYOUTS(pa, a);
	DATA_PAYOUTS(pb, b);
	cmp_t c = CMP_BIGINT(pa->payoutid, pb->payoutid);
	if (c == 0)
		c = CMP_TV(pa->expirydate, pb->expirydate);
	return c;
}

/* order by workinfoidend asc,expirydate asc
 * This must use workinfoidend, not workinfoidstart, since a change
 *  in the payout PPLNS N could have 2 payouts with the same start,
 *  but currently there is only one payout per block
 *   i.e. workinfoidend can only have one payout */
cmp_t cmp_payouts_wid(K_ITEM *a, K_ITEM *b)
{
	PAYOUTS *pa, *pb;
	DATA_PAYOUTS(pa, a);
	DATA_PAYOUTS(pb, b);
	cmp_t c = CMP_BIGINT(pa->workinfoidend, pb->workinfoidend);
	if (c == 0)
		c = CMP_TV(pa->expirydate, pb->expirydate);
	return c;
}

K_ITEM *find_payouts(int32_t height, char *blockhash)
{
	PAYOUTS payouts;
	K_TREE_CTX ctx[1];
	K_ITEM look;

	payouts.height = height;
	STRNCPY(payouts.blockhash, blockhash);
	payouts.expirydate.tv_sec = default_expiry.tv_sec;
	payouts.expirydate.tv_usec = default_expiry.tv_usec;

	INIT_PAYOUTS(&look);
	look.data = (void *)(&payouts);
	return find_in_ktree(payouts_root, &look, ctx);
}

// The first (any state) payouts record with the given height
K_ITEM *first_payouts(int32_t height, K_TREE_CTX *ctx)
{
	PAYOUTS payouts;
	K_TREE_CTX ctx0[1];
	K_ITEM look;

	if (ctx == NULL)
		ctx = ctx0;

	payouts.height = height;
	payouts.blockhash[0] = '\0';
	DATE_ZERO(&(payouts.expirydate));

	INIT_PAYOUTS(&look);
	look.data = (void *)(&payouts);
	return find_after_in_ktree(payouts_root, &look, ctx);
}

// Last block payout calculated
K_ITEM *find_last_payouts()
{
	K_TREE_CTX ctx[1];
	PAYOUTS *payouts;
	K_ITEM *p_item;

	p_item = last_in_ktree(payouts_root, ctx);
	while (p_item) {
		DATA_PAYOUTS(payouts, p_item);
		if (CURRENT(&(payouts->expirydate)))
			return p_item;
		p_item = prev_in_ktree(ctx);
	}
	return NULL;
}

K_ITEM *find_payoutid(int64_t payoutid)
{
	PAYOUTS payouts;
	K_TREE_CTX ctx[1];
	K_ITEM look;

	payouts.payoutid = payoutid;
	payouts.expirydate.tv_sec = default_expiry.tv_sec;
	payouts.expirydate.tv_usec = default_expiry.tv_usec;

	INIT_PAYOUTS(&look);
	look.data = (void *)(&payouts);
	return find_in_ktree(payouts_id_root, &look, ctx);
}

// First payouts workinfoidend equal or before workinfoidend
K_ITEM *find_payouts_wid(int64_t workinfoidend, K_TREE_CTX *ctx)
{
	PAYOUTS payouts;
	K_TREE_CTX ctx0[1];
	K_ITEM look;

	if (ctx == NULL)
		ctx = ctx0;

	payouts.workinfoidend = workinfoidend+1;
	DATE_ZERO(&(payouts.expirydate));

	INIT_PAYOUTS(&look);
	look.data = (void *)(&payouts);
	return find_before_in_ktree(payouts_wid_root, &look, ctx);
}

/* Values from payout stats, returns -1 if statname isn't found
 * If code needs a value then it probably really should be a new payouts field
 *  rather than stored in the stats passed to the pplns2 web page
 *  but anyway ... */
double payout_stats(PAYOUTS *payouts, char *statname)
{
	char buf[1024]; // If a number is bigger than this ... bad luck
	double ret = -1.0;
	size_t numlen, len = strlen(statname);
	char *pos, *tab;

	pos = payouts->stats;
	while (pos && *pos) {
		if (strncmp(pos, statname, len) == 0 && pos[len] == '=') {
			pos += len+1;
			// They should only contain +ve numbers
			if (*pos && isdigit(*pos)) {
				tab = strchr(pos, FLDSEP);
				if (!tab)
					numlen = strlen(pos);
				else
					numlen = tab - pos;
				if (numlen >= sizeof(buf))
					numlen = sizeof(buf) - 1;
				STRNCPYSIZ(buf, pos, numlen+1);
				// ctv will only return the seconds
				ret = atof(buf);
			}
			break;
		}
		pos = strchr(pos, FLDSEP);
		if (pos)
			pos++;
	}
	return ret;
}

/* Find the block_workinfoid of the block requested
    then add all it's diffacc shares
    then keep stepping back shares until diffacc_total matches or exceeds
     the number required (diff_want) - this is begin_workinfoid
     (also summarising diffacc per user)
    then keep stepping back until we complete the current begin_workinfoid
     (also summarising diffacc per user)
   While we are still below diff_want
    find each next workmarker and add on the full set of worksummary
     diffacc shares (also summarising diffacc per user)
   This will give us the total number of diff1 shares (diffacc_total)
    to use for the payment calculations
   The value of diff_want defaults to the block's network difficulty
    (block_ndiff) but can be changed with diff_times and diff_add to:
	block_ndiff * diff_times + diff_add
    they are stored in the optioncontrol table and thus can use the
    block number to change their values over time
    N.B. diff_times and diff_add can be zero, positive or negative
   The pplns_elapsed time of the shares is from the createdate of the
    begin_workinfoid that has shares accounted to the total,
    up to the createdate of the last share
   The user average hashrate would be:
	diffacc_user * 2^32 / pplns_elapsed
   PPLNS fraction of the payout would be:
	diffacc_user / diffacc_total

   N.B. 'begin' means the oldest back in time and 'end' means the newest
	'end' should usually be the info of the found block with the pplns
	data going back in time to 'begin'

 The data processing procedure is to:
  create a separate tree/store of miningpayouts during the diff_used
   calculation,
  store the payout in the db with a 'processing' status,
  create a seperate store of payments per miningpayout that are stored
   in the db,
  store each mininging payout in the db after storing the payments for the
   given miningpayout,
  commit that all and if it succeeds then update the ram tables for all
   of the above
  then update the payout status, in the db and ram, to 'generated'

 TODO: recheck the payout if it already exists?

 N.B. process_pplns() is only automatically triggered once after the block
	summarisation is verified, so it can always report all errors
*/
bool process_pplns(int32_t height, char *blockhash, tv_t *addr_cd)
{
	K_TREE_CTX b_ctx[1], ss_ctx[1], wm_ctx[1], ms_ctx[1], pay_ctx[1], mu_ctx[1];
	bool allow_aged = true, conned = false, begun = false;
	bool countbacklimit, ok = false;
	PGconn *conn = NULL;
	MININGPAYOUTS *miningpayouts;
	OPTIONCONTROL *optioncontrol;
	PAYMENTS *payments;
	WORKINFO *workinfo;
	PAYOUTS *payouts, *payouts2;
	BLOCKS *blocks;
	USERS *users;
	K_ITEM *p_item, *old_p_item, *b_item, *w_item, *wb_item;
	K_ITEM *u_item, *mu_item, *oc_item, *pay_item, *p2_item, *old_p2_item;
	SHARESUMMARY looksharesummary, *sharesummary;
	WORKMARKERS lookworkmarkers, *workmarkers;
	MARKERSUMMARY lookmarkersummary, *markersummary;
	K_ITEM ss_look, *ss_item, wm_look, *wm_item, ms_look, *ms_item;
	int64_t amount, used, d64, g64, begin_workinfoid, end_workinfoid;
	int64_t total_share_count, acc_share_count;
	int64_t ss_count, wm_count, ms_count;
	K_STORE *mu_store = NULL, *pay_store = NULL, *addr_store = NULL;
	K_TREE *mu_root = NULL;
	int usercount;
	double ndiff, total_diff, diff_want, elapsed;
	char rewardbuf[32];
	double diff_times, diff_add;
	char cd_buf[CDATE_BUFSIZ];
	tv_t end_tv = { 0L, 0L };
	tv_t begin_tv, now;
	char buf[1024];

	/*
	 * Only allow one process_pplns() at a time
	 * This ensures that a payout can't be processed twice at the same time
	 *  and simply avoids the problems that would cause without much more
	 *  strict locking than is used already
	 */
	ck_wlock(&process_pplns_lock);

	setnow(&now);

	K_RLOCK(payouts_free);
	p_item = find_payouts(height, blockhash);
	K_RUNLOCK(payouts_free);
	// TODO: regenerate miningpayouts and payments if required or missing?
	if (p_item) {
		DATA_PAYOUTS(payouts, p_item);
		tv_to_buf(&(payouts->createdate), cd_buf, sizeof(cd_buf));
		LOGERR("%s(): payout for block %"PRId32"/%s already exists "
			"%"PRId64"/%"PRId64"/%"PRId64"/%s",
			__func__, height, blockhash, payouts->payoutid,
			payouts->workinfoidstart, payouts->workinfoidend,
			cd_buf);
		goto oku;
	}

	// Check the block status
	K_RLOCK(blocks_free);
	b_item = find_blocks(height, blockhash, b_ctx);
	K_RUNLOCK(blocks_free);
	if (!b_item) {
		LOGERR("%s(): no block %"PRId32"/%s for payout",
			__func__, height, blockhash);
		goto oku;
	}
	DATA_BLOCKS(blocks, b_item);
	copy_tv(&end_tv, &(blocks->blockcreatedate));
	if (!addr_cd)
		addr_cd = &(blocks->blockcreatedate);

	LOGDEBUG("%s(): block %"PRId32"/%"PRId64"/%s/%s/%"PRId64,
		 __func__, blocks->height, blocks->workinfoid,
		 blocks->workername, blocks->confirmed, blocks->reward);

	switch (blocks->confirmed[0]) {
		case BLOCKS_NEW:
		case BLOCKS_ORPHAN:
		case BLOCKS_REJECT:
			LOGERR("%s(): can't process block %"PRId32"/%"
				PRId64"/%s/%"PRId64" status: %s/%s",
				__func__, blocks->height, blocks->workinfoid,
				blocks->workername, blocks->reward,
				blocks->confirmed,
				blocks_confirmed(blocks->confirmed));
			goto oku;
	}
	w_item = find_workinfo(blocks->workinfoid, NULL);
	if (!w_item) {
		LOGEMERG("%s(): missing block workinfoid %"PRId32"/%"PRId64
			 "/%s/%s/%"PRId64,
			 __func__, blocks->height, blocks->workinfoid,
			 blocks->workername, blocks->confirmed,
			 blocks->reward);
		goto oku;
	}
	DATA_WORKINFO(workinfo, w_item);

	// Get the PPLNS N values
	K_RLOCK(optioncontrol_free);
	oc_item = find_optioncontrol(PPLNSDIFFTIMES, &(blocks->blockcreatedate),
				     height);
	K_RUNLOCK(optioncontrol_free);
	if (!oc_item) {
		tv_to_buf(&(blocks->blockcreatedate), cd_buf, sizeof(cd_buf));
		LOGEMERG("%s(): missing optioncontrol %s (%s/%"PRId32")",
			 __func__, PPLNSDIFFTIMES, cd_buf, blocks->height);
		goto oku;
	}
	DATA_OPTIONCONTROL(optioncontrol, oc_item);
	diff_times = atof(optioncontrol->optionvalue);

	K_RLOCK(optioncontrol_free);
	oc_item = find_optioncontrol(PPLNSDIFFADD, &(blocks->blockcreatedate),
				     height);
	K_RUNLOCK(optioncontrol_free);
	if (!oc_item) {
		tv_to_buf(&(blocks->blockcreatedate), cd_buf, sizeof(cd_buf));
		LOGEMERG("%s(): missing optioncontrol %s (%s/%"PRId32")",
			 __func__, PPLNSDIFFADD, cd_buf, blocks->height);
		goto oku;
	}
	DATA_OPTIONCONTROL(optioncontrol, oc_item);
	diff_add = atof(optioncontrol->optionvalue);

	ndiff = workinfo->diff_target;
	diff_want = ndiff * diff_times + diff_add;
	if (diff_want < 1.0) {
		LOGERR("%s(): invalid diff_want %.1f, block %"PRId32"/%"
			PRId64"/%s/%s/%"PRId64,
			__func__, diff_want, blocks->height, blocks->workinfoid,
			blocks->workername, blocks->confirmed, blocks->reward);
		goto oku;
	}

	// Check for the hard coded limit
	if (blocks->height > FIVExSTT)
		countbacklimit = true;
	else
		countbacklimit = false;
	LOGDEBUG("%s(): ndiff %.1f limit %c",
		 __func__, ndiff, countbacklimit ? 'Y' : 'N');

	// add up all the shares ...
	begin_workinfoid = end_workinfoid = 0;
	total_share_count = acc_share_count = 0;
	total_diff = 0;
	ss_count = wm_count = ms_count = 0;

	mu_store = k_new_store(miningpayouts_free);
	mu_root = new_ktree(cmp_mu);

	looksharesummary.workinfoid = blocks->workinfoid;
	looksharesummary.userid = MAXID;
	looksharesummary.workername = EMPTY;
	INIT_SHARESUMMARY(&ss_look);
	ss_look.data = (void *)(&looksharesummary);
	K_RLOCK(sharesummary_free);
	K_RLOCK(workmarkers_free);
	K_RLOCK(markersummary_free);
	ss_item = find_before_in_ktree(sharesummary_workinfoid_root, &ss_look,
					ss_ctx);
	DATA_SHARESUMMARY_NULL(sharesummary, ss_item);
	if (ss_item)
		end_workinfoid = sharesummary->workinfoid;
	/* Add up all sharesummaries until >= diff_want
	 * also record the latest lastshareacc - that will be the end pplns time
	 *  which will be >= blocks->blockcreatedate */
	while (total_diff < diff_want && ss_item) {
		switch (sharesummary->complete[0]) {
			case SUMMARY_CONFIRM:
				break;
			case SUMMARY_COMPLETE:
				if (allow_aged)
					break;
			default:
				// Release ASAP
				K_RUNLOCK(markersummary_free);
				K_RUNLOCK(workmarkers_free);
				K_RUNLOCK(sharesummary_free);
				LOGERR("%s(): sharesummary not ready %"
					PRId64"/%s/%"PRId64"/%s. allow_aged=%s",
					__func__, sharesummary->userid,
					sharesummary->workername,
					sharesummary->workinfoid,
					sharesummary->complete,
					allow_aged ? "true" : "false");
				goto shazbot;
		}

		// Stop before FIVExWID if necessary
		if (countbacklimit && sharesummary->workinfoid <= FIVExWID)
			break;

		ss_count++;
		total_share_count += sharesummary->sharecount;
		acc_share_count += sharesummary->shareacc;
		total_diff += sharesummary->diffacc;
		begin_workinfoid = sharesummary->workinfoid;
		if (tv_newer(&end_tv, &(sharesummary->lastshareacc)))
			copy_tv(&end_tv, &(sharesummary->lastshareacc));
		mu_root = upd_add_mu(mu_root, mu_store,
				     sharesummary->userid,
				     sharesummary->diffacc);
		ss_item = prev_in_ktree(ss_ctx);
		DATA_SHARESUMMARY_NULL(sharesummary, ss_item);
	}

	// Include the rest of the sharesummaries matching begin_workinfoid
	while (ss_item && sharesummary->workinfoid == begin_workinfoid) {
		switch (sharesummary->complete[0]) {
			case SUMMARY_CONFIRM:
				break;
			case SUMMARY_COMPLETE:
				if (allow_aged)
					break;
			default:
				// Release ASAP
				K_RUNLOCK(markersummary_free);
				K_RUNLOCK(workmarkers_free);
				K_RUNLOCK(sharesummary_free);
				LOGERR("%s(): sharesummary2 not ready %"
					PRId64"/%s/%"PRId64"/%s. allow_aged=%s",
					__func__, sharesummary->userid,
					sharesummary->workername,
					sharesummary->workinfoid,
					sharesummary->complete,
					allow_aged ? "true" : "false");
				goto shazbot;
		}
		ss_count++;
		total_share_count += sharesummary->sharecount;
		acc_share_count += sharesummary->shareacc;
		total_diff += sharesummary->diffacc;
		if (tv_newer(&end_tv, &(sharesummary->lastshareacc)))
			copy_tv(&end_tv, &(sharesummary->lastshareacc));
		mu_root = upd_add_mu(mu_root, mu_store,
				     sharesummary->userid,
				     sharesummary->diffacc);
		ss_item = prev_in_ktree(ss_ctx);
		DATA_SHARESUMMARY_NULL(sharesummary, ss_item);
	}
	LOGDEBUG("%s(): ss %"PRId64" total %.1f want %.1f",
		 __func__, ss_count, total_diff, diff_want);

	/* If we haven't met or exceeded the required N,
	 * move on to the markersummaries ... this is now mandatory */
	if (total_diff < diff_want) {
		lookworkmarkers.expirydate.tv_sec = default_expiry.tv_sec;
		lookworkmarkers.expirydate.tv_usec = default_expiry.tv_usec;
		if (begin_workinfoid != 0)
			lookworkmarkers.workinfoidend = begin_workinfoid;
		else
			lookworkmarkers.workinfoidend = blocks->workinfoid + 1;
		INIT_WORKMARKERS(&wm_look);
		wm_look.data = (void *)(&lookworkmarkers);
		wm_item = find_before_in_ktree(workmarkers_workinfoid_root,
					       &wm_look, wm_ctx);
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
				ms_item = find_before_in_ktree(markersummary_root,
							       &ms_look, ms_ctx);
				DATA_MARKERSUMMARY_NULL(markersummary, ms_item);
				// add the whole markerid
				while (ms_item && markersummary->markerid == workmarkers->markerid) {
					if (end_workinfoid == 0)
						end_workinfoid = workmarkers->workinfoidend;
					ms_count++;
					total_share_count += markersummary->sharecount;
					acc_share_count += markersummary->shareacc;
					total_diff += markersummary->diffacc;
					begin_workinfoid = workmarkers->workinfoidstart;
					if (tv_newer(&end_tv, &(markersummary->lastshareacc)))
						copy_tv(&end_tv, &(markersummary->lastshareacc));
					mu_root = upd_add_mu(mu_root, mu_store,
							     markersummary->userid,
							     markersummary->diffacc);
					ms_item = prev_in_ktree(ms_ctx);
					DATA_MARKERSUMMARY_NULL(markersummary, ms_item);
				}
			}
			wm_item = prev_in_ktree(wm_ctx);
			DATA_WORKMARKERS_NULL(workmarkers, wm_item);
		}
		LOGDEBUG("%s(): wm %"PRId64" ms %"PRId64" total %.1f want %.1f",
			 __func__, wm_count, ms_count, total_diff, diff_want);
	}
	K_RUNLOCK(markersummary_free);
	K_RUNLOCK(workmarkers_free);
	K_RUNLOCK(sharesummary_free);

	usercount = mu_store->count;

	if (wm_count < 1) {
		/* Problem means either workmarkers are not being processed
		 *  or if they are, then when the shifts are later created,
		 *  they almost certainly won't match the begin_workinfo
		 *  calculated
		 *  i.e. the payout N is too small, it's less than the time
		 *   needed to create and process any workmarkers for this
		 *   block - so abort
		 * The fix is to create the marks and summaries needed via
		 *  cmd_marks() then manually trigger the payout generation
		 *  via cmd_payouts() */
		LOGEMERG("%s(): payout had < 1 (%"PRId64") workmarkers for "
			 "block %"PRId32"/%"PRId64"/%s/%s/%"PRId64
			 " beginwi=%"PRId64" ss=%"PRId64" diff=%.1f",
			 __func__, wm_count, blocks->height, blocks->workinfoid,
			 blocks->workername, blocks->confirmed, blocks->reward,
			 begin_workinfoid, ss_count, total_diff);
		goto shazbot;
	}

	LOGDEBUG("%s(): total %.1f want %.1f", __func__, total_diff, diff_want);
	if (total_diff == 0.0) {
		LOGERR("%s(): total share diff zero before block %"PRId32
			"/%"PRId64"/%s/%s/%"PRId64,
			__func__, blocks->height, blocks->workinfoid,
			blocks->workername, blocks->confirmed,
			blocks->reward);
		goto shazbot;
	}

	wb_item = find_workinfo(begin_workinfoid, NULL);
	if (!wb_item) {
		LOGEMERG("%s(): missing begin workinfo record %"PRId64
			 " payout of block %"PRId32"/%"PRId64"/%s/%s/%"PRId64,
			 __func__, begin_workinfoid, blocks->height,
			 blocks->workinfoid, blocks->workername,
			 blocks->confirmed, blocks->reward);
		goto shazbot;
	}
	DATA_WORKINFO(workinfo, wb_item);

	copy_tv(&begin_tv, &(workinfo->createdate));
	/* Elapsed is from the start of the first workinfoid used,
	 *  to the time of the last share accepted -
	 *  which can be after the block, but must have the same workinfoid as
	 *  the block, if it is after the block
	 * Any shares accepted in all workinfoids after the block's workinfoid
	 *  will not be creditied to this block no matter what the height
	 *  of their workinfoid - but will be candidates for subsequent blocks */
	elapsed = tvdiff(&end_tv, &begin_tv);

	// Create the payout
	K_WLOCK(payouts_free);
	p_item = k_unlink_head(payouts_free);
	K_WUNLOCK(payouts_free);
	DATA_PAYOUTS(payouts, p_item);

	bzero(payouts, sizeof(*payouts));
	payouts->height = height;
	STRNCPY(payouts->blockhash, blockhash);
	copy_tv(&(payouts->blockcreatedate), &(blocks->blockcreatedate));
	d64 = blocks->reward * 9 / 1000;
	g64 = blocks->reward - d64;
	payouts->minerreward = g64;

	/* We can hard code a miner reward for a block in optioncontrol
	 *  if it ever needs adjusting - so just expire the payout and
	 *  re-process the reward ... before it's paid */
	bool oname;
	oname = reward_override_name(blocks->height, rewardbuf,
				     sizeof(rewardbuf));
	if (oname) {
		OPTIONCONTROL *oc;
		K_ITEM *oc_item;
		// optioncontrol must be default limits or below these limits
		oc_item = find_optioncontrol(rewardbuf, &now, blocks->height+1);
		if (oc_item) {
			int64_t override, delta;
			char *moar = "more";
			double per;
			DATA_OPTIONCONTROL(oc, oc_item);
			override = (int64_t)atol(oc->optionvalue);
			delta = override - g64;
			if (delta < 0) {
				moar = "less";
				delta = -delta;
			}
			per = 100.0 * (double)delta / (double)g64;
			LOGWARNING("%s(): *** block %"PRId32" payout reward"
				   " overridden, was %"PRId64" now %"PRId64
				   " = %"PRId64" (%.4f%%) %s",
				   __func__, blocks->height,
				   g64, override, delta, per, moar);
			payouts->minerreward = override;
		}
	}

	payouts->workinfoidstart = begin_workinfoid;
	payouts->workinfoidend = end_workinfoid;
	payouts->elapsed = elapsed;
	STRNCPY(payouts->status, PAYOUTS_PROCESSING_STR);
	payouts->diffwanted = diff_want;
	payouts->diffused = total_diff;
	payouts->shareacc = acc_share_count;
	copy_tv(&(payouts->lastshareacc), &end_tv);

	ctv_to_buf(addr_cd, cd_buf, sizeof(cd_buf));
	snprintf(buf, sizeof(buf),
		 "diff_times=%f%cdiff_add=%f%ctotal_share_count=%"PRId64
		 "%css_count=%"PRId64"%cwm_count=%"PRId64"%cms_count=%"PRId64
		 "%caddr_cd=%s",
		 diff_times, FLDSEP, diff_add, FLDSEP, total_share_count,
		 FLDSEP, ss_count, FLDSEP, wm_count, FLDSEP, ms_count,
		 FLDSEP, cd_buf);
	DUP_POINTER(payouts_free, payouts->stats, &buf[0]);

	conned = CKPQConn(&conn);
	begun = CKPQBegin(conn);
	if (!begun)
		goto shazbot;

	// begun is true
	ok = payouts_add(conn, true, p_item, &old_p_item, (char *)by_default,
			 (char *)__func__, (char *)inet_default, &now, NULL,
			 begun);
	if (!ok)
		goto shazbot;

	// Update and store the miningpayouts and payments
	pay_store = k_new_store(payments_free);
	mu_item = first_in_ktree(mu_root, mu_ctx);
	while (mu_item) {
		DATA_MININGPAYOUTS(miningpayouts, mu_item);

		K_RLOCK(users_free);
		u_item = find_userid(miningpayouts->userid);
		K_RUNLOCK(users_free);
		if (!u_item) {
			LOGEMERG("%s(): unknown userid %"PRId64"/%.1f in "
				 "payout for block %"PRId32,
				 __func__, miningpayouts->userid,
				 miningpayouts->diffacc, blocks->height);
			goto shazbot;
		}
		DATA_USERS(users, u_item);

		K_ITEM *pa_item, *pa_item2;
		PAYMENTADDRESSES *pa, *pa2;
		int64_t paytotal = 0;
		int count = 0;

		used = 0;
		amount = floor((double)(payouts->minerreward) *
				miningpayouts->diffacc / payouts->diffused);

		/* Get the paymentaddresses active as at *addr_cd
		 *  which defaults to when the block was found */
		addr_store = k_new_store(paymentaddresses_free);
		K_WLOCK(paymentaddresses_free);
		pa_item = find_paymentaddresses_create(miningpayouts->userid,
						       pay_ctx);
		if (pa_item) {
			DATA_PAYMENTADDRESSES(pa, pa_item);
			/* The tv_newer and tv_newer_eq are critical since:
			 *  when a record is replaced, the expirydate is set
			 *  to 'now' and the new record will have the same
			 *  createdate of 'now', so to avoid possibly selecting
			 *  both records, we get the one that was created
			 *  before addr_cd and expires on or after addr_cd
			 */
			while (pa_item && pa->userid == miningpayouts->userid &&
			       tv_newer(&(pa->createdate), addr_cd)) {
				if (tv_newer_eq(addr_cd, &(pa->expirydate))) {
					paytotal += pa->payratio;

					/* Duplicate it to a new store -
					 * thus changes to paymentaddresses
					 * can't affect the code below
					 * and we don't need to keep
					 * paymentaddresses locked until we
					 * have completed the db
					 * additions/updates */
					pa_item2 = k_unlink_head(paymentaddresses_free);
					DATA_PAYMENTADDRESSES(pa2, pa_item2);
					pa2->userid = pa->userid;
					STRNCPY(pa2->payaddress, pa->payaddress);
					pa2->payratio = pa->payratio;
					k_add_tail(addr_store, pa_item2);
				}
				pa_item = next_in_ktree(pay_ctx);
				DATA_PAYMENTADDRESSES_NULL(pa, pa_item);
			}
		}
		K_WUNLOCK(paymentaddresses_free);

		pa_item = addr_store->head;
		if (pa_item) {
			// Normal user with at least 1 paymentaddress
			while (pa_item) {
				DATA_PAYMENTADDRESSES(pa, pa_item);
				K_WLOCK(payments_free);
				pay_item = k_unlink_head(payments_free);
				K_WUNLOCK(payments_free);
				DATA_PAYMENTS(payments, pay_item);
				bzero(payments, sizeof(*payments));
				payments->payoutid = payouts->payoutid;
				payments->userid = miningpayouts->userid;
				snprintf(payments->subname,
					 sizeof(payments->subname),
					 "%s.%d", users->username, ++count);
				STRNCPY(payments->payaddress, pa->payaddress);
				d64 = floor((double)amount *
					    (double)(pa->payratio) /
					    (double)paytotal);
				payments->amount = d64;
				payments->diffacc = miningpayouts->diffacc *
						    (double)(pa->payratio) /
						    (double)paytotal;
				used += d64;
				k_add_tail(pay_store, pay_item);
				ok = payments_add(conn, true, pay_item,
						  &(payments->old_item),
						  (char *)by_default,
						  (char *)__func__,
						  (char *)inet_default, &now,
						  NULL, begun);
				if (!ok)
					goto shazbot;

				pa_item = pa_item->next;
			}
		} else {
			/* Address user or normal user without a paymentaddress */
			if (users->userbits & USER_ADDRESS) {
				K_WLOCK(payments_free);
				pay_item = k_unlink_head(payments_free);
				K_WUNLOCK(payments_free);
				DATA_PAYMENTS(payments, pay_item);
				bzero(payments, sizeof(*payments));
				payments->payoutid = payouts->payoutid;
				payments->userid = miningpayouts->userid;
				snprintf(payments->subname,
					 sizeof(payments->subname),
					 "%s.0", users->username);
				STRNCPY(payments->payaddress, users->username);
				payments->amount = amount;
				payments->diffacc = miningpayouts->diffacc;
				used = amount;
				k_add_tail(pay_store, pay_item);
				ok = payments_add(conn, true, pay_item,
						  &(payments->old_item),
						  (char *)by_default,
						  (char *)__func__,
						  (char *)inet_default, &now,
						  NULL, begun);
				if (!ok)
					goto shazbot;
			} // else they go to their dust balance
		}

		/* N.B. there will, of course, be a miningpayouts record without
		 *  any payments record if the paymentaddress was missing */
		miningpayouts->payoutid = payouts->payoutid;
		if (used == 0)
			miningpayouts->amount = amount;
		else
			miningpayouts->amount = used;

		ok = miningpayouts_add(conn, true, mu_item,
					&(miningpayouts->old_item),
					(char *)by_default, (char *)__func__,
					(char *)inet_default, &now, NULL, begun);
		if (!ok)
			goto shazbot;

		if (addr_store->count) {
			K_WLOCK(paymentaddresses_free);
			k_list_transfer_to_head(addr_store, paymentaddresses_free);
			K_WUNLOCK(addr_store);
		}
		addr_store = k_free_store(addr_store);

		mu_item = next_in_ktree(mu_ctx);
	}

	// begun is true
	CKPQEnd(conn, begun);

	payouts_add_ram(true, p_item, old_p_item, &now);

	free_ktree(mu_root, NULL);
	mu_item = k_unlink_head(mu_store);
	while (mu_item) {
		DATA_MININGPAYOUTS(miningpayouts, mu_item);
		miningpayouts_add_ram(true, mu_item, miningpayouts->old_item, &now);
		mu_item = k_unlink_head(mu_store);
	}
	mu_store = k_free_store(mu_store);

	pay_item = k_unlink_head(pay_store);
	while (pay_item) {
		DATA_PAYMENTS(payments, pay_item);
		payments_add_ram(true, pay_item, payments->old_item, &now);
		pay_item = k_unlink_head(pay_store);
	}
	pay_store = k_free_store(pay_store);

	ctv_to_buf(addr_cd, cd_buf, sizeof(cd_buf));
	LOGWARNING("%s(): payout %"PRId64" setup for block %"PRId32"/%"PRId64
		   "/%s/%"PRId64" ss=%"PRId64" wm=%"PRId64" ms=%"PRId64
		   " users=%d times=%.1f add=%.1f addr_cd=%s",
		   __func__, payouts->payoutid, blocks->height,
		   blocks->workinfoid, blocks->confirmed, blocks->reward,
		   ss_count, wm_count, ms_count, usercount, diff_times,
		   diff_add, cd_buf);

	/* At this point the payout is complete, but it just hasn't been
	 *  flagged complete yet in the DB */

	K_WLOCK(payouts_free);
	p2_item = k_unlink_head(payouts_free);
	K_WUNLOCK(payouts_free);
	DATA_PAYOUTS(payouts2, p2_item);
	bzero(payouts2, sizeof(*payouts2));
	payouts2->payoutid = payouts->payoutid;
	payouts2->height = payouts->height;
	STRNCPY(payouts2->blockhash, payouts->blockhash);
	copy_tv(&(payouts2->blockcreatedate), &(payouts->blockcreatedate));
	payouts2->minerreward = payouts->minerreward;
	payouts2->workinfoidstart = payouts->workinfoidstart;
	payouts2->workinfoidend = payouts->workinfoidend;
	payouts2->elapsed = payouts->elapsed;
	STRNCPY(payouts2->status, PAYOUTS_GENERATED_STR);
	payouts2->diffwanted = payouts->diffwanted;
	payouts2->diffused = payouts->diffused;
	payouts2->shareacc = payouts->shareacc;
	copy_tv(&(payouts2->lastshareacc), &(payouts->lastshareacc));
	DUP_POINTER(payouts_free, payouts2->stats, payouts->stats);

	setnow(&now);
	/* N.B. the PROCESSING payouts could have expirydate = createdate
	 *  if the code above executes faster than the pgsql time resolution */
	ok = payouts_add(conn, true, p2_item, &old_p2_item, (char *)by_default,
			 (char *)__func__, (char *)inet_default, &now, NULL,
			 false);

	if (!ok) {
		/* All that's required is to mark the payout GENERATED
		 *  since it already exists in the DB and in RAM, thus a manual
		 *  cmd_payouts 'generated' is all that's needed to fix it */
		LOGEMERG("%s(): payout %"PRId64" for block %"PRId32"/%s "
			 "NOT set generated - it needs to be set manually",
			 __func__, payouts->payoutid, blocks->height,
			 blocks->blockhash);
	}

	// Flag each shift as rewarded
	reward_shifts(payouts2, true, 1);

	CKPQDisco(&conn, conned);

	goto oku;

shazbot:
	ok = false;

	if (begun)
		CKPQEnd(conn, false);
	CKPQDisco(&conn, conned);

	if (p_item) {
		K_WLOCK(payouts_free);
		free_payouts_data(p_item);
		k_add_head(payouts_free, p_item);
		K_WUNLOCK(payouts_free);
	}

oku:
	;
	ck_wunlock(&process_pplns_lock);
	if (mu_root)
		free_ktree(mu_root, NULL);
	if (mu_store) {
		if (mu_store->count) {
			K_WLOCK(mu_store);
			k_list_transfer_to_head(mu_store, miningpayouts_free);
			K_WUNLOCK(mu_store);
		}
		mu_store = k_free_store(mu_store);
	}
	if (pay_store) {
		if (pay_store->count) {
			K_WLOCK(pay_store);
			k_list_transfer_to_head(pay_store, payments_free);
			K_WUNLOCK(pay_store);
		}
		pay_store = k_free_store(pay_store);
	}
	if (addr_store) {
		if (addr_store->count) {
			K_WLOCK(addr_store);
			k_list_transfer_to_head(addr_store, paymentaddresses_free);
			K_WUNLOCK(addr_store);
		}
		addr_store = k_free_store(addr_store);
	}
	return ok;
}

// order by userid asc,createdate asc,authid asc,expirydate desc
cmp_t cmp_auths(K_ITEM *a, K_ITEM *b)
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

// order by poolinstance asc,createdate asc
cmp_t cmp_poolstats(K_ITEM *a, K_ITEM *b)
{
	POOLSTATS *pa, *pb;
	DATA_POOLSTATS(pa, a);
	DATA_POOLSTATS(pb, b);
	cmp_t c = CMP_STR(pa->poolinstance, pb->poolinstance);
	if (c == 0)
		c = CMP_TV(pa->createdate, pb->createdate);
	return c;
}

void dsp_userstats(K_ITEM *item, FILE *stream)
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

/* order by userid asc,workername asc */
cmp_t cmp_userstats(K_ITEM *a, K_ITEM *b)
{
	USERSTATS *ua, *ub;
	DATA_USERSTATS(ua, a);
	DATA_USERSTATS(ub, b);
	cmp_t c = CMP_BIGINT(ua->userid, ub->userid);
	if (c == 0)
		c = CMP_STR(ua->workername, ub->workername);
	return c;
}

K_ITEM *find_userstats(int64_t userid, char *workername)
{
	USERSTATS userstats;
	K_TREE_CTX ctx[1];
	K_ITEM look;

	userstats.userid = userid;
	STRNCPY(userstats.workername, workername);

	INIT_USERSTATS(&look);
	look.data = (void *)(&userstats);
	return find_in_ktree(userstats_root, &look, ctx);
}

void dsp_markersummary(K_ITEM *item, FILE *stream)
{
	MARKERSUMMARY *ms;

	if (!item)
		fprintf(stream, "%s() called with (null) item\n", __func__);
	else {
		DATA_MARKERSUMMARY(ms, item);
		fprintf(stream, " markerid=%"PRId64" userid=%"PRId64
				" worker='%s' " "diffacc=%f shares=%"PRId64
				" errs=%"PRId64" lastdiff=%f\n",
				ms->markerid, ms->userid, ms->workername,
				ms->diffacc, ms->sharecount, ms->errorcount,
				ms->lastdiffacc);
	}
}

// order by markerid asc,userid asc,workername asc (has no expirydate)
cmp_t cmp_markersummary(K_ITEM *a, K_ITEM *b)
{
	MARKERSUMMARY *ma, *mb;
	DATA_MARKERSUMMARY(ma, a);
	DATA_MARKERSUMMARY(mb, b);
	cmp_t c = CMP_BIGINT(ma->markerid, mb->markerid);
	if (c == 0) {
		c = CMP_BIGINT(ma->userid, mb->userid);
		if (c == 0)
			c = CMP_STR(ma->workername, mb->workername);
	}
	return c;
}

// order by userid asc,workername asc,lastshare asc (has no expirydate)
cmp_t cmp_markersummary_userid(K_ITEM *a, K_ITEM *b)
{
	MARKERSUMMARY *ma, *mb;
	DATA_MARKERSUMMARY(ma, a);
	DATA_MARKERSUMMARY(mb, b);
	cmp_t c = CMP_BIGINT(ma->userid, mb->userid);
	if (c == 0) {
		c = CMP_STR(ma->workername, mb->workername);
		if (c == 0)
			c = CMP_TV(ma->lastshare, mb->lastshare);
	}
	return c;
}

// Finds the last markersummary for the worker and optionally return the CTX
K_ITEM *find_markersummary_userid(int64_t userid, char *workername,
				  K_TREE_CTX *ctx)
{
	K_TREE_CTX ctx0[1];
	K_ITEM look, *ms_item = NULL;
	MARKERSUMMARY markersummary, *ms;

	if (ctx == NULL)
		ctx = ctx0;

	markersummary.userid = userid;
	markersummary.workername = workername;
	markersummary.lastshare.tv_sec = DATE_S_EOT;

	INIT_MARKERSUMMARY(&look);
	look.data = (void *)(&markersummary);
	ms_item = find_before_in_ktree(markersummary_userid_root, &look, ctx);
	if (ms_item) {
		DATA_MARKERSUMMARY(ms, ms_item);
		if (ms->userid != userid || strcmp(ms->workername, workername))
			ms_item = NULL;
	}
	return ms_item;
}

K_ITEM *_find_markersummary(int64_t markerid, int64_t workinfoid,
			    int64_t userid, char *workername, bool pool)
{
	K_ITEM look, *wm_item, *ms_item = NULL;
	MARKERSUMMARY markersummary;
	WORKMARKERS *wm;
	K_TREE_CTX ctx[1];

	if (markerid == 0) {
		wm_item = find_workmarkers(workinfoid, false, MARKER_PROCESSED, NULL);
		if (wm_item) {
			DATA_WORKMARKERS(wm, wm_item);
			markerid = wm->markerid;
		}
	} else {
		wm_item = find_workmarkerid(markerid, false, MARKER_PROCESSED);
		if (!wm_item)
			markerid = 0;
	}

	if (markerid != 0) {
		markersummary.markerid = markerid;
		markersummary.userid = userid;
		markersummary.workername = workername;

		INIT_MARKERSUMMARY(&look);
		look.data = (void *)(&markersummary);
		if (pool) {
			ms_item = find_in_ktree(markersummary_pool_root,
						&look, ctx);
		} else {
			ms_item = find_in_ktree(markersummary_root,
						&look, ctx);
		}
	}

	return ms_item;
}

bool make_markersummaries(bool msg, char *by, char *code, char *inet,
			  tv_t *cd, K_TREE *trf_root)
{
	K_TREE_CTX ctx[1];
	WORKMARKERS *workmarkers;
	K_ITEM *wm_item, *wm_last = NULL;
	tv_t now;
	bool ok;

	K_RLOCK(workmarkers_free);
	wm_item = last_in_ktree(workmarkers_workinfoid_root, ctx);
	while (wm_item) {
		DATA_WORKMARKERS(workmarkers, wm_item);
		if (!CURRENT(&(workmarkers->expirydate)))
			break;
		// find the oldest READY workinfoid
		if (WMREADY(workmarkers->status))
			wm_last = wm_item;
		wm_item = prev_in_ktree(ctx);
	}
	K_RUNLOCK(workmarkers_free);

	if (!wm_last) {
		if (!msg)
			LOGDEBUG("%s() no READY workmarkers", __func__);
		else
			LOGWARNING("%s() no READY workmarkers", __func__);
		return false;
	}

	DATA_WORKMARKERS(workmarkers, wm_last);

	LOGDEBUG("%s() processing workmarkers %"PRId64"/%s/End %"PRId64"/"
		 "Stt %"PRId64"/%s/%s",
		 __func__, workmarkers->markerid, workmarkers->poolinstance,
		 workmarkers->workinfoidend, workmarkers->workinfoidstart,
		 workmarkers->description, workmarkers->status);

	if (by == NULL)
		by = (char *)by_default;
	if (code == NULL)
		code = (char *)__func__;
	if (inet == NULL)
		inet = (char *)inet_default;
	if (cd)
		copy_tv(&now, cd);
	else
		setnow(&now);

	/* So we can't change any sharesummaries/markersummaries while a
	 *  payout is being generated
	 * N.B. this is a long lock since it stores the markersummaries */
	ck_wlock(&process_pplns_lock);
	ok = sharesummaries_to_markersummaries(NULL, workmarkers, by, code,
						inet, &now, trf_root);
	ck_wunlock(&process_pplns_lock);

	return ok;
}

void dsp_workmarkers(K_ITEM *item, FILE *stream)
{
	WORKMARKERS *wm;

	if (!item)
		fprintf(stream, "%s() called with (null) item\n", __func__);
	else {
		DATA_WORKMARKERS(wm, item);
		fprintf(stream, " id=%"PRId64" pi='%s' end=%"PRId64" stt=%"
				PRId64" sta='%s' des='%s'\n",
				wm->markerid, wm->poolinstance,
				wm->workinfoidend, wm->workinfoidstart,
				wm->status, wm->description);
	}
}

// order by expirydate asc,markerid asc
cmp_t cmp_workmarkers(K_ITEM *a, K_ITEM *b)
{
	WORKMARKERS *wa, *wb;
	DATA_WORKMARKERS(wa, a);
	DATA_WORKMARKERS(wb, b);
	cmp_t c = CMP_TV(wa->expirydate, wb->expirydate);
	if (c == 0)
		c = CMP_BIGINT(wa->markerid, wb->markerid);
	return c;
}

// order by expirydate asc,workinfoidend asc
// TODO: add poolinstance
cmp_t cmp_workmarkers_workinfoid(K_ITEM *a, K_ITEM *b)
{
	WORKMARKERS *wa, *wb;
	DATA_WORKMARKERS(wa, a);
	DATA_WORKMARKERS(wb, b);
	cmp_t c = CMP_TV(wa->expirydate, wb->expirydate);
	if (c == 0)
		c = CMP_BIGINT(wa->workinfoidend, wb->workinfoidend);
	return c;
}

K_ITEM *find_workmarkers(int64_t workinfoid, bool anystatus, char status, K_TREE_CTX *ctx)
{
	WORKMARKERS workmarkers, *wm;
	K_TREE_CTX ctx0[1];
	K_ITEM look, *wm_item;

	if (ctx == NULL)
		ctx = ctx0;

	workmarkers.expirydate.tv_sec = default_expiry.tv_sec;
	workmarkers.expirydate.tv_usec = default_expiry.tv_usec;
	workmarkers.workinfoidend = workinfoid-1;

	INIT_WORKMARKERS(&look);
	look.data = (void *)(&workmarkers);
	wm_item = find_after_in_ktree(workmarkers_workinfoid_root, &look, ctx);
	if (wm_item) {
		DATA_WORKMARKERS(wm, wm_item);
		if (!CURRENT(&(wm->expirydate)) ||
		    (!anystatus && wm->status[0] != status) ||
		    workinfoid < wm->workinfoidstart ||
		    workinfoid > wm->workinfoidend)
			wm_item = NULL;
	}
	return wm_item;
}

K_ITEM *find_workmarkerid(int64_t markerid, bool anystatus, char status)
{
	WORKMARKERS workmarkers, *wm;
	K_TREE_CTX ctx[1];
	K_ITEM look, *wm_item;

	workmarkers.expirydate.tv_sec = default_expiry.tv_sec;
	workmarkers.expirydate.tv_usec = default_expiry.tv_usec;
	workmarkers.markerid = markerid;

	INIT_WORKMARKERS(&look);
	look.data = (void *)(&workmarkers);
	wm_item = find_in_ktree(workmarkers_root, &look, ctx);
	if (wm_item) {
		DATA_WORKMARKERS(wm, wm_item);
		if (!CURRENT(&(wm->expirydate)) ||
		    (!anystatus && wm->status[0] != status))
			wm_item = NULL;
	}
	return wm_item;
}

// Create one
static bool gen_workmarkers(PGconn *conn, MARKS *stt, bool after, MARKS *fin,
			    bool before, char *by, char *code, char *inet,
			    tv_t *cd, K_TREE *trf_root)
{
	K_ITEM look, *wi_stt_item, *wi_fin_item, *old_wm_item;
	WORKMARKERS *old_wm;
	WORKINFO workinfo, *wi_stt, *wi_fin;
	K_TREE_CTX ctx[1];
	char description[TXT_BIG+1];
	bool ok;

	workinfo.workinfoid = stt->workinfoid;
	workinfo.expirydate.tv_sec = default_expiry.tv_sec;
	workinfo.expirydate.tv_usec = default_expiry.tv_usec;

	INIT_WORKINFO(&look);
	look.data = (void *)(&workinfo);
	K_RLOCK(workinfo_free);
	if (after) {
		wi_stt_item = find_after_in_ktree(workinfo_root, &look, ctx);
		while (wi_stt_item) {
			DATA_WORKINFO(wi_stt, wi_stt_item);
			if (CURRENT(&(wi_stt->expirydate)))
				break;
			wi_stt_item = next_in_ktree(ctx);
		}
	} else {
		wi_stt_item = find_in_ktree(workinfo_root, &look, ctx);
		DATA_WORKINFO_NULL(wi_stt, wi_stt_item);
	}
	K_RUNLOCK(workinfo_free);
	if (!wi_stt_item)
		return false;
	if (!CURRENT(&(wi_stt->expirydate)))
		return false;

	workinfo.workinfoid = fin->workinfoid;

	INIT_WORKINFO(&look);
	look.data = (void *)(&workinfo);
	K_RLOCK(workinfo_free);
	if (before) {
		DATE_ZERO(&(workinfo.expirydate));
		wi_fin_item = find_before_in_ktree(workinfo_root, &look, ctx);
		while (wi_fin_item) {
			DATA_WORKINFO(wi_fin, wi_fin_item);
			if (CURRENT(&(wi_fin->expirydate)))
				break;
			wi_fin_item = prev_in_ktree(ctx);
		}
	} else {
		workinfo.expirydate.tv_sec = default_expiry.tv_sec;
		workinfo.expirydate.tv_usec = default_expiry.tv_usec;
		wi_fin_item = find_in_ktree(workinfo_root, &look, ctx);
		DATA_WORKINFO_NULL(wi_fin, wi_fin_item);
	}
	K_RUNLOCK(workinfo_free);
	if (!wi_fin_item)
		return false;
	if (!CURRENT(&(wi_fin->expirydate)))
		return false;

	/* If two marks in a row are fin(+after) then stt(-before),
	 *  it may be that there should be no workmarkers range between them
	 * This may show up as the calculated finish id being before
	 *  the start id - so no need to create it since it will be empty
	 * Also note that empty workmarkers are not a problem,
	 *  but simply unnecessary and in this specific case,
	 *  we don't create it since a negative range would cause tree
	 *  sort order and matching errors */
	if (wi_fin->workinfoid >= wi_stt->workinfoid) {
		K_RLOCK(workmarkers_free);
		old_wm_item = find_workmarkers(wi_fin->workinfoid, true, '\0',
					       NULL);
		K_RUNLOCK(workmarkers_free);
		DATA_WORKMARKERS_NULL(old_wm, old_wm_item);
		if (old_wm_item && (WMREADY(old_wm->status) ||
		    WMPROCESSED(old_wm->status))) {
			/* This actually means a code bug or a DB marks has
			 * been set incorrectly via cmd_marks (or pgsql) */
			LOGEMERG("%s(): marks workinfoid %"PRId64" matches or"
				 " is part of the existing markerid %"PRId64,
				 __func__, wi_fin->workinfoid,
				 old_wm->markerid);
			return false;
		}

		snprintf(description, sizeof(description), "%s%s to %s%s",
			 stt->description, after ? "++" : "",
			 fin->description, before ? "--" : "");

		ok = workmarkers_process(conn, false, true, 0, EMPTY,
					 wi_fin->workinfoid, wi_stt->workinfoid,
					 description, MARKER_READY_STR,
					 by, code, inet, cd, trf_root);

		if (!ok)
			return false;
	}

	ok = marks_process(conn, true, EMPTY, fin->workinfoid,
			   fin->description, fin->extra, fin->marktype,
			   MARK_USED_STR, by, code, inet, cd, trf_root);

	return ok;
}

/* Generate workmarkers from the last USED mark
 * Will only use the last USED mark and the contiguous READY
 *  marks after the last USED mark
 * If a mark is found not READY it will stop at that one and
 *  report success with a message regarding the not READY one
 * No checks are done for the validity of the mark status
 *  information */
bool workmarkers_generate(PGconn *conn, char *err, size_t siz, char *by,
			  char *code, char *inet, tv_t *cd, K_TREE *trf_root,
			  bool none_error)
{
	K_ITEM *m_item, *m_next_item;
	MARKS *mused, *mnext;
	MARKS marks;
	K_TREE_CTX ctx[1];
	K_ITEM look;
	bool any = false, ok;

	marks.expirydate.tv_sec = default_expiry.tv_sec;
	marks.expirydate.tv_usec = default_expiry.tv_usec;
	marks.workinfoid = MAXID;

	INIT_MARKS(&look);
	look.data = (void *)(&marks);
	K_RLOCK(marks_free);
	m_item = find_before_in_ktree(marks_root, &look, ctx);
	while (m_item) {
		DATA_MARKS(mused, m_item);
		if (CURRENT(&(mused->expirydate)) && MUSED(mused->status))
			break;
		m_item = prev_in_ktree(ctx);
	}
	K_RUNLOCK(marks_free);
	if (!m_item || !CURRENT(&(mused->expirydate)) || !MUSED(mused->status)) {
		snprintf(err, siz, "%s", "No trailing used mark found");
		return false;
	}
	K_RLOCK(marks_free);
	m_item = next_in_ktree(ctx);
	K_RUNLOCK(marks_free);
	while (m_item) {
		DATA_MARKS(mnext, m_item);
		if (!CURRENT(&(mnext->expirydate)) || !!MREADY(mused->status))
			break;
		/* We need to get the next marks in advance since
		 *  gen_workmarker will create a new m_item flagged USED
		 *  and the tree position ctx for m_item will no longer give
		 *  us the correct 'next'
		 * However, we can still use mnext as mused in the subsequent
		 *  loop since the data that we need hasn't been changed
		 */
		K_RLOCK(marks_free);
		m_next_item = next_in_ktree(ctx);
		K_RUNLOCK(marks_free);

// save code space ...
#define GENWM(m1, b1, m2, b2) \
	gen_workmarkers(conn, m1, b1, m2, b2, by, code, inet, cd, trf_root)

		ok = true;
		switch(mused->marktype[0]) {
			case MARKTYPE_BLOCK:
			case MARKTYPE_SHIFT_END:
			case MARKTYPE_OTHER_FINISH:
				switch(mnext->marktype[0]) {
					case MARKTYPE_BLOCK:
					case MARKTYPE_SHIFT_END:
					case MARKTYPE_OTHER_FINISH:
						ok = GENWM(mused, true, mnext, false);
						if (ok)
							any = true;
						break;
					case MARKTYPE_PPLNS:
					case MARKTYPE_SHIFT_BEGIN:
					case MARKTYPE_OTHER_BEGIN:
						ok = GENWM(mused, true, mnext, true);
						if (ok)
							any = true;
						break;
					default:
						snprintf(err, siz,
							 "Mark %"PRId64" has"
							 " an unknown marktype"
							 " '%s' - aborting",
							 mnext->workinfoid,
							 mnext->marktype);
						return false;
				}
				break;
			case MARKTYPE_PPLNS:
			case MARKTYPE_SHIFT_BEGIN:
			case MARKTYPE_OTHER_BEGIN:
				switch(mnext->marktype[0]) {
					case MARKTYPE_BLOCK:
					case MARKTYPE_SHIFT_END:
					case MARKTYPE_OTHER_FINISH:
						ok = GENWM(mused, false, mnext, false);
						if (ok)
							any = true;
						break;
					case MARKTYPE_PPLNS:
					case MARKTYPE_SHIFT_BEGIN:
					case MARKTYPE_OTHER_BEGIN:
						ok = GENWM(mused, false, mnext, true);
						if (ok)
							any = true;
						break;
					default:
						snprintf(err, siz,
							 "Mark %"PRId64" has"
							 " an unknown marktype"
							 " '%s' - aborting",
							 mnext->workinfoid,
							 mnext->marktype);
						return false;
				}
				break;
			default:
				snprintf(err, siz,
					 "Mark %"PRId64" has an unknown "
					 "marktype '%s' - aborting",
					 mused->workinfoid,
					 mused->marktype);
				return false;
		}
		if (!ok) {
			snprintf(err, siz,
				 "Processing marks %"PRId64" to "
				 "%"PRId64" failed - aborting",
				 mused->workinfoid,
				 mnext->workinfoid);
			return false;
		}
		mused = mnext;
		m_item = m_next_item;
	}
	if (!any) {
		if (none_error) {
			snprintf(err, siz, "%s", "No ready marks found");
			return false;
		}
	}
	return true;
}

// delta = 1 or -1 i.e. reward or undo reward
bool reward_shifts(PAYOUTS *payouts, bool lock, int delta)
{
	// TODO: PPS calculations
	K_TREE_CTX ctx[1];
	K_ITEM *wm_item;
	WORKMARKERS *wm;
	bool did_one = false;
	double payout_pps;

	payout_pps = (double)delta * (double)(payouts->minerreward) /
			payouts->diffused;

	if (lock)
		K_WLOCK(workmarkers_free);

	wm_item = find_workmarkers(payouts->workinfoidstart, false,
				   MARKER_PROCESSED, ctx);
	while (wm_item) {
		DATA_WORKMARKERS(wm, wm_item);
		if (wm->workinfoidstart > payouts->workinfoidend)
			break;
		/* The status doesn't matter since we want the rewards passed
		 *  onto the PROCESSED status if it isn't already processed */
		if (CURRENT(&(wm->expirydate))) {
			wm->rewards += delta;
			wm->rewarded += payout_pps;
			did_one = true;
		}
		wm_item = next_in_ktree(ctx);
	}

	if (lock)
		K_WUNLOCK(workmarkers_free);

	return did_one;
}

/* (re)calculate rewards for a shift
 * N.B. we don't need to zero/undo a workmarkers rewards directly
 *  since this is just a counter of how many times it's been rewarded
 *  and thus if the shift is expired the counter is ignored
 * We only need to (re)calculate it when the workmarker is created
 * Payouts code processing will increment/decrement all current rewards as
 *  needed with reward_shifts() when payouts are added/changed/removed,
 *  however, the last shift in a payout can be created after the payout
 *  is generated so we need to update all from the payouts */
bool shift_rewards(K_ITEM *wm_item)
{
	PAYOUTS *payouts = NULL;
	K_TREE_CTX ctx[1];
	WORKMARKERS *wm;
	K_ITEM *p_item;
	int rewards = 0;
	double pps = 0.0;

	DATA_WORKMARKERS(wm, wm_item);

	// Deadlock risk since calling code should have workmarkers locked
	K_RLOCK(payouts_free);
	p_item = find_payouts_wid(wm->workinfoidend, ctx);
	DATA_PAYOUTS_NULL(payouts, p_item);
	// a workmarker should not cross a payout boundary
	while (p_item && payouts->workinfoidstart <= wm->workinfoidstart &&
	       wm->workinfoidend <= payouts->workinfoidend) {
		if (CURRENT(&(payouts->expirydate))) {
			rewards++;
			pps += (double)(payouts->minerreward) /
				payouts->diffused;
		}
		p_item = prev_in_ktree(ctx);
		DATA_PAYOUTS_NULL(payouts, p_item);
	}
	K_RUNLOCK(payouts_free);

	wm->rewards = rewards;
	wm->rewarded = pps;

	return (rewards > 0);
}

// order by expirydate asc,workinfoid asc
// TODO: add poolinstance
cmp_t cmp_marks(K_ITEM *a, K_ITEM *b)
{
	MARKS *ma, *mb;
	DATA_MARKS(ma, a);
	DATA_MARKS(mb, b);
	cmp_t c = CMP_TV(ma->expirydate, mb->expirydate);
	if (c == 0)
		c = CMP_BIGINT(ma->workinfoid, mb->workinfoid);
	return c;
}

K_ITEM *find_marks(int64_t workinfoid)
{
	MARKS marks;
	K_TREE_CTX ctx[1];
	K_ITEM look;

	marks.expirydate.tv_sec = default_expiry.tv_sec;
	marks.expirydate.tv_usec = default_expiry.tv_usec;
	marks.workinfoid = workinfoid;

	INIT_MARKS(&look);
	look.data = (void *)(&marks);
	return find_in_ktree(marks_root, &look, ctx);
}

const char *marks_marktype(char *marktype)
{
	switch (marktype[0]) {
		case MARKTYPE_BLOCK:
			return marktype_block;
		case MARKTYPE_PPLNS:
			return marktype_pplns;
		case MARKTYPE_SHIFT_BEGIN:
			return marktype_shift_begin;
		case MARKTYPE_SHIFT_END:
			return marktype_shift_end;
		case MARKTYPE_OTHER_BEGIN:
			return marktype_other_begin;
		case MARKTYPE_OTHER_FINISH:
			return marktype_other_finish;
	}
	return NULL;
}

bool _marks_description(char *description, size_t siz, char *marktype,
			int32_t height, char *shift, char *other,
			WHERE_FFL_ARGS)
{
	switch (marktype[0]) {
		case MARKTYPE_BLOCK:
			if (height < START_POOL_HEIGHT) {
				LOGERR("%s() invalid pool height %"PRId32
					"for mark %s " WHERE_FFL,
					__func__, height,
					marks_marktype(marktype),
					WHERE_FFL_PASS);
				return false;
			}
			snprintf(description, siz,
				 marktype_block_fmt, height);
			break;
		case MARKTYPE_PPLNS:
			if (height < START_POOL_HEIGHT) {
				LOGERR("%s() invalid pool height %"PRId32
					"for mark %s " WHERE_FFL,
					__func__, height,
					marks_marktype(marktype),
					WHERE_FFL_PASS);
				return false;
			}
			snprintf(description, siz,
				 marktype_pplns_fmt, height);
			break;
		case MARKTYPE_SHIFT_BEGIN:
			if (shift == NULL || !*shift) {
				LOGERR("%s() invalid mark shift NULL/empty "
					"for mark %s " WHERE_FFL,
					__func__,
					marks_marktype(marktype),
					WHERE_FFL_PASS);
				return false;
			}
			snprintf(description, siz,
				 marktype_shift_begin_fmt, shift);
			break;
		case MARKTYPE_SHIFT_END:
			if (shift == NULL || !*shift) {
				LOGERR("%s() invalid mark shift NULL/empty "
					"for mark %s " WHERE_FFL,
					__func__,
					marks_marktype(marktype),
					WHERE_FFL_PASS);
				return false;
			}
			snprintf(description, siz,
				 marktype_shift_end_fmt, shift);
			break;
		case MARKTYPE_OTHER_BEGIN:
			if (other == NULL) {
				LOGERR("%s() invalid mark other NULL/empty "
					"for mark %s " WHERE_FFL,
					__func__,
					marks_marktype(marktype),
					WHERE_FFL_PASS);
				return false;
			}
			snprintf(description, siz,
				 marktype_other_begin_fmt, other);
			break;
		case MARKTYPE_OTHER_FINISH:
			if (other == NULL) {
				LOGERR("%s() invalid mark other NULL/empty "
					"for mark %s " WHERE_FFL,
					__func__,
					marks_marktype(marktype),
					WHERE_FFL_PASS);
				return false;
			}
			snprintf(description, siz,
				 marktype_other_finish_fmt, other);
			break;
		default:
			LOGERR("%s() invalid marktype '%s'" WHERE_FFL,
				__func__, marktype,
				WHERE_FFL_PASS);
			return false;
	}
	return true;
}

#define CODEBASE 32
#define CODESHIFT(_x) ((_x) >> 5)
#define CODECHAR(_x) (codebase[((_x) & (CODEBASE-1))])
static char codebase[] = "23456789abcdefghjkmnopqrstuvwxyz";

#define ASSERT3(condition) __maybe_unused static char codebase_length_must_be_CODEBASE[(condition)?1:-1]
ASSERT3(sizeof(codebase) == (CODEBASE+1));

static int shift_code(long code, char *code_buf)
{
	int pos;

	if (code > 0) {
		pos = shift_code(CODESHIFT(code), code_buf);
		code_buf[pos++] = codebase[code & (CODEBASE-1)];
		return(pos);
	} else
		return(0);

}

// NON-thread safe
char *shiftcode(tv_t *createdate)
{
	static char code_buf[64];
	long code;
	int pos;

	// To reduce the code size, ignore the last 4 bits
	code = (createdate->tv_sec - DATE_BEGIN) >> 4;
	LOGDEBUG("%s() code=%ld cd=%ld BEGIN=%ld",
		 __func__, code, createdate->tv_sec, DATE_BEGIN);
	if (code <= 0)
		strcpy(code_buf, "0");
	else {
		pos = shift_code(code, code_buf);
		code_buf[pos] = '\0';
	}

	LOGDEBUG("%s() code_buf='%s'", __func__, code_buf);
	return(code_buf);
}

// order by userid asc
cmp_t cmp_userinfo(K_ITEM *a, K_ITEM *b)
{
	USERINFO *ua, *ub;
	DATA_USERINFO(ua, a);
	DATA_USERINFO(ub, b);
	return CMP_BIGINT(ua->userid, ub->userid);
}

K_ITEM *_get_userinfo(int64_t userid, bool lock)
{
	USERINFO userinfo;
	K_TREE_CTX ctx[1];
	K_ITEM look, *find;

	userinfo.userid = userid;

	INIT_USERINFO(&look);
	look.data = (void *)(&userinfo);
	if (lock)
		K_RLOCK(userinfo_free);
	find = find_in_ktree(userinfo_root, &look, ctx);
	if (lock)
		K_RUNLOCK(userinfo_free);
	return find;
}

K_ITEM *_find_create_userinfo(int64_t userid, bool lock, WHERE_FFL_ARGS)
{
	K_ITEM *ui_item, *u_item;
	USERS *users = NULL;
	USERINFO *row;

	ui_item = _get_userinfo(userid, lock);
	if (!ui_item) {
		if (lock)
			K_RLOCK(users_free);
		u_item = find_userid(userid);
		if (lock)
			K_RUNLOCK(users_free);
		DATA_USERS_NULL(users, u_item);

		if (lock)
			K_WLOCK(userinfo_free);
		ui_item = k_unlink_head(userinfo_free);
		DATA_USERINFO(row, ui_item);

		bzero(row, sizeof(*row));
		row->userid = userid;
		if (u_item)
			STRNCPY(row->username, users->username);
		else
			bigint_to_buf(userid, row->username, sizeof(row->username));

		add_to_ktree(userinfo_root, ui_item);
		k_add_head(userinfo_store, ui_item);
		if (lock)
			K_WUNLOCK(userinfo_free);
	}
	return ui_item;
}

void _userinfo_update(SHARES *shares, SHARESUMMARY *sharesummary,
		      MARKERSUMMARY *markersummary, bool ss_sub, bool lock)
{
	USERINFO *row;
	K_ITEM *item;

	if (shares) {
		item = _find_userinfo(shares->userid, lock);
		DATA_USERINFO(row, item);
		if (lock)
			K_WLOCK(userinfo_free);
		switch (shares->errn) {
			case SE_NONE:
				row->diffacc += shares->diff;
				row->shareacc++;
				break;
			case SE_STALE:
				row->diffsta += shares->diff;
				row->sharesta++;
				break;
			case SE_DUPE:
				row->diffdup += shares->diff;
				row->sharedup++;
				break;
			case SE_HIGH_DIFF:
				row->diffhi += shares->diff;
				row->sharehi++;
				break;
			default:
				row->diffrej += shares->diff;
				row->sharerej++;
				break;
		}
		if (lock)
			K_WUNLOCK(userinfo_free);
	}

	// Only during db load so no locking required
	if (sharesummary) {
		item = _find_userinfo(sharesummary->userid, false);
		DATA_USERINFO(row, item);
		if (ss_sub) {
			row->diffacc -= sharesummary->diffacc;
			row->diffsta -= sharesummary->diffsta;
			row->diffdup -= sharesummary->diffdup;
			row->diffhi -= sharesummary->diffhi;
			row->diffrej -= sharesummary->diffrej;
			row->shareacc -= sharesummary->shareacc;
			row->sharesta -= sharesummary->sharesta;
			row->sharedup -= sharesummary->sharedup;
			row->sharehi -= sharesummary->sharehi;
			row->sharerej -= sharesummary->sharerej;
		} else {
			row->diffacc += sharesummary->diffacc;
			row->diffsta += sharesummary->diffsta;
			row->diffdup += sharesummary->diffdup;
			row->diffhi += sharesummary->diffhi;
			row->diffrej += sharesummary->diffrej;
			row->shareacc += sharesummary->shareacc;
			row->sharesta += sharesummary->sharesta;
			row->sharedup += sharesummary->sharedup;
			row->sharehi += sharesummary->sharehi;
			row->sharerej += sharesummary->sharerej;
		}
	}

	// Only during db load so no locking required
	if (markersummary) {
		item = _find_userinfo(markersummary->userid, false);
		DATA_USERINFO(row, item);
		row->diffacc += markersummary->diffacc;
		row->diffsta += markersummary->diffsta;
		row->diffdup += markersummary->diffdup;
		row->diffhi += markersummary->diffhi;
		row->diffrej += markersummary->diffrej;
		row->shareacc += markersummary->shareacc;
		row->sharesta += markersummary->sharesta;
		row->sharedup += markersummary->sharedup;
		row->sharehi += markersummary->sharehi;
		row->sharerej += markersummary->sharerej;
	}
}

// N.B. good blocks = blocks - (orphans + rejects)
void _userinfo_block(BLOCKS *blocks, enum info_type isnew, int delta, bool lock)
{
	USERINFO *row;
	K_ITEM *item;

	item = find_userinfo(blocks->userid);
	DATA_USERINFO(row, item);
	if (lock)
		K_WLOCK(userinfo_free);
	if (isnew == INFO_NEW) {
		row->blocks += delta;
		copy_tv(&(row->last_block), &(blocks->createdate));
	} else if (isnew == INFO_ORPHAN)
		row->orphans += delta;
	else if (isnew == INFO_REJECT)
		row->rejects += delta;

	if (lock)
		K_WUNLOCK(userinfo_free);
}
