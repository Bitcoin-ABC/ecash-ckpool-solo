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
		msgline->trf_root = free_ktree(msgline->trf_root, NULL);
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

void free_workinfo_data(K_ITEM *item)
{
	WORKINFO *workinfo;

	DATA_WORKINFO(workinfo, item);
	if (workinfo->transactiontree)
		FREENULL(workinfo->transactiontree);
	if (workinfo->merklehash)
		FREENULL(workinfo->merklehash);
}

void free_sharesummary_data(K_ITEM *item)
{
	SHARESUMMARY *sharesummary;

	DATA_SHARESUMMARY(sharesummary, item);
	if (sharesummary->workername) {
		LIST_MEM_SUB(sharesummary_free, sharesummary->workername);
		FREENULL(sharesummary->workername);
	}
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
	if (optioncontrol->optionvalue)
		FREENULL(optioncontrol->optionvalue);
}

void free_markersummary_data(K_ITEM *item)
{
	MARKERSUMMARY *markersummary;

	DATA_MARKERSUMMARY(markersummary, item);
	if (markersummary->workername)
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
	if (workmarkers->poolinstance)
		FREENULL(workmarkers->poolinstance);
	if (workmarkers->description)
		FREENULL(workmarkers->description);
}

void free_marks_data(K_ITEM *item)
{
	MARKS *marks;

	DATA_MARKS(marks, item);
	if (marks->poolinstance && marks->poolinstance != EMPTY)
		FREENULL(marks->poolinstance);
	if (marks->description && marks->description != EMPTY)
		FREENULL(marks->description);
	if (marks->extra && marks->extra != EMPTY)
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

// Clear text printable version of txt up to first '\0'
char *_safe_text(char *txt, bool shownull)
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
	return find_in_ktree(trf_root, &look, cmp_transfer, ctx);
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
K_ITEM *get_workerstatus(int64_t userid, char *workername)
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
 * If it is missing, it will check for and create the worker if needed
 *  and create a new workerstatus and return it
 * This has 2 sets of file/func/line to allow 2 levels of traceback
 *  to see why it happened
 */
K_ITEM *_find_create_workerstatus(int64_t userid, char *workername,
				  bool create, const char *file2,
				  const char *func2, const int line2,
				  WHERE_FFL_ARGS)
{
	WORKERSTATUS *row;
	K_ITEM *ws_item, *w_item = NULL;
	bool ws_err = false, w_err = false;
	tv_t now;

	ws_item = get_workerstatus(userid, workername);
	if (!ws_item) {
		if (!create) {
			ws_err = true;

			w_item = find_workers(userid, workername);
			if (!w_item) {
				w_err = true;
				setnow(&now);
				w_item = workers_add(NULL, userid, workername,
						     NULL, NULL, NULL,
						     by_default,
						     (char *)__func__,
						     (char *)inet_default,
						     &now, NULL);
			}
		}

		K_WLOCK(workerstatus_free);
		ws_item = k_unlink_head(workerstatus_free);

		DATA_WORKERSTATUS(row, ws_item);

		bzero(row, sizeof(*row));
		row->userid = userid;
		STRNCPY(row->workername, workername);

		workerstatus_root = add_to_ktree(workerstatus_root, ws_item, cmp_workerstatus);
		k_add_head(workerstatus_store, ws_item);
		K_WUNLOCK(workerstatus_free);

		if (ws_err) {
			LOGERR("%s(): CREATED Missing workerstatus %"PRId64"/%s"
				WHERE_FFL WHERE_FFL,
				__func__, userid, workername,
				file2, func2, line2, WHERE_FFL_PASS);
			if (w_err) {
				LOGERR("%s(): %s Missing worker %"PRId64"/%s",
					__func__,
					w_item ? "CREATED" : "FAILED TO CREATE",
					userid, workername);
			}
		}
	}
	return ws_item;
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

		K_RLOCK(markersummary_free);
		// This is the last share datestamp
		ms_item = find_markersummary_userid(workerstatus->userid,
						    workerstatus->workername,
						    NULL);
		K_RUNLOCK(markersummary_free);
		if (ms_item) {
			DATA_MARKERSUMMARY(markersummary, ms_item);
			if (tv_newer(&(workerstatus->last_share),
				     &(markersummary->lastshare))) {
				copy_tv(&(workerstatus->last_share),
					&(markersummary->lastshare));
				workerstatus->last_diff =
					markersummary->lastdiffacc;
			}
		}

		K_RLOCK(sharesummary_free);
		ss_item = find_last_sharesummary(workerstatus->userid,
						 workerstatus->workername);
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

	LOGWARNING("%s(): Update workerstatus complete", __func__);
}

void _workerstatus_update(AUTHS *auths, SHARES *shares,
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
	return find_in_ktree(users_root, &look, cmp_users, ctx);
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
	return find_in_ktree(userid_root, &look, cmp_userid, ctx);
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
	return find_in_ktree(useratts_root, &look, cmp_useratts, ctx);
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
	return find_in_ktree(workers_root, &look, cmp_workers, ctx);
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
	workers.expirydate.tv_sec = 0L;
	workers.expirydate.tv_usec = 0L;

	INIT_WORKERS(&look);
	look.data = (void *)(&workers);
	// Caller needs to check userid/expirydate if the result != NULL
	return find_after_in_ktree(workers_root, &look, cmp_workers, ctx);
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
		item = workers_add(conn, userid, workername, diffdef,
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
	item = find_before_in_ktree(paymentaddresses_root, &look, cmp_paymentaddresses, ctx);
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
	paymentaddresses.createdate.tv_sec = 0;
	paymentaddresses.createdate.tv_usec = 0;
	paymentaddresses.payaddress[0] = '\0';

	INIT_PAYMENTADDRESSES(&look);
	look.data = (void *)(&paymentaddresses);
	item = find_after_in_ktree(paymentaddresses_create_root, &look,
				    cmp_payaddr_create, ctx);
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
	return find_in_ktree(paymentaddresses_root, &look, cmp_paymentaddresses, ctx);
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
	return find_in_ktree(payments_root, &look, cmp_payments, ctx);
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
	item = find_after_in_ktree(payments_root, &look, cmp_payments, ctx);
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
	item = find_after_in_ktree(payments_root, &look, cmp_payments, ctx);
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
	item = find_in_ktree(accountbalance_root, &look, cmp_accountbalance, ctx);
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

// Must be R or W locked before call
K_ITEM *find_optioncontrol(char *optionname, tv_t *now, int32_t height)
{
	OPTIONCONTROL optioncontrol, *oc, *ocbest;
	K_TREE_CTX ctx[1];
	K_ITEM look, *item, *best;

	/* Step through all records having optionname and check:
	 * 1) activationdate is <= now
	 *  and
	 * 2) height <= specified height (pool.height = current)
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
			 int64_t setting_default, tv_t *now)
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

int32_t _coinbase1height(char *coinbase1, WHERE_FFL_ARGS)
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

cmp_t _cmp_height(char *coinbase1a, char *coinbase1b, WHERE_FFL_ARGS)
{
	return CMP_INT(_coinbase1height(coinbase1a, WHERE_FFL_PASS),
		       _coinbase1height(coinbase1b, WHERE_FFL_PASS));
}

// order by height asc,createdate asc
cmp_t cmp_workinfo_height(K_ITEM *a, K_ITEM *b)
{
	WORKINFO *wa, *wb;
	DATA_WORKINFO(wa, a);
	DATA_WORKINFO(wb, b);
	cmp_t c = cmp_height(wa->coinbase1, wb->coinbase1);
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
	item = find_in_ktree(workinfo_root, &look, cmp_workinfo, ctx);
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
	item = find_after_in_ktree(workinfo_root, &look, cmp_workinfo, ctx);
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

bool workinfo_age(PGconn *conn, int64_t workinfoid, char *poolinstance,
		  char *by, char *code, char *inet, tv_t *cd,
		  tv_t *ss_first, tv_t *ss_last, int64_t *ss_count,
		  int64_t *s_count, int64_t *s_diff)
{
	K_ITEM *wi_item, ss_look, *ss_item, s_look, *s_item;
	K_ITEM *wm_item, *tmp_item;
	K_TREE_CTX ss_ctx[1], s_ctx[1];
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
	wm_item = find_workmarkers(workinfoid, false, MARKER_PROCESSED);
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
			shares_root = remove_from_ktree(shares_root, s_item, cmp_shares);
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

void zero_sharesummary(SHARESUMMARY *row, tv_t *cd, double diff)
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
	if (pool) {
		return find_in_ktree(sharesummary_pool_root, &look,
				     cmp_sharesummary, ctx);
	} else {
		return find_in_ktree(sharesummary_root, &look,
				     cmp_sharesummary, ctx);
	}
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
	item = find_before_in_ktree(sharesummary_root, &look, cmp_sharesummary, ctx);
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
void auto_age_older(PGconn *conn, int64_t workinfoid, char *poolinstance,
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
	looksharesummary.workername = EMPTY;
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
	return find_in_ktree(blocks_root, &look, cmp_blocks, ctx);
}

// Must be R or W locked before call
K_ITEM *find_prev_blocks(int32_t height)
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
	}
	return blocks_unknown;
}

void zero_on_new_block()
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

	zero_on_new_block();

	ws_item = NULL;
	/* From the end backwards so we can skip the workinfoid's we don't
	 * want by jumping back to just before the current worker when the
	 * workinfoid goes below the limit */
	K_RLOCK(sharesummary_free);
	ss_item = last_in_ktree(sharesummary_root, ctx);
	while (ss_item) {
		DATA_SHARESUMMARY(sharesummary, ss_item);
		if (sharesummary->workinfoid <= pool.workinfoid) {
			// Skip back to the next worker
			looksharesummary.userid = sharesummary->userid;
			looksharesummary.workername = sharesummary->workername;
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
			ms_item = find_before_in_ktree(markersummary_root, &ms_look, cmp_markersummary, ctx_ms);
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
					ws_item = find_workerstatus(markersummary->userid,
								    markersummary->workername,
								    __FILE__, __func__, __LINE__);
					if (!ws_item) {
						ws_item = find_create_workerstatus(markersummary->userid,
										   markersummary->workername,
										   __FILE__, __func__, __LINE__);
					}
					DATA_WORKERSTATUS(workerstatus, ws_item);
				}

				pool.diffacc += markersummary->diffacc;
				pool.diffinv += markersummary->diffsta + markersummary->diffdup +
						markersummary->diffhi + markersummary->diffrej;
				workerstatus->diffacc += markersummary->diffacc;
				workerstatus->diffinv += markersummary->diffsta + markersummary->diffdup +
							 markersummary->diffhi + markersummary->diffrej;
				workerstatus->diffsta += markersummary->diffsta;
				workerstatus->diffdup += markersummary->diffdup;
				workerstatus->diffhi += markersummary->diffhi;
				workerstatus->diffrej += markersummary->diffrej;
				workerstatus->shareacc += markersummary->shareacc;
				workerstatus->shareinv += markersummary->sharesta + markersummary->sharedup +
							  markersummary->sharehi + markersummary->sharerej;
				workerstatus->sharesta += markersummary->sharesta;
				workerstatus->sharedup += markersummary->sharedup;
				workerstatus->sharehi += markersummary->sharehi;
				workerstatus->sharerej += markersummary->sharerej;

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
	char ndiffbin[TXT_SML+1];
	double ok, diffacc, netsumm, diffmean, pending;
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
				if (blocks->confirmed[0] == BLOCKS_ORPHAN)
					blocks->diffcalc = 0.0;
				else {
					blocks->diffcalc = pending;
					pending = 0.0;
				}
			}
			b_item = next_in_ktree(ctx);
		}
		ok = diffacc = netsumm = diffmean = 0.0;
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
						if (!blocks->workinfoid != last_missing_workinfoid ||
						    tvdiff(&now, &last_message) >= 5.0) {
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
					hex2bin(ndiffbin, workinfo->bits, 4);
					blocks->netdiff = diff_from_nbits(ndiffbin);
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

				/* Orphans are treated as +diffacc but no block
				 *  i.e. they simply add shares to the later block
				 *  and have running stats set to zero */
				if (blocks->confirmed[0] == BLOCKS_ORPHAN) {
					blocks->diffratio = 0.0;
					blocks->diffmean = 0.0;
					blocks->cdferl = 0.0;
					blocks->luck = 0.0;
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
	return find_in_ktree(miningpayouts_root, &look, cmp_miningpayouts, ctx);
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
	miningpayouts.expirydate.tv_sec = 0;
	miningpayouts.expirydate.tv_usec = 0;

	INIT_MININGPAYOUTS(&look);
	look.data = (void *)(&miningpayouts);
	return find_after_in_ktree(miningpayouts_root, &look, cmp_miningpayouts, ctx);
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
	mu_item = find_in_ktree(mu_root, &look, cmp_mu, ctx);
	if (mu_item) {
		DATA_MININGPAYOUTS(miningpayouts, mu_item);
		miningpayouts->diffacc += diffacc;
	} else {
		K_WLOCK(mu_store);
		mu_item = k_unlink_head(miningpayouts_free);
		DATA_MININGPAYOUTS(miningpayouts, mu_item);
		miningpayouts->userid = userid;
		miningpayouts->diffacc = diffacc;
		mu_root = add_to_ktree(mu_root, mu_item, cmp_mu);
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
	return find_in_ktree(payouts_root, &look, cmp_payouts, ctx);
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
	return find_in_ktree(payouts_id_root, &look, cmp_payouts_id, ctx);
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
				tab = strchr(pos, '\t');
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
		pos = strchr(pos, '\t');
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
	BLOCKS *blocks, *blocks2;
	USERS *users;
	K_ITEM *p_item, *old_p_item, *b_item, *b2_item, *w_item, *wb_item;
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
	char ndiffbin[TXT_SML+1];
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
		LOGERR("%s(): payout for block %"PRId32"/%s already exists"
			"%"PRId64"/%"PRId64"/%"PRId64"/%s",
			__func__, height, blockhash, payouts->payoutid,
			payouts->workinfoidstart, payouts->workinfoidend,
			cd_buf);
		goto oku;
	}

	// Check the block status
	K_RLOCK(blocks_free);
	b_item = find_blocks(height, blockhash, b_ctx);
	if (!b_item) {
		K_RUNLOCK(blocks_free);
		LOGERR("%s(): no block %"PRId32"/%s for payout",
			__func__, height, blockhash);
		goto oku;
	}
	DATA_BLOCKS(blocks, b_item);
	b2_item = b_item;
	DATA_BLOCKS(blocks2, b2_item);
	while (b2_item && blocks2->height == height &&
	       strcmp(blocks2->blockhash, blockhash) == 0) {
		if (blocks2->confirmed[0] == BLOCKS_NEW) {
			copy_tv(&end_tv, &(blocks2->createdate));
			if (!addr_cd)
				addr_cd = &(blocks2->createdate);
			break;
		}
		b2_item = next_in_ktree(b_ctx);
		DATA_BLOCKS_NULL(blocks2, b2_item);
	}
	K_RUNLOCK(blocks_free);
	// If addr_cd was null it should've been set to the block NEW createdate
	if (!addr_cd || end_tv.tv_sec == 0) {
		LOGEMERG("%s(): missing %s record for block %"PRId32
			 "/%"PRId64"/%s/%s/%"PRId64,
			 __func__, blocks_confirmed(BLOCKS_NEW_STR),
			 blocks->height, blocks->workinfoid,
			 blocks->workername, blocks->confirmed,
			 blocks->reward);
		goto oku;
	}

	LOGDEBUG("%s(): block %"PRId32"/%"PRId64"/%s/%s/%"PRId64,
		 __func__, blocks->height, blocks->workinfoid,
		 blocks->workername, blocks->confirmed, blocks->reward);

	switch (blocks->confirmed[0]) {
		case BLOCKS_NEW:
		case BLOCKS_ORPHAN:
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
	oc_item = find_optioncontrol(PPLNSDIFFTIMES, &(blocks->createdate),
				     height);
	K_RUNLOCK(optioncontrol_free);
	if (!oc_item) {
		tv_to_buf(&(blocks->createdate), cd_buf, sizeof(cd_buf));
		LOGEMERG("%s(): missing optioncontrol %s (%s/%"PRId32")",
			 __func__, PPLNSDIFFTIMES, cd_buf, blocks->height);
		goto oku;
	}
	DATA_OPTIONCONTROL(optioncontrol, oc_item);
	diff_times = atof(optioncontrol->optionvalue);

	K_RLOCK(optioncontrol_free);
	oc_item = find_optioncontrol(PPLNSDIFFADD, &(blocks->createdate),
				     height);
	K_RUNLOCK(optioncontrol_free);
	if (!oc_item) {
		tv_to_buf(&(blocks->createdate), cd_buf, sizeof(cd_buf));
		LOGEMERG("%s(): missing optioncontrol %s (%s/%"PRId32")",
			 __func__, PPLNSDIFFADD, cd_buf, blocks->height);
		goto oku;
	}
	DATA_OPTIONCONTROL(optioncontrol, oc_item);
	diff_add = atof(optioncontrol->optionvalue);

	hex2bin(ndiffbin, workinfo->bits, 4);
	ndiff = diff_from_nbits(ndiffbin);
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
	mu_root = new_ktree();

	looksharesummary.workinfoid = blocks->workinfoid;
	looksharesummary.userid = MAXID;
	looksharesummary.workername = EMPTY;
	INIT_SHARESUMMARY(&ss_look);
	ss_look.data = (void *)(&looksharesummary);
	K_RLOCK(sharesummary_free);
	K_RLOCK(workmarkers_free);
	K_RLOCK(markersummary_free);
	ss_item = find_before_in_ktree(sharesummary_workinfoid_root, &ss_look,
					cmp_sharesummary_workinfoid, ss_ctx);
	DATA_SHARESUMMARY_NULL(sharesummary, ss_item);
	if (ss_item)
		end_workinfoid = sharesummary->workinfoid;
	/* Add up all sharesummaries until >= diff_want
	 * also record the latest lastshare - that will be the end pplns time
	 *  which will be >= blocks->createdate */
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
		// TODO: add lastshareacc to sharesummary and markersummary
		if (sharesummary->shareacc > 0 &&
		    tv_newer(&end_tv, &(sharesummary->lastshare)))
			copy_tv(&end_tv, &(sharesummary->lastshare));
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
		// TODO: add lastshareacc to sharesummary and markersummary
		if (sharesummary->shareacc > 0 &&
		    tv_newer(&end_tv, &(sharesummary->lastshare)))
			copy_tv(&end_tv, &(sharesummary->lastshare));
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
					total_diff += markersummary->diffacc;
					begin_workinfoid = workmarkers->workinfoidstart;
					if (markersummary->shareacc > 0 &&
					    tv_newer(&end_tv, &(markersummary->lastshare)))
						copy_tv(&end_tv, &(markersummary->lastshare));
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
		 *  TODO: via cmd_payouts() ... which isn't available yet */
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
	d64 = blocks->reward * 9 / 1000;
	g64 = blocks->reward - d64;
	payouts->minerreward = g64;
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
	payouts->stats = buf;

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
			/* Address user or normal user without a paymentaddress
			 * TODO: user table needs a flag to say which it is ...
			 *  for now use a simple test */
			bool gotaddr = false;
			size_t len;

			switch (users->username[0]) {
				case '1':
				case '3':
					len = strlen(users->username);
					if (len >= ADDR_MIN_LEN && len <= ADDR_MAX_LEN)
						gotaddr = true;
			}
			if (gotaddr) {
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

	mu_root = free_ktree(mu_root, NULL);
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

	// convert the stack memory to heap memeory
	payouts->stats = strdup(payouts->stats);

	K_WLOCK(payouts_free);
	p2_item = k_unlink_head(payouts_free);
	K_WUNLOCK(payouts_free);
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

	setnow(&now);
	/* N.B. the PROCESSING payouts could have expirydate = createdate
	 *  if the code above executes faster than the pgsql time resolution */
	ok = payouts_add(conn, true, p2_item, &old_p2_item, (char *)by_default,
			 (char *)__func__, (char *)inet_default, &now, NULL,
			 false);
	if (!ok) {
		LOGEMERG("%s(): payout %"PRId64" for block %"PRId32"/%s "
			 "NOT set generated - it needs to be set manually",
			 __func__, payouts->payoutid, blocks->height,
			 blocks->blockhash);
	}

	CKPQDisco(&conn, conned);

	goto oku;

shazbot:
	ok = false;

	if (begun)
		CKPQEnd(conn, false);
	CKPQDisco(&conn, conned);

	if (p_item) {
		K_WLOCK(payouts_free);
		k_add_head(payouts_free, p_item);
		K_WUNLOCK(payouts_free);
	}

oku:
	;
	ck_wunlock(&process_pplns_lock);
	if (mu_root)
		mu_root = free_ktree(mu_root, NULL);
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
	return find_in_ktree(userstats_root, &look, cmp_userstats, ctx);
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
	ms_item = find_before_in_ktree(markersummary_userid_root, &look, cmp_markersummary_userid, ctx);
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
		wm_item = find_workmarkers(workinfoid, false, MARKER_PROCESSED);
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
			ms_item = find_in_ktree(markersummary_pool_root, &look,
						cmp_markersummary, ctx);
		} else {
			ms_item = find_in_ktree(markersummary_root, &look,
						cmp_markersummary, ctx);
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

	return sharesummaries_to_markersummaries(NULL, workmarkers, by, code,
						 inet, &now, trf_root);
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

K_ITEM *find_workmarkers(int64_t workinfoid, bool anystatus, char status)
{
	WORKMARKERS workmarkers, *wm;
	K_TREE_CTX ctx[1];
	K_ITEM look, *wm_item;

	workmarkers.expirydate.tv_sec = default_expiry.tv_sec;
	workmarkers.expirydate.tv_usec = default_expiry.tv_usec;
	workmarkers.workinfoidend = workinfoid-1;

	INIT_WORKMARKERS(&look);
	look.data = (void *)(&workmarkers);
	wm_item = find_after_in_ktree(workmarkers_workinfoid_root, &look, cmp_workmarkers_workinfoid, ctx);
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
	wm_item = find_in_ktree(workmarkers_root, &look, cmp_workmarkers, ctx);
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
		wi_stt_item = find_after_in_ktree(workinfo_root, &look,
						  cmp_workinfo, ctx);
		while (wi_stt_item) {
			DATA_WORKINFO(wi_stt, wi_stt_item);
			if (CURRENT(&(wi_stt->expirydate)))
				break;
			wi_stt_item = next_in_ktree(ctx);
		}
	} else {
		wi_stt_item = find_in_ktree(workinfo_root, &look,
					    cmp_workinfo, ctx);
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
		workinfo.expirydate.tv_sec = 0;
		workinfo.expirydate.tv_usec = 0;
		wi_fin_item = find_before_in_ktree(workinfo_root, &look,
						   cmp_workinfo, ctx);
		while (wi_fin_item) {
			DATA_WORKINFO(wi_fin, wi_fin_item);
			if (CURRENT(&(wi_fin->expirydate)))
				break;
			wi_fin_item = prev_in_ktree(ctx);
		}
	} else {
		workinfo.expirydate.tv_sec = default_expiry.tv_sec;
		workinfo.expirydate.tv_usec = default_expiry.tv_usec;
		wi_fin_item = find_in_ktree(workinfo_root, &look,
					    cmp_workinfo, ctx);
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
		old_wm_item = find_workmarkers(wi_fin->workinfoid, true, '\0');
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
	m_item = find_before_in_ktree(marks_root, &look, cmp_marks, ctx);
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
	return find_in_ktree(marks_root, &look, cmp_marks, ctx);
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
