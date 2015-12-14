/*
 * Copyright 1995-2015 Andrew Smith
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#include "ckdb.h"

// Doesn't work with negative numbers ...
void pcom(int n)
{
	if (n < 1000)
		printf("%d", n);
	else {
		pcom(n/1000);
		printf(",%03d", n % 1000);
	}
}

char *pqerrmsg(PGconn *conn)
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

#define PQ_GET_FLD(__res, __row, __name, __fld, __ok) do { \
		int __col = PQfnumber(__res, __name); \
		if (__col == -1) { \
			LOGERR("%s(): Unknown field '%s' row %d", __func__, __name, __row); \
			__ok = false; \
		} else { \
			__fld = PQgetvalue(__res, __row, __col); \
			if (__fld == NULL) { \
				LOGERR("%s(): Invalid field '%s' or row %d", __func__, __name, __row); \
				__ok = false; \
			}\
		} \
	} while (0)

// HISTORY FIELDS
#define HISTORYDATEFLDS(_res, _row, _data, _ok) do { \
		char *_fld; \
		PQ_GET_FLD(_res, _row, CDDB, _fld, _ok); \
		if (!_ok) \
			break; \
		TXT_TO_TV(CDDB, _fld, (_data)->createdate); \
		PQ_GET_FLD(_res, _row, BYDB, _fld, _ok); \
		if (!_ok) \
			break; \
		TXT_TO_STR(BYDB, _fld, (_data)->createby); \
		PQ_GET_FLD(_res, _row, CODEDB, _fld, _ok); \
		if (!_ok) \
			break; \
		TXT_TO_STR(CODEDB, _fld, (_data)->createcode); \
		PQ_GET_FLD(_res, _row, INETDB, _fld, _ok); \
		if (!_ok) \
			break; \
		TXT_TO_STR(INETDB, _fld, (_data)->createinet); \
		PQ_GET_FLD(_res, _row, EDDB, _fld, _ok); \
		if (!_ok) \
			break; \
		TXT_TO_TV(EDDB, _fld, (_data)->expirydate); \
	} while (0)

#define HISTORYDATEPARAMS(_params, _his_pos, _row) do { \
		_params[_his_pos++] = tv_to_buf(&(_row->createdate), NULL, 0); \
		_params[_his_pos++] = str_to_buf(_row->createby, NULL, 0); \
		_params[_his_pos++] = str_to_buf(_row->createcode, NULL, 0); \
		_params[_his_pos++] = str_to_buf(_row->createinet, NULL, 0); \
		_params[_his_pos++] = tv_to_buf(&(_row->expirydate), NULL, 0); \
	} while (0)

// MODIFY FIELDS
#define MODIFYDATEFLDPOINTERS(_list, _res, _row, _data, _ok) do { \
		char *_fld; \
		PQ_GET_FLD(_res, _row, CDDB, _fld, _ok); \
		if (!_ok) \
			break; \
		TXT_TO_TV(CDDB, _fld, (_data)->createdate); \
		PQ_GET_FLD(_res, _row, BYDB, _fld, _ok); \
		if (!_ok) \
			break; \
		SET_CREATEBY(_list, (_data)->createby, _fld); \
		PQ_GET_FLD(_res, _row, CODEDB, _fld, _ok); \
		if (!_ok) \
			break; \
		SET_CREATECODE(_list, (_data)->createcode, _fld); \
		PQ_GET_FLD(_res, _row, INETDB, _fld, _ok); \
		if (!_ok) \
			break; \
		SET_CREATEINET(_list, (_data)->createinet, _fld); \
		PQ_GET_FLD(_res, _row, MDDB, _fld, _ok); \
		if (!_ok) \
			break; \
		TXT_TO_TV(MDDB, _fld, (_data)->modifydate); \
		PQ_GET_FLD(_res, _row, MBYDB, _fld, _ok); \
		if (!_ok) \
			break; \
		SET_MODIFYBY(_list, (_data)->modifyby, _fld); \
		PQ_GET_FLD(_res, _row, MCODEDB, _fld, _ok); \
		if (!_ok) \
			break; \
		SET_MODIFYCODE(_list, (_data)->modifycode, _fld); \
		PQ_GET_FLD(_res, _row, MINETDB, _fld, _ok); \
		if (!_ok) \
			break; \
		SET_MODIFYINET(_list, (_data)->modifyinet, _fld); \
	} while (0)

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

// SIMPLE FIELDS
#define SIMPLEDATEFLDS(_res, _row, _data, _ok) do { \
		char *_fld; \
		PQ_GET_FLD(_res, _row, CDDB, _fld, _ok); \
		if (!_ok) \
			break; \
		TXT_TO_TV(CDDB, _fld, (_data)->createdate); \
		PQ_GET_FLD(_res, _row, BYDB, _fld, _ok); \
		if (!_ok) \
			break; \
		TXT_TO_STR(BYDB, _fld, (_data)->createby); \
		PQ_GET_FLD(_res, _row, CODEDB, _fld, _ok); \
		if (!_ok) \
			break; \
		TXT_TO_STR(CODEDB, _fld, (_data)->createcode); \
		PQ_GET_FLD(_res, _row, INETDB, _fld, _ok); \
		if (!_ok) \
			break; \
		TXT_TO_STR(INETDB, _fld, (_data)->createinet); \
	} while (0)

#define SIMPLEDATEPARAMS(_params, _his_pos, _row) do { \
		_params[_his_pos++] = tv_to_buf(&(_row->createdate), NULL, 0); \
		_params[_his_pos++] = str_to_buf(_row->createby, NULL, 0); \
		_params[_his_pos++] = str_to_buf(_row->createcode, NULL, 0); \
		_params[_his_pos++] = str_to_buf(_row->createinet, NULL, 0); \
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
#define PQPARAM17 PQPARAM16 ",$17"
#define PQPARAM18 PQPARAM16 ",$17,$18"
#define PQPARAM22 PQPARAM16 ",$17,$18,$19,$20,$21,$22"
#define PQPARAM23 PQPARAM16 ",$17,$18,$19,$20,$21,$22,$23"
#define PQPARAM26 PQPARAM22 ",$23,$24,$25,$26"
#define PQPARAM27 PQPARAM26 ",$27"
#define PQPARAM28 PQPARAM26 ",$27,$28"

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

#undef PQexec
#undef PQexecParams

// Bug check to ensure no unexpected write txns occur
PGresult *_CKPQexec(PGconn *conn, const char *qry, bool isread, WHERE_FFL_ARGS)
{
	// It would slow it down, but could check qry for insert/update/...
	if (!isread && confirm_sharesummary)
		quitfrom(1, file, func, line, "BUG: write txn during confirm");

	return PQexec(conn, qry);
}

PGresult *_CKPQexecParams(PGconn *conn, const char *qry,
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

#define PQexec CKPQexec
#define PQexecParams CKPQexecParams

// TODO: switch all to use this
bool CKPQConn(PGconn **conn)
{
	if (*conn == NULL) {
		LOGDEBUG("%s(): connecting", __func__);
		*conn = dbconnect();
		return true;
	}
	return false;
}

// TODO: switch all to use this
void CKPQDisco(PGconn **conn, bool conned)
{
	if (conned) {
		LOGDEBUG("%s(): disco", __func__);
		PQfinish(*conn);
	}
}

// TODO: switch all to use this
bool _CKPQBegin(PGconn *conn, WHERE_FFL_ARGS)
{
	ExecStatusType rescode;
	PGresult *res;

	res = PQexec(conn, "Begin", CKPQ_WRITE);
	rescode = PQresultStatus(res);
	PQclear(res);
	if (!PGOK(rescode)) {
		char *buf = pqerrmsg(conn);
		LOGEMERG("%s(): Begin failed (%d) '%s'" WHERE_FFL,
			 __func__, (int)rescode, buf, WHERE_FFL_PASS);
		free(buf);
		return false;
	}
	LOGDEBUG("%s(): begin", __func__);
	return true;
}

// TODO: switch all to use this
void _CKPQEnd(PGconn *conn, bool commit, WHERE_FFL_ARGS)
{
	ExecStatusType rescode;
	PGresult *res;

	if (commit) {
		LOGDEBUG("%s(): commit", __func__);
		res = PQexec(conn, "Commit", CKPQ_WRITE);
	} else {
		LOGDEBUG("%s(): rollback", __func__);
		res = PQexec(conn, "Rollback", CKPQ_WRITE);
	}
	rescode = PQresultStatus(res);
	PQclear(res);
	if (!PGOK(rescode)) {
		char *buf = pqerrmsg(conn);
		LOGEMERG("%s(): %s failed (%d) '%s'" WHERE_FFL,
			 __func__, commit ? "commit" : "rollback",
			 (int)rescode, buf, WHERE_FFL_PASS);
		free(buf);
	}
}

int64_t nextid(PGconn *conn, char *idname, int64_t increment,
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
				   "lastid=$1,"MDDB"=$2,"MBYDB"=$3,"
				   MCODEDB"=$4,"MINETDB"=$5 "
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

// status was added to the end so type checking intercepts new mistakes
bool users_update(PGconn *conn, K_ITEM *u_item, char *oldhash,
		  char *newhash, char *email, char *by, char *code,
		  char *inet, tv_t *cd, K_TREE *trf_root, char *status)
{
	ExecStatusType rescode;
	bool conned = false;
	PGresult *res;
	K_ITEM *item;
	USERS *row, *users;
	char *upd, *ins;
	bool ok = false;
	char *params[6 + HISTORYDATECOUNT];
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
	copy_users(row, users);

	// Update each one supplied
	if (hash) {
		// New salt each password change
		make_salt(row);
		password_hash(row->username, newhash, row->salt,
			      row->passwordhash, sizeof(row->passwordhash));
	}
	if (email)
		STRNCPY(row->emailaddress, email);
	if (status)
		STRNCPY(row->status, status);

	HISTORYDATEINIT(row, cd, by, code, inet);
	HISTORYDATETRANSFER(trf_root, row);

	upd = "update users set "EDDB"=$1 where userid=$2 and "EDDB"=$3";
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
	// Copy them all in - at least one will be new
	params[par++] = str_to_buf(row->status, NULL, 0);
	params[par++] = str_to_buf(row->emailaddress, NULL, 0);
	params[par++] = str_to_buf(row->passwordhash, NULL, 0);
	// New salt for each password change (or recopy old)
	params[par++] = str_to_buf(row->salt, NULL, 0);
	HISTORYDATEPARAMS(params, par, row);
	PARCHKVAL(par, 6 + HISTORYDATECOUNT, params); // 11 as per ins

	ins = "insert into users "
		"(userid,username,status,emailaddress,joineddate,"
		"passwordhash,secondaryuserid,salt,userdata,userbits"
		HISTORYDATECONTROL ") select "
		"userid,username,$3,$4,joineddate,"
		"$5,secondaryuserid,$6,userdata,userbits,"
		"$7,$8,$9,$10,$11 from users where "
		"userid=$1 and "EDDB"=$2";

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
	if (!ok) {
		free_users_data(item);
		k_add_head(users_free, item);
	} else {
		remove_from_ktree(users_root, u_item);
		remove_from_ktree(userid_root, u_item);
		copy_tv(&(users->expirydate), cd);
		add_to_ktree(users_root, u_item);
		add_to_ktree(userid_root, u_item);

		add_to_ktree(users_root, item);
		add_to_ktree(userid_root, item);
		k_add_head(users_store, item);
	}
	K_WUNLOCK(users_free);

	return ok;
}

K_ITEM *users_add(PGconn *conn, char *username, char *emailaddress,
			char *passwordhash, int64_t userbits, char *by,
			char *code, char *inet, tv_t *cd, K_TREE *trf_root)
{
	ExecStatusType rescode;
	bool conned = false;
	PGresult *res;
	K_ITEM *item, *u_item;
	USERS *row, *users;
	char *ins;
	char tohash[64];
	uint64_t hash;
	__maybe_unused uint64_t tmp;
	bool dup, ok = false;
	char *params[10 + HISTORYDATECOUNT];
	int n, par = 0;

	LOGDEBUG("%s(): add", __func__);

	K_WLOCK(users_free);
	item = k_unlink_head(users_free);
	K_WUNLOCK(users_free);

	DATA_USERS(row, item);
	bzero(row, sizeof(*row));

	STRNCPY(row->username, username);
	username_trim(row);

	dup = false;
	K_RLOCK(users_free);
	u_item = STORE_RHEAD(users_store);
	while (u_item) {
		DATA_USERS(users, u_item);
		if (strcmp(row->usertrim, users->usertrim) == 0) {
			dup = true;
			break;
		}
		u_item = u_item->next;
	}
	K_RUNLOCK(users_free);

	if (dup)
		goto unitem;

	row->userid = nextid(conn, "userid", (int64_t)(666 + (random() % 334)),
				cd, by, code, inet);
	if (row->userid == 0)
		goto unitem;

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

	row->userdata = EMPTY;
	row->userbits = userbits;

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
	params[par++] = str_to_buf(row->userdata, NULL, 0);
	params[par++] = bigint_to_buf(row->userbits, NULL, 0);
	HISTORYDATEPARAMS(params, par, row);
	PARCHK(par, params);

	ins = "insert into users "
		"(userid,username,status,emailaddress,joineddate,passwordhash,"
		"secondaryuserid,salt,userdata,userbits"
		HISTORYDATECONTROL ") values (" PQPARAM15 ")";

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
	if (!ok) {
		free_users_data(item);
		k_add_head(users_free, item);
	} else {
		add_to_ktree(users_root, item);
		add_to_ktree(userid_root, item);
		k_add_head(users_store, item);
	}
	K_WUNLOCK(users_free);

	if (ok)
		return item;
	else
		return NULL;
}

// Replace the current users record with u_item, and expire the old one
bool users_replace(PGconn *conn, K_ITEM *u_item, K_ITEM *old_u_item, char *by,
		   char *code, char *inet, tv_t *cd, K_TREE *trf_root)
{
	ExecStatusType rescode;
	bool conned = false;
	PGresult *res;
	bool ok = false;
	USERS *users, *old_users;
	char *upd, *ins;
	char *params[10 + HISTORYDATECOUNT];
	int n, par = 0;

	LOGDEBUG("%s(): replace", __func__);

	DATA_USERS(users, u_item);
	DATA_USERS(old_users, old_u_item);

	HISTORYDATEINIT(users, cd, by, code, inet);
	HISTORYDATETRANSFER(trf_root, users);

	upd = "update users set "EDDB"=$1 where userid=$2 and "EDDB"=$3";
	par = 0;
	params[par++] = tv_to_buf(cd, NULL, 0);
	params[par++] = bigint_to_buf(old_users->userid, NULL, 0);
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
	params[par++] = bigint_to_buf(users->userid, NULL, 0);
	params[par++] = str_to_buf(users->username, NULL, 0);
	params[par++] = str_to_buf(users->status, NULL, 0);
	params[par++] = str_to_buf(users->emailaddress, NULL, 0);
	params[par++] = tv_to_buf(&(users->joineddate), NULL, 0);
	params[par++] = str_to_buf(users->passwordhash, NULL, 0);
	params[par++] = str_to_buf(users->secondaryuserid, NULL, 0);
	params[par++] = str_to_buf(users->salt, NULL, 0);
	params[par++] = str_to_buf(users->userdata, NULL, 0);
	params[par++] = bigint_to_buf(users->userbits, NULL, 0);
	HISTORYDATEPARAMS(params, par, users);
	PARCHKVAL(par, 10 + HISTORYDATECOUNT, params);

	ins = "insert into users "
		"(userid,username,status,emailaddress,joineddate,"
		"passwordhash,secondaryuserid,salt,userdata,userbits"
		HISTORYDATECONTROL ") values (" PQPARAM15 ")";

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
	if (!ok) {
		// cleanup done here
		free_users_data(u_item);
		k_add_head(users_free, u_item);
	} else {
		remove_from_ktree(users_root, old_u_item);
		remove_from_ktree(userid_root, old_u_item);
		copy_tv(&(old_users->expirydate), cd);
		add_to_ktree(users_root, old_u_item);
		add_to_ktree(userid_root, old_u_item);

		add_to_ktree(users_root, u_item);
		add_to_ktree(userid_root, u_item);
		k_add_head(users_store, u_item);
	}
	K_WUNLOCK(users_free);

	return ok;
}

bool users_fill(PGconn *conn)
{
	ExecStatusType rescode;
	PGresult *res;
	K_ITEM *item;
	int n, i;
	USERS *row;
	char *field;
	char *sel;
	int fields = 10;
	bool ok;

	LOGDEBUG("%s(): select", __func__);

	sel = "select "
		"userid,username,status,emailaddress,joineddate,"
		"passwordhash,secondaryuserid,salt,userdata,userbits"
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
		bzero(row, sizeof(*row));

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

		// TODO: good case for invariant
		PQ_GET_FLD(res, i, "userdata", field, ok);
		if (!ok)
			break;
		TXT_TO_PTR("userdata", field, row->userdata);
		LIST_MEM_ADD(users_free, row->userdata);
		users_databits(row);

		PQ_GET_FLD(res, i, "userbits", field, ok);
		if (!ok)
			break;
		TXT_TO_BIGINT("userbits", field, row->userbits);

		HISTORYDATEFLDS(res, i, row, ok);
		if (!ok)
			break;

		username_trim(row);

		add_to_ktree(users_root, item);
		add_to_ktree(userid_root, item);
		k_add_head(users_store, item);
	}
	if (!ok) {
		free_users_data(item);
		k_add_head(users_free, item);
	}

	K_WUNLOCK(users_free);
	PQclear(res);

	if (ok) {
		LOGDEBUG("%s(): built", __func__);
		LOGWARNING("%s(): loaded %d users records", __func__, n);
	}

	return ok;
}

bool useratts_item_add(PGconn *conn, K_ITEM *ua_item, tv_t *cd, bool begun)
{
	ExecStatusType rescode;
	bool conned = false;
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
		upd = "update useratts set "EDDB"=$1 where userid=$2 and "
			"attname=$3 and "EDDB"=$4";
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
			remove_from_ktree(useratts_root, old_item);
			copy_tv(&(old_useratts->expirydate), cd);
			add_to_ktree(useratts_root, old_item);
		}
		add_to_ktree(useratts_root, ua_item);
		k_add_head(useratts_store, ua_item);
	}
	K_WUNLOCK(useratts_free);

	return ok;
}

K_ITEM *useratts_add(PGconn *conn, char *username, char *attname,
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
	char *st = NULL;

	LOGDEBUG("%s(): add", __func__);

	K_WLOCK(useratts_free);
	item = k_unlink_head(useratts_free);
	K_WUNLOCK(useratts_free);
	DATA_USERATTS(row, item);
	bzero(row, sizeof(*row));

	K_RLOCK(users_free);
	u_item = find_users(username);
	K_RUNLOCK(users_free);
	if (!u_item) {
		LOGERR("%s(): unknown user '%s'",
			__func__,
			st = safe_text_nonull(username));
		FREENULL(st);
		goto unitem;
	}
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
		DATE_ZERO(&(row->attdate));
	else
		TXT_TO_TV("attdate", attdate, row->attdate);
	if (attdate2 == NULL || attdate2[0] == '\0')
		DATE_ZERO(&(row->attdate2));
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

bool useratts_item_expire(PGconn *conn, K_ITEM *ua_item, tv_t *cd)
{
	ExecStatusType rescode;
	bool conned = false;
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

		upd = "update useratts set "EDDB"=$1 where userid=$2 and "
			"attname=$3 and "EDDB"=$4";
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
		remove_from_ktree(useratts_root, item);
		copy_tv(&(useratts->expirydate), cd);
		add_to_ktree(useratts_root, item);
	}
	K_WUNLOCK(useratts_free);

	return ok;
}

bool useratts_fill(PGconn *conn)
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
		bzero(row, sizeof(*row));

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

		add_to_ktree(useratts_root, item);
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

K_ITEM *workers_add(PGconn *conn, int64_t userid, char *workername, bool add_ws,
			char *difficultydefault, char *idlenotificationenabled,
			char *idlenotificationtime, char *by, char *code,
			char *inet, tv_t *cd, K_TREE *trf_root)
{
	ExecStatusType rescode;
	bool conned = false;
	PGresult *res;
	K_ITEM *item, *ret = NULL;
	WORKERS *row;
	char *ins;
	char *params[7 + HISTORYDATECOUNT];
	int n, par = 0;
	int32_t diffdef;
	int32_t nottime;

	LOGDEBUG("%s(): add", __func__);

	/* Since shares can add workers and there's lotsa shares :) ...
	 *  and workers_add() and workers_fill() are the only places where
	 *  workers can be added, to ensure that the existence of the worker
	 *  hasn't changed, we check it again under a lock here that's unique
	 *  to workers_add() and workers_fill()
	 *   i.e. multiple threads trying to add the same worker will only end
	 *    up adding one and thus avoid wasted DB IO and avoid DB duplicate
	 *    errors */
	K_WLOCK(workers_db_free);

	ret = find_workers(false, userid, workername);
	if (ret)
		goto hadit;

	K_WLOCK(workers_free);
	item = k_unlink_head(workers_free);
	K_WUNLOCK(workers_free);

	DATA_WORKERS(row, item);

	if (conn == NULL) {
		conn = dbconnect();
		conned = true;
	}

	bzero(row, sizeof(*row));
	row->workerid = nextid(conn, "workerid", (int64_t)1, cd, by, code, inet);
	if (row->workerid == 0)
		goto unitem;

	row->userid = userid;
	STRNCPY(row->workername, workername);
	if (difficultydefault && *difficultydefault) {
		diffdef = atoi(difficultydefault);
		// If out of the range, set it in the range
		if (diffdef != DIFFICULTYDEFAULT_DEF) {
			if (diffdef < DIFFICULTYDEFAULT_MIN)
				diffdef = DIFFICULTYDEFAULT_MIN;
			if (diffdef > DIFFICULTYDEFAULT_MAX)
				diffdef = DIFFICULTYDEFAULT_MAX;
		}
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
		if (nottime != IDLENOTIFICATIONTIME_DEF) {
			// If out of the range, set to default
			if (nottime < IDLENOTIFICATIONTIME_MIN ||
			    nottime > IDLENOTIFICATIONTIME_MAX)
				nottime = IDLENOTIFICATIONTIME_DEF;
		}
		row->idlenotificationtime = nottime;
	} else
		row->idlenotificationtime = IDLENOTIFICATIONTIME_DEF;

	// Default is disabled
	if (row->idlenotificationtime == IDLENOTIFICATIONTIME_DEF)
		row->idlenotificationenabled[0] = IDLENOTIFICATIONDISABLED[0];

	row->workerbits = 0;

	HISTORYDATEINIT(row, cd, by, code, inet);
	HISTORYDATETRANSFER(trf_root, row);

	par = 0;
	params[par++] = bigint_to_buf(row->workerid, NULL, 0);
	params[par++] = bigint_to_buf(row->userid, NULL, 0);
	params[par++] = str_to_buf(row->workername, NULL, 0);
	params[par++] = int_to_buf(row->difficultydefault, NULL, 0);
	params[par++] = str_to_buf(row->idlenotificationenabled, NULL, 0);
	params[par++] = int_to_buf(row->idlenotificationtime, NULL, 0);
	params[par++] = bigint_to_buf(row->workerbits, NULL, 0);
	HISTORYDATEPARAMS(params, par, row);
	PARCHK(par, params);

	ins = "insert into workers "
		"(workerid,userid,workername,difficultydefault,"
		"idlenotificationenabled,idlenotificationtime,workerbits"
		HISTORYDATECONTROL ") values (" PQPARAM12 ")";

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
		add_to_ktree(workers_root, item);
		k_add_head(workers_store, item);
	}
	K_WUNLOCK(workers_free);

hadit:
	;
	K_WUNLOCK(workers_db_free);

	if (ret && add_ws) {
		/* Ensure there is a matching workerstatus
		 * WARNING - find_create_workerstatus() can call workers_add()!
		 *  The hasworker=true argument guarantees it wont and
		 *   add_ws=false above ensures it wont call back */
		find_create_workerstatus(false, false, userid, workername, true,
					 __FILE__, __func__, __LINE__);
	}

	return ret;
}

/* The assumption is that the worker already exists in the DB
 * and in the RAM tables and the item passed is already in the tree
 * Since there is no change to the key, there's no tree reorg required
 * check = false means just update it, ignore the passed char* vars */
bool workers_update(PGconn *conn, K_ITEM *item, char *difficultydefault,
			char *idlenotificationenabled,
			char *idlenotificationtime, char *by, char *code,
			char *inet, tv_t *cd, K_TREE *trf_root, bool check)
{
	ExecStatusType rescode;
	bool conned = false;
	PGresult *res;
	WORKERS *row;
	char *upd, *ins;
	bool ok = false;
	char *params[7 + HISTORYDATECOUNT];
	int n, par = 0;
	int32_t diffdef;
	char idlenot;
	int32_t nottime;

	LOGDEBUG("%s(): update", __func__);

	DATA_WORKERS(row, item);

	if (check) {
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

		if (diffdef == row->difficultydefault &&
		    idlenot == row->idlenotificationenabled[0] &&
		    nottime == row->idlenotificationtime) {
			ok = true;
			goto early;
		}

		row->difficultydefault = diffdef;
		row->idlenotificationenabled[0] = idlenot;
		row->idlenotificationenabled[1] = '\0';
		row->idlenotificationtime = nottime;
	}

	HISTORYDATEINIT(row, cd, by, code, inet);
	HISTORYDATETRANSFER(trf_root, row);

	upd = "update workers set "EDDB"=$1 where workerid=$2 and "EDDB"=$3";
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
		"idlenotificationenabled,idlenotificationtime,workerbits"
		HISTORYDATECONTROL ") values (" PQPARAM12 ")";

	par = 0;
	params[par++] = bigint_to_buf(row->workerid, NULL, 0);
	params[par++] = bigint_to_buf(row->userid, NULL, 0);
	params[par++] = str_to_buf(row->workername, NULL, 0);
	params[par++] = int_to_buf(row->difficultydefault, NULL, 0);
	params[par++] = str_to_buf(row->idlenotificationenabled, NULL, 0);
	params[par++] = int_to_buf(row->idlenotificationtime, NULL, 0);
	params[par++] = bigint_to_buf(row->workerbits, NULL, 0);
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

bool workers_fill(PGconn *conn)
{
	ExecStatusType rescode;
	PGresult *res;
	K_ITEM *item;
	int n, t, i;
	WORKERS *row;
	char *field;
	char *sel;
	int fields = 7;
	bool ok = false;

	LOGDEBUG("%s(): select", __func__);

	sel = "declare wk cursor for select "
		"userid,workername,difficultydefault,"
		"idlenotificationenabled,idlenotificationtime,workerbits"
		HISTORYDATECONTROL
		",workerid from workers";
	res = PQexec(conn, "Begin", CKPQ_READ);
	rescode = PQresultStatus(res);
	PQclear(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Begin", rescode, conn);
		return false;
	}

	// See workers_add() about this lock
	K_WLOCK(workers_db_free);

	res = PQexec(conn, sel, CKPQ_READ);
	rescode = PQresultStatus(res);
	PQclear(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Declare", rescode, conn);
		goto flail;
	}

	LOGDEBUG("%s(): fetching ...", __func__);

	res = PQexec(conn, "fetch 1 in wk", CKPQ_READ);
	rescode = PQresultStatus(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Fetch first", rescode, conn);
		PQclear(res);
		goto flail;
	}

	n = PQnfields(res);
	if (n != (fields + HISTORYDATECOUNT)) {
		LOGERR("%s(): Invalid field count - should be %d, but is %d",
			__func__, fields + HISTORYDATECOUNT, n);
		PQclear(res);
		goto flail;
	}

	n = 0;
	ok = true;
	while ((t = PQntuples(res)) > 0) {
		for (i = 0; i < t; i++) {
			K_WLOCK(workers_free);
			item = k_unlink_head(workers_free);
			K_WUNLOCK(workers_free);
			DATA_WORKERS(row, item);
			bzero(row, sizeof(*row));

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

			PQ_GET_FLD(res, i, "workerbits", field, ok);
			if (!ok)
				break;
			TXT_TO_BIGINT("workerbits", field, row->workerbits);

			HISTORYDATEFLDS(res, i, row, ok);
			if (!ok)
				break;

			PQ_GET_FLD(res, i, "workerid", field, ok);
			if (!ok)
				break;
			TXT_TO_BIGINT("workerid", field, row->workerid);

			K_WLOCK(workers_free);
			add_to_ktree(workers_root, item);
			k_add_head(workers_store, item);
			K_WUNLOCK(workers_free);

			// Make sure a workerstatus exists for each worker
			find_create_workerstatus(false, false, row->userid,
						 row->workername, true,
						 __FILE__, __func__, __LINE__);
			tick();
			n++;
		}
		PQclear(res);
		res = PQexec(conn, "fetch 9999 in wk", CKPQ_READ);
		rescode = PQresultStatus(res);
		if (!PGOK(rescode)) {
			PGLOGERR("Fetch next", rescode, conn);
			ok = false;
			break;
		}
	}
	if (!ok)
		k_add_head(workers_free, item);

	PQclear(res);
flail:
	res = PQexec(conn, "Commit", CKPQ_READ);
	PQclear(res);

	K_WUNLOCK(workers_db_free);

	if (ok) {
		LOGDEBUG("%s(): built", __func__);
		LOGWARNING("%s(): fetched %d workers records", __func__, n);
	}

	return ok;
}

// Absolute address limit
#define ABS_ADDR_LIMIT 999

/* Whatever the current paymentaddresses are, replace them with the list
 *  in pa_store
 * Code allows for zero, one or more current payment address */
bool paymentaddresses_set(PGconn *conn, int64_t userid, K_STORE *pa_store,
			  char *by, char *code, char *inet, tv_t *cd,
			  K_TREE *trf_root)
{
	ExecStatusType rescode;
	bool conned = false;
	PGresult *res;
	K_TREE_CTX ctx[1];
	K_ITEM *item, *match, *next, *prev;
	PAYMENTADDRESSES *row, *pa;
	char *upd = NULL, *ins;
	size_t len, off;
	bool ok = false, first, locked = false;
	char *params[ABS_ADDR_LIMIT+3];
	char tmp[1024];
	int n, par = 0, count, matches;

	LOGDEBUG("%s(): add", __func__);

	// Quick early abort
	if (pa_store->count > ABS_ADDR_LIMIT)
		return false;

	if (conn == NULL) {
		conn = dbconnect();
		conned = true;
	}

	/* This means the nextid updates will rollback on an error, but also
	 *  means that it will lock the nextid record for the whole update */
	res = PQexec(conn, "Begin", CKPQ_WRITE);
	rescode = PQresultStatus(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Begin", rescode, conn);
		goto unparam;
	}
	PQclear(res);

	// First step - DB expire all the old/changed records in RAM
	LOGDEBUG("%s(): Step 1 userid=%"PRId64, __func__, userid);
	count = matches = 0;
	APPEND_REALLOC_INIT(upd, off, len);
	APPEND_REALLOC(upd, off, len,
			"update paymentaddresses set "EDDB"=$1 where "
			"userid=$2 and "EDDB"=$3 and payaddress in (");
	par = 0;
	params[par++] = tv_to_buf(cd, NULL, 0);
	params[par++] = bigint_to_buf(userid, NULL, 0);
	params[par++] = tv_to_buf((tv_t *)&default_expiry, NULL, 0);

	/* Since we are merging the changes in rather than just
	 *  replacing the db contents, lock the data for the duration
	 *  of the update to ensure nothing else changes it
	 * N.B. 'payname' isn't the start of the key
	 *  thus 2 different addresses can have the same 'payname' */
	K_WLOCK(paymentaddresses_free);
	locked = true;

	first = true;
	item = find_paymentaddresses(userid, ctx);
	DATA_PAYMENTADDRESSES_NULL(row, item);
	while (item && CURRENT(&(row->expirydate)) && row->userid == userid) {
		/* This is only possible if the DB was directly updated with more
		 * than ABS_ADDR_LIMIT records then reloaded (or a code bug) */
		if (++count > ABS_ADDR_LIMIT)
			break;

		// Find the RAM record in pa_store
		match = STORE_HEAD_NOLOCK(pa_store);
		while (match) {
			DATA_PAYMENTADDRESSES(pa, match);
			if (strcmp(pa->payaddress, row->payaddress) == 0 &&
			    pa->payratio == row->payratio &&
			    strcmp(pa->payname, row->payname) == 0) {
				pa->match = true; // Don't store it
				matches++;
				break;
			}
			match = match->next;
		}
		if (!match) {
			// No matching replacement, so expire 'row'
			params[par++] = str_to_buf(row->payaddress, NULL, 0);
			if (!first)
				APPEND_REALLOC(upd, off, len, ",");
			first = false;
			snprintf(tmp, sizeof(tmp), "$%d", par);
			APPEND_REALLOC(upd, off, len, tmp);
		}
		item = prev_in_ktree(ctx);
		DATA_PAYMENTADDRESSES_NULL(row, item);
	}
	LOGDEBUG("%s(): Step 1 par=%d count=%d matches=%d first=%s", __func__,
		 par, count, matches, TFSTR(first));
	// Too many, or none need expiring = don't do the update
	if (count > ABS_ADDR_LIMIT || first == true) {
		for (n = 0; n < par; n++)
			free(params[n]);
		par = 0;
		// Too many
		if (count > ABS_ADDR_LIMIT)
			goto rollback;
	} else {
		APPEND_REALLOC(upd, off, len, ")");
		PARCHKVAL(par, par, params);
		res = PQexecParams(conn, upd, par, NULL, (const char **)params, NULL, NULL, 0, CKPQ_WRITE);
		rescode = PQresultStatus(res);
		PQclear(res);
		if (!PGOK(rescode)) {
			PGLOGERR("Update", rescode, conn);
			goto rollback;
		}

		LOGDEBUG("%s(): Step 1 expired %d", __func__, par-3);

		for (n = 0; n < par; n++)
			free(params[n]);
		par = 0;
	}

	// Second step - add the non-matching records to the DB
	LOGDEBUG("%s(): Step 2", __func__);
	ins = "insert into paymentaddresses "
		"(paymentaddressid,userid,payaddress,payratio,payname"
		HISTORYDATECONTROL ") values (" PQPARAM10 ")";

	count = 0;
	match = STORE_HEAD_NOLOCK(pa_store);
	while (match) {
		DATA_PAYMENTADDRESSES(row, match);
		if (!row->match) {
			row->paymentaddressid = nextid(conn, "paymentaddressid", 1,
							cd, by, code, inet);
			if (row->paymentaddressid == 0)
				goto rollback;

			row->userid = userid;

			HISTORYDATEINIT(row, cd, by, code, inet);
			HISTORYDATETRANSFER(trf_root, row);

			par = 0;
			params[par++] = bigint_to_buf(row->paymentaddressid, NULL, 0);
			params[par++] = bigint_to_buf(row->userid, NULL, 0);
			params[par++] = str_to_buf(row->payaddress, NULL, 0);
			params[par++] = int_to_buf(row->payratio, NULL, 0);
			params[par++] = str_to_buf(row->payname, NULL, 0);
			HISTORYDATEPARAMS(params, par, row);
			PARCHKVAL(par, 10, params); // As per PQPARAM10 above

			res = PQexecParams(conn, ins, par, NULL, (const char **)params,
					   NULL, NULL, 0, CKPQ_WRITE);
			rescode = PQresultStatus(res);
			PQclear(res);
			if (!PGOK(rescode)) {
				PGLOGERR("Insert", rescode, conn);
				goto rollback;
			}

			for (n = 0; n < par; n++)
				free(params[n]);
			par = 0;

			count++;
		}
		match = match->next;
	}
	LOGDEBUG("%s(): Step 2 inserted %d", __func__, count);

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
	FREENULL(upd);
	// Third step - do step 1 and 2 to the RAM version of the DB
	LOGDEBUG("%s(): Step 3, ok=%s", __func__, TFSTR(ok));
	matches = count = n = 0;
	if (ok) {
		// Change the expiry on all records that we expired in the DB
		item = find_paymentaddresses(userid, ctx);
		DATA_PAYMENTADDRESSES_NULL(row, item);
		while (item && CURRENT(&(row->expirydate)) && row->userid == userid) {
			prev = prev_in_ktree(ctx);
			// Find the RAM record in pa_store
			match = STORE_HEAD_NOLOCK(pa_store);
			while (match) {
				DATA_PAYMENTADDRESSES(pa, match);
				if (strcmp(pa->payaddress, row->payaddress) == 0 &&
				    pa->payratio == row->payratio &&
				    strcmp(pa->payname, row->payname) == 0) {
					break;
				}
				match = match->next;
			}
			if (match)
				matches++;
			else {
				// It wasn't a match, thus it was expired
				n++;
				remove_from_ktree(paymentaddresses_root, item);
				remove_from_ktree(paymentaddresses_create_root, item);
				copy_tv(&(row->expirydate), cd);
				add_to_ktree(paymentaddresses_root, item);
				add_to_ktree(paymentaddresses_create_root, item);
			}
			item = prev;
			DATA_PAYMENTADDRESSES_NULL(row, item);
		}

		// Add in all the non-matching ps_store
		match = STORE_HEAD_NOLOCK(pa_store);
		while (match) {
			next = match->next;
			DATA_PAYMENTADDRESSES(pa, match);
			if (!pa->match) {
				add_to_ktree(paymentaddresses_root, match);
				add_to_ktree(paymentaddresses_create_root, match);
				k_unlink_item(pa_store, match);
				k_add_head(paymentaddresses_store, match);
				count++;
			}
			match = next;
		}
	}
	if (locked)
		K_WUNLOCK(paymentaddresses_free);

	LOGDEBUG("%s(): Step 3, untouched %d expired %d added %d", __func__, matches, n, count);

	// Calling function must clean up anything left in pa_store
	return ok;
}

bool paymentaddresses_fill(PGconn *conn)
{
	ExecStatusType rescode;
	PGresult *res;
	K_ITEM *item;
	PAYMENTADDRESSES *row;
	int n, i;
	char *field;
	char *sel;
	int fields = 5;
	bool ok;

	LOGDEBUG("%s(): select", __func__);

	sel = "select "
		"paymentaddressid,userid,payaddress,payratio,payname"
		HISTORYDATECONTROL
		" from paymentaddresses";
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
	K_WLOCK(paymentaddresses_free);
	for (i = 0; i < n; i++) {
		item = k_unlink_head(paymentaddresses_free);
		DATA_PAYMENTADDRESSES(row, item);
		bzero(row, sizeof(*row));

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

		PQ_GET_FLD(res, i, "payname", field, ok);
		if (!ok)
			break;
		TXT_TO_STR("payname", field, row->payname);

		HISTORYDATEFLDS(res, i, row, ok);
		if (!ok)
			break;

		add_to_ktree(paymentaddresses_root, item);
		add_to_ktree(paymentaddresses_create_root, item);
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

// The timing of the memory table updates depends on 'already'
void payments_add_ram(bool ok, K_ITEM *p_item, K_ITEM *old_p_item, tv_t *cd)
{
	PAYMENTS *oldp;

	LOGDEBUG("%s(): ok %c", __func__, ok ? 'Y' : 'N');

	K_WLOCK(payments_free);
	if (!ok) {
		// Cleanup for the calling function
		k_add_head(payments_free, p_item);
	} else {
		if (old_p_item) {
			DATA_PAYMENTS(oldp, old_p_item);
			remove_from_ktree(payments_root, old_p_item);
			copy_tv(&(oldp->expirydate), cd);
			add_to_ktree(payments_root, old_p_item);
		}
		add_to_ktree(payments_root, p_item);
		k_add_head(payments_store, p_item);
	}
	K_WUNLOCK(payments_free);
}

/* Add means create a new one and expire the old one if it exists,
 *  otherwise we only expire the old one if it exists
 * It's the calling functions job to determine if a new one is required
 *  - i.e. if there is a difference between the old and new
 * already = already begun a transaction - and don't update the ram table */
bool payments_add(PGconn *conn, bool add, K_ITEM *p_item, K_ITEM **old_p_item,
		  char *by, char *code, char *inet, tv_t *cd, K_TREE *trf_root,
		  bool already)
{
	ExecStatusType rescode;
	bool conned = false;
	PGresult *res;
	bool ok = false, begun = false;
	PAYMENTS *row, *oldp = NULL;
	char *upd, *ins;
	char *params[11 + HISTORYDATECOUNT];
	int n, par = 0;

	LOGDEBUG("%s(): add %c already %c", __func__,
		 add ? 'Y' : 'N', already ? 'Y' : 'N');

	DATA_PAYMENTS(row, p_item);
	K_RLOCK(payments_free);
	*old_p_item = find_payments(row->payoutid, row->userid, row->subname);
	K_RUNLOCK(payments_free);

	conned = CKPQConn(&conn);
	if (!already) {
		begun = CKPQBegin(conn);
		if (!begun)
			goto unparam;
	}
		
	if (*old_p_item) {
		LOGDEBUG("%s(): updating old", __func__);

		DATA_PAYMENTS(oldp, *old_p_item);

		upd = "update payments set "EDDB"=$1 where paymentid=$2"
			" and "EDDB"=$3";
		par = 0;
		params[par++] = tv_to_buf(cd, NULL, 0);
		params[par++] = bigint_to_buf(oldp->paymentid, NULL, 0);
		params[par++] = tv_to_buf((tv_t *)&default_expiry, NULL, 0);
		PARCHKVAL(par, 3, params);

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

		// Expiring an old record
		row->paymentid = oldp->paymentid;
	} else {
		if (add) {
			// Creating a new record
			row->paymentid = nextid(conn, "paymentid", (int64_t)1, cd, by, code, inet);
			if (row->paymentid == 0)
				goto rollback;
		}
	}

	if (add) {
		LOGDEBUG("%s(): adding new", __func__);

		HISTORYDATEINIT(row, cd, by, code, inet);
		HISTORYDATETRANSFER(trf_root, row);

		par = 0;
		params[par++] = bigint_to_buf(row->paymentid, NULL, 0);
		params[par++] = bigint_to_buf(row->payoutid, NULL, 0);
		params[par++] = bigint_to_buf(row->userid, NULL, 0);
		params[par++] = str_to_buf(row->subname, NULL, 0);
		params[par++] = tv_to_buf(&(row->paydate), NULL, 0);
		params[par++] = str_to_buf(row->payaddress, NULL, 0);
		params[par++] = str_to_buf(row->originaltxn, NULL, 0);
		params[par++] = bigint_to_buf(row->amount, NULL, 0);
		params[par++] = double_to_buf(row->diffacc, NULL, 0);
		params[par++] = str_to_buf(row->committxn, NULL, 0);
		params[par++] = str_to_buf(row->commitblockhash, NULL, 0);
		HISTORYDATEPARAMS(params, par, row);
		PARCHK(par, params);

		ins = "insert into payments "
			"(paymentid,payoutid,userid,subname,paydate,payaddress,"
			"originaltxn,amount,diffacc,committxn,commitblockhash"
			HISTORYDATECONTROL ") values (" PQPARAM16 ")";

		res = PQexecParams(conn, ins, par, NULL, (const char **)params, NULL, NULL, 0, CKPQ_WRITE);
		rescode = PQresultStatus(res);
		if (!PGOK(rescode)) {
			PGLOGERR("Insert", rescode, conn);
			goto unparam;
		}
	}

	ok = true;
rollback:
	if (begun)
		CKPQEnd(conn, ok);
unparam:
	for (n = 0; n < par; n++)
		free(params[n]);

	CKPQDisco(&conn, conned);

	if (!already)
		payments_add_ram(ok, p_item, *old_p_item, cd);

	return ok;
}

bool payments_fill(PGconn *conn)
{
	ExecStatusType rescode;
	PGresult *res;
	K_ITEM *item;
	PAYMENTS *row;
	int n, t, i;
	char *field;
	char *sel;
	int fields = 11;
	bool ok = false;

	LOGDEBUG("%s(): select", __func__);

	sel = "declare ps cursor for select "
		"paymentid,payoutid,userid,subname,paydate,payaddress,"
		"originaltxn,amount,diffacc,committxn,commitblockhash"
		HISTORYDATECONTROL
		" from payments";
	res = PQexec(conn, "Begin", CKPQ_READ);
	rescode = PQresultStatus(res);
	PQclear(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Begin", rescode, conn);
		return false;
	}

	res = PQexec(conn, sel, CKPQ_READ);
	rescode = PQresultStatus(res);
	PQclear(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Declare", rescode, conn);
		goto flail;
	}

	LOGDEBUG("%s(): fetching ...", __func__);

	res = PQexec(conn, "fetch 1 in ps", CKPQ_READ);
	rescode = PQresultStatus(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Fetch first", rescode, conn);
		PQclear(res);
		goto flail;
	}

	n = PQnfields(res);
	if (n != (fields + HISTORYDATECOUNT)) {
		LOGERR("%s(): Invalid field count - should be %d, but is %d",
			__func__, fields + HISTORYDATECOUNT, n);
		PQclear(res);
		goto flail;
	}

	n = 0;
	ok = true;
	K_WLOCK(payments_free);
	while ((t = PQntuples(res)) > 0) {
		for (i = 0; i < t; i++) {
			item = k_unlink_head(payments_free);
			DATA_PAYMENTS(row, item);
			bzero(row, sizeof(*row));

			if (everyone_die) {
				ok = false;
				break;
			}

			PQ_GET_FLD(res, i, "paymentid", field, ok);
			if (!ok)
				break;
			TXT_TO_BIGINT("paymentid", field, row->paymentid);

			PQ_GET_FLD(res, i, "payoutid", field, ok);
			if (!ok)
				break;
			TXT_TO_BIGINT("payoutid", field, row->payoutid);

			PQ_GET_FLD(res, i, "userid", field, ok);
			if (!ok)
				break;
			TXT_TO_BIGINT("userid", field, row->userid);

			PQ_GET_FLD(res, i, "subname", field, ok);
			if (!ok)
				break;
			TXT_TO_STR("subname", field, row->subname);

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

			PQ_GET_FLD(res, i, "diffacc", field, ok);
			if (!ok)
				break;
			TXT_TO_DOUBLE("diffacc", field, row->diffacc);

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

			add_to_ktree(payments_root, item);
			k_add_head(payments_store, item);
			tick();
			n++;
		}
		PQclear(res);
		res = PQexec(conn, "fetch 9999 in ps", CKPQ_READ);
		rescode = PQresultStatus(res);
		if (!PGOK(rescode)) {
			PGLOGERR("Fetch next", rescode, conn);
			ok = false;
			break;
		}
	}
	if (!ok)
		k_add_head(payments_free, item);

	K_WUNLOCK(payments_free);
	PQclear(res);
flail:
	res = PQexec(conn, "Commit", CKPQ_READ);
	PQclear(res);

	if (ok) {
		LOGDEBUG("%s(): built", __func__);
		LOGWARNING("%s(): fetched %d payments records", __func__, n);
	}

	return ok;
}

bool idcontrol_add(PGconn *conn, char *idname, char *idvalue, char *by,
		   char *code, char *inet, tv_t *cd,
		   __maybe_unused K_TREE *trf_root)
{
	K_ITEM *look;
	IDCONTROL *row;
	char *params[2 + MODIFYDATECOUNT];
	int n, par = 0;
	bool ok = false;
	ExecStatusType rescode;
	bool conned = false;
	PGresult *res;
	char *ins;

	LOGDEBUG("%s(): add", __func__);

	K_WLOCK(idcontrol_free);
	look = k_unlink_head(idcontrol_free);
	K_WUNLOCK(idcontrol_free);

	DATA_IDCONTROL(row, look);

	STRNCPY(row->idname, idname);
	TXT_TO_BIGINT("idvalue", idvalue, row->lastid);
	MODIFYDATEINIT(row, cd, by, code, inet);

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
	PQclear(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Insert", rescode, conn);
		goto foil;
	}

	ok = true;
foil:
	if (conned)
		PQfinish(conn);
	for (n = 0; n < par; n++)
		free(params[n]);

	K_WLOCK(idcontrol_free);
	k_add_head(idcontrol_free, look);
	K_WUNLOCK(idcontrol_free);

	return ok;
}

K_ITEM *optioncontrol_item_add(PGconn *conn, K_ITEM *oc_item, tv_t *cd, bool begun)
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

	// Enforce the rule that switch_state isn't date/height controlled
	if (strcmp(row->optionname, SWITCH_STATE_NAME) == 0) {
		row->activationdate.tv_sec = date_begin.tv_sec;
		row->activationdate.tv_usec = date_begin.tv_usec;
		row->activationheight = OPTIONCONTROL_HEIGHT;
	}

	// Update if it's changed
	if (strcmp(row->optionname, DIFF_PERCENT_NAME) == 0) {
		diff_percent = DIFF_VAL(strtod(row->optionvalue, NULL));
		if (errno == ERANGE)
			diff_percent = DIFF_VAL(DIFF_PERCENT_DEFAULT);
	}

	INIT_OPTIONCONTROL(&look);
	look.data = (void *)row;
	K_RLOCK(optioncontrol_free);
	old_item = find_in_ktree(optioncontrol_root, &look, ctx);
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
			"set "EDDB"=$1 where optionname=$2 and "
			"activationdate=$3 and activationheight=$4 and "
			EDDB"=$5";

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
	if (!ok) {
		// Cleanup item passed in
		free_optioncontrol_data(oc_item);
		k_add_head(optioncontrol_free, oc_item);
	} else {
		// Discard old
		if (old_item) {
			remove_from_ktree(optioncontrol_root, old_item);
			k_unlink_item(optioncontrol_store, old_item);
			free_optioncontrol_data(old_item);
			k_add_head(optioncontrol_free, old_item);
		}
		add_to_ktree(optioncontrol_root, oc_item);
		k_add_head(optioncontrol_store, oc_item);
		if (strcmp(row->optionname, SWITCH_STATE_NAME) == 0) {
			switch_state = atoi(row->optionvalue);
			LOGWARNING("%s() set switch_state to %d",
				   __func__, switch_state);
		}
	}
	K_WUNLOCK(optioncontrol_free);

	if (ok)
		return oc_item;
	else
		return NULL;
}

K_ITEM *optioncontrol_add(PGconn *conn, char *optionname, char *optionvalue,
			  char *activationdate, char *activationheight,
			  char *by, char *code, char *inet, tv_t *cd,
			  K_TREE *trf_root, bool begun)
{
	K_ITEM *item;
	OPTIONCONTROL *row;

	LOGDEBUG("%s(): add", __func__);

	K_WLOCK(optioncontrol_free);
	item = k_unlink_head(optioncontrol_free);
	K_WUNLOCK(optioncontrol_free);

	DATA_OPTIONCONTROL(row, item);
	bzero(row, sizeof(*row));

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
		row->activationheight = OPTIONCONTROL_HEIGHT;

	HISTORYDATEINIT(row, cd, by, code, inet);
	HISTORYDATETRANSFER(trf_root, row);

	return optioncontrol_item_add(conn, item, cd, begun);
}

bool optioncontrol_fill(PGconn *conn)
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
		" from optioncontrol where "EDDB"=$1";
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
		bzero(row, sizeof(*row));

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
		LIST_MEM_ADD(optioncontrol_free, row->optionvalue);

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

		add_to_ktree(optioncontrol_root, item);
		k_add_head(optioncontrol_store, item);

		// There should only be one CURRENT version of switch_state
		if (CURRENT(&(row->expirydate)) &&
		    strcmp(row->optionname, SWITCH_STATE_NAME) == 0) {
			switch_state = atoi(row->optionvalue);
			LOGWARNING("%s() set switch_state to %d",
				   __func__, switch_state);
		}

		// The last loaded CURRENT value will be used
		if (CURRENT(&(row->expirydate)) &&
		    strcmp(row->optionname, DIFF_PERCENT_NAME) == 0) {
			diff_percent = DIFF_VAL(strtod(row->optionvalue, NULL));
			if (errno == ERANGE)
				diff_percent = DIFF_VAL(DIFF_PERCENT_DEFAULT);
		}
	}
	if (!ok) {
		free_optioncontrol_data(item);
		k_add_head(optioncontrol_free, item);
	}

	K_WUNLOCK(optioncontrol_free);
	PQclear(res);

	if (ok) {
		LOGDEBUG("%s(): built", __func__);
		LOGWARNING("%s(): loaded %d optioncontrol records", __func__, n);
		LOGWARNING("%s() switch_state initially %d",
			   __func__, switch_state);
	}

	return ok;
}

int64_t workinfo_add(PGconn *conn, char *workinfoidstr, char *poolinstance,
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
	bool zero_active = false;

	LOGDEBUG("%s(): add", __func__);

	K_WLOCK(workinfo_free);
	item = k_unlink_head(workinfo_free);
	K_WUNLOCK(workinfo_free);

	DATA_WORKINFO(row, item);
	bzero(row, sizeof(*row));

	TXT_TO_BIGINT("workinfoid", workinfoidstr, row->workinfoid);
	STRNCPY(row->poolinstance, poolinstance);
	DUP_POINTER(workinfo_free, row->transactiontree, transactiontree);
	DUP_POINTER(workinfo_free, row->merklehash, merklehash);
	STRNCPY(row->prevhash, prevhash);
	STRNCPY(row->coinbase1, coinbase1);
	STRNCPY(row->coinbase2, coinbase2);
	STRNCPY(row->version, version);
	STRNCPY(row->bits, bits);
	STRNCPY(row->ntime, ntime);
	TXT_TO_BIGINT("reward", reward, row->reward);
	pool.reward = row->reward;

	HISTORYDATEINIT(row, cd, by, code, inet);
	HISTORYDATETRANSFER(trf_root, row);

	K_WLOCK(workinfo_free);
	if (find_in_ktree(workinfo_root, item, ctx)) {
		workinfoid = row->workinfoid;
		free_workinfo_data(item);
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
		free_workinfo_data(item);
		k_add_head(workinfo_free, item);
	} else {
		// Not currently needed in RAM
		LIST_MEM_SUB(workinfo_free, row->transactiontree);
		FREENULL(row->transactiontree);

		row->height = coinbase1height(row);
		hex2bin(ndiffbin, row->bits, 4);
		row->diff_target = current_ndiff = diff_from_nbits(ndiffbin);

		add_to_ktree(workinfo_root, item);
		k_add_head(workinfo_store, item);

		// Remember the bc = 'cd' when the height changes
		if (workinfo_current) {
			WORKINFO *wic;
			DATA_WORKINFO(wic, workinfo_current);
			if (wic->height != row->height) {
				copy_tv(&last_bc, cd);
				zero_active = true;
			}
		}

		workinfo_current = item;
	}
	K_WUNLOCK(workinfo_free);

	if (zero_active)
		zero_all_active(cd);

	return workinfoid;
}

bool workinfo_fill(PGconn *conn)
{
	char ndiffbin[TXT_SML+1];
	ExecStatusType rescode;
	PGresult *res;
	K_ITEM *item;
	WORKINFO *row;
	char *params[3];
	int n, t, i, par = 0;
	char *field;
	char *sel = NULL;
	size_t len, off;
	int fields = 10;
	bool ok = false;

	LOGDEBUG("%s(): select", __func__);

	printf(TICK_PREFIX"wi 0\r");
	fflush(stdout);

	// TODO: select the data based on sharesummary since old data isn't needed
	//  however, the ageing rules for workinfo will decide that also
	//  keep the last block + current? Rules will depend on payout scheme also

	APPEND_REALLOC_INIT(sel, off, len);
	APPEND_REALLOC(sel, off, len,
			"declare wi cursor for select "
//			"workinfoid,poolinstance,transactiontree,merklehash,prevhash,"
			"workinfoid,poolinstance,merklehash,prevhash,"
			"coinbase1,coinbase2,version,bits,ntime,reward"
			HISTORYDATECONTROL
			" from workinfo where "EDDB"=$1 and"
			" ((workinfoid>=$2 and workinfoid<=$3)");

	// If we aren't loading the full range, ensure the necessary ones are loaded
	if ((!dbload_only_sharesummary && dbload_workinfoid_start != -1) ||
	    dbload_workinfoid_finish != MAXID) {
		APPEND_REALLOC(sel, off, len,
				// we need all blocks workinfoids
				" or workinfoid in (select workinfoid from blocks)"
				// we need all marks workinfoids
				" or workinfoid in (select workinfoid from marks)"
				// we need all workmarkers workinfoids (start and end)
				" or workinfoid in (select workinfoidstart from workmarkers)"
				" or workinfoid in (select workinfoidend from workmarkers)");
	}
	APPEND_REALLOC(sel, off, len, ")");

	par = 0;
	params[par++] = tv_to_buf((tv_t *)(&default_expiry), NULL, 0);
	if (dbload_only_sharesummary)
		params[par++] = bigint_to_buf(-1, NULL, 0);
	else
		params[par++] = bigint_to_buf(dbload_workinfoid_start, NULL, 0);
	params[par++] = bigint_to_buf(dbload_workinfoid_finish, NULL, 0);
	PARCHK(par, params);

	res = PQexec(conn, "Begin", CKPQ_READ);
	rescode = PQresultStatus(res);
	PQclear(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Begin", rescode, conn);
		return false;
	}

	res = PQexecParams(conn, sel, par, NULL, (const char **)params, NULL, NULL, 0, CKPQ_READ);
	rescode = PQresultStatus(res);
	PQclear(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Declare", rescode, conn);
		goto flail;
	}

	LOGDEBUG("%s(): fetching ...", __func__);

	res = PQexec(conn, "fetch 1 in wi", CKPQ_READ);
	rescode = PQresultStatus(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Fetch first", rescode, conn);
		PQclear(res);
		goto flail;
	}

	n = PQnfields(res);
	if (n != (fields + HISTORYDATECOUNT)) {
		LOGERR("%s(): Invalid field count - should be %d, but is %d",
			__func__, fields + HISTORYDATECOUNT, n);
		PQclear(res);
		goto flail;
	}

	n = 0;
	ok = true;
	K_WLOCK(workinfo_free);
	while ((t = PQntuples(res)) > 0) {
		for (i = 0; i < t; i++) {
			item = k_unlink_head(workinfo_free);
			DATA_WORKINFO(row, item);
			bzero(row, sizeof(*row));

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
			LIST_MEM_ADD(workinfo_free, row->transactiontree);
*/
			row->transactiontree = EMPTY;

			PQ_GET_FLD(res, i, "merklehash", field, ok);
			if (!ok)
				break;
			TXT_TO_BLOB("merklehash", field, row->merklehash);
			LIST_MEM_ADD(workinfo_free, row->merklehash);

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
			pool.reward = row->reward;

			HISTORYDATEFLDS(res, i, row, ok);
			if (!ok)
				break;

			row->height = coinbase1height(row);
			hex2bin(ndiffbin, row->bits, 4);
			row->diff_target = diff_from_nbits(ndiffbin);

			add_to_ktree(workinfo_root, item);
			if (!confirm_sharesummary)
				add_to_ktree(workinfo_height_root, item);
			k_add_head(workinfo_store, item);

			if (tv_newer(&(dbstatus.newest_createdate_workinfo), &(row->createdate))) {
				copy_tv(&(dbstatus.newest_createdate_workinfo), &(row->createdate));
				dbstatus.newest_workinfoid = row->workinfoid;
			}

			if (n == 0 || ((n+1) % 100000) == 0) {
				printf(TICK_PREFIX"wi ");
				pcom(n+1);
				putchar('\r');
				fflush(stdout);
			}
			tick();
			n++;
		}
		PQclear(res);
		res = PQexec(conn, "fetch 9999 in wi", CKPQ_READ);
		rescode = PQresultStatus(res);
		if (!PGOK(rescode)) {
			PGLOGERR("Fetch next", rescode, conn);
			ok = false;
			break;
		}
	}
	if (!ok) {
		free_workinfo_data(item);
		k_add_head(workinfo_free, item);
	} else {
		K_WLOCK(blocks_free);
		ok = set_prevcreatedate(0);
		K_WUNLOCK(blocks_free);
	}

	K_WUNLOCK(workinfo_free);
	PQclear(res);
flail:
	res = PQexec(conn, "Commit", CKPQ_READ);
	PQclear(res);


	if (ok) {
		LOGDEBUG("%s(): built", __func__);
		LOGWARNING("%s(): fetched %d workinfo records", __func__, n);
	}

	return ok;
}

static bool shares_process(PGconn *conn, SHARES *shares, K_ITEM *wi_item,
			   K_TREE *trf_root)
{
	K_ITEM *w_item, *wm_item, *ss_item;
	SHARESUMMARY *sharesummary;
	WORKINFO *workinfo;
	char *st = NULL;

	LOGDEBUG("%s() add", __func__);

	if (diff_percent >= 0.0) {
		DATA_WORKINFO(workinfo, wi_item);
		if (shares->sdiff >= (workinfo->diff_target * diff_percent)) {
			bool block = (shares->sdiff >= workinfo->diff_target);
			char *sta = NULL, pct[16] = "?", est[16] = "";
			switch (shares->errn) {
				case SE_NONE:
					break;
				case SE_STALE:
					sta = "STALE";
					break;
				case SE_DUPE:
					sta = "Dup";
					break;
				case SE_HIGH_DIFF:
					sta = "HI";
					break;
				default:
					sta = "UNKNOWN";
					break;
			}
			if (pool.diffacc >= 1000.0) {
				est[0] = ' ';
				suffix_string(pool.diffacc, est+1, sizeof(est)-2, 0);
			}
			if (workinfo->diff_target > 0.0) {
				snprintf(pct, sizeof(pct), " %.2f%%",
					 100.0 * pool.diffacc /
					 workinfo->diff_target);
			}
			LOGWARNING("%s %s Diff %.1f%% (%.0f/%.1f) %s "
				   "Pool %.1f%s%s",
				   block ? "BLOCK!" : "Share",
				   (sta == NULL) ? "ok" : sta,
				   100.0 * shares->sdiff / workinfo->diff_target,
				   shares->sdiff, workinfo->diff_target,
				   st = safe_text_nonull(shares->workername),
				   pool.diffacc, est, pct);
			FREENULL(st);
		}
	}

	w_item = new_default_worker(conn, false, shares->userid,
				    shares->workername, shares->createby,
				    shares->createcode, shares->createinet,
				    &(shares->createdate), trf_root);
	if (!w_item) {
		LOGDEBUG("%s(): new_default_worker failed %"PRId64"/%s/%ld,%ld",
			 __func__, shares->userid,
			 st = safe_text_nonull(shares->workername),
			 shares->createdate.tv_sec, shares->createdate.tv_usec);
		FREENULL(st);
		return false;
	}

	if (reloading && !confirm_sharesummary) {
		// We only need to know if the workmarker is processed
		K_RLOCK(workmarkers_free);
		wm_item = find_workmarkers(shares->workinfoid, false,
					   MARKER_PROCESSED, NULL);
		K_RUNLOCK(workmarkers_free);
		if (wm_item) {
			LOGDEBUG("%s(): workmarker exists for wid %"PRId64
				 " %"PRId64"/%s/%ld,%ld",
				 __func__, shares->workinfoid, shares->userid,
				 st = safe_text_nonull(shares->workername),
				 shares->createdate.tv_sec,
				 shares->createdate.tv_usec);
			FREENULL(st);
			return false;
		}

		K_RLOCK(sharesummary_free);
		ss_item = find_sharesummary(shares->userid, shares->workername,
					    shares->workinfoid);
		K_RUNLOCK(sharesummary_free);
		if (ss_item) {
			DATA_SHARESUMMARY(sharesummary, ss_item);
			if (sharesummary->complete[0] != SUMMARY_NEW) {
				LOGDEBUG("%s(): '%s' sharesummary exists "
					 "%"PRId64" %"PRId64"/%s/%ld,%ld",
					 __func__, sharesummary->complete,
					 shares->workinfoid, shares->userid,
					 st = safe_text_nonull(shares->workername),
					 shares->createdate.tv_sec,
					 shares->createdate.tv_usec);
				FREENULL(st);
				// Reloading a share already summarised
				return true;
			}
		}
	}

	if (!confirm_sharesummary) {
		workerstatus_update(NULL, shares, NULL);
		K_WLOCK(userinfo_free);
		userinfo_update(shares, NULL, NULL, false);
		K_WUNLOCK(userinfo_free);
	}

	sharesummary_update(shares, NULL, shares->createby, shares->createcode,
			    shares->createinet, &(shares->createdate));

	return true;
}

// If it exists and it can be processed, process the oldest early share
static void shares_process_early(PGconn *conn, K_ITEM *wi, tv_t *good_cd,
				 K_TREE *trf_root)
{
	K_TREE_CTX ctx[1];
	K_ITEM *es_item, *wi_item;
	WORKINFO *workinfo;
	SHARES *early_shares;
	char cd_buf[DATE_BUFSIZ];
	char *why = EMPTY;
	char *st = NULL;
	char tmp[1024];
	double delta;
	bool ok;

	LOGDEBUG("%s() add", __func__);

	DATA_WORKINFO(workinfo, wi);
	K_WLOCK(shares_free);
	if (shares_early_store->count == 0) {
		K_WUNLOCK(shares_free);
		// None
		return;
	}
	es_item = last_in_ktree(shares_early_root, ctx);
	if (es_item) {
		remove_from_ktree(shares_early_root, es_item);
		k_unlink_item(shares_early_store, es_item);
	}
	K_WUNLOCK(shares_free);
	if (es_item) {
		DATA_SHARES(early_shares, es_item);
		/* If the last (oldest) is newer than the
		 *  current workinfo, leave it til later */
		if (early_shares->workinfoid > workinfo->workinfoid)
			goto redo;

		/* If it matches the 'ok' share we just processed,
		 *  we don't need to check the workinfoid */
		if (early_shares->workinfoid == workinfo->workinfoid) {
			ok = shares_process(conn, early_shares, wi, trf_root);
			if (ok)
				goto keep;
			else
				goto discard;
		} else {
			wi_item = find_workinfo(early_shares->workinfoid, NULL);
			if (!wi_item) {
				// good_cd is 'now'
				delta = tvdiff(good_cd,
						&(early_shares->createdate));
				if (early_shares->oldcount > 0) {
					snprintf(tmp, sizeof(tmp),
						 " too old (%.1fs/%"PRId32")",
						 delta,
						 early_shares->oldcount);
					why = tmp;
					goto discard;
				}
				if (delta > EARLYSHARESLIMIT)
					early_shares->oldcount++;
				early_shares->redo++;
				goto redo;
			} else {
				ok = shares_process(conn, early_shares,
						    wi_item, trf_root);
				if (ok)
					goto keep;
				else
					goto discard;
			}
		}
	}
	return;
redo:
	K_WLOCK(shares_free);
	add_to_ktree(shares_early_root, es_item);
	k_add_tail(shares_early_store, es_item);
	K_WUNLOCK(shares_free);
	return;
keep:
	btv_to_buf(&(early_shares->createdate), cd_buf, sizeof(cd_buf));
	LOGERR("%s() %"PRId64"/%s/%ld,%ld %s/%"PRId32"/%"PRId32
		" Early share procured",
		__func__, early_shares->workinfoid,
		st = safe_text_nonull(early_shares->workername),
		early_shares->createdate.tv_sec,
		early_shares->createdate.tv_usec, cd_buf,
		early_shares->oldcount, early_shares->redo);
	FREENULL(st);
	K_WLOCK(shares_free);
	add_to_ktree(shares_root, es_item);
	k_add_head(shares_store, es_item);
	K_WUNLOCK(shares_free);
	return;
discard:
	btv_to_buf(&(early_shares->createdate), cd_buf, sizeof(cd_buf));
	LOGERR("%s() %"PRId64"/%s/%ld,%ld %s/%"PRId32"/%"PRId32
		" Early share discarded!%s",
		__func__, early_shares->workinfoid,
		st = safe_text_nonull(early_shares->workername),
		early_shares->createdate.tv_sec,
		early_shares->createdate.tv_usec, cd_buf,
		early_shares->oldcount, early_shares->redo, why);
	FREENULL(st);
	K_WLOCK(shares_free);
	k_add_head(shares_free, es_item);
	K_WUNLOCK(shares_free);
	return;
}

static void shareerrors_process_early(PGconn *conn, int64_t good_wid,
				      tv_t *good_cd, K_TREE *trf_root);

// Memory (and log file) only
bool shares_add(PGconn *conn, char *workinfoid, char *username, char *workername,
		char *clientid, char *errn, char *enonce1, char *nonce2,
		char *nonce, char *diff, char *sdiff, char *secondaryuserid,
		char *by, char *code, char *inet, tv_t *cd, K_TREE *trf_root)
{
	K_ITEM *s_item = NULL, *u_item, *wi_item;
	char cd_buf[DATE_BUFSIZ];
	SHARES *shares = NULL;
	USERS *users;
	bool ok = false;
	char *st = NULL;

	LOGDEBUG("%s(): %s/%s/%s/%s/%ld,%ld",
		 __func__,
		 workinfoid, st = safe_text_nonull(workername), nonce,
		 errn, cd->tv_sec, cd->tv_usec);
	FREENULL(st);

	K_WLOCK(shares_free);
	s_item = k_unlink_head(shares_free);
	K_WUNLOCK(shares_free);

	DATA_SHARES(shares, s_item);
	bzero(shares, sizeof(*shares));

	K_RLOCK(users_free);
	u_item = find_users(username);
	K_RUNLOCK(users_free);
	if (!u_item) {
		btv_to_buf(cd, cd_buf, sizeof(cd_buf));
		/* This should never happen unless there's a bug in ckpool
		    or the authentication information got to ckdb after
		    the shares ... which shouldn't ever happen */
		LOGERR("%s() %s/%ld,%ld %s no user! Share discarded!",
			__func__, st = safe_text_nonull(username),
			cd->tv_sec, cd->tv_usec, cd_buf);
		FREENULL(st);
		goto tisbad;
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
			btv_to_buf(cd, cd_buf, sizeof(cd_buf));
			LOGERR("%s() %s/%ld,%ld %s missing secondaryuserid! "
				"Share corrected",
				__func__, st = safe_text_nonull(username),
				cd->tv_sec, cd->tv_usec, cd_buf);
			FREENULL(st);
		}
	}

	HISTORYDATEINIT(shares, cd, by, code, inet);
	HISTORYDATETRANSFER(trf_root, shares);

	wi_item = find_workinfo(shares->workinfoid, NULL);
	if (!wi_item) {
		btv_to_buf(cd, cd_buf, sizeof(cd_buf));
		LOGERR("%s() %"PRId64"/%s/%ld,%ld %s no workinfo! "
			"Early share queued!",
			__func__, shares->workinfoid,
			st = safe_text_nonull(workername),
			cd->tv_sec, cd->tv_usec, cd_buf);
		FREENULL(st);
		shares->redo = 0;
		shares->oldcount = 0;
		K_WLOCK(shares_free);
		// They need to be sorted by workinfoid
		add_to_ktree(shares_early_root, s_item);
		k_add_head(shares_early_store, s_item);
		K_WUNLOCK(shares_free);
		/* It was all OK except the missing workinfoid
		 *  and it was queued, so most likely OK */
		return true;
	}

	ok = shares_process(conn, shares, wi_item, trf_root);
	if (ok) {
		K_WLOCK(shares_free);
		add_to_ktree(shares_root, s_item);
		k_add_head(shares_store, s_item);
		K_WUNLOCK(shares_free);

		shares_process_early(conn, wi_item, &(shares->createdate),
				     trf_root);
		// Call both since shareerrors may be rare
		shareerrors_process_early(conn, shares->workinfoid,
					  &(shares->createdate), trf_root);

		// The original share was ok
		return true;
	}

tisbad:
	K_WLOCK(shares_free);
	k_add_head(shares_free, s_item);
	K_WUNLOCK(shares_free);
	return false;
}

static bool shareerrors_process(PGconn *conn, SHAREERRORS *shareerrors,
				K_TREE *trf_root)
{
	K_ITEM *w_item, *wm_item, *ss_item;
	SHARESUMMARY *sharesummary;
	char *st = NULL;

	LOGDEBUG("%s() add", __func__);

	w_item = new_default_worker(conn, false, shareerrors->userid,
				    shareerrors->workername,
				    shareerrors->createby,
				    shareerrors->createcode,
				    shareerrors->createinet,
				    &(shareerrors->createdate), trf_root);
	if (!w_item) {
		LOGDEBUG("%s(): new_default_worker failed %"PRId64"/%s/%ld,%ld",
			 __func__, shareerrors->userid,
			 st = safe_text_nonull(shareerrors->workername),
			 shareerrors->createdate.tv_sec,
			 shareerrors->createdate.tv_usec);
		FREENULL(st);
		return false;
	}

	if (reloading && !confirm_sharesummary) {
		// We only need to know if the workmarker is processed
		K_RLOCK(workmarkers_free);
		wm_item = find_workmarkers(shareerrors->workinfoid, false,
					   MARKER_PROCESSED, NULL);
		K_RUNLOCK(workmarkers_free);
		if (wm_item) {
			LOGDEBUG("%s(): workmarker exists for wid %"PRId64
				 " %"PRId64"/%s/%ld,%ld",
				 __func__, shareerrors->workinfoid,
				 shareerrors->userid,
				 st = safe_text_nonull(shareerrors->workername),
				 shareerrors->createdate.tv_sec,
				 shareerrors->createdate.tv_usec);
			FREENULL(st);
			return false;
		}

		K_RLOCK(sharesummary_free);
		ss_item = find_sharesummary(shareerrors->userid,
					    shareerrors->workername,
					    shareerrors->workinfoid);
		K_RUNLOCK(sharesummary_free);
		if (ss_item) {
			DATA_SHARESUMMARY(sharesummary, ss_item);
			if (sharesummary->complete[0] != SUMMARY_NEW) {
				LOGDEBUG("%s(): '%s' sharesummary exists "
					 "%"PRId64" %"PRId64"/%s/%ld,%ld",
					 __func__, sharesummary->complete,
					 shareerrors->workinfoid,
					 shareerrors->userid,
					 st = safe_text_nonull(shareerrors->workername),
					 shareerrors->createdate.tv_sec,
					 shareerrors->createdate.tv_usec);
				FREENULL(st);
				return false;
			}
		}
	}

	sharesummary_update(NULL, shareerrors, shareerrors->createby,
			    shareerrors->createcode, shareerrors->createinet,
			    &(shareerrors->createdate));

	return true;
}

// If it exists and it can be processed, process the oldest early shareerror
static void shareerrors_process_early(PGconn *conn, int64_t good_wid,
				      tv_t *good_cd, K_TREE *trf_root)
{
	K_TREE_CTX ctx[1];
	K_ITEM *es_item, *wi_item;
	SHAREERRORS *early_shareerrors;
	char cd_buf[DATE_BUFSIZ];
	char *why = EMPTY;
	char *st = NULL;
	char tmp[1024];
	double delta;
	bool ok;

	LOGDEBUG("%s() add", __func__);

	K_WLOCK(shareerrors_free);
	if (shareerrors_early_store->count == 0) {
		K_WUNLOCK(shareerrors_free);
		// None
		return;
	}
	es_item = last_in_ktree(shareerrors_early_root, ctx);
	if (es_item) {
		remove_from_ktree(shareerrors_early_root, es_item);
		k_unlink_item(shareerrors_early_store, es_item);
	}
	K_WUNLOCK(shareerrors_free);
	if (es_item) {
		DATA_SHAREERRORS(early_shareerrors, es_item);
		/* If the last (oldest) is newer than the
		 *  current workinfo, leave it til later */
		if (early_shareerrors->workinfoid > good_wid)
			goto redo;

		/* If it matches the 'ok' share/shareerror we just processed,
		 *  we don't need to check the workinfoid */
		if (early_shareerrors->workinfoid == good_wid) {
			ok = shareerrors_process(conn, early_shareerrors,
						 trf_root);
			if (ok)
				goto keep;
			else
				goto discard;
		} else {
			wi_item = find_workinfo(early_shareerrors->workinfoid, NULL);
			if (!wi_item) {
				// good_cd is 'now'
				delta = tvdiff(good_cd,
						&(early_shareerrors->createdate));
				if (early_shareerrors->oldcount > 0) {
					snprintf(tmp, sizeof(tmp),
						 " too old (%.1fs/%"PRId32")",
						 delta,
						 early_shareerrors->oldcount);
					why = tmp;
					goto discard;
				}
				if (delta > EARLYSHARESLIMIT)
					early_shareerrors->oldcount++;
				early_shareerrors->redo++;
				goto redo;
			} else {
				ok = shareerrors_process(conn,
							 early_shareerrors,
							 trf_root);
				if (ok)
					goto keep;
				else
					goto discard;
			}
		}
	}
	return;
redo:
	K_WLOCK(shareerrors_free);
	add_to_ktree(shareerrors_early_root, es_item);
	k_add_tail(shareerrors_early_store, es_item);
	K_WUNLOCK(shareerrors_free);
	return;
keep:
	btv_to_buf(&(early_shareerrors->createdate), cd_buf, sizeof(cd_buf));
	LOGERR("%s() %"PRId64"/%s/%ld,%ld %s/%"PRId32"/%"PRId32
		" Early share procured",
		__func__, early_shareerrors->workinfoid,
		st = safe_text_nonull(early_shareerrors->workername),
		early_shareerrors->createdate.tv_sec,
		early_shareerrors->createdate.tv_usec, cd_buf,
		early_shareerrors->oldcount, early_shareerrors->redo);
	FREENULL(st);
	K_WLOCK(shareerrors_free);
	add_to_ktree(shareerrors_root, es_item);
	k_add_head(shareerrors_store, es_item);
	K_WUNLOCK(shareerrors_free);
	return;
discard:
	btv_to_buf(&(early_shareerrors->createdate), cd_buf, sizeof(cd_buf));
	LOGERR("%s() %"PRId64"/%s/%ld,%ld %s/%"PRId32"/%"PRId32
		" Early share discarded!%s",
		__func__, early_shareerrors->workinfoid,
		st = safe_text_nonull(early_shareerrors->workername),
		early_shareerrors->createdate.tv_sec,
		early_shareerrors->createdate.tv_usec, cd_buf,
		early_shareerrors->oldcount, early_shareerrors->redo, why);
	FREENULL(st);
	K_WLOCK(shareerrors_free);
	k_add_head(shareerrors_free, es_item);
	K_WUNLOCK(shareerrors_free);
	return;
}

// Memory (and log file) only
bool shareerrors_add(PGconn *conn, char *workinfoid, char *username,
			char *workername, char *clientid, char *errn,
			char *error, char *secondaryuserid, char *by,
			char *code, char *inet, tv_t *cd, K_TREE *trf_root)
{
	K_ITEM *s_item = NULL, *u_item, *wi_item;
	char cd_buf[DATE_BUFSIZ];
	SHAREERRORS *shareerrors = NULL;
	USERS *users;
	bool ok = false;
	char *st = NULL;

	LOGDEBUG("%s(): %s/%s/%s/%s/%ld,%ld",
		 __func__,
		 workinfoid, st = safe_text_nonull(workername), errn,
		 error, cd->tv_sec, cd->tv_usec);
	FREENULL(st);

	K_WLOCK(shareerrors_free);
	s_item = k_unlink_head(shareerrors_free);
	K_WUNLOCK(shareerrors_free);

	DATA_SHAREERRORS(shareerrors, s_item);
	bzero(shareerrors, sizeof(*shareerrors));

	K_RLOCK(users_free);
	u_item = find_users(username);
	K_RUNLOCK(users_free);
	if (!u_item) {
		btv_to_buf(cd, cd_buf, sizeof(cd_buf));
		LOGERR("%s() %s/%ld,%ld %s no user! Shareerror discarded!",
			__func__, st = safe_text_nonull(username),
			cd->tv_sec, cd->tv_usec, cd_buf);
		FREENULL(st);
		goto tisbad;
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
			btv_to_buf(cd, cd_buf, sizeof(cd_buf));
			LOGERR("%s() %s/%ld,%ld %s missing secondaryuserid! "
				"Sharerror corrected",
				__func__, st = safe_text_nonull(username),
				cd->tv_sec, cd->tv_usec, cd_buf);
			FREENULL(st);
		}
	}

	HISTORYDATEINIT(shareerrors, cd, by, code, inet);
	HISTORYDATETRANSFER(trf_root, shareerrors);

	wi_item = find_workinfo(shareerrors->workinfoid, NULL);
	if (!wi_item) {
		btv_to_buf(cd, cd_buf, sizeof(cd_buf));
		LOGERR("%s() %"PRId64"/%s/%ld,%ld %s no workinfo! "
			"Early shareerror queued!",
			__func__, shareerrors->workinfoid,
			st = safe_text_nonull(workername),
			cd->tv_sec, cd->tv_usec, cd_buf);
		FREENULL(st);
		shareerrors->redo = 0;
		shareerrors->oldcount = 0;
		K_WLOCK(shareerrors_free);
		// They need to be sorted by workinfoid
		add_to_ktree(shareerrors_early_root, s_item);
		k_add_head(shareerrors_early_store, s_item);
		K_WUNLOCK(shareerrors_free);
		/* It was all OK except the missing workinfoid
		 *  and it was queued, so most likely OK */
		return true;
	}

	ok = shareerrors_process(conn, shareerrors, trf_root);
	if (ok) {
		K_WLOCK(shareerrors_free);
		add_to_ktree(shareerrors_root, s_item);
		k_add_head(shareerrors_store, s_item);
		K_WUNLOCK(shareerrors_free);

		shareerrors_process_early(conn, shareerrors->workinfoid,
					  &(shareerrors->createdate),
					  trf_root);
		// Call both in case we are only getting errors on bad work
		shares_process_early(conn, wi_item, &(shareerrors->createdate),
				     trf_root);

		// The original share was ok
		return true;
	}

tisbad:
	K_WLOCK(shareerrors_free);
	k_add_head(shareerrors_free, s_item);
	K_WUNLOCK(shareerrors_free);
	return false;
}

bool shareerrors_fill()
{
	return true;
}

static void markersummary_to_pool(MARKERSUMMARY *p_row, MARKERSUMMARY *row)
{
	p_row->diffacc += row->diffacc;
	p_row->diffsta += row->diffsta;
	p_row->diffdup += row->diffdup;
	p_row->diffhi += row->diffhi;
	p_row->diffrej += row->diffrej;
	p_row->shareacc += row->shareacc;
	p_row->sharesta += row->sharesta;
	p_row->sharedup += row->sharedup;
	p_row->sharehi += row->sharehi;
	p_row->sharerej += row->sharerej;
	p_row->sharecount += row->sharecount;
	p_row->errorcount += row->errorcount;
	if (!p_row->firstshare.tv_sec ||
	     !tv_newer(&(p_row->firstshare), &(row->firstshare))) {
		copy_tv(&(p_row->firstshare), &(row->firstshare));
	}
	if (tv_newer(&(p_row->lastshare), &(row->lastshare)))
		copy_tv(&(p_row->lastshare), &(row->lastshare));
	if (row->diffacc > 0) {
		if (!p_row->firstshareacc.tv_sec ||
		     !tv_newer(&(p_row->firstshareacc), &(row->firstshareacc))) {
			copy_tv(&(p_row->firstshareacc), &(row->firstshareacc));
		}
		if (tv_newer(&(p_row->lastshareacc), &(row->lastshareacc))) {
			copy_tv(&(p_row->lastshareacc), &(row->lastshareacc));
			p_row->lastdiffacc = row->lastdiffacc;
		}
	}
}

/* TODO: what to do about a failure?
 *  since it will repeat every ~13s
 * Of course manual intervention is possible via cmd_marks,
 *  so that is probably the best solution since
 *  we should be watching the pool all the time :)
 * The cause would most likely be either a code bug or a DB problem
 *  so there may be no obvious automated fix
 *  and flagging the workmarkers to be skipped may or may not be the solution,
 *  thus manual intervention will be the rule for now */
bool sharesummaries_to_markersummaries(PGconn *conn, WORKMARKERS *workmarkers,
				       char *by, char *code, char *inet, tv_t *cd,
				       K_TREE *trf_root)
{
	// shorter name for log messages
	static const char *shortname = "SS_to_MS";
	ExecStatusType rescode;
	PGresult *res;
	K_TREE_CTX ss_ctx[1], ms_ctx[1];
	SHARESUMMARY *sharesummary, looksharesummary;
	MARKERSUMMARY *markersummary, lookmarkersummary, *p_markersummary = NULL;
	K_ITEM *ss_item, *ss_prev, ss_look, *ms_item, ms_look;
	K_ITEM *p_ss_item, *p_ms_item;
	bool ok = false, conned = false;
	int64_t diffacc, shareacc;
	char *reason = NULL;
	int ss_count, ms_count;
	char *st = NULL;

	LOGWARNING("%s() Processing: workmarkers %"PRId64"/%s/"
		   "End %"PRId64"/Stt %"PRId64"/%s/%s",
		   shortname, workmarkers->markerid, workmarkers->poolinstance,
		   workmarkers->workinfoidend, workmarkers->workinfoidstart,
		   workmarkers->description, workmarkers->status);

	K_STORE *old_sharesummary_store = k_new_store(sharesummary_free);
	K_STORE *new_markersummary_store = k_new_store(markersummary_free);
	K_TREE *ms_root = new_ktree(cmp_markersummary, markersummary_free);

	if (!CURRENT(&(workmarkers->expirydate))) {
		reason = "unexpired";
		goto flail;
	}

	if (!WMREADY(workmarkers->status)) {
		reason = "not ready";
		goto flail;
	}

	// Check there aren't already any matching markersummaries
	lookmarkersummary.markerid = workmarkers->markerid;
	lookmarkersummary.userid = 0;
	lookmarkersummary.workername = EMPTY;

	INIT_MARKERSUMMARY(&ms_look);
	ms_look.data = (void *)(&lookmarkersummary);
	K_RLOCK(markersummary_free);
	ms_item = find_after_in_ktree(markersummary_root, &ms_look, ms_ctx);
	K_RUNLOCK(markersummary_free);
	DATA_MARKERSUMMARY_NULL(markersummary, ms_item);
	if (ms_item && markersummary->markerid == workmarkers->markerid) {
		/* The fix here is either to set the workmarker as processed
		 *  with the marks action=processed
		 *  if the markersummaries are OK but the workmarker failed to
		 *  have it's status set to processed
		 * OR
		 *  delete the markersummaries with the marks action=cancel
		 *  so this will continue and regenerate the markersummaries
		 */
		reason = "markersummaries already exist";
		goto flail;
	}

	diffacc = shareacc = 0;
	ms_item = NULL;

	looksharesummary.workinfoid = workmarkers->workinfoidend;
	looksharesummary.userid = MAXID;
	looksharesummary.workername = EMPTY;

	INIT_SHARESUMMARY(&ss_look);
	ss_look.data = (void *)(&looksharesummary);
	/* Since shares come in from ckpool at a high rate,
	 *  we don't want to lock sharesummary for long
	 * Those incoming shares will not be touching the sharesummaries
	 *  we are processing here */
	K_RLOCK(sharesummary_free);
	ss_item = find_before_in_ktree(sharesummary_workinfoid_root,
					&ss_look, ss_ctx);
	K_RUNLOCK(sharesummary_free);
	while (ss_item) {
		DATA_SHARESUMMARY(sharesummary, ss_item);
		if (sharesummary->workinfoid < workmarkers->workinfoidstart)
			break;
		K_RLOCK(sharesummary_free);
		ss_prev = prev_in_ktree(ss_ctx);
		K_RUNLOCK(sharesummary_free);

		// Find/create the markersummary only once per worker change
		if (!ms_item || markersummary->userid != sharesummary->userid ||
		    strcmp(markersummary->workername, sharesummary->workername) != 0) {
			lookmarkersummary.markerid = workmarkers->markerid;
			lookmarkersummary.userid = sharesummary->userid;
			lookmarkersummary.workername = sharesummary->workername;

			ms_look.data = (void *)(&lookmarkersummary);
			ms_item = find_in_ktree_nolock(ms_root, &ms_look, ms_ctx);
			if (!ms_item) {
				K_WLOCK(markersummary_free);
				ms_item = k_unlink_head(markersummary_free);
				K_WUNLOCK(markersummary_free);
				k_add_head_nolock(new_markersummary_store, ms_item);
				DATA_MARKERSUMMARY(markersummary, ms_item);
				bzero(markersummary, sizeof(*markersummary));
				markersummary->markerid = workmarkers->markerid;
				markersummary->userid = sharesummary->userid;
				DUP_POINTER(markersummary_free,
					    markersummary->workername,
					    sharesummary->workername);
				add_to_ktree_nolock(ms_root, ms_item);

				LOGDEBUG("%s() new ms %"PRId64"/%"PRId64"/%s",
					 shortname, markersummary->markerid,
					 markersummary->userid,
					 st = safe_text(markersummary->workername));
				FREENULL(st);
			} else {
				DATA_MARKERSUMMARY(markersummary, ms_item);
			}
		}
		markersummary->diffacc += sharesummary->diffacc;
		markersummary->diffsta += sharesummary->diffsta;
		markersummary->diffdup += sharesummary->diffdup;
		markersummary->diffhi += sharesummary->diffhi;
		markersummary->diffrej += sharesummary->diffrej;
		markersummary->shareacc += sharesummary->shareacc;
		markersummary->sharesta += sharesummary->sharesta;
		markersummary->sharedup += sharesummary->sharedup;
		markersummary->sharehi += sharesummary->sharehi;
		markersummary->sharerej += sharesummary->sharerej;
		markersummary->sharecount += sharesummary->sharecount;
		markersummary->errorcount += sharesummary->errorcount;
		if (!markersummary->firstshare.tv_sec ||
		     !tv_newer(&(markersummary->firstshare), &(sharesummary->firstshare))) {
			copy_tv(&(markersummary->firstshare), &(sharesummary->firstshare));
		}
		if (tv_newer(&(markersummary->lastshare), &(sharesummary->lastshare)))
			copy_tv(&(markersummary->lastshare), &(sharesummary->lastshare));
		if (sharesummary->diffacc > 0) {
			if (!markersummary->firstshareacc.tv_sec ||
			     !tv_newer(&(markersummary->firstshareacc), &(sharesummary->firstshareacc))) {
				copy_tv(&(markersummary->firstshareacc), &(sharesummary->firstshareacc));
			}
			if (tv_newer(&(markersummary->lastshareacc), &(sharesummary->lastshareacc))) {
				copy_tv(&(markersummary->lastshareacc), &(sharesummary->lastshareacc));
				markersummary->lastdiffacc = sharesummary->lastdiffacc;
			}
		}

		diffacc += sharesummary->diffacc;
		shareacc += sharesummary->shareacc;

		K_WLOCK(sharesummary_free);
		k_unlink_item(sharesummary_store, ss_item);
		K_WUNLOCK(sharesummary_free);
		k_add_head_nolock(old_sharesummary_store, ss_item);

		ss_item = ss_prev;
	}

	if (conn == NULL) {
		conn = dbconnect();
		conned = true;
	}

	res = PQexec(conn, "Begin", CKPQ_WRITE);
	rescode = PQresultStatus(res);
	PQclear(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Begin", rescode, conn);
		goto flail;
	}

	ms_item = STORE_HEAD_NOLOCK(new_markersummary_store);
	while (ms_item) {
		if (!(markersummary_add(conn, ms_item, by, code, inet,
					cd, trf_root))) {
			reason = "db error";
			goto rollback;
		}
		ms_item = ms_item->next;
	}

	ok = workmarkers_process(conn, true, true,
				 workmarkers->markerid,
				 workmarkers->poolinstance,
				 workmarkers->workinfoidend,
				 workmarkers->workinfoidstart,
				 workmarkers->description,
				 MARKER_PROCESSED_STR,
				 by, code, inet, cd, trf_root);
rollback:
	if (ok)
		res = PQexec(conn, "Commit", CKPQ_WRITE);
	else
		res = PQexec(conn, "Rollback", CKPQ_WRITE);

	PQclear(res);
flail:
	if (conned)
		PQfinish(conn);

	if (reason) {
		// already displayed the full workmarkers detail at the top
		LOGERR("%s() %s: workmarkers %"PRId64"/%s/%s",
			shortname, reason, workmarkers->markerid,
			workmarkers->description, workmarkers->status);

		ok = false;
	}

	if (!ok) {
		if (new_markersummary_store->count > 0) {
			// Throw them away (they don't exist anywhere else)
			ms_item = STORE_HEAD_NOLOCK(new_markersummary_store);
			while (ms_item) {
				free_markersummary_data(ms_item);
				ms_item = ms_item->next;
			}
			K_WLOCK(markersummary_free);
			k_list_transfer_to_head(new_markersummary_store, markersummary_free);
			K_WUNLOCK(markersummary_free);
		}
		if (old_sharesummary_store->count > 0) {
			// Put them back in the store where they came from
			K_WLOCK(sharesummary_free);
			k_list_transfer_to_head(old_sharesummary_store, sharesummary_store);
			K_WUNLOCK(sharesummary_free);
		}
	} else {
		ms_count = new_markersummary_store->count;
		ss_count = old_sharesummary_store->count;

		K_WLOCK(sharesummary_free);
		K_WLOCK(markersummary_free);
		K_RLOCK(workmarkers_free);
		ms_item = STORE_HEAD_NOLOCK(new_markersummary_store);
		while (ms_item) {
			// move the new markersummaries into the trees/stores
			add_to_ktree(markersummary_root, ms_item);
			add_to_ktree(markersummary_userid_root, ms_item);

			// create/update the pool markersummaries
			DATA_MARKERSUMMARY(markersummary, ms_item);
			p_ms_item = find_markersummary_p(markersummary->markerid);
			if (!p_ms_item) {
				p_ms_item = k_unlink_head(markersummary_free);
				DATA_MARKERSUMMARY(p_markersummary, p_ms_item);
				bzero(p_markersummary, sizeof(*p_markersummary));
				p_markersummary->markerid = markersummary->markerid;
				POOL_MS(p_markersummary);
				add_to_ktree(markersummary_pool_root, p_ms_item);
				k_add_head(markersummary_pool_store, p_ms_item);
			}
			markersummary_to_pool(p_markersummary, markersummary);

			ms_item = ms_item->next;
		}
		k_list_transfer_to_head(new_markersummary_store, markersummary_store);

		/* For normal shift processing this wont be very quick
		 *  so it will be a 'long' LOCK */
		ss_item = STORE_HEAD_NOLOCK(old_sharesummary_store);
		while (ss_item) {
			// remove the old sharesummaries from the trees
			remove_from_ktree(sharesummary_root, ss_item);
			remove_from_ktree(sharesummary_workinfoid_root, ss_item);

			// remove the pool sharesummaries
			DATA_SHARESUMMARY(sharesummary, ss_item);
			p_ss_item = find_sharesummary_p(sharesummary->workinfoid);
			if (p_ss_item) {
				remove_from_ktree(sharesummary_pool_root, p_ss_item);
				k_unlink_item(sharesummary_pool_store, p_ss_item);
				free_sharesummary_data(p_ss_item);
				k_add_head(sharesummary_free, p_ss_item);
			}

			free_sharesummary_data(ss_item);
			ss_item = ss_item->next;
		}
		k_list_transfer_to_head(old_sharesummary_store, sharesummary_free);
		K_RUNLOCK(workmarkers_free);
		K_WUNLOCK(markersummary_free);
		K_WUNLOCK(sharesummary_free);

		LOGWARNING("%s() Processed: %d ms %d ss %"PRId64" shares "
			   "%"PRId64" diff for workmarkers %"PRId64"/%s/"
			   "End %"PRId64"/Stt %"PRId64"/%s/%s",
			   shortname, ms_count, ss_count, shareacc, diffacc,
			   workmarkers->markerid, workmarkers->poolinstance,
			   workmarkers->workinfoidend,
			   workmarkers->workinfoidstart,
			   workmarkers->description,
			   workmarkers->status);
	}
	free_ktree(ms_root, NULL);
	new_markersummary_store = k_free_store(new_markersummary_store);
	old_sharesummary_store = k_free_store(old_sharesummary_store);

	return ok;
}

bool delete_markersummaries(PGconn *conn, WORKMARKERS *wm)
{
	// shorter name for log messages
	static const char *shortname = "DEL_MS";
	K_STORE *del_markersummary_store = NULL;
	ExecStatusType rescode;
	PGresult *res;
	K_TREE_CTX ms_ctx[1];
	MARKERSUMMARY *markersummary = NULL, lookmarkersummary;
	K_ITEM *ms_item, ms_look, *p_ms_item = NULL;
	bool ok = false, conned = false;
	int64_t diffacc, shareacc;
	char *reason = "unknown";
	int ms_count;
	char *params[1];
	int par = 0, ms_del = 0;
	char *del, *tuples = NULL;

	if (WMPROCESSED(wm->status)) {
		reason = "status processed";
		goto flail;
	}

	LOGWARNING("%s() Deleting: markersummaries for workmarkers "
		   "%"PRId64"/%s/End %"PRId64"/Stt %"PRId64"/%s/%s",
		   shortname, wm->markerid, wm->poolinstance,
		   wm->workinfoidend, wm->workinfoidstart, wm->description,
		   wm->status);

	del_markersummary_store = k_new_store(markersummary_free);

	lookmarkersummary.markerid = wm->markerid;
	lookmarkersummary.userid = 0;
	lookmarkersummary.workername = EMPTY;

	ms_count = diffacc = shareacc = 0;
	ms_item = NULL;

	INIT_MARKERSUMMARY(&ms_look);
	ms_look.data = (void *)(&lookmarkersummary);

	K_WLOCK(markersummary_free);
	K_WLOCK(workmarkers_free);

	ms_item = find_after_in_ktree(markersummary_root, &ms_look, ms_ctx);
	DATA_MARKERSUMMARY_NULL(markersummary, ms_item);
	if (!ms_item || markersummary->markerid != wm->markerid) {
		reason = "no markersummaries";
		goto flail;
	}

	// Build the delete list of markersummaries
	while (ms_item && markersummary->markerid == wm->markerid) {
		ms_count++;
		diffacc += markersummary->diffacc;
		shareacc += markersummary->shareacc;

		k_unlink_item(markersummary_store, ms_item);
		k_add_tail(del_markersummary_store, ms_item);

		ms_item = next_in_ktree(ms_ctx);
		DATA_MARKERSUMMARY_NULL(markersummary, ms_item);
	}

	par = 0;
	params[par++] = bigint_to_buf(wm->markerid, NULL, 0);
	PARCHK(par, params);

	del = "delete from markersummary where markerid=$1";

	if (conn == NULL) {
		conn = dbconnect();
		conned = true;
	}

	res = PQexecParams(conn, del, par, NULL, (const char **)params, NULL, NULL, 0, CKPQ_WRITE);
	rescode = PQresultStatus(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Delete", rescode, conn);
		reason = "db error";
		goto unparam;
	}

	if (PGOK(rescode)) {
		tuples = PQcmdTuples(res);
		if (tuples && *tuples) {
			ms_del = atoi(tuples);
			if (ms_del != ms_count) {
				LOGERR("%s() deleted markersummaries should be"
					" %d but deleted=%d",
					shortname, ms_count, ms_del);
				reason = "del mismatch";
				goto unparam;
			}
		}
	}

	ok = true;
unparam:
	PQclear(res);
flail:
	if (conned)
		PQfinish(conn);

	if (!ok) {
		if (del_markersummary_store && del_markersummary_store->count) {
			k_list_transfer_to_head(del_markersummary_store,
						markersummary_store);
		}
	} else {
		/* TODO: add a list garbage collection thread so as to not
		 *  invalidate the data immediately (free_*), rather after
		 *  some delay */
		ms_item = STORE_HEAD_NOLOCK(del_markersummary_store);
		while (ms_item) {
			remove_from_ktree(markersummary_root, ms_item);
			remove_from_ktree(markersummary_userid_root, ms_item);
			free_markersummary_data(ms_item);
			ms_item = ms_item->next;
		}

		k_list_transfer_to_head(del_markersummary_store,
					markersummary_free);

		p_ms_item = find_markersummary_p(wm->markerid);
		if (p_ms_item) {
			remove_from_ktree(markersummary_pool_root, p_ms_item);
			free_markersummary_data(p_ms_item);
			k_unlink_item(markersummary_pool_store, p_ms_item);
			k_add_head(markersummary_free, p_ms_item);
		}
	}

	K_WUNLOCK(workmarkers_free);
	K_WUNLOCK(markersummary_free);

	if (!ok) {
		// already displayed the full workmarkers detail at the top
		LOGERR("%s() %s: workmarkers %"PRId64"/%s/%s",
			shortname, reason, wm->markerid, wm->description,
			wm->status);
	} else {
		LOGWARNING("%s() Deleted: %d ms %"PRId64" shares "
			   "%"PRId64" diff for workmarkers %"PRId64"/%s/"
			   "End %"PRId64"/Stt %"PRId64"/%s/%s",
			   shortname, ms_count, shareacc, diffacc,
			   wm->markerid, wm->poolinstance, wm->workinfoidend,
			   wm->workinfoidstart, wm->description, wm->status);
	}

	if (del_markersummary_store)
		del_markersummary_store = k_free_store(del_markersummary_store);

	return ok;
}

static void set_sharesummary_stats(SHARESUMMARY *row, SHARES *s_row,
				   SHAREERRORS *e_row, bool new,
				   double *tdf, double *tdl)
{
	tv_t *createdate;

	K_WLOCK(sharesummary_free);

	if (s_row)
		createdate = &(s_row->createdate);
	else
		createdate = &(e_row->createdate);

	if (new) {
		zero_sharesummary(row);
		copy_tv(&(row->firstshare), createdate);
		copy_tv(&(row->lastshare), createdate);
	} else {
		if (!row->firstshare.tv_sec ||
		     !tv_newer(&(row->firstshare), createdate)) {
			copy_tv(&(row->firstshare), createdate);
		}
		if (tv_newer(&(row->lastshare), createdate))
			copy_tv(&(row->lastshare), createdate);
	}

	if (s_row) {
		row->sharecount += 1;
		switch (s_row->errn) {
			case SE_NONE:
				row->diffacc += s_row->diff;
				row->shareacc++;
				// should always be true
				if (s_row->diff > 0) {
					if (!row->firstshareacc.tv_sec ||
					     !tv_newer(&(row->firstshareacc), createdate)) {
						copy_tv(&(row->firstshareacc), createdate);
					}
					if (tv_newer(&(row->lastshareacc), createdate)) {
						copy_tv(&(row->lastshareacc), createdate);
						row->lastdiffacc = s_row->diff;
					}
				}
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
	} else
		row->errorcount += 1;

	// Only if required
	if (!new) {
		*tdf = tvdiff(createdate, &(row->firstshare));
		*tdl = tvdiff(createdate, &(row->lastshare));
	}

	K_WUNLOCK(sharesummary_free);
}

/* Keep some simple stats on how often shares are out of order
 *  and how often they produce a WARNING due to OOOLIMIT */
static int64_t ooof0, ooof, oool0, oool;
#define OOOLIMIT -2.0

/* This isn't locked so it is possible - but very unlikely -
 *  to get an invalid set of numbers if any ooo variables change
 *  during the snprintf, but that will simply display a wrong number */
char *ooo_status(char *buf, size_t siz)
{
	snprintf(buf, siz,
		 "F%"PRId64":%"PRId64"/L%"PRId64":%"PRId64"/%.1f/T%"PRId64,
		 ooof, ooof0, oool, oool0, OOOLIMIT,
		 ooof + ooof0 + oool + oool0);
	return buf;
}

// No longer stored in the DB but fields are updated as before
bool _sharesummary_update(SHARES *s_row, SHAREERRORS *e_row, char *by,
			  char *code, char *inet, tv_t *cd, WHERE_FFL_ARGS)
{
	WORKMARKERS *wm;
	SHARESUMMARY *row, *p_row;
	K_ITEM *ss_item, *wm_item, *p_item = NULL;
	bool new = false, p_new = false;
	int64_t userid, workinfoid;
	char *workername;
	char *st = NULL, *db = NULL;
	char ooo_buf[256];
	double tdf, tdl;

	LOGDEBUG("%s(): update", __func__);

	if (s_row) {
		if (e_row) {
			quithere(1, "ERR: only one of s_row and e_row allowed"
				    WHERE_FFL,
				    WHERE_FFL_PASS);
		}
		userid = s_row->userid;
		workername = s_row->workername;
		workinfoid = s_row->workinfoid;
	} else {
		if (!e_row) {
			quithere(1, "ERR: both s_row and e_row are NULL"
				    WHERE_FFL,
				    WHERE_FFL_PASS);
		}
		userid = e_row->userid;
		workername = e_row->workername;
		workinfoid = e_row->workinfoid;
	}

	K_RLOCK(workmarkers_free);
	wm_item = find_workmarkers(workinfoid, false, MARKER_PROCESSED,
				   NULL);
	K_RUNLOCK(workmarkers_free);
	if (wm_item) {
		DATA_WORKMARKERS(wm, wm_item);
		LOGERR("%s(): attempt to update sharesummary "
		       "with %s %"PRId64"/%"PRId64"/%s "CDDB" %s"
		       " but processed workmarkers %"PRId64" exists",
			__func__, s_row ? "shares" : "shareerrors",
			workinfoid, userid, st = safe_text(workername),
				db = ctv_to_buf(cd, NULL, 0),
				wm->markerid);
			FREENULL(st);
			FREENULL(db);
			return false;
	}

	K_RLOCK(sharesummary_free);
	ss_item = find_sharesummary(userid, workername, workinfoid);
	p_item = find_sharesummary_p(workinfoid);
	K_RUNLOCK(sharesummary_free);

	if (ss_item) {
		DATA_SHARESUMMARY(row, ss_item);
	} else {
		new = true;
		K_WLOCK(sharesummary_free);
		ss_item = k_unlink_head(sharesummary_free);
		K_WUNLOCK(sharesummary_free);
		DATA_SHARESUMMARY(row, ss_item);
		bzero(row, sizeof(*row));
		row->userid = userid;
		DUP_POINTER(sharesummary_free, row->workername,
			    workername);
		row->workinfoid = workinfoid;
	}

	// N.B. this directly updates the non-key data
	set_sharesummary_stats(row, s_row, e_row, new, &tdf, &tdl);

	if (!new) {
		// don't LOG '=' in case shares come from ckpool with the same timestamp
		if (tdf < 0.0) {
			char *tmp1, *tmp2;
			int level = LOG_DEBUG;
			// WARNING for shares exceeding the OOOLIMIT but not during startup
			if (tdf < OOOLIMIT) {
				ooof++;
				if (startup_complete)
					level = LOG_WARNING;
			} else
				ooof0++;
			LOGMSG(level, "%s(): OoO %s "CDDB" (%s) is < summary"
				" firstshare (%s) (%s)",
				__func__, s_row ? "shares" : "shareerrors",
				(tmp1 = ctv_to_buf(cd, NULL, 0)),
				(tmp2 = ctv_to_buf(&(row->firstshare), NULL, 0)),
				ooo_status(ooo_buf, sizeof(ooo_buf)));
			free(tmp2);
			free(tmp1);
		}

		// don't LOG '=' in case shares come from ckpool with the same timestamp
		if (tdl < 0.0) {
			char *tmp1, *tmp2;
			int level = LOG_DEBUG;
			// WARNING for shares exceeding the OOOLIMIT but not during startup
			if (tdl < OOOLIMIT) {
				oool++;
				if (startup_complete)
					level = LOG_WARNING;
			} else
				oool0++;
			LOGMSG(level, "%s(): OoO %s "CDDB" (%s) is < summary"
				" lastshare (%s) (%s)",
				__func__, s_row ? "shares" : "shareerrors",
				(tmp1 = ctv_to_buf(cd, NULL, 0)),
				(tmp2 = ctv_to_buf(&(row->lastshare), NULL, 0)),
				ooo_status(ooo_buf, sizeof(ooo_buf)));
			free(tmp2);
			free(tmp1);
		}

		if (row->complete[0] != SUMMARY_NEW) {
			LOGDEBUG("%s(): updating sharesummary not '%c'"
				 " %"PRId64"/%s/%"PRId64"/%s",
				__func__, SUMMARY_NEW, row->userid,
				st = safe_text_nonull(row->workername),
				row->workinfoid, row->complete);
			FREENULL(st);
		}
	}

	if (p_item) {
		DATA_SHARESUMMARY(p_row, p_item);
	} else {
		p_new = true;
		K_WLOCK(sharesummary_free);
		p_item = k_unlink_head(sharesummary_free);
		K_WUNLOCK(sharesummary_free);
		DATA_SHARESUMMARY(p_row, p_item);
		bzero(p_row, sizeof(*p_row));
		POOL_SS(p_row);
		p_row->workinfoid = workinfoid;
	}

	set_sharesummary_stats(p_row, s_row, e_row, p_new, &tdf, &tdl);

	MODIFYDATEPOINTERS(sharesummary_free, row, cd, by, code, inet);

	// Store either new item
	if (new || p_new) {
		K_WLOCK(sharesummary_free);
		if (new) {
			add_to_ktree(sharesummary_root, ss_item);
			add_to_ktree(sharesummary_workinfoid_root, ss_item);
			k_add_head(sharesummary_store, ss_item);
		}
		if (p_new) {
			add_to_ktree(sharesummary_pool_root, p_item);
			k_add_head(sharesummary_pool_store, p_item);
		}
		K_WUNLOCK(sharesummary_free);
	}

	return true;
}

// No key fields are modified
bool _sharesummary_age(K_ITEM *ss_item, char *by, char *code, char *inet,
			tv_t *cd, WHERE_FFL_ARGS)
{
	SHARESUMMARY *row;

	LOGDEBUG("%s(): update", __func__);

	DATA_SHARESUMMARY(row, ss_item);
	row->complete[0] = SUMMARY_COMPLETE;
	row->complete[1] = '\0';

	MODIFYDATEPOINTERS(sharesummary_free, row, cd, by, code, inet);

	return true;
}

bool blocks_stats(PGconn *conn, int32_t height, char *blockhash,
			double diffacc, double diffinv, double shareacc,
			double shareinv, int64_t elapsed,
			char *by, char *code, char *inet, tv_t *cd)
{
	ExecStatusType rescode;
	bool conned = false;
	PGresult *res = NULL;
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
	old_b_item = find_blocks(height, blockhash, NULL);
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
	copy_blocks(row, oldblocks);
	row->diffacc = diffacc;
	row->diffinv = diffinv;
	row->shareacc = shareacc;
	row->shareinv = shareinv;
	row->elapsed = elapsed;
	row->statsconfirmed[0] = BLOCKS_STATSCONFIRMED;
	row->statsconfirmed[1] = '\0';
	HISTORYDATEINIT(row, cd, by, code, inet);

	upd = "update blocks set "EDDB"=$1 where blockhash=$2 and "EDDB"=$3";
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
		"blockhash=$1 and "EDDB"=$2";

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
			remove_from_ktree(blocks_root, old_b_item);
			copy_tv(&(oldblocks->expirydate), cd);
			add_to_ktree(blocks_root, old_b_item);
			// Copy it over to avoid having to recalculate it
			row->netdiff = oldblocks->netdiff;
		} else
			row->netdiff = 0;
		add_to_ktree(blocks_root, b_item);
		k_add_head(blocks_store, b_item);
		blocks_stats_rebuild = true;
		// 'confirmed' is unchanged so no need to recalc *createdate
	}
	K_WUNLOCK(blocks_free);

	return ok;
}

bool blocks_add(PGconn *conn, int32_t height, char *blockhash,
		char *confirmed, char *info, char *workinfoid,
		char *username, char *workername, char *clientid,
		char *enonce1, char *nonce2, char *nonce, char *reward,
		char *by, char *code, char *inet, tv_t *cd,
		bool igndup, char *id, K_TREE *trf_root)
{
	ExecStatusType rescode;
	bool conned = false;
	PGresult *res = NULL;
	K_ITEM *b_item, *u_item, *old_b_item;
	char cd_buf[DATE_BUFSIZ];
	char hash_dsp[16+1];
	double hash_diff;
	BLOCKS *row, *oldblocks;
	USERS *users;
	char *upd, *ins;
	char *params[18 + HISTORYDATECOUNT];
	bool ok = false, update_old = false;
	int n, par = 0;
	char *want = NULL, *st = NULL;

	LOGDEBUG("%s(): add", __func__);

	K_WLOCK(blocks_free);
	b_item = k_unlink_head(blocks_free);
	K_WUNLOCK(blocks_free);

	DATA_BLOCKS(row, b_item);
	bzero(row, sizeof(*row));

	row->height = height;
	STRNCPY(row->blockhash, blockhash);

	dsp_hash(blockhash, hash_dsp, sizeof(hash_dsp));
	hash_diff = blockhash_diff(blockhash);

	K_RLOCK(blocks_free);
	old_b_item = find_blocks(row->height, blockhash, NULL);
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
						"%s, Block: %"PRId32"/...%s/%s",
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
			STRNCPY(row->info, info);
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
			params[par++] = str_to_buf(row->info, NULL, 0);
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
				"info,diffacc,diffinv,shareacc,shareinv,elapsed,"
				"statsconfirmed"
				HISTORYDATECONTROL ") values (" PQPARAM23 ")";

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
			userinfo_block(row, INFO_NEW, 1);
			goto unparam;
			break;
		case BLOCKS_ORPHAN:
		case BLOCKS_REJECT:
		case BLOCKS_42:
			// These shouldn't be possible until startup completes
			if (!startup_complete) {
				tv_to_buf(cd, cd_buf, sizeof(cd_buf));
				LOGERR("%s(): Status: %s invalid during startup. "
					"Ignored: Block: %"PRId32"/...%s/%s",
					__func__,
					blocks_confirmed(confirmed),
					height, hash_dsp, cd_buf);
				goto flail;
			}
		case BLOCKS_CONFIRM:
			if (!old_b_item) {
				tv_to_buf(cd, cd_buf, sizeof(cd_buf));
				LOGERR("%s(): Can't %s a non-existent Block: %"PRId32"/...%s/%s",
					__func__, blocks_confirmed(confirmed),
					height, hash_dsp, cd_buf);
				goto flail;
			}
			switch (confirmed[0]) {
				case BLOCKS_CONFIRM:
					if (oldblocks->confirmed[0] != BLOCKS_NEW)
						want = BLOCKS_NEW_STR;
					break;
				case BLOCKS_42:
					if (oldblocks->confirmed[0] != BLOCKS_CONFIRM)
						want = BLOCKS_CONFIRM_STR;
					break;
				case BLOCKS_ORPHAN:
					if (oldblocks->confirmed[0] != BLOCKS_NEW &&
					    oldblocks->confirmed[0] != BLOCKS_CONFIRM)
						want = BLOCKS_N_C_STR;
					break;
				case BLOCKS_REJECT:
					if (oldblocks->confirmed[0] != BLOCKS_NEW &&
					    oldblocks->confirmed[0] != BLOCKS_CONFIRM &&
					    oldblocks->confirmed[0] != BLOCKS_ORPHAN &&
					    oldblocks->confirmed[0] != BLOCKS_REJECT)
						want = BLOCKS_N_C_O_R_STR;
					break;
			}
			if (want) {
				// No mismatch messages during startup
				if (startup_complete) {
					tv_to_buf(cd, cd_buf, sizeof(cd_buf));
					LOGERR("%s(): New Status: (%s)%s requires Status: %s. "
						"Ignored: Status: (%s)%s, Block: %"PRId32"/...%s/%s",
						__func__,
						confirmed, blocks_confirmed(confirmed),
						want, oldblocks->confirmed,
						blocks_confirmed(oldblocks->confirmed),
						height, hash_dsp, cd_buf);
				}
				goto flail;
			}

			upd = "update blocks set "EDDB"=$1 where blockhash=$2 and "EDDB"=$3";
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
			copy_blocks(row, oldblocks);
			STRNCPY(row->confirmed, confirmed);
			if (info && *info)
				STRNCPY(row->info, info);
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
			params[par++] = str_to_buf(row->info, NULL, 0);

			if (confirmed[0] == BLOCKS_CONFIRM) {
				params[par++] = double_to_buf(row->diffacc, NULL, 0);
				params[par++] = double_to_buf(row->diffinv, NULL, 0);
				params[par++] = double_to_buf(row->shareacc, NULL, 0);
				params[par++] = double_to_buf(row->shareinv, NULL, 0);
				HISTORYDATEPARAMS(params, par, row);
				PARCHKVAL(par, 8 + HISTORYDATECOUNT, params); // 13 as per ins

				ins = "insert into blocks "
					"(height,blockhash,workinfoid,userid,workername,"
					"clientid,enonce1,nonce2,nonce,reward,confirmed,"
					"info,diffacc,diffinv,shareacc,shareinv,elapsed,"
					"statsconfirmed"
					HISTORYDATECONTROL ") select "
					"height,blockhash,workinfoid,userid,workername,"
					"clientid,enonce1,nonce2,nonce,reward,"
					"$3,$4,$5,$6,$7,$8,elapsed,statsconfirmed,"
					"$9,$10,$11,$12,$13 from blocks where "
					"blockhash=$1 and "EDDB"=$2";
			} else {
				HISTORYDATEPARAMS(params, par, row);
				PARCHKVAL(par, 4 + HISTORYDATECOUNT, params); // 9 as per ins

				ins = "insert into blocks "
					"(height,blockhash,workinfoid,userid,workername,"
					"clientid,enonce1,nonce2,nonce,reward,confirmed,"
					"info,diffacc,diffinv,shareacc,shareinv,elapsed,"
					"statsconfirmed"
					HISTORYDATECONTROL ") select "
					"height,blockhash,workinfoid,userid,workername,"
					"clientid,enonce1,nonce2,nonce,reward,"
					"$3,$4,diffacc,diffinv,shareacc,shareinv,elapsed,"
					"statsconfirmed,"
					"$5,$6,$7,$8,$9 from blocks where "
					"blockhash=$1 and "EDDB"=$2";
			}

			res = PQexecParams(conn, ins, par, NULL, (const char **)params, NULL, NULL, 0, CKPQ_WRITE);
			rescode = PQresultStatus(res);
			PQclear(res);
			if (!PGOK(rescode)) {
				PGLOGERR("Insert", rescode, conn);
				goto rollback;
			}

			update_old = true;
			/* handle confirmed state changes for userinfo
			 * this case statement handles all possible combinations
			 *  even if they can't happen (yet) */
			switch (oldblocks->confirmed[0]) {
				case BLOCKS_ORPHAN:
					switch (confirmed[0]) {
						case BLOCKS_ORPHAN:
							break;
						case BLOCKS_REJECT:
							userinfo_block(row, INFO_ORPHAN, -1);
							userinfo_block(row, INFO_REJECT, 1);
							break;
						default:
							userinfo_block(row, INFO_ORPHAN, -1);
							break;
					}
					break;
				case BLOCKS_REJECT:
					switch (confirmed[0]) {
						case BLOCKS_REJECT:
							break;
						case BLOCKS_ORPHAN:
							userinfo_block(row, INFO_REJECT, -1);
							userinfo_block(row, INFO_ORPHAN, 1);
							break;
						default:
							userinfo_block(row, INFO_REJECT, -1);
							break;
					}
					break;
				default:
					switch (confirmed[0]) {
						case BLOCKS_ORPHAN:
							userinfo_block(row, INFO_ORPHAN, 1);
							break;
						case BLOCKS_REJECT:
							userinfo_block(row, INFO_REJECT, 1);
							break;
						default:
							break;
					}
					break;
			}
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

	K_RLOCK(workinfo_free);
	K_WLOCK(blocks_free);
	if (!ok)
		k_add_head(blocks_free, b_item);
	else {
		if (update_old) {
			remove_from_ktree(blocks_root, old_b_item);
			copy_tv(&(oldblocks->expirydate), cd);
			add_to_ktree(blocks_root, old_b_item);
			// Copy it over to avoid having to recalculate it
			row->netdiff = oldblocks->netdiff;
		} else
			row->netdiff = 0;
		add_to_ktree(blocks_root, b_item);
		k_add_head(blocks_store, b_item);
		blocks_stats_rebuild = true;
		// recalc the *createdate fields for possibly affected blocks
		set_blockcreatedate(row->height);
		set_prevcreatedate(row->height);
	}
	K_WUNLOCK(blocks_free);
	K_RUNLOCK(workinfo_free);

	if (ok) {
		char pct[16] = "?";
		char est[16] = "";
		char diff[16] = "";
		K_ITEM *w_item;
		char tmp[256] = "";
		bool blk = false;

		suffix_string(hash_diff, diff, sizeof(diff)-1, 0);

		switch (confirmed[0]) {
			case BLOCKS_NEW:
				blk = true;
				tv_to_buf(&(row->createdate), cd_buf, sizeof(cd_buf));
				snprintf(tmp, sizeof(tmp), " UTC:%s", cd_buf);
				break;
			case BLOCKS_CONFIRM:
				blk = true;
				if (pool.diffacc >= 1000.0) {
					suffix_string(pool.diffacc, est, sizeof(est)-2, 0);
					strcat(est, " ");
				}
				w_item = find_workinfo(row->workinfoid, NULL);
				if (w_item) {
					WORKINFO *workinfo;
					DATA_WORKINFO(workinfo, w_item);
					if (workinfo->diff_target > 0.0) {
						snprintf(pct, sizeof(pct), "%.2f%% ",
							 100.0 * pool.diffacc /
							 workinfo->diff_target);
					}
				}
				tv_to_buf(&(row->createdate), cd_buf, sizeof(cd_buf));
				snprintf(tmp, sizeof(tmp),
					 " Reward: %f, Worker: %s, ShareEst: %.1f %s%sUTC:%s",
					 BTC_TO_D(row->reward),
					 st = safe_text_nonull(row->workername),
					 pool.diffacc, est, pct, cd_buf);
				FREENULL(st);
				if (pool.workinfoid < row->workinfoid) {
					pool.workinfoid = row->workinfoid;
					pool.height = row->height;
					zero_on_new_block(false);
				}
				break;
			case BLOCKS_ORPHAN:
			case BLOCKS_REJECT:
			case BLOCKS_42:
			default:
				break;
		}

		LOGWARNING("%s(): %sStatus: %s, Block: %"PRId32"/...%s Diff %s%s",
			   __func__, blk ? "BLOCK! " : "",
			   blocks_confirmed(confirmed),
			   height, hash_dsp, diff, tmp);
	}

	return ok;
}

bool blocks_fill(PGconn *conn)
{
	ExecStatusType rescode;
	PGresult *res;
	K_TREE_CTX ctx[1];
	K_ITEM *item;
	int n, i;
	BLOCKS *row;
	char *field;
	char *sel;
	int fields = 18;
	bool ok;

	LOGDEBUG("%s(): select", __func__);

	sel = "select "
		"height,blockhash,workinfoid,userid,workername,"
		"clientid,enonce1,nonce2,nonce,reward,confirmed,info,"
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
	K_WLOCK(blocks_free);
	for (i = 0; i < n; i++) {
		item = k_unlink_head(blocks_free);
		DATA_BLOCKS(row, item);
		bzero(row, sizeof(*row));

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

		PQ_GET_FLD(res, i, "info", field, ok);
		if (!ok)
			break;
		TXT_TO_STR("info", field, row->info);

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

		add_to_ktree(blocks_root, item);
		k_add_head(blocks_store, item);

		if (tv_newer(&(dbstatus.newest_createdate_blocks), &(row->createdate)))
			copy_tv(&(dbstatus.newest_createdate_blocks), &(row->createdate));

		if (dbstatus.newest_height_blocks < row->height)
			dbstatus.newest_height_blocks = row->height;

		if (pool.workinfoid < row->workinfoid) {
			pool.workinfoid = row->workinfoid;
			pool.height = row->height;
		}

		// first add all the NEW blocks
		if (row->confirmed[0] == BLOCKS_NEW)
			userinfo_block(row, INFO_NEW, 1);
	}

	if (!ok)
		k_add_head(blocks_free, item);
	else
		ok = set_blockcreatedate(0);

	// Now update all the CURRENT orphan/reject stats
	if (ok) {
		item = first_in_ktree(blocks_root, ctx);
		while (item) {
			DATA_BLOCKS(row, item);
			if (CURRENT(&(row->expirydate))) {
				if (row->confirmed[0] == BLOCKS_ORPHAN)
					userinfo_block(row, INFO_ORPHAN, 1);
				else if (row->confirmed[0] == BLOCKS_REJECT)
					userinfo_block(row, INFO_REJECT, 1);
			}
			item = next_in_ktree(ctx);
		}
	}

	K_WUNLOCK(blocks_free);
	PQclear(res);

	if (ok) {
		LOGDEBUG("%s(): built", __func__);
		LOGWARNING("%s(): loaded %d blocks records", __func__, n);
	}

	return ok;
}

// The timing of the memory table updates depends on 'already'
void miningpayouts_add_ram(bool ok, K_ITEM *mp_item, K_ITEM *old_mp_item, tv_t *cd)
{
	MININGPAYOUTS *oldmp;

	LOGDEBUG("%s(): ok %c", __func__, ok ? 'Y' : 'N');

	K_WLOCK(miningpayouts_free);
	if (!ok) {
		// Cleanup for the calling function
		k_add_head(miningpayouts_free, mp_item);
	} else {
		if (old_mp_item) {
			DATA_MININGPAYOUTS(oldmp, old_mp_item);
			remove_from_ktree(miningpayouts_root, old_mp_item);
			copy_tv(&(oldmp->expirydate), cd);
			add_to_ktree(miningpayouts_root, old_mp_item);
		}
		add_to_ktree(miningpayouts_root, mp_item);
		k_add_head(miningpayouts_store, mp_item);
	}
	K_WUNLOCK(miningpayouts_free);
}

/* Add means create a new one and expire the old one if it exists,
 *  otherwise we only expire the old one if it exists
 * It's the calling functions job to determine if a new one is required
 *  - i.e. if there is a difference between the old and new
 * already = already begun a transaction - and don't update the ram table */
bool miningpayouts_add(PGconn *conn, bool add, K_ITEM *mp_item,
			K_ITEM **old_mp_item, char *by, char *code, char *inet,
			tv_t *cd, K_TREE *trf_root, bool already)
{
	ExecStatusType rescode;
	bool conned = false;
	PGresult *res;
	bool ok = false, begun = false;
	MININGPAYOUTS *row, *oldmp = NULL;
	char *upd, *ins;
	char *params[4 + HISTORYDATECOUNT];
	int n, par = 0;

	LOGDEBUG("%s(): add %c already %c", __func__,
		 add ? 'Y' : 'N', already ? 'Y' : 'N');

	DATA_MININGPAYOUTS(row, mp_item);
	K_RLOCK(miningpayouts_free);
	*old_mp_item = find_miningpayouts(row->payoutid, row->userid);
	K_RUNLOCK(miningpayouts_free);

	conned = CKPQConn(&conn);
	if (!already) {
		begun = CKPQBegin(conn);
		if (!begun)
			goto unparam;
	}
		
	if (*old_mp_item) {
		LOGDEBUG("%s(): updating old", __func__);

		DATA_MININGPAYOUTS(oldmp, *old_mp_item);

		upd = "update miningpayouts set "EDDB"=$1 where payoutid=$2"
			" and userid=$3 and "EDDB"=$4";
		par = 0;
		params[par++] = tv_to_buf(cd, NULL, 0);
		params[par++] = bigint_to_buf(oldmp->payoutid, NULL, 0);
		params[par++] = bigint_to_buf(oldmp->userid, NULL, 0);
		params[par++] = tv_to_buf((tv_t *)&default_expiry, NULL, 0);
		PARCHKVAL(par, 4, params);

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
	}

	if (add) {
		LOGDEBUG("%s(): adding new", __func__);

		HISTORYDATEINIT(row, cd, by, code, inet);
		HISTORYDATETRANSFER(trf_root, row);

		par = 0;
		params[par++] = bigint_to_buf(row->payoutid, NULL, 0);
		params[par++] = bigint_to_buf(row->userid, NULL, 0);
		params[par++] = double_to_buf(row->diffacc, NULL, 0);
		params[par++] = bigint_to_buf(row->amount, NULL, 0);
		HISTORYDATEPARAMS(params, par, row);
		PARCHK(par, params);

		ins = "insert into miningpayouts "
			"(payoutid,userid,diffacc,amount"
			HISTORYDATECONTROL ") values (" PQPARAM9 ")";

		res = PQexecParams(conn, ins, par, NULL, (const char **)params, NULL, NULL, 0, CKPQ_WRITE);
		rescode = PQresultStatus(res);
		if (!PGOK(rescode)) {
			PGLOGERR("Insert", rescode, conn);
			goto unparam;
		}
	}

	ok = true;
rollback:
	if (begun)
		CKPQEnd(conn, ok);
unparam:
	for (n = 0; n < par; n++)
		free(params[n]);

	CKPQDisco(&conn, conned);

	if (!already)
		miningpayouts_add_ram(ok, mp_item, *old_mp_item, cd);

	return ok;
}

bool miningpayouts_fill(PGconn *conn)
{
	ExecStatusType rescode;
	PGresult *res;
	K_ITEM *item;
	MININGPAYOUTS *row;
	int n, t, i;
	char *field;
	char *sel;
	int fields = 4;
	bool ok = false;

	LOGDEBUG("%s(): select", __func__);

	sel = "declare mp cursor for select "
		"payoutid,userid,diffacc,amount"
		HISTORYDATECONTROL
		" from miningpayouts";
	res = PQexec(conn, "Begin", CKPQ_READ);
	rescode = PQresultStatus(res);
	PQclear(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Begin", rescode, conn);
		return false;
	}

	res = PQexec(conn, sel, CKPQ_READ);
	rescode = PQresultStatus(res);
	PQclear(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Declare", rescode, conn);
		goto flail;
	}

	LOGDEBUG("%s(): fetching ...", __func__);

	res = PQexec(conn, "fetch 1 in mp", CKPQ_READ);
	rescode = PQresultStatus(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Fetch first", rescode, conn);
		PQclear(res);
		goto flail;
	}

	n = PQnfields(res);
	if (n != (fields + HISTORYDATECOUNT)) {
		LOGERR("%s(): Invalid field count - should be %d, but is %d",
			__func__, fields + HISTORYDATECOUNT, n);
		PQclear(res);
		goto flail;
	}

	n = 0;
	ok = true;
	K_WLOCK(miningpayouts_free);
	while ((t = PQntuples(res)) > 0) {
		for (i = 0; i < t; i++) {
			item = k_unlink_head(miningpayouts_free);
			DATA_MININGPAYOUTS(row, item);
			bzero(row, sizeof(*row));

			if (everyone_die) {
				ok = false;
				break;
			}

			PQ_GET_FLD(res, i, "payoutid", field, ok);
			if (!ok)
				break;
			TXT_TO_BIGINT("payoutid", field, row->payoutid);

			PQ_GET_FLD(res, i, "userid", field, ok);
			if (!ok)
				break;
			TXT_TO_BIGINT("userid", field, row->userid);

			PQ_GET_FLD(res, i, "diffacc", field, ok);
			if (!ok)
				break;
			TXT_TO_DOUBLE("diffacc", field, row->diffacc);

			PQ_GET_FLD(res, i, "amount", field, ok);
			if (!ok)
				break;
			TXT_TO_BIGINT("amount", field, row->amount);

			HISTORYDATEFLDS(res, i, row, ok);
			if (!ok)
				break;

			add_to_ktree(miningpayouts_root, item);
			k_add_head(miningpayouts_store, item);
			tick();
			n++;
		}
		PQclear(res);
		res = PQexec(conn, "fetch 9999 in mp", CKPQ_READ);
		rescode = PQresultStatus(res);
		if (!PGOK(rescode)) {
			PGLOGERR("Fetch next", rescode, conn);
			ok = false;
			break;
		}
	}
	if (!ok)
		k_add_head(miningpayouts_free, item);

	K_WUNLOCK(miningpayouts_free);
	PQclear(res);
flail:
	res = PQexec(conn, "Commit", CKPQ_READ);
	PQclear(res);

	if (ok) {
		LOGDEBUG("%s(): built", __func__);
		LOGWARNING("%s(): fetched %d miningpayout records", __func__, n);
	}

	return ok;
}

// The timing of the memory table updates depends on 'already'
void payouts_add_ram(bool ok, K_ITEM *p_item, K_ITEM *old_p_item, tv_t *cd)
{
	PAYOUTS *oldp;

	LOGDEBUG("%s(): ok %c", __func__, ok ? 'Y' : 'N');

	K_WLOCK(payouts_free);
	if (!ok) {
		// Cleanup for the calling function
		free_payouts_data(p_item);
		k_add_head(payouts_free, p_item);
	} else {
		if (old_p_item) {
			DATA_PAYOUTS(oldp, old_p_item);
			remove_from_ktree(payouts_root, old_p_item);
			remove_from_ktree(payouts_id_root, old_p_item);
			remove_from_ktree(payouts_wid_root, old_p_item);
			copy_tv(&(oldp->expirydate), cd);
			add_to_ktree(payouts_root, old_p_item);
			add_to_ktree(payouts_id_root, old_p_item);
			add_to_ktree(payouts_wid_root, old_p_item);
		}
		add_to_ktree(payouts_root, p_item);
		add_to_ktree(payouts_id_root, p_item);
		add_to_ktree(payouts_wid_root, p_item);
		k_add_head(payouts_store, p_item);
	}
	K_WUNLOCK(payouts_free);
}

/* Add means create a new one and expire the old one if it exists,
 *  otherwise we only expire the old one if it exists
 * It's the calling functions job to determine if a new one is required
 *  - i.e. if there is a difference between the old and new
 * already = already begun a transaction - and don't update the ram table */
bool payouts_add(PGconn *conn, bool add, K_ITEM *p_item, K_ITEM **old_p_item,
		 char *by, char *code, char *inet, tv_t *cd, K_TREE *trf_root,
		 bool already)
{
	ExecStatusType rescode;
	bool conned = false;
	PGresult *res;
	bool ok = false, begun = false;
	PAYOUTS *row, *oldpayouts = NULL;
	char *upd, *ins;
	char *params[13 + HISTORYDATECOUNT];
	int n, par = 0;

	LOGDEBUG("%s(): add %c already %c", __func__,
		 add ? 'Y' : 'N', already ? 'Y' : 'N');

	DATA_PAYOUTS(row, p_item);
	K_RLOCK(payouts_free);
	*old_p_item = find_payouts(row->height, row->blockhash);
	K_RUNLOCK(payouts_free);

	conned = CKPQConn(&conn);
	if (!already) {
		begun = CKPQBegin(conn);
		if (!begun)
			goto unparam;
	}

	if (*old_p_item) {
		LOGDEBUG("%s(): updating old", __func__);

		DATA_PAYOUTS(oldpayouts, *old_p_item);

		upd = "update payouts set "EDDB"=$1 where payoutid=$2"
			" and "EDDB"=$3";
		par = 0;
		params[par++] = tv_to_buf(cd, NULL, 0);
		params[par++] = bigint_to_buf(oldpayouts->payoutid, NULL, 0);
		params[par++] = tv_to_buf((tv_t *)&default_expiry, NULL, 0);
		PARCHKVAL(par, 3, params);

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

		// Expiring an old record
		row->payoutid = oldpayouts->payoutid;
	} else {
		if (add) {
			// Creating a new record
			row->payoutid = nextid(conn, "payoutid", (int64_t)1, cd, by, code, inet);
			if (row->payoutid == 0)
				goto rollback;
		}
	}

	if (add) {
		LOGDEBUG("%s(): adding new", __func__);

		HISTORYDATEINIT(row, cd, by, code, inet);
		HISTORYDATETRANSFER(trf_root, row);

		par = 0;
		params[par++] = bigint_to_buf(row->payoutid, NULL, 0);
		params[par++] = int_to_buf(row->height, NULL, 0);
		params[par++] = str_to_buf(row->blockhash, NULL, 0);
		params[par++] = bigint_to_buf(row->minerreward, NULL, 0);
		params[par++] = bigint_to_buf(row->workinfoidstart, NULL, 0);
		params[par++] = bigint_to_buf(row->workinfoidend, NULL, 0);
		params[par++] = bigint_to_buf(row->elapsed, NULL, 0);
		params[par++] = str_to_buf(row->status, NULL, 0);
		params[par++] = double_to_buf(row->diffwanted, NULL, 0);
		params[par++] = double_to_buf(row->diffused, NULL, 0);
		params[par++] = double_to_buf(row->shareacc, NULL, 0);
		params[par++] = tv_to_buf(&(row->lastshareacc), NULL, 0);
		params[par++] = str_to_buf(row->stats, NULL, 0);
		HISTORYDATEPARAMS(params, par, row);
		PARCHK(par, params);

		ins = "insert into payouts "
			"(payoutid,height,blockhash,minerreward,workinfoidstart,"
			"workinfoidend,elapsed,status,diffwanted,diffused,shareacc,"
			"lastshareacc,stats"
			HISTORYDATECONTROL ") values (" PQPARAM18 ")";

		res = PQexecParams(conn, ins, par, NULL, (const char **)params, NULL, NULL, 0, CKPQ_WRITE);
		rescode = PQresultStatus(res);
		if (!PGOK(rescode)) {
			PGLOGERR("Insert", rescode, conn);
			goto unparam;
		}
	}

	ok = true;
rollback:
	if (begun)
		CKPQEnd(conn, ok);
unparam:
	for (n = 0; n < par; n++)
		free(params[n]);

	CKPQDisco(&conn, conned);

	if (!already)
		payouts_add_ram(ok, p_item, *old_p_item, cd);

	return ok;
}

/* Expire the entire payout, miningpayouts and payments
 * If it returns false, nothing was changed
 *  and a console message will say why */
K_ITEM *payouts_full_expire(PGconn *conn, int64_t payoutid, tv_t *now, bool lock)
{
	bool locked = false, conned = false, begun = false, ok = false;
	K_TREE_CTX mp_ctx[1], pm_ctx[1];
	K_ITEM *po_item = NULL, *mp_item, *pm_item, *next_item;
	PAYMENTS *payments = NULL;
	MININGPAYOUTS *mp = NULL;
	PAYOUTS *payouts = NULL;
	ExecStatusType rescode;
	PGresult *res;
	char *params[8];
	int n, par = 0;
	char *upd, *tuples = NULL;
	int po_upd = -7, mp_upd = -7, pm_upd = -7;

	// If not already done before calling
	if (lock)
		K_WLOCK(process_pplns_free);

	// This will be rare so a full lock is best
	K_WLOCK(payouts_free);
	K_WLOCK(miningpayouts_free);
	K_WLOCK(payments_free);
	locked = true;

	po_item = find_payoutid(payoutid);
	if (!po_item) {
		LOGERR("%s(): unknown payoutid %"PRId64, __func__, payoutid);
		goto matane;
	}

	conned = CKPQConn(&conn);

	begun = CKPQBegin(conn);
	if (!begun)
		goto matane;

	upd = "update payouts set "EDDB"=$1 where payoutid=$2 and "EDDB"=$3";
	par = 0;
	params[par++] = tv_to_buf(now, NULL, 0);
	params[par++] = bigint_to_buf(payoutid, NULL, 0);
	params[par++] = tv_to_buf((tv_t *)&default_expiry, NULL, 0);
	PARCHKVAL(par, 3, params);

	res = PQexecParams(conn, upd, par, NULL, (const char **)params, NULL, NULL, 0, CKPQ_WRITE);
	rescode = PQresultStatus(res);
	if (PGOK(rescode)) {
		tuples = PQcmdTuples(res);
		if (tuples && *tuples) {
			po_upd = atoi(tuples);
			if (po_upd != 1) {
				LOGERR("%s() updated payouts should be 1"
					" but updated=%d",
					__func__, po_upd);
				goto matane;
			}
		}
	}
	PQclear(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Update payouts", rescode, conn);
		goto matane;
	}

	for (n = 0; n < par; n++)
		free(params[n]);

	upd = "update miningpayouts set "EDDB"=$1 where payoutid=$2 and "EDDB"=$3";
	par = 0;
	params[par++] = tv_to_buf(now, NULL, 0);
	params[par++] = bigint_to_buf(payoutid, NULL, 0);
	params[par++] = tv_to_buf((tv_t *)&default_expiry, NULL, 0);
	PARCHKVAL(par, 3, params);

	res = PQexecParams(conn, upd, par, NULL, (const char **)params, NULL, NULL, 0, CKPQ_WRITE);
	rescode = PQresultStatus(res);
	if (PGOK(rescode)) {
		tuples = PQcmdTuples(res);
		if (tuples && *tuples)
			mp_upd = atoi(tuples);
	}
	PQclear(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Update miningpayouts", rescode, conn);
		goto matane;
	}

	for (n = 0; n < par; n++)
		free(params[n]);

	upd = "update payments set "EDDB"=$1 where payoutid=$2 and "EDDB"=$3";
	par = 0;
	params[par++] = tv_to_buf(now, NULL, 0);
	params[par++] = bigint_to_buf(payoutid, NULL, 0);
	params[par++] = tv_to_buf((tv_t *)&default_expiry, NULL, 0);
	PARCHKVAL(par, 3, params);

	res = PQexecParams(conn, upd, par, NULL, (const char **)params, NULL, NULL, 0, CKPQ_WRITE);
	rescode = PQresultStatus(res);
	if (PGOK(rescode)) {
		tuples = PQcmdTuples(res);
		if (tuples && *tuples)
			pm_upd = atoi(tuples);
	}
	PQclear(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Update payments", rescode, conn);
		goto matane;
	}

	for (n = 0; n < par; n++)
		free(params[n]);
	par = 0;

	// Check miningpayouts failure condition
	mp_item = first_miningpayouts(payoutid, mp_ctx);
	if (!mp_item) {
		if (mp_upd != 0) {
			LOGERR("%s() updated miningpayouts should be 0 but"
				" updated=%d",
				__func__, mp_upd);
			goto matane;
		}
	} else {
		int count = 0;
		DATA_MININGPAYOUTS(mp, mp_item);
		while (mp_item && mp->payoutid == payoutid) {
			if (CURRENT(&(mp->expirydate)))
				count++;
			mp_item = next_in_ktree(mp_ctx);
			DATA_MININGPAYOUTS_NULL(mp, mp_item);
		}
		if (count != mp_upd) {
			LOGERR("%s() updated miningpayouts should be %d but"
				" updated=%d",
				__func__, count, mp_upd);
			goto matane;
		}
	}

	/* Check payments failure condition
	 *
	 * This does a full table search since there is no index
	 * This should be so rare that adding an index/tree for it
	 *  would be a waste */
	pm_item = first_in_ktree(payments_root, pm_ctx);
	if (!pm_item) {
		if (pm_upd != 0) {
			LOGERR("%s() updated payments should be 0 but"
				" updated=%d",
				__func__, pm_upd);
			goto matane;
		}
	} else {
		int count = 0;
		DATA_PAYMENTS(payments, pm_item);
		while (pm_item) {
			if (payments->payoutid == payoutid &&
			    CURRENT(&(payments->expirydate))) {
				count++;
			}
			pm_item = next_in_ktree(pm_ctx);
			DATA_PAYMENTS_NULL(payments, pm_item);
		}
		if (count != pm_upd) {
			LOGERR("%s() updated payments should be %d but"
				" updated=%d",
				__func__, count, pm_upd);
			goto matane;
		}
	}

	// No more possible errors, so update the ram tables
	DATA_PAYOUTS(payouts, po_item);
	remove_from_ktree(payouts_root, po_item);
	remove_from_ktree(payouts_id_root, po_item);
	remove_from_ktree(payouts_wid_root, po_item);
	copy_tv(&(payouts->expirydate), now);
	add_to_ktree(payouts_root, po_item);
	add_to_ktree(payouts_id_root, po_item);
	add_to_ktree(payouts_wid_root, po_item);

	mp_item = first_miningpayouts(payoutid, mp_ctx);
	DATA_MININGPAYOUTS_NULL(mp, mp_item);
	while (mp_item && mp->payoutid == payoutid) {
		if (CURRENT(&(mp->expirydate))) {
			next_item = next_in_ktree(mp_ctx);
			remove_from_ktree(miningpayouts_root, mp_item);
			copy_tv(&(mp->expirydate), now);
			add_to_ktree(miningpayouts_root, mp_item);
			mp_item = next_item;
		} else
			mp_item = next_in_ktree(mp_ctx);

		DATA_MININGPAYOUTS_NULL(mp, mp_item);
	}

	pm_item = first_in_ktree(payments_root, pm_ctx);
	DATA_PAYMENTS_NULL(payments, pm_item);
	while (pm_item) {
		if (payments->payoutid == payoutid &&
		    CURRENT(&(payments->expirydate))) {
			next_item = next_in_ktree(pm_ctx);
			remove_from_ktree(payments_root, pm_item);
			copy_tv(&(payments->expirydate), now);
			add_to_ktree(payments_root, pm_item);
			pm_item = next_item;
		} else
			pm_item = next_in_ktree(pm_ctx);

		DATA_PAYMENTS_NULL(payments, pm_item);
	}

	if (PAYGENERATED(payouts->status)) {
		// Original was generated, so undo the reward
		reward_shifts(payouts, -1);

	}

	ok = true;
matane:
	if (begun)
		CKPQEnd(conn, ok);

	if (locked) {
		K_WUNLOCK(payments_free);
		K_WUNLOCK(miningpayouts_free);
		K_WUNLOCK(payouts_free);
	}

	CKPQDisco(&conn, conned);

	if (lock)
		K_WUNLOCK(process_pplns_free);

	for (n = 0; n < par; n++)
		free(params[n]);

	if (ok)
		return po_item;
	else
		return NULL;
}

bool payouts_fill(PGconn *conn)
{
	ExecStatusType rescode;
	PGresult *res;
	K_ITEM *item, *b_item;
	K_TREE_CTX ctx[1];
	PAYOUTS *row;
	BLOCKS *blocks;
	int n, i;
	char *field;
	char *sel;
	int fields = 13;
	bool ok;

	LOGDEBUG("%s(): select", __func__);

	sel = "select "
		"payoutid,height,blockhash,minerreward,workinfoidstart,workinfoidend,"
		"elapsed,status,diffwanted,diffused,shareacc,lastshareacc,stats"
		HISTORYDATECONTROL
		" from payouts";
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
	K_WLOCK(payouts_free);
	for (i = 0; i < n; i++) {
		item = k_unlink_head(payouts_free);
		DATA_PAYOUTS(row, item);
		bzero(row, sizeof(*row));

		if (everyone_die) {
			ok = false;
			break;
		}

		PQ_GET_FLD(res, i, "payoutid", field, ok);
		if (!ok)
			break;
		TXT_TO_BIGINT("payoutid", field, row->payoutid);

		PQ_GET_FLD(res, i, "height", field, ok);
		if (!ok)
			break;
		TXT_TO_INT("height", field, row->height);

		PQ_GET_FLD(res, i, "blockhash", field, ok);
		if (!ok)
			break;
		TXT_TO_STR("blockhash", field, row->blockhash);

		PQ_GET_FLD(res, i, "minerreward", field, ok);
		if (!ok)
			break;
		TXT_TO_BIGINT("minerreward", field, row->minerreward);

		PQ_GET_FLD(res, i, "workinfoidstart", field, ok);
		if (!ok)
			break;
		TXT_TO_BIGINT("workinfoidstart", field, row->workinfoidstart);

		PQ_GET_FLD(res, i, "workinfoidend", field, ok);
		if (!ok)
			break;
		TXT_TO_BIGINT("workinfoidend", field, row->workinfoidend);

		PQ_GET_FLD(res, i, "elapsed", field, ok);
		if (!ok)
			break;
		TXT_TO_BIGINT("elapsed", field, row->elapsed);

		PQ_GET_FLD(res, i, "status", field, ok);
		if (!ok)
			break;
		TXT_TO_STR("status", field, row->status);

		PQ_GET_FLD(res, i, "diffwanted", field, ok);
		if (!ok)
			break;
		TXT_TO_DOUBLE("diffwanted", field, row->diffwanted);

		PQ_GET_FLD(res, i, "diffused", field, ok);
		if (!ok)
			break;
		TXT_TO_DOUBLE("diffused", field, row->diffused);

		PQ_GET_FLD(res, i, "shareacc", field, ok);
		if (!ok)
			break;
		TXT_TO_DOUBLE("shareacc", field, row->shareacc);

		PQ_GET_FLD(res, i, "lastshareacc", field, ok);
		if (!ok)
			break;
		TXT_TO_TV("lastshareacc", field, row->lastshareacc);

		PQ_GET_FLD(res, i, "stats", field, ok);
		if (!ok)
			break;
		TXT_TO_BLOB("stats", field, row->stats);
		LIST_MEM_ADD(payouts_free, row->stats);

		HISTORYDATEFLDS(res, i, row, ok);
		if (!ok)
			break;

		// This also of course, verifies the payouts -> blocks reference
		K_RLOCK(blocks_free);
		b_item = find_blocks(row->height, row->blockhash, ctx);
		K_RUNLOCK(blocks_free);
		if (!b_item) {
			LOGERR("%s(): payoutid %"PRId64" references unknown "
				"block %"PRId32"/%s",
				__func__, row->payoutid, row->height,
				row->blockhash);
			ok = false;
			break;
		} else {
			// blockcreatedate will already be set
			DATA_BLOCKS(blocks, b_item);
			copy_tv(&(row->blockcreatedate),
				&(blocks->blockcreatedate));
		}

		add_to_ktree(payouts_root, item);
		add_to_ktree(payouts_id_root, item);
		add_to_ktree(payouts_wid_root, item);
		k_add_head(payouts_store, item);

		if (CURRENT(&(row->expirydate)) && PAYGENERATED(row->status))
			reward_shifts(row, 1);

		tick();
	}
	if (!ok) {
		free_payouts_data(item);
		k_add_head(payouts_free, item);
	}

	K_WUNLOCK(payouts_free);
	PQclear(res);

	if (ok) {
		LOGDEBUG("%s(): built", __func__);
		LOGWARNING("%s(): loaded %d payout records", __func__, n);
	}

	return ok;
}

// TODO: discard them from RAM
bool auths_add(PGconn *conn, char *poolinstance, char *username,
		char *workername, char *clientid, char *enonce1,
		char *useragent, char *preauth, char *by, char *code,
		char *inet, tv_t *cd, K_TREE *trf_root,
		bool addressuser, USERS **users, WORKERS **workers)
{
	K_TREE_CTX ctx[1];
	K_ITEM *a_item, *u_item, *w_item;
	char cd_buf[DATE_BUFSIZ];
	AUTHS *row;
	bool ok = false;
	char *st = NULL;

	LOGDEBUG("%s(): add", __func__);

	K_WLOCK(auths_free);
	a_item = k_unlink_head(auths_free);
	K_WUNLOCK(auths_free);

	DATA_AUTHS(row, a_item);
	bzero(row, sizeof(*row));

	K_RLOCK(users_free);
	u_item = find_users(username);
	K_RUNLOCK(users_free);
	if (!u_item) {
		if (addressuser) {
			u_item = users_add(conn, username, EMPTY, EMPTY,
					   USER_ADDRESS, by, code, inet, cd,
					   trf_root);
		} else {
			LOGDEBUG("%s(): unknown user '%s'",
				 __func__,
				 st = safe_text_nonull(username));
			FREENULL(st);
		}
		if (!u_item)
			goto unitem;
	}
	DATA_USERS(*users, u_item);

	// Any status content means disallow mining
	if ((*users)->status[0])
		goto unitem;

	STRNCPY(row->poolinstance, poolinstance);
	row->userid = (*users)->userid;
	// since update=false, a dup will be ok and do nothing when igndup=true
	w_item = new_worker(conn, false, row->userid, workername,
			    DIFFICULTYDEFAULT_DEF_STR,
			    IDLENOTIFICATIONENABLED_DEF,
			    IDLENOTIFICATIONTIME_DEF_STR,
			    by, code, inet, cd, trf_root);
	if (!w_item)
		goto unitem;

	DATA_WORKERS(*workers, w_item);
	STRNCPY(row->workername, workername);
	TXT_TO_INT("clientid", clientid, row->clientid);
	STRNCPY(row->enonce1, enonce1);
	STRNCPY(row->useragent, useragent);
	STRNCPY(row->preauth, preauth);

	HISTORYDATEINIT(row, cd, by, code, inet);
	HISTORYDATETRANSFER(trf_root, row);

	K_WLOCK(auths_free);
	if (find_in_ktree(auths_root, a_item, ctx)) {
		k_add_head(auths_free, a_item);
		K_WUNLOCK(auths_free);

		// Shouldn't actually be possible unless twice in the logs
		tv_to_buf(cd, cd_buf, sizeof(cd_buf));
		LOGERR("%s(): Duplicate auths ignored %s/%s/%s",
			__func__, poolinstance, st = safe_text_nonull(workername),
			cd_buf);
		FREENULL(st);

		/* Let them mine, that's what matters :)
		 *  though this would normally only be during a reload */
		return true;
	}
	K_WUNLOCK(auths_free);

	// Update even if DB fails
	workerstatus_update(row, NULL, NULL);

	row->authid = 1;

	ok = true;
unitem:
	K_WLOCK(auths_free);
#if 1
	/* To save ram for now, don't store them,
	 * we don't actually use them anywhere yet */
	k_add_head(auths_free, a_item);
#else
	if (!ok)
		k_add_head(auths_free, a_item);
	else {
		add_to_ktree(auths_root, a_item);
		k_add_head(auths_store, a_item);
	}
#endif
	K_WUNLOCK(auths_free);

	return ok;
}

bool poolstats_add(PGconn *conn, bool store, char *poolinstance,
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
	bzero(row, sizeof(*row));

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

	K_WLOCK(poolstats_free);
	if (igndup && find_in_ktree(poolstats_root, p_item, ctx)) {
		k_add_head(poolstats_free, p_item);
		K_WUNLOCK(poolstats_free);
		return true;
	}
	K_WUNLOCK(poolstats_free);

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
			bool show_msg = true;
			char *code;
			if (igndup) {
				code = PQresultErrorField(res, PG_DIAG_SQLSTATE);
				if (code && strcmp(code, SQL_UNIQUE_VIOLATION) == 0)
					show_msg = false;
			}
			if (show_msg)
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
		add_to_ktree(poolstats_root, p_item);
		k_add_head(poolstats_store, p_item);
	}
	K_WUNLOCK(poolstats_free);

	return ok;
}

// TODO: data selection - only require ?
bool poolstats_fill(PGconn *conn)
{
	ExecStatusType rescode;
	PGresult *res;
	K_ITEM *item;
	int n, i;
	struct tm tm;
	time_t now_t;
	char tzinfo[16], stamp[128];
	POOLSTATS *row;
	char *field;
	char *sel = NULL;
	size_t len, off;
	int fields = 8;
	long minoff, hroff;
	char tzch;
	bool ok;

	LOGDEBUG("%s(): select", __func__);

	// Temoprarily ... load last 24hrs worth
	now_t = time(NULL);
	now_t -= 24 * 60 * 60;
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
			"'%d-%02d-%02d %02d:%02d:%02d%s'",
			tm.tm_year + 1900,
			tm.tm_mon + 1,
			tm.tm_mday,
			tm.tm_hour,
			tm.tm_min,
			tm.tm_sec,
			tzinfo);

	APPEND_REALLOC_INIT(sel, off, len);
	APPEND_REALLOC(sel, off, len,
			"select "
			"poolinstance,elapsed,users,workers,hashrate,"
			"hashrate5m,hashrate1hr,hashrate24hr"
			SIMPLEDATECONTROL
			" from poolstats where "CDDB">");
	APPEND_REALLOC(sel, off, len, stamp);

	res = PQexec(conn, sel, CKPQ_READ);
	rescode = PQresultStatus(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Select", rescode, conn);
		PQclear(res);
		ok = false;
		goto clean;
	}

	n = PQnfields(res);
	if (n != (fields + SIMPLEDATECOUNT)) {
		LOGERR("%s(): Invalid field count - should be %d, but is %d",
			__func__, fields + SIMPLEDATECOUNT, n);
		PQclear(res);
		ok = false;
		goto clean;
	}

	n = PQntuples(res);
	LOGDEBUG("%s(): tree build count %d", __func__, n);
	ok = true;
	K_WLOCK(poolstats_free);
	for (i = 0; i < n; i++) {
		item = k_unlink_head(poolstats_free);
		DATA_POOLSTATS(row, item);
		bzero(row, sizeof(*row));

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

		add_to_ktree(poolstats_root, item);
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
clean:
	free(sel);
	return ok;
}

// To RAM
bool userstats_add(char *poolinstance, char *elapsed, char *username,
			char *workername, char *hashrate, char *hashrate5m,
			char *hashrate1hr, char *hashrate24hr, bool idle,
			bool eos, char *by, char *code, char *inet, tv_t *cd,
			K_TREE *trf_root)
{
	K_ITEM *us_item, *u_item, *us_match, *us_next;
	USERSTATS *row, *match, *next;
	USERS *users;
	K_TREE_CTX ctx[1];
	char *st = NULL;

	LOGDEBUG("%s(): add", __func__);

	K_WLOCK(userstats_free);
	us_item = k_unlink_head(userstats_free);
	K_WUNLOCK(userstats_free);

	DATA_USERSTATS(row, us_item);
	bzero(row, sizeof(*row));

	STRNCPY(row->poolinstance, poolinstance);
	TXT_TO_BIGINT("elapsed", elapsed, row->elapsed);
	K_RLOCK(users_free);
	u_item = find_users(username);
	K_RUNLOCK(users_free);
	if (!u_item) {
		LOGERR("%s(): unknown user '%s'",
			__func__,
			st = safe_text_nonull(username));
		FREENULL(st);
		return false;
	}
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

	workerstatus_update(NULL, NULL, row);

	/* group at: userid,workername */
	K_WLOCK(userstats_free);
	us_match = STORE_WHEAD(userstats_eos_store);
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
		k_add_head(userstats_free, us_item);
	} else {
		// New user+worker
		k_add_head(userstats_eos_store, us_item);
	}
	K_WUNLOCK(userstats_free);

	if (eos) {
		K_WLOCK(userstats_free);
		us_next = STORE_WHEAD(userstats_eos_store);
		while (us_next) {
			us_item = find_in_ktree(userstats_root, us_next, ctx);
			if (!us_item) {
				// New user+worker - store it in RAM
				us_match = us_next;
				us_next = us_match->next;
				k_unlink_item(userstats_eos_store, us_match);
				add_to_ktree(userstats_root, us_match);
				k_add_head(userstats_store, us_match);
			} else {
				DATA_USERSTATS(next, us_next);
				// Old user+worker - update RAM if us_item is newer
				DATA_USERSTATS(row, us_item);
				if (tv_newer(&(next->createdate), &(row->createdate))) {
					// the tree index data is the same
					memcpy(next, row, sizeof(*row));
				}
				us_next = us_next->next;
			}
		}
		// Discard them
		if (userstats_eos_store->count > 0)
			k_list_transfer_to_head(userstats_eos_store, userstats_free);
		K_WUNLOCK(userstats_free);
	}

	return true;
}

// To RAM
bool workerstats_add(char *poolinstance, char *elapsed, char *username,
			char *workername, char *hashrate, char *hashrate5m,
			char *hashrate1hr, char *hashrate24hr, bool idle,
			char *by, char *code, char *inet, tv_t *cd,
			K_TREE *trf_root)
{
	K_ITEM *us_item, *u_item, *us_match;
	USERSTATS *row, *match;
	USERS *users;
	K_TREE_CTX ctx[1];

	LOGDEBUG("%s(): add", __func__);

	K_WLOCK(userstats_free);
	us_item = k_unlink_head(userstats_free);
	K_WUNLOCK(userstats_free);

	DATA_USERSTATS(row, us_item);
	bzero(row, sizeof(*row));

	STRNCPY(row->poolinstance, poolinstance);
	TXT_TO_BIGINT("elapsed", elapsed, row->elapsed);
	K_RLOCK(users_free);
	u_item = find_users(username);
	K_RUNLOCK(users_free);
	if (!u_item) {
		char *usr = NULL, *wrk = NULL;
		LOGERR("%s(): unknown user '%s' (worker=%s)",
			__func__,
			usr = safe_text_nonull(username),
			wrk = safe_text_nonull(workername));
		FREENULL(usr);
		FREENULL(wrk);
		return false;
	}
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

	workerstatus_update(NULL, NULL, row);

	K_WLOCK(userstats_free);
	us_match = find_in_ktree(userstats_root, us_item, ctx);
	if (!us_match) {
		// New user+worker - store it in RAM
		add_to_ktree(userstats_root, us_item);
		k_add_head(userstats_store, us_item);
	} else {
		DATA_USERSTATS(match, us_match);
		// Old user+worker - update RAM if us_item is newer
		if (tv_newer(&(match->createdate), &(row->createdate))) {
			// the tree index data is the same
			memcpy(match, row, sizeof(*row));
		}
		k_add_head(userstats_free, us_item);
	}
	K_WUNLOCK(userstats_free);

	return true;
}

bool markersummary_add(PGconn *conn, K_ITEM *ms_item, char *by, char *code,
			char *inet, tv_t *cd, K_TREE *trf_root)
{
	ExecStatusType rescode;
	bool conned = false;
	PGresult *res;
	MARKERSUMMARY *row;
	char *params[20 + MODIFYDATECOUNT];
	int n, par = 0;
	char *ins;
	bool ok = false;
	char *st = NULL;

	LOGDEBUG("%s(): add", __func__);

	DATA_MARKERSUMMARY(row, ms_item);

	MODIFYDATEPOINTERS(markersummary_free, row, cd, by, code, inet);
	MODIFYDATETRANSFER(markersummary_free, trf_root, row);

	par = 0;
	params[par++] = bigint_to_buf(row->markerid, NULL, 0);
	params[par++] = bigint_to_buf(row->userid, NULL, 0);
	params[par++] = str_to_buf(row->workername, NULL, 0);
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
	params[par++] = tv_to_buf(&(row->firstshareacc), NULL, 0);
	params[par++] = tv_to_buf(&(row->lastshareacc), NULL, 0);
	params[par++] = double_to_buf(row->lastdiffacc, NULL, 0);
	MODIFYDATEPARAMS(params, par, row);
	PARCHK(par, params);

	ins = "insert into markersummary "
		"(markerid,userid,workername,diffacc,diffsta,diffdup,diffhi,"
		"diffrej,shareacc,sharesta,sharedup,sharehi,sharerej,"
		"sharecount,errorcount,firstshare,lastshare,firstshareacc,"
		"lastshareacc,lastdiffacc"
		MODIFYDATECONTROL ") values (" PQPARAM28 ")";

	LOGDEBUG("%s() adding ms %"PRId64"/%"PRId64"/%s/%.0f",
		 __func__, row->markerid, row->userid,
		 st = safe_text_nonull(row->workername),
		 row->diffacc);
	FREENULL(st);

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

	// caller must do tree/list/store changes

	return ok;
}

bool markersummary_fill(PGconn *conn)
{
	ExecStatusType rescode;
	PGresult *res;
	K_ITEM *item, *p_item;
	int n, t, i, p_n;
	MARKERSUMMARY *row, *p_row;
	char *params[1];
	char *field;
	char *sel;
	int fields = 20, par = 0;
	bool ok = false;

	LOGDEBUG("%s(): select", __func__);

	printf(TICK_PREFIX"ms 0\r");
	fflush(stdout);

	// TODO: limit how far back
	sel = "declare ws cursor for select "
		"markerid,userid,workername,diffacc,diffsta,diffdup,diffhi,"
		"diffrej,shareacc,sharesta,sharedup,sharehi,sharerej,"
		"sharecount,errorcount,firstshare,lastshare,firstshareacc,"
		"lastshareacc,lastdiffacc"
		MODIFYDATECONTROL
		" from markersummary where markerid>=$1";
	par = 0;
	if (mark_start)
		params[par++] = mark_start;
	else
		params[par++] = "0";
	PARCHK(par, params);

	LOGWARNING("%s(): loading from markerid>=%s", __func__, params[0]);

	res = PQexec(conn, "Begin", CKPQ_READ);
	rescode = PQresultStatus(res);
	PQclear(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Begin", rescode, conn);
		return false;
	}

	res = PQexecParams(conn, sel, par, NULL, (const char **)params, NULL, NULL, 0, CKPQ_READ);
	rescode = PQresultStatus(res);
	PQclear(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Declare", rescode, conn);
		goto flail;
	}

	LOGDEBUG("%s(): fetching ...", __func__);

	res = PQexec(conn, "fetch 1 in ws", CKPQ_READ);
	rescode = PQresultStatus(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Fetch first", rescode, conn);
		PQclear(res);
		goto flail;
	}

	n = PQnfields(res);
	if (n != (fields + MODIFYDATECOUNT)) {
		LOGERR("%s(): Invalid field count - should be %d, but is %d",
			__func__, fields + MODIFYDATECOUNT, n);
		PQclear(res);
		goto flail;
	}

	n = 0;
	ok = true;
	K_WLOCK(markersummary_free);
	while ((t = PQntuples(res)) > 0) {
		// Avoid locking them too many times
		K_RLOCK(workmarkers_free);
		K_WLOCK(userinfo_free);
		for (i = 0; i < t; i++) {
			item = k_unlink_head(markersummary_free);
			DATA_MARKERSUMMARY(row, item);
			bzero(row, sizeof(*row));

			if (everyone_die) {
				ok = false;
				break;
			}

			PQ_GET_FLD(res, i, "markerid", field, ok);
			if (!ok)
				break;
			TXT_TO_BIGINT("markerid", field, row->markerid);

			PQ_GET_FLD(res, i, "userid", field, ok);
			if (!ok)
				break;
			TXT_TO_BIGINT("userid", field, row->userid);

			PQ_GET_FLD(res, i, "workername", field, ok);
			if (!ok)
				break;
			TXT_TO_PTR("workername", field, row->workername);
			LIST_MEM_ADD(markersummary_free, row->workername);

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

			PQ_GET_FLD(res, i, "firstshare", field, ok);
			if (!ok)
				break;
			TXT_TO_TV("firstshare", field, row->firstshare);

			PQ_GET_FLD(res, i, "lastshare", field, ok);
			if (!ok)
				break;
			TXT_TO_TV("lastshare", field, row->lastshare);

			PQ_GET_FLD(res, i, "firstshareacc", field, ok);
			if (!ok)
				break;
			TXT_TO_TV("firstshareacc", field, row->firstshareacc);

			PQ_GET_FLD(res, i, "lastshareacc", field, ok);
			if (!ok)
				break;
			TXT_TO_TV("lastshareacc", field, row->lastshareacc);

			PQ_GET_FLD(res, i, "lastdiffacc", field, ok);
			if (!ok)
				break;
			TXT_TO_DOUBLE("lastdiffacc", field, row->lastdiffacc);

			MODIFYDATEFLDPOINTERS(markersummary_free, res, i, row, ok);
			if (!ok)
				break;

			/* Save having to do this everywhere in the code for old data
			 * It's not always accurate, but soon after when it's not,
			 *  and also what was used before the 2 fields were added */
			if (row->diffacc > 0) {
				if (row->firstshareacc.tv_sec == 0L)
					copy_tv(&(row->firstshareacc), &(row->firstshare));
				if (row->lastshareacc.tv_sec == 0L)
					copy_tv(&(row->lastshareacc), &(row->lastshare));
			}

			add_to_ktree(markersummary_root, item);
			add_to_ktree(markersummary_userid_root, item);
			k_add_head(markersummary_store, item);

			p_item = find_markersummary_p(row->markerid);
			if (!p_item) {
				/* N.B. this could be false due to the markerid
				 *  having the wrong status TODO: deal with that? */
				p_item = k_unlink_head(markersummary_free);
				DATA_MARKERSUMMARY(p_row, p_item);
				bzero(p_row, sizeof(*p_row));
				p_row->markerid = row->markerid;
				POOL_MS(p_row);
				add_to_ktree(markersummary_pool_root, p_item);
				k_add_head(markersummary_pool_store, p_item);
			} else {
				DATA_MARKERSUMMARY(p_row, p_item);
			}

			markersummary_to_pool(p_row, row);

			userinfo_update(NULL, NULL, row, false);

			if (n == 0 || ((n+1) % 100000) == 0) {
				printf(TICK_PREFIX"ms ");
				pcom(n+1);
				putchar('\r');
				fflush(stdout);
			}
			tick();
			n++;
		}
		K_WUNLOCK(userinfo_free);
		K_RUNLOCK(workmarkers_free);
		PQclear(res);
		res = PQexec(conn, "fetch 9999 in ws", CKPQ_READ);
		rescode = PQresultStatus(res);
		if (!PGOK(rescode)) {
			PGLOGERR("Fetch next", rescode, conn);
			ok = false;
			break;
		}
	}
	if (!ok) {
		free_markersummary_data(item);
		k_add_head(markersummary_free, item);
	}

	p_n = markersummary_pool_store->count;

	K_WUNLOCK(markersummary_free);
	PQclear(res);
flail:
	res = PQexec(conn, "Commit", CKPQ_READ);
	PQclear(res);

	if (ok) {
		LOGDEBUG("%s(): built", __func__);
		LOGWARNING("%s(): fetched %d markersummary records", __func__, n);
		LOGWARNING("%s(): created %d markersummary pool records", __func__, p_n);
	}

	return ok;
}

/* Already means there is a transaction already in progress
 *  so don't begin or commit/rollback
 * Add means create a new one and expire the old one if it exists,
 *  otherwise we only expire the old one if it exists
 * Add requires all db fields except markerid, however if markerid
 *  is non-zero, it will be used instead of getting a new one
 *  i.e. this effectively means updating a workmarker
 * !Add requires markerid or workinfoidend, only
 *  workinfoidend is used if markerid is zero
 * N.B. if you expire a workmarker without creating a new one,
 *  it's markerid is effectively cancelled, since creating a
 *  new matching workmarker later, will get a new markerid,
 *  since we only check for a CURRENT workmarkers
 * N.B. also, this returns success if !add and there is no matching
 *  old workmarkers */
bool _workmarkers_process(PGconn *conn, bool already, bool add,
			  int64_t markerid, char *poolinstance,
			  int64_t workinfoidend, int64_t workinfoidstart,
			  char *description, char *status, char *by, char *code,
			  char *inet, tv_t *cd, K_TREE *trf_root,
			  WHERE_FFL_ARGS)
{
	ExecStatusType rescode;
	bool conned = false;
	PGresult *res = NULL;
	K_ITEM *wm_item = NULL, *old_wm_item = NULL, *w_item;
	WORKMARKERS *row, *oldworkmarkers = NULL;
	char *upd, *ins;
	char *params[6 + HISTORYDATECOUNT];
	bool ok = false, begun = false;
	int n, par = 0;

	LOGDEBUG("%s(): add %c already %c", __func__,
		 add ? 'Y' : 'N', already ? 'Y' : 'N');

	if (markerid == 0) {
		K_RLOCK(workmarkers_free);
		old_wm_item = find_workmarkers(workinfoidend, true, '\0', NULL);
		K_RUNLOCK(workmarkers_free);
	} else {
		K_RLOCK(workmarkers_free);
		old_wm_item = find_workmarkerid(markerid, true, '\0');
		K_RUNLOCK(workmarkers_free);
	}
	if (old_wm_item) {
		LOGDEBUG("%s(): updating old", __func__);

		DATA_WORKMARKERS(oldworkmarkers, old_wm_item);
		if (!conn) {
			conn = dbconnect();
			conned = true;
		}
		if (!already) {
			res = PQexec(conn, "Begin", CKPQ_WRITE);
			rescode = PQresultStatus(res);
			PQclear(res);
			if (!PGOK(rescode)) {
				PGLOGERR("Begin", rescode, conn);
				goto unparam;
			}

			begun = true;
		}

		upd = "update workmarkers set "EDDB"=$1 where markerid=$2"
			" and "EDDB"=$3";
		par = 0;
		params[par++] = tv_to_buf(cd, NULL, 0);
		params[par++] = bigint_to_buf(oldworkmarkers->markerid, NULL, 0);
		params[par++] = tv_to_buf((tv_t *)&default_expiry, NULL, 0);
		PARCHKVAL(par, 3, params);

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
	}

	if (add) {
		LOGDEBUG("%s(): adding new", __func__);

		if (poolinstance == NULL || description == NULL ||
		    status == NULL) {
			LOGEMERG("%s(): NULL field(s) passed:%s%s%s"
				 WHERE_FFL, __func__,
				 poolinstance ? "" : " poolinstance",
				 description ? "" : " description",
				 status ? "" : " status",
				 WHERE_FFL_PASS);
			goto rollback;
		}
		w_item = find_workinfo(workinfoidstart, NULL);
		if (!w_item)
			goto rollback;
		w_item = find_workinfo(workinfoidend, NULL);
		if (!w_item)
			goto rollback;

		K_WLOCK(workmarkers_free);
		wm_item = k_unlink_head(workmarkers_free);
		K_WUNLOCK(workmarkers_free);
		DATA_WORKMARKERS(row, wm_item);
		bzero(row, sizeof(*row));

		if (conn == NULL) {
			conn = dbconnect();
			conned = true;
		}

		if (!already && !begun) {
			res = PQexec(conn, "Begin", CKPQ_WRITE);
			rescode = PQresultStatus(res);
			PQclear(res);
			if (!PGOK(rescode)) {
				PGLOGERR("Begin", rescode, conn);
				goto unparam;
			}
			begun = true;
		}

		if (old_wm_item)
			row->markerid = oldworkmarkers->markerid;
		else {
			if (markerid != 0)
				row->markerid = markerid;
			else {
				row->markerid = nextid(conn, "markerid", 1,
							cd, by, code, inet);
				if (row->markerid == 0)
					goto rollback;
			}
		}

		DUP_POINTER(workmarkers_free, row->poolinstance, poolinstance);
		row->workinfoidend = workinfoidend;
		row->workinfoidstart = workinfoidstart;
		DUP_POINTER(workmarkers_free, row->description, description);
		STRNCPY(row->status, status);
		HISTORYDATEINIT(row, cd, by, code, inet);
		HISTORYDATETRANSFER(trf_root, row);

		ins = "insert into workmarkers "
			"(markerid,poolinstance,workinfoidend,workinfoidstart,"
			"description,status"
			HISTORYDATECONTROL ") values (" PQPARAM11 ")";
		par = 0;
		params[par++] = bigint_to_buf(row->markerid, NULL, 0);
		params[par++] = str_to_buf(row->poolinstance, NULL, 0);
		params[par++] = bigint_to_buf(row->workinfoidend, NULL, 0);
		params[par++] = bigint_to_buf(row->workinfoidstart, NULL, 0);
		params[par++] = str_to_buf(row->description, NULL, 0);
		params[par++] = str_to_buf(row->status, NULL, 0);
		HISTORYDATEPARAMS(params, par, row);
		PARCHK(par, params);

		res = PQexecParams(conn, ins, par, NULL, (const char **)params, NULL, NULL, 0, CKPQ_WRITE);
		rescode = PQresultStatus(res);
		PQclear(res);
		if (!PGOK(rescode)) {
			PGLOGERR("Insert", rescode, conn);
			goto rollback;
		}
		row->pps_value = workinfo_pps(w_item, workinfoidend);
	}

	ok = true;
rollback:
	if (begun) {
		if (ok)
			res = PQexec(conn, "Commit", CKPQ_WRITE);
		else
			res = PQexec(conn, "Rollback", CKPQ_WRITE);

		PQclear(res);
	}
unparam:
	for (n = 0; n < par; n++)
		free(params[n]);

	if (conned)
		PQfinish(conn);

	if (!ok) {
		if (wm_item) {
			K_WLOCK(workmarkers_free);
			free_workmarkers_data(wm_item);
			k_add_head(workmarkers_free, wm_item);
			K_WUNLOCK(workmarkers_free);
		}
	} else {
		if (wm_item)
			shift_rewards(wm_item);
		K_WLOCK(workmarkers_free);
		if (old_wm_item) {
			remove_from_ktree(workmarkers_root, old_wm_item);
			remove_from_ktree(workmarkers_workinfoid_root,
					  old_wm_item);
			copy_tv(&(oldworkmarkers->expirydate), cd);
			add_to_ktree(workmarkers_root, old_wm_item);
			add_to_ktree(workmarkers_workinfoid_root, old_wm_item);
		}
		if (wm_item) {
			add_to_ktree(workmarkers_root, wm_item);
			add_to_ktree(workmarkers_workinfoid_root, wm_item);
			k_add_head(workmarkers_store, wm_item);
		}
		K_WUNLOCK(workmarkers_free);
	}

	return ok;
}

bool workmarkers_fill(PGconn *conn)
{
	ExecStatusType rescode;
	PGresult *res;
	K_ITEM *item, *wi_item;
	WORKINFO *workinfo;
	int n, i;
	WORKMARKERS *row;
	char *field;
	char *sel;
	int fields = 6;
	bool ok;

	LOGDEBUG("%s(): select", __func__);

	// TODO: limit how far back
	sel = "select "
		"markerid,poolinstance,workinfoidend,workinfoidstart,"
		"description,status"
		HISTORYDATECONTROL
		" from workmarkers";
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
	K_WLOCK(workmarkers_free);
	for (i = 0; i < n; i++) {
		item = k_unlink_head(workmarkers_free);
		DATA_WORKMARKERS(row, item);
		bzero(row, sizeof(*row));

		if (everyone_die) {
			ok = false;
			break;
		}

		PQ_GET_FLD(res, i, "markerid", field, ok);
		if (!ok)
			break;
		TXT_TO_BIGINT("markerid", field, row->markerid);

		PQ_GET_FLD(res, i, "poolinstance", field, ok);
		if (!ok)
			break;
		TXT_TO_PTR("poolinstance", field, row->poolinstance);
		LIST_MEM_ADD(workmarkers_free, row->poolinstance);

		PQ_GET_FLD(res, i, "workinfoidend", field, ok);
		if (!ok)
			break;
		TXT_TO_BIGINT("workinfoidend", field, row->workinfoidend);

		PQ_GET_FLD(res, i, "workinfoidstart", field, ok);
		if (!ok)
			break;
		TXT_TO_BIGINT("workinfoidstart", field, row->workinfoidstart);

		PQ_GET_FLD(res, i, "description", field, ok);
		if (!ok)
			break;
		TXT_TO_PTR("description", field, row->description);
		LIST_MEM_ADD(workmarkers_free, row->description);

		PQ_GET_FLD(res, i, "status", field, ok);
		if (!ok)
			break;
		TXT_TO_STR("status", field, row->status);

		HISTORYDATEFLDS(res, i, row, ok);
		if (!ok)
			break;

		add_to_ktree(workmarkers_root, item);
		add_to_ktree(workmarkers_workinfoid_root, item);
		k_add_head(workmarkers_store, item);

		wi_item = find_workinfo(row->workinfoidend, NULL);
		if (!wi_item) {
			LOGERR("%s(): ERROR workmarkerid %"PRId64
				" wid end %"PRId64" doesn't exist! "
				"PPS value will be zero",
				__func__, row->markerid,
				row->workinfoidend);
		}
		row->pps_value = workinfo_pps(wi_item, row->workinfoidend);

		if (CURRENT(&(row->expirydate)) &&
		    !WMPROCESSED(row->status)) {
			LOGWARNING("%s(): WARNING workmarkerid %"PRId64" (%s)"
				   " wid end %"PRId64" isn't processed! (%s) "
				   "You need to correct it after the startup "
				   "completes, with a marks action: processed"
				   " or cancel",
				   __func__, row->markerid, row->description,
				   row->workinfoidend, row->status);
		}

		/* Ignore any workmarker that isn't processed, so that the
		 *  necessary data to process it can be reloaded, if the
		 *  workmarker is after the last processed shift
		 * Any CURRENT non-processed workmarkers will give a console
		 *  warning (above) */
		if (CURRENT(&(row->expirydate)) &&
		    WMPROCESSED(row->status) &&
		    dbstatus.newest_workmarker_workinfoid < row->workinfoidend) {
			dbstatus.newest_workmarker_workinfoid = row->workinfoidend;
			if (!wi_item) {
				LOGEMERG("%s(): FAILURE workmarkerid %"PRId64
					 " wid end %"PRId64" doesn't exist! "
					 "You should abort ckdb and fix it, "
					 "since the reload may skip some data",
					 __func__, row->markerid,
					 row->workinfoidend);
			} else {
				DATA_WORKINFO(workinfo, wi_item);
				copy_tv(&(dbstatus.newest_createdate_workmarker_workinfo),
					&(workinfo->createdate));
			}
		}

		tick();
	}
	if (!ok) {
		free_workmarkers_data(item);
		k_add_head(workmarkers_free, item);
	}

	K_WUNLOCK(workmarkers_free);
	PQclear(res);

	if (ok) {
		LOGDEBUG("%s(): built", __func__);
		LOGWARNING("%s(): loaded %d workmarkers records", __func__, n);
	}

	return ok;
}

/* Add means create a new one and expire the old one if it exists,
 *  otherwise we only expire the old one if it exists
 * Add requires all db fields
 * !Add only requires the (poolinstance and) workinfoid db fields */
bool _marks_process(PGconn *conn, bool add, char *poolinstance,
		    int64_t workinfoid, char *description, char *extra,
		    char *marktype, char *status, char *by, char *code,
		    char *inet, tv_t *cd, K_TREE *trf_root, WHERE_FFL_ARGS)
{
	ExecStatusType rescode;
	bool conned = false;
	PGresult *res = NULL;
	K_ITEM *m_item = NULL, *old_m_item = NULL, *w_item;
	MARKS *row, *oldmarks = NULL;
	char *upd, *ins;
	char *params[6 + HISTORYDATECOUNT];
	bool ok = false, begun = false;
	int n, par = 0;

	LOGDEBUG("%s(): add %c", __func__, add ? 'Y' : 'N');

	K_RLOCK(marks_free);
	old_m_item = find_marks(workinfoid);
	K_RUNLOCK(marks_free);
	if (old_m_item) {
		LOGDEBUG("%s(): updating old", __func__);

		DATA_MARKS(oldmarks, old_m_item);
		if (!conn) {
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

		begun = true;

		upd = "update marks set "EDDB"=$1 where workinfoid=$2"
			" and "EDDB"=$3";
		par = 0;
		params[par++] = tv_to_buf(cd, NULL, 0);
		params[par++] = bigint_to_buf(workinfoid, NULL, 0);
		params[par++] = tv_to_buf((tv_t *)&default_expiry, NULL, 0);
		PARCHKVAL(par, 3, params);

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
	}

	if (add) {
		LOGDEBUG("%s(): adding new", __func__);

		if (poolinstance == NULL || description == NULL ||
		    extra == NULL || marktype == NULL || status == NULL) {
			LOGEMERG("%s(): NULL field(s) passed:%s%s%s%s%s"
				 WHERE_FFL, __func__,
				 poolinstance ? "" : " poolinstance",
				 description ? "" : " description",
				 extra ? "" : " extra",
				 marktype ? "" : " marktype",
				 status ? "" : " status",
				 WHERE_FFL_PASS);
			goto rollback;
		}
		w_item = find_workinfo(workinfoid, NULL);
		if (!w_item)
			goto rollback;
		K_WLOCK(marks_free);
		m_item = k_unlink_head(marks_free);
		K_WUNLOCK(marks_free);
		DATA_MARKS(row, m_item);
		bzero(row, sizeof(*row));
		DUP_POINTER(marks_free, row->poolinstance, poolinstance);
		row->workinfoid = workinfoid;
		DUP_POINTER(marks_free, row->description, description);
		DUP_POINTER(marks_free, row->extra, extra);
		STRNCPY(row->marktype, marktype);
		STRNCPY(row->status, status);
		HISTORYDATEINIT(row, cd, by, code, inet);
		HISTORYDATETRANSFER(trf_root, row);

		ins = "insert into marks "
			"(poolinstance,workinfoid,description,extra,marktype,"
			"status"
			HISTORYDATECONTROL ") values (" PQPARAM11 ")";
		par = 0;
		params[par++] = str_to_buf(row->poolinstance, NULL, 0);
		params[par++] = bigint_to_buf(workinfoid, NULL, 0);
		params[par++] = str_to_buf(row->description, NULL, 0);
		params[par++] = str_to_buf(row->extra, NULL, 0);
		params[par++] = str_to_buf(row->marktype, NULL, 0);
		params[par++] = str_to_buf(row->status, NULL, 0);
		HISTORYDATEPARAMS(params, par, row);
		PARCHK(par, params);

		if (conn == NULL) {
			conn = dbconnect();
			conned = true;
		}

		if (!begun) {
			res = PQexec(conn, "Begin", CKPQ_WRITE);
			rescode = PQresultStatus(res);
			PQclear(res);
			if (!PGOK(rescode)) {
				PGLOGERR("Begin", rescode, conn);
				goto unparam;
			}
			begun = true;
		}

		res = PQexecParams(conn, ins, par, NULL, (const char **)params, NULL, NULL, 0, CKPQ_WRITE);
		rescode = PQresultStatus(res);
		PQclear(res);
		if (!PGOK(rescode)) {
			PGLOGERR("Insert", rescode, conn);
			goto rollback;
		}
	}

	ok = true;
rollback:
	if (begun) {
		if (ok)
			res = PQexec(conn, "Commit", CKPQ_WRITE);
		else
			res = PQexec(conn, "Rollback", CKPQ_WRITE);

		PQclear(res);
	}
unparam:
	for (n = 0; n < par; n++)
		free(params[n]);

	if (conned)
		PQfinish(conn);

	K_WLOCK(marks_free);
	if (!ok) {
		if (m_item) {
			free_marks_data(m_item);
			k_add_head(marks_free, m_item);
		}
	} else {
		if (old_m_item) {
			remove_from_ktree(marks_root, old_m_item);
			copy_tv(&(oldmarks->expirydate), cd);
			add_to_ktree(marks_root, old_m_item);
		}
		if (m_item) {
			add_to_ktree(marks_root, m_item);
			k_add_head(marks_store, m_item);
		}
	}
	K_WUNLOCK(marks_free);

	return ok;
}

bool marks_fill(PGconn *conn)
{
	ExecStatusType rescode;
	PGresult *res;
	K_ITEM *item;
	int n, i;
	MARKS *row;
	char *field;
	char *sel;
	int fields = 6;
	bool ok;

	LOGDEBUG("%s(): select", __func__);

	// TODO: limit how far back
	sel = "select "
		"poolinstance,workinfoid,description,extra,marktype,status"
		HISTORYDATECONTROL
		" from marks";
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
	K_WLOCK(marks_free);
	for (i = 0; i < n; i++) {
		item = k_unlink_head(marks_free);
		DATA_MARKS(row, item);
		bzero(row, sizeof(*row));

		if (everyone_die) {
			ok = false;
			break;
		}

		PQ_GET_FLD(res, i, "poolinstance", field, ok);
		if (!ok)
			break;
		TXT_TO_PTR("poolinstance", field, row->poolinstance);
		LIST_MEM_ADD(marks_free, row->poolinstance);

		PQ_GET_FLD(res, i, "workinfoid", field, ok);
		if (!ok)
			break;
		TXT_TO_BIGINT("workinfoid", field, row->workinfoid);

		PQ_GET_FLD(res, i, "description", field, ok);
		if (!ok)
			break;
		TXT_TO_PTR("description", field, row->description);
		LIST_MEM_ADD(marks_free, row->description);

		PQ_GET_FLD(res, i, "extra", field, ok);
		if (!ok)
			break;
		TXT_TO_PTR("extra", field, row->extra);
		LIST_MEM_ADD(marks_free, row->extra);

		PQ_GET_FLD(res, i, "marktype", field, ok);
		if (!ok)
			break;
		TXT_TO_STR("marktype", field, row->marktype);

		PQ_GET_FLD(res, i, "status", field, ok);
		if (!ok)
			break;
		TXT_TO_STR("status", field, row->status);

		HISTORYDATEFLDS(res, i, row, ok);
		if (!ok)
			break;

		add_to_ktree(marks_root, item);
		k_add_head(marks_store, item);

		tick();
	}
	if (!ok) {
		free_marks_data(item);
		k_add_head(marks_free, item);
	}

	K_WUNLOCK(marks_free);
	PQclear(res);

	if (ok) {
		LOGDEBUG("%s(): built", __func__);
		LOGWARNING("%s(): loaded %d marks records", __func__, n);
	}

	return ok;
}

bool check_db_version(PGconn *conn)
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

char *cmd_newid(PGconn *conn, char *cmd, char *id, tv_t *now, char *by,
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
