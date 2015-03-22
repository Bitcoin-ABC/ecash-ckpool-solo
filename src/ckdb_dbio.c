/*
 * Copyright 1995-2015 Andrew Smith
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#include "ckdb.h"

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
		} else \
			__fld = PQgetvalue(__res, __row, __col); \
	} while (0)

// HISTORY FIELDS
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
		PQ_GET_FLD(_res, _row, "createdate", _fld, _ok); \
		if (!_ok) \
			break; \
		TXT_TO_TV("createdate", _fld, (_data)->createdate); \
		PQ_GET_FLD(_res, _row, "createby", _fld, _ok); \
		if (!_ok) \
			break; \
		SET_CREATEBY(_list, (_data)->createby, _fld); \
		PQ_GET_FLD(_res, _row, "createcode", _fld, _ok); \
		if (!_ok) \
			break; \
		SET_CREATECODE(_list, (_data)->createcode, _fld); \
		PQ_GET_FLD(_res, _row, "createinet", _fld, _ok); \
		if (!_ok) \
			break; \
		SET_CREATEINET(_list, (_data)->createinet, _fld); \
		PQ_GET_FLD(_res, _row, "modifydate", _fld, _ok); \
		if (!_ok) \
			break; \
		TXT_TO_TV("modifydate", _fld, (_data)->modifydate); \
		PQ_GET_FLD(_res, _row, "modifyby", _fld, _ok); \
		if (!_ok) \
			break; \
		SET_MODIFYBY(_list, (_data)->modifyby, _fld); \
		PQ_GET_FLD(_res, _row, "modifycode", _fld, _ok); \
		if (!_ok) \
			break; \
		SET_MODIFYCODE(_list, (_data)->modifycode, _fld); \
		PQ_GET_FLD(_res, _row, "modifyinet", _fld, _ok); \
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
#define PQPARAM26 PQPARAM22 ",$23,$24,$25,$26"
#define PQPARAM27 PQPARAM26 ",$27"

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
	memcpy(row, users, sizeof(*row));

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
		"passwordhash,secondaryuserid,salt"
		HISTORYDATECONTROL ") select "
		"userid,username,$3,$4,joineddate,"
		"$5,secondaryuserid,$6,"
		"$7,$8,$9,$10,$11 from users where "
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
		users_root = remove_from_ktree(users_root, u_item, cmp_users);
		userid_root = remove_from_ktree(userid_root, u_item, cmp_userid);
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

K_ITEM *users_add(PGconn *conn, char *username, char *emailaddress,
			char *passwordhash, char *by, char *code, char *inet,
			tv_t *cd, K_TREE *trf_root)
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
	char *params[8 + HISTORYDATECOUNT];
	int n, par = 0;

	LOGDEBUG("%s(): add", __func__);

	K_WLOCK(users_free);
	item = k_unlink_head(users_free);
	K_WUNLOCK(users_free);

	DATA_USERS(row, item);

	STRNCPY(row->username, username);
	username_trim(row);

	dup = false;
	K_RLOCK(users_free);
	u_item = users_store->head;
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

bool users_fill(PGconn *conn)
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

		username_trim(row);

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
			useratts_root = remove_from_ktree(useratts_root, old_item, cmp_useratts);
			copy_tv(&(old_useratts->expirydate), cd);
			useratts_root = add_to_ktree(useratts_root, old_item, cmp_useratts);
		}
		useratts_root = add_to_ktree(useratts_root, ua_item, cmp_useratts);
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

	LOGDEBUG("%s(): add", __func__);

	K_WLOCK(useratts_free);
	item = k_unlink_head(useratts_free);
	K_WUNLOCK(useratts_free);
	DATA_USERATTS(row, item);

	K_RLOCK(users_free);
	u_item = find_users(username);
	K_RUNLOCK(users_free);
	if (!u_item) {
		char *txt;
		LOGERR("%s(): unknown user '%s'",
			__func__,
			txt = safe_text(username));
		free(txt);
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
		useratts_root = remove_from_ktree(useratts_root, item, cmp_useratts);
		copy_tv(&(useratts->expirydate), cd);
		useratts_root = add_to_ktree(useratts_root, item, cmp_useratts);
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

K_ITEM *workers_add(PGconn *conn, int64_t userid, char *workername,
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
	char *params[6 + HISTORYDATECOUNT];
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

bool workers_fill(PGconn *conn)
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
	char *params[1002]; // Limit of 999 addresses per user
	char tmp[1024];
	int n, par = 0, count, matches;

	LOGDEBUG("%s(): add", __func__);

	// Quick early abort
	if (pa_store->count > 999)
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
			"update paymentaddresses set expirydate=$1 where "
			"userid=$2 and expirydate=$3 and payaddress in (");
	par = 0;
	params[par++] = tv_to_buf(cd, NULL, 0);
	params[par++] = bigint_to_buf(userid, NULL, 0);
	params[par++] = tv_to_buf((tv_t *)&default_expiry, NULL, 0);

	/* Since we are merging the changes in rather than just
	 *  replacing the db contents, lock the data for the duration
	 *  of the update to ensure nothing else changes it */
	K_WLOCK(paymentaddresses_free);
	locked = true;

	first = true;
	item = find_paymentaddresses(userid, ctx);
	DATA_PAYMENTADDRESSES_NULL(row, item);
	while (item && CURRENT(&(row->expirydate)) && row->userid == userid) {
		/* This is only possible if the DB was directly updated with
		 * more than 999 records then reloaded (or a code bug) */
		if (++count > 999)
			break;

		// Find the RAM record in pa_store
		match = pa_store->head;
		while (match) {
			DATA_PAYMENTADDRESSES(pa, match);
			if (strcmp(pa->payaddress, row->payaddress) == 0 &&
			    pa->payratio == row->payratio) {
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
		 par, count, matches, first ? "true" : "false");
	// Too many, or none need expiring = don't do the update
	if (count > 999 || first == true) {
		for (n = 0; n < par; n++)
			free(params[n]);
		par = 0;
		// Too many
		if (count > 999)
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
		"(paymentaddressid,userid,payaddress,payratio"
		HISTORYDATECONTROL ") values (" PQPARAM9 ")";

	count = 0;
	match = pa_store->head;
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
			HISTORYDATEPARAMS(params, par, row);
			PARCHKVAL(par, 9, params); // As per PQPARAM9 above

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
	LOGDEBUG("%s(): Step 3, ok=%s", __func__, ok ? "true" : "false");
	matches = count = n = 0;
	if (ok) {
		// Change the expiry on all records that we expired in the DB
		item = find_paymentaddresses(userid, ctx);
		DATA_PAYMENTADDRESSES_NULL(row, item);
		while (item && CURRENT(&(row->expirydate)) && row->userid == userid) {
			prev = prev_in_ktree(ctx);
			// Find the RAM record in pa_store
			match = pa_store->head;
			while (match) {
				DATA_PAYMENTADDRESSES(pa, match);
				if (strcmp(pa->payaddress, row->payaddress) == 0 &&
				    pa->payratio == row->payratio) {
					break;
				}
				match = match->next;
			}
			if (match)
				matches++;
			else {
				// It wasn't a match, thus it was expired
				n++;
				paymentaddresses_root = remove_from_ktree(paymentaddresses_root, item,
									  cmp_paymentaddresses);
				paymentaddresses_create_root = remove_from_ktree(paymentaddresses_create_root,
										 item, cmp_payaddr_create);
				copy_tv(&(row->expirydate), cd);
				paymentaddresses_root = add_to_ktree(paymentaddresses_root, item,
								     cmp_paymentaddresses);
				paymentaddresses_create_root = add_to_ktree(paymentaddresses_create_root,
									    item, cmp_payaddr_create);
			}
			item = prev;
			DATA_PAYMENTADDRESSES_NULL(row, item);
		}

		// Add in all the non-matching ps_store
		match = pa_store->head;
		while (match) {
			next = match->next;
			DATA_PAYMENTADDRESSES(pa, match);
			if (!pa->match) {
				paymentaddresses_root = add_to_ktree(paymentaddresses_root, match,
								     cmp_paymentaddresses);
				paymentaddresses_create_root = add_to_ktree(paymentaddresses_create_root,
									    match, cmp_payaddr_create);
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
	int fields = 4;
	bool ok;

	LOGDEBUG("%s(): select", __func__);

	sel = "select "
		"paymentaddressid,userid,payaddress,payratio"
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

		paymentaddresses_root = add_to_ktree(paymentaddresses_root, item,
						     cmp_paymentaddresses);
		paymentaddresses_create_root = add_to_ktree(paymentaddresses_create_root,
							    item, cmp_payaddr_create);
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
			payments_root = remove_from_ktree(payments_root, old_p_item, cmp_payments);
			copy_tv(&(oldp->expirydate), cd);
			payments_root = add_to_ktree(payments_root, old_p_item, cmp_payments);
		}
		payments_root = add_to_ktree(payments_root, p_item, cmp_payments);
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

		upd = "update payments set expirydate=$1 where paymentid=$2"
			" and expirydate=$3";
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
	int n, i;
	char *field;
	char *sel;
	int fields = 11;
	bool ok;

	LOGDEBUG("%s(): select", __func__);

	sel = "select "
		"paymentid,payoutid,userid,subname,paydate,payaddress,"
		"originaltxn,amount,diffacc,committxn,commitblockhash"
		HISTORYDATECONTROL
		" from payments";
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
	K_WLOCK(payments_free);
	for (i = 0; i < n; i++) {
		item = k_unlink_head(payments_free);
		DATA_PAYMENTS(row, item);

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
	OPTIONCONTROL *row, *optioncontrol;
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
	if (!ok) {
		// Cleanup item passed in
		FREENULL(row->optionvalue);
		k_add_head(optioncontrol_free, oc_item);
	} else {
		// Discard old
		if (old_item) {
			DATA_OPTIONCONTROL(optioncontrol, old_item);
			optioncontrol_root = remove_from_ktree(optioncontrol_root, old_item,
							       cmp_optioncontrol);
			FREENULL(optioncontrol->optionvalue);
			k_add_head(optioncontrol_free, old_item);
		}
		optioncontrol_root = add_to_ktree(optioncontrol_root, oc_item, cmp_optioncontrol);
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

		// There should only be one CURRENT version of switch_state
		if (CURRENT(&(row->expirydate)) &&
		    strcmp(row->optionname, SWITCH_STATE_NAME) == 0) {
			switch_state = atoi(row->optionvalue);
			LOGWARNING("%s() set switch_state to %d",
				   __func__, switch_state);
		}
	}
	if (!ok) {
		FREENULL(row->optionvalue);
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
	pool.reward = row->reward;

	HISTORYDATEINIT(row, cd, by, code, inet);
	HISTORYDATETRANSFER(trf_root, row);

	K_WLOCK(workinfo_free);
	if (find_in_ktree(workinfo_root, item, cmp_workinfo, ctx)) {
		FREENULL(row->transactiontree);
		FREENULL(row->merklehash);
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
		FREENULL(row->transactiontree);
		FREENULL(row->merklehash);
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

bool workinfo_fill(PGconn *conn)
{
	ExecStatusType rescode;
	PGresult *res;
	K_ITEM *item;
	WORKINFO *row;
	char *params[3];
	int n, i, par = 0;
	char *field;
	char *sel = NULL;
	size_t len, off;
	int fields = 10;
	bool ok;

	LOGDEBUG("%s(): select", __func__);

	// TODO: select the data based on sharesummary since old data isn't needed
	//  however, the ageing rules for workinfo will decide that also
	//  keep the last block + current? Rules will depend on payout scheme also

	APPEND_REALLOC_INIT(sel, off, len);
	APPEND_REALLOC(sel, off, len,
			"select "
//			"workinfoid,poolinstance,transactiontree,merklehash,prevhash,"
			"workinfoid,poolinstance,merklehash,prevhash,"
			"coinbase1,coinbase2,version,bits,ntime,reward"
			HISTORYDATECONTROL
			" from workinfo where expirydate=$1 and"
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
		pool.reward = row->reward;

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

// Memory (and log file) only
bool shares_add(PGconn *conn, char *workinfoid, char *username, char *workername,
		char *clientid, char *errn, char *enonce1, char *nonce2,
		char *nonce, char *diff, char *sdiff, char *secondaryuserid,
		char *by, char *code, char *inet, tv_t *cd, K_TREE *trf_root)
{
	K_ITEM *s_item, *u_item, *wi_item, *w_item, *wm_item, *ss_item;
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
		char *txt;
		tv_to_buf(cd, cd_buf, sizeof(cd_buf));
		LOGERR("%s() %s/%ld,%ld %.19s no user! Share discarded!",
			__func__, txt = safe_text(username),
			cd->tv_sec, cd->tv_usec, cd_buf);
		free(txt);
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

	wi_item = find_workinfo(shares->workinfoid, NULL);
	if (!wi_item) {
		tv_to_buf(cd, cd_buf, sizeof(cd_buf));
		// TODO: store it for a few workinfoid changes
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
		// We only need to know if the workmarker is processed
		wm_item = find_workmarkers(shares->workinfoid, false,
					   MARKER_PROCESSED);
		if (wm_item) {
			K_WLOCK(shares_free);
			k_add_head(shares_free, s_item);
			K_WUNLOCK(shares_free);
			return true;
		}
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

// Memory (and log file) only
// TODO: handle shareerrors that appear after a workinfoid is aged or doesn't exist?
bool shareerrors_add(PGconn *conn, char *workinfoid, char *username,
			char *workername, char *clientid, char *errn,
			char *error, char *secondaryuserid, char *by,
			char *code, char *inet, tv_t *cd, K_TREE *trf_root)
{
	K_ITEM *s_item, *u_item, *wi_item, *w_item, *wm_item, *ss_item;
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
		char *txt;
		tv_to_buf(cd, cd_buf, sizeof(cd_buf));
		LOGERR("%s() %s/%ld,%ld %.19s no user! Shareerror discarded!",
			__func__, txt = safe_text(username),
			cd->tv_sec, cd->tv_usec, cd_buf);
		free(txt);
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

	wi_item = find_workinfo(shareerrors->workinfoid, NULL);
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
		// We only need to know if the workmarker is processed
		wm_item = find_workmarkers(shareerrors->workinfoid, false,
					   MARKER_PROCESSED);
		if (wm_item) {
			K_WLOCK(shareerrors_free);
			k_add_head(shareerrors_free, s_item);
			K_WUNLOCK(shareerrors_free);
			return true;
		}
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

bool shareerrors_fill()
{
	return true;
}

/* TODO: what to do about a failure?
 *  since it will repeat every ~13s
 * Of course manual intervention is possible via cmd_marks,
 *  so that is probably the best solution since
 *  we should be watching the pool all the time :)
 * The cause would most likely be either a code bug or a DB problem
 *  so there many be no obvious automated fix
 *  and flagging the workmarkers to be skipped may or may not be the solution,
 *  thus manual intervention will be the rule for now */
bool sharesummaries_to_markersummaries(PGconn *conn, WORKMARKERS *workmarkers,
				       char *by, char *code, char *inet, tv_t *cd,
				       K_TREE *trf_root)
{
	// shorter name for log messages
	const char *shortname = "SS_to_MS";
	ExecStatusType rescode;
	PGresult *res;
	K_TREE_CTX ss_ctx[1], ms_ctx[1];
	SHARESUMMARY *sharesummary, looksharesummary;
	MARKERSUMMARY *markersummary, lookmarkersummary;
	K_ITEM *ss_item, *ss_prev, ss_look, *ms_item, ms_look;
	bool ok = false, conned = false;
	int64_t diffacc, shareacc;
	char *reason = NULL, *tuples = NULL;
	char *params[2];
	int n, par = 0, deleted = -7;
	int ss_count, ms_count;
	char *del;

	LOGWARNING("%s() Processing: workmarkers %"PRId64"/%s/"
		   "End %"PRId64"/Stt %"PRId64"/%s/%s",
		   shortname, workmarkers->markerid, workmarkers->poolinstance,
		   workmarkers->workinfoidend, workmarkers->workinfoidstart,
		   workmarkers->description, workmarkers->status);

	K_STORE *old_sharesummary_store = k_new_store(sharesummary_free);
	K_STORE *new_markersummary_store = k_new_store(markersummary_free);
	K_TREE *ms_root = new_ktree();

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
	ms_item = find_after_in_ktree(markersummary_root, &ms_look,
					cmp_markersummary, ms_ctx);
	K_RUNLOCK(markersummary_free);
	DATA_MARKERSUMMARY_NULL(markersummary, ms_item);
	if (ms_item && markersummary->markerid == workmarkers->markerid) {
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
	ss_item = find_before_in_ktree(sharesummary_workinfoid_root, &ss_look,
					cmp_sharesummary_workinfoid, ss_ctx);
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
			ms_item = find_in_ktree(ms_root, &ms_look,
						cmp_markersummary, ms_ctx);
			if (!ms_item) {
				K_WLOCK(markersummary_free);
				ms_item = k_unlink_head(markersummary_free);
				K_WUNLOCK(markersummary_free);
				k_add_head(new_markersummary_store, ms_item);
				DATA_MARKERSUMMARY(markersummary, ms_item);
				bzero(markersummary, sizeof(*markersummary));
				markersummary->markerid = workmarkers->markerid;
				markersummary->userid = sharesummary->userid;
				markersummary->workername = strdup(sharesummary->workername);
				LIST_MEM_ADD(markersummary_free, markersummary->workername);
				ms_root = add_to_ktree(ms_root, ms_item, cmp_markersummary);

				LOGDEBUG("%s() new ms %"PRId64"/%"PRId64"/%s",
					 shortname, markersummary->markerid,
					 markersummary->userid,
					 markersummary->workername);
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
		if (tv_newer(&(markersummary->lastshare), &(sharesummary->lastshare))) {
			copy_tv(&(markersummary->lastshare), &(sharesummary->lastshare));
			markersummary->lastdiffacc = sharesummary->lastdiffacc;
		}

		diffacc += sharesummary->diffacc;
		shareacc += sharesummary->shareacc;

		k_unlink_item(sharesummary_store, ss_item);
		k_add_head(old_sharesummary_store, ss_item);

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

	ms_item = new_markersummary_store->head;
	while (ms_item) {
		if (!(markersummary_add(conn, ms_item, by, code, inet,
					cd, trf_root))) {
			reason = "db error";
			goto rollback;
		}
		ms_item = ms_item->next;
	}

	if (old_sharesummary_store->count > 0) {
		par = 0;
		params[par++] = bigint_to_buf(workmarkers->workinfoidstart, NULL, 0);
		params[par++] = bigint_to_buf(workmarkers->workinfoidend, NULL, 0);
		PARCHK(par, params);

		del = "delete from sharesummary "
			"where workinfoid >= $1 and workinfoid <= $2";

		res = PQexecParams(conn, del, par, NULL, (const char **)params, NULL, NULL, 0, CKPQ_WRITE);
		rescode = PQresultStatus(res);
		if (PGOK(rescode)) {
			tuples = PQcmdTuples(res);
			if (tuples && *tuples)
				deleted = atoi(tuples);
		}
		PQclear(res);
		if (!PGOK(rescode)) {
			PGLOGERR("Delete", rescode, conn);
			reason = "delete failure";
			goto rollback;
		}

		if (deleted != old_sharesummary_store->count) {
			LOGERR("%s() processed sharesummaries=%d but deleted=%d",
				shortname, old_sharesummary_store->count, deleted);
			reason = "delete mismatch";
			goto rollback;
		}
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
	for (n = 0; n < par; n++)
		free(params[n]);

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
			ms_item = new_markersummary_store->head;
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
		// Deadlock alert for other newer code ...
		K_WLOCK(sharesummary_free);
		K_WLOCK(markersummary_free);
		ms_item = new_markersummary_store->head;
		while (ms_item) {
			// Move the new markersummaries into the trees/stores
			markersummary_root = add_to_ktree(markersummary_root,
							  ms_item,
							  cmp_markersummary);
			markersummary_userid_root = add_to_ktree(markersummary_userid_root,
								 ms_item,
								 cmp_markersummary_userid);
			ms_item = ms_item->next;
		}
		k_list_transfer_to_head(new_markersummary_store, markersummary_store);

		/* For normal shift processing this wont be very quick
		 *  so it will be a 'long' LOCK */
		ss_item = old_sharesummary_store->head;
		while (ss_item) {
			// remove the old sharesummaries from the trees
			sharesummary_root = remove_from_ktree(sharesummary_root,
							      ss_item,
							      cmp_sharesummary);
			sharesummary_workinfoid_root = remove_from_ktree(sharesummary_workinfoid_root,
									 ss_item,
									 cmp_sharesummary_workinfoid);
			free_sharesummary_data(ss_item);

			ss_item = ss_item->next;
		}
		k_list_transfer_to_head(old_sharesummary_store, sharesummary_free);
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
	ms_root = free_ktree(ms_root, NULL);
	new_markersummary_store = k_free_store(new_markersummary_store);
	old_sharesummary_store = k_free_store(old_sharesummary_store);

	return ok;
}

/* Keep some simple stats on how often shares are out of order
 *  and how often they produce a WARNING due to OOOLIMIT */
static int64_t ooof0, ooof, oool0, oool;
#define OOOLIMIT -2.0

bool _sharesummary_update(PGconn *conn, SHARES *s_row, SHAREERRORS *e_row, K_ITEM *ss_item,
				char *by, char *code, char *inet, tv_t *cd, WHERE_FFL_ARGS)
{
	ExecStatusType rescode;
	PGresult *res = NULL;
	WORKMARKERS *wm;
	SHARESUMMARY *row;
	K_ITEM *item, *wm_item;
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

		K_RLOCK(workmarkers_free);
		wm_item = find_workmarkers(workinfoid, false, MARKER_PROCESSED);
		K_RUNLOCK(workmarkers_free);
		if (wm_item) {
			char *tmp;
			DATA_WORKMARKERS(wm, wm_item);
			LOGERR("%s(): attempt to update sharesummary "
			       "with %s %"PRId64"/%"PRId64"/%s createdate %s"
			       " but processed workmarkers %"PRId64" exists",
				__func__, s_row ? "shares" : "shareerrors",
				workinfoid, userid, workername,
				(tmp = ctv_to_buf(sharecreatedate, NULL, 0)),
				wm->markerid);
			free(tmp);
			return false;
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
			row->workername = strdup(workername);
			LIST_MEM_ADD(sharesummary_free, row->workername);
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
			// don't LOG '=' in case shares come from ckpool with the same timestamp
			if (td < 0.0) {
				char *tmp1, *tmp2;
				int level;
				// DEBUG only for shares out of order up to OOOLIMIT seconds
				if (td < OOOLIMIT) {
					level = LOG_WARNING;
					ooof++;
				} else {
					level = LOG_DEBUG;
					ooof0++;
				}
				LOGMSG(level, "%s(): OoO %s createdate (%s) is < summary"
					" firstshare (%s) (F%"PRId64":%"PRId64
					"/L%"PRId64":%"PRId64"/%.1f)",
					__func__, s_row ? "shares" : "shareerrors",
					(tmp1 = ctv_to_buf(sharecreatedate, NULL, 0)),
					(tmp2 = ctv_to_buf(&(row->firstshare), NULL, 0)),
					ooof, ooof0, oool, oool0, OOOLIMIT);
				free(tmp2);
				free(tmp1);
				row->firstshare.tv_sec = sharecreatedate->tv_sec;
				row->firstshare.tv_usec = sharecreatedate->tv_usec;
				// Don't change lastdiffacc
			}
			td = tvdiff(sharecreatedate, &(row->lastshare));
			// don't LOG '=' in case shares come from ckpool with the same timestamp
			if (td >= 0.0) {
				row->lastshare.tv_sec = sharecreatedate->tv_sec;
				row->lastshare.tv_usec = sharecreatedate->tv_usec;
				row->lastdiffacc = diff;
			} else {
				char *tmp1, *tmp2;
				int level;
				// DEBUG only for shares out of order up to OOOLIMIT seconds
				if (td < OOOLIMIT) {
					level = LOG_WARNING;
					oool++;
				} else {
					level = LOG_DEBUG;
					oool0++;
				}
				LOGMSG(level, "%s(): OoO %s createdate (%s) is < summary"
					" lastshare (%s) (F%"PRId64":%"PRId64
					"/L%"PRId64":%"PRId64"/%.1f)",
					__func__, s_row ? "shares" : "shareerrors",
					(tmp1 = ctv_to_buf(sharecreatedate, NULL, 0)),
					(tmp2 = ctv_to_buf(&(row->lastshare), NULL, 0)),
					ooof, ooof0, oool, oool0, OOOLIMIT);
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
	// ... and also during normal processing
	if (row->complete[0] == SUMMARY_NEW)
		goto startupskip;

	if (conn == NULL && !confirm_sharesummary) {
		conn = dbconnect();
		conned = true;
	}

	if (new || !(row->inserted)) {
		MODIFYDATEPOINTERS(sharesummary_free, row, cd, by, code, inet);

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

		MODIFYUPDATEPOINTERS(sharesummary_free, row, cd, by, code, inet);

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
	if (new) {
		K_WLOCK(sharesummary_free);
		sharesummary_root = add_to_ktree(sharesummary_root, item, cmp_sharesummary);
		sharesummary_workinfoid_root = add_to_ktree(sharesummary_workinfoid_root,
							    item,
							    cmp_sharesummary_workinfoid);
		k_add_head(sharesummary_store, item);
		K_WUNLOCK(sharesummary_free);
	}

	return ok;
}

bool sharesummary_fill(PGconn *conn)
{
	ExecStatusType rescode;
	PGresult *res;
	K_TREE_CTX ctx[1];
	K_ITEM *item, *m_item;
	int n, i, par = 0;
	SHARESUMMARY *row;
	MARKS *marks;
	char *params[2];
	char *field;
	char *sel;
	int fields = 19;
	bool ok;

	LOGDEBUG("%s(): select", __func__);

	/* Load needs to go back to the last marks workinfoid(+1)
	 * If it is later than that, we can't create markersummaries
	 *  since some of the required data is missing -
	 *  thus we also can't make the shift markersummaries */
	m_item = last_in_ktree(marks_root, ctx);
	if (!m_item) {
		if (dbload_workinfoid_start != -1) {
			sharesummary_marks_limit = true;
			LOGWARNING("WARNING: dbload -w start used "
				   "but there are no marks ...");
		}
	} else {
		DATA_MARKS(marks, m_item);
		if (dbload_workinfoid_start > marks->workinfoid) {
			sharesummary_marks_limit = true;
			LOGWARNING("WARNING: dbload -w start %"PRId64
				   " is after the last mark %"PRId64" ...",
				   dbload_workinfoid_start,
				   marks->workinfoid);
		}
	}
	if (sharesummary_marks_limit) {
		LOGWARNING("WARNING: ... markersummaries cannot be created "
			   "and pplns calculations may be wrong");
	}

	// TODO: limit how far back
	sel = "select "
		"userid,workername,workinfoid,diffacc,diffsta,diffdup,diffhi,"
		"diffrej,shareacc,sharesta,sharedup,sharehi,sharerej,"
		"sharecount,errorcount,firstshare,lastshare,"
		"lastdiffacc,complete"
		MODIFYDATECONTROL
		" from sharesummary where workinfoid>=$1 and workinfoid<=$2";
	par = 0;
	params[par++] = bigint_to_buf(dbload_workinfoid_start, NULL, 0);
	params[par++] = bigint_to_buf(dbload_workinfoid_finish, NULL, 0);
	PARCHK(par, params);
	res = PQexecParams(conn, sel, par, NULL, (const char **)params, NULL, NULL, 0, CKPQ_READ);
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
		row->workername = NULL;

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
		row->workername = strdup(field);
		LIST_MEM_ADD(sharesummary_free, row->workername);

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

		MODIFYDATEFLDPOINTERS(sharesummary_free, res, i, row, ok);
		if (!ok)
			break;

		sharesummary_root = add_to_ktree(sharesummary_root, item, cmp_sharesummary);
		sharesummary_workinfoid_root = add_to_ktree(sharesummary_workinfoid_root, item, cmp_sharesummary_workinfoid);
		k_add_head(sharesummary_store, item);

		// A share summary is shares in a single workinfo, at all 3 levels n,a,y
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
	if (!ok) {
		DATA_SHARESUMMARY(row, item);
		if (row->workername) {
			LIST_MEM_SUB(sharesummary_free, row->workername);
			FREENULL(row->workername);
		}
		k_add_head(sharesummary_free, item);
	}

	PQclear(res);

	if (ok) {
		LOGDEBUG("%s(): built", __func__);
		LOGWARNING("%s(): loaded %d sharesummary records", __func__, n);
	}

	return ok;
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
			blocks_root = remove_from_ktree(blocks_root, old_b_item, cmp_blocks);
			copy_tv(&(oldblocks->expirydate), cd);
			blocks_root = add_to_ktree(blocks_root, old_b_item, cmp_blocks);
			// Copy it over to avoid having to recalculate it
			row->netdiff = oldblocks->netdiff;
		} else
			row->netdiff = 0;
		blocks_root = add_to_ktree(blocks_root, b_item, cmp_blocks);
		k_add_head(blocks_store, b_item);
		blocks_stats_rebuild = true;
	}
	K_WUNLOCK(blocks_free);

	return ok;
}

bool blocks_add(PGconn *conn, char *height, char *blockhash,
		char *confirmed, char *workinfoid, char *username,
		char *workername, char *clientid, char *enonce1,
		char *nonce2, char *nonce, char *reward,
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
			blocks_root = remove_from_ktree(blocks_root, old_b_item, cmp_blocks);
			copy_tv(&(oldblocks->expirydate), cd);
			blocks_root = add_to_ktree(blocks_root, old_b_item, cmp_blocks);
			// Copy it over to avoid having to recalculate it
			row->netdiff = oldblocks->netdiff;
		} else
			row->netdiff = 0;
		blocks_root = add_to_ktree(blocks_root, b_item, cmp_blocks);
		k_add_head(blocks_store, b_item);
		blocks_stats_rebuild = true;
	}
	K_WUNLOCK(blocks_free);

	if (ok) {
		char pct[16] = "?";
		char est[16] = "";
		char diff[16] = "";
		K_ITEM *w_item;
		char tmp[256];
		bool blk;

		suffix_string(hash_diff, diff, sizeof(diff)-1, 0);

		switch (confirmed[0]) {
			case BLOCKS_NEW:
				blk = true;
				tv_to_buf(&(row->createdate), cd_buf, sizeof(cd_buf));
				snprintf(tmp, sizeof(tmp), " UTC:%s", cd_buf);
				break;
			case BLOCKS_CONFIRM:
				blk = true;
				w_item = find_workinfo(row->workinfoid, NULL);
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

		LOGWARNING("%s(): %sStatus: %s, Block: %s/...%s Diff %s%s",
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
			miningpayouts_root = remove_from_ktree(miningpayouts_root, old_mp_item, cmp_miningpayouts);
			copy_tv(&(oldmp->expirydate), cd);
			miningpayouts_root = add_to_ktree(miningpayouts_root, old_mp_item, cmp_miningpayouts);
		}
		miningpayouts_root = add_to_ktree(miningpayouts_root, mp_item, cmp_miningpayouts);
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

		upd = "update miningpayouts set expirydate=$1 where payoutid=$2"
			" and userid=$3 and expirydate=$4";
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
	int n, i;
	char *field;
	char *sel;
	int fields = 4;
	bool ok;

	LOGDEBUG("%s(): select", __func__);

	sel = "select "
		"payoutid,userid,diffacc,amount"
		HISTORYDATECONTROL
		" from miningpayouts";
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
	K_WLOCK(miningpayouts_free);
	for (i = 0; i < n; i++) {
		item = k_unlink_head(miningpayouts_free);
		DATA_MININGPAYOUTS(row, item);

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

// The timing of the memory table updates depends on 'already'
void payouts_add_ram(bool ok, K_ITEM *p_item, K_ITEM *old_p_item, tv_t *cd)
{
	PAYOUTS *oldp;

	LOGDEBUG("%s(): ok %c", __func__, ok ? 'Y' : 'N');

	K_WLOCK(payouts_free);
	if (!ok) {
		// Cleanup for the calling function
		k_add_head(payouts_free, p_item);
	} else {
		if (old_p_item) {
			DATA_PAYOUTS(oldp, old_p_item);
			payouts_root = remove_from_ktree(payouts_root, old_p_item, cmp_payouts);
			payouts_id_root = remove_from_ktree(payouts_id_root, old_p_item, cmp_payouts_id);
			copy_tv(&(oldp->expirydate), cd);
			payouts_root = add_to_ktree(payouts_root, old_p_item, cmp_payouts);
			payouts_id_root = add_to_ktree(payouts_id_root, old_p_item, cmp_payouts_id);
		}
		payouts_root = add_to_ktree(payouts_root, p_item, cmp_payouts);
		payouts_id_root = add_to_ktree(payouts_id_root, p_item, cmp_payouts_id);
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

		upd = "update payouts set expirydate=$1 where payoutid=$2"
			" and expirydate=$3";
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

bool payouts_fill(PGconn *conn)
{
	ExecStatusType rescode;
	PGresult *res;
	K_ITEM *item;
	PAYOUTS *row;
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

		HISTORYDATEFLDS(res, i, row, ok);
		if (!ok)
			break;

		payouts_root = add_to_ktree(payouts_root, item, cmp_payouts);
		payouts_id_root = add_to_ktree(payouts_id_root, item, cmp_payouts_id);
		k_add_head(payouts_store, item);

		tick();
	}
	if (!ok)
		k_add_head(payouts_free, item);

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
			u_item = users_add(conn, username, EMPTY, EMPTY,
					   by, code, inet, cd, trf_root);
		} else {
			char *txt;
			LOGDEBUG("%s(): unknown user '%s'",
				 __func__,
				 txt = safe_text(username));
			free(txt);
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
	if (find_in_ktree(auths_root, a_item, cmp_auths, ctx)) {
		k_add_head(auths_free, a_item);
		K_WUNLOCK(auths_free);

		// Shouldn't actually be possible unless twice in the logs
		tv_to_buf(cd, cd_buf, sizeof(cd_buf));
		LOGERR("%s(): Duplicate auths ignored %s/%s/%s",
			__func__, poolinstance, workername, cd_buf);

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
		auths_root = add_to_ktree(auths_root, a_item, cmp_auths);
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
			" from poolstats where createdate>");
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
	if (!u_item) {
		char *txt;
		LOGERR("%s(): unknown user '%s'",
			__func__,
			txt = safe_text(username));
		free(txt);
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
		// New user+worker
		K_WLOCK(userstats_free);
		k_add_head(userstats_eos_store, us_item);
		K_WUNLOCK(userstats_free);
	}

	if (eos) {
		K_WLOCK(userstats_free);
		us_next = userstats_eos_store->head;
		while (us_next) {
			us_item = find_in_ktree(userstats_root, us_next,
						cmp_userstats, ctx);
			if (!us_item) {
				// New user+worker - store it in RAM
				us_match = us_next;
				us_next = us_match->next;
				k_unlink_item(userstats_eos_store, us_match);
				userstats_root = add_to_ktree(userstats_root, us_match,
								cmp_userstats);
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

	STRNCPY(row->poolinstance, poolinstance);
	TXT_TO_BIGINT("elapsed", elapsed, row->elapsed);
	K_RLOCK(users_free);
	u_item = find_users(username);
	K_RUNLOCK(users_free);
	if (!u_item) {
		char *usr, *wrk;
		LOGERR("%s(): unknown user '%s' (worker=%s)",
			__func__,
			usr = safe_text(username),
			wrk = safe_text(workername));
		free(usr);
		free(wrk);
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
	us_match = find_in_ktree(userstats_root, us_item,
				 cmp_userstats, ctx);
	if (!us_match) {
		// New user+worker - store it in RAM
		userstats_root = add_to_ktree(userstats_root, us_item,
						cmp_userstats);
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
	char *params[18 + MODIFYDATECOUNT];
	int n, par = 0;
	char *ins;
	bool ok = false;

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
	params[par++] = double_to_buf(row->lastdiffacc, NULL, 0);
	MODIFYDATEPARAMS(params, par, row);
	PARCHK(par, params);

	ins = "insert into markersummary "
		"(markerid,userid,workername,diffacc,diffsta,diffdup,diffhi,"
		"diffrej,shareacc,sharesta,sharedup,sharehi,sharerej,"
		"sharecount,errorcount,firstshare,lastshare,lastdiffacc"
		MODIFYDATECONTROL ") values (" PQPARAM26 ")";

	LOGDEBUG("%s() adding ms %"PRId64"/%"PRId64"/%s/%.0f",
		 __func__, row->markerid, row->userid, row->workername,
		 row->diffacc);

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
	K_ITEM *item;
	int n, i;
	MARKERSUMMARY *row;
	char *field;
	char *sel;
	int fields = 18;
	bool ok;

	LOGDEBUG("%s(): select", __func__);

	// TODO: limit how far back
	sel = "select "
		"markerid,userid,workername,diffacc,diffsta,diffdup,diffhi,"
		"diffrej,shareacc,sharesta,sharedup,sharehi,sharerej,"
		"sharecount,errorcount,firstshare,lastshare,"
		"lastdiffacc"
		MODIFYDATECONTROL
		" from markersummary";
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
		item = k_unlink_head(markersummary_free);
		DATA_MARKERSUMMARY(row, item);

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

		PQ_GET_FLD(res, i, "lastdiffacc", field, ok);
		if (!ok)
			break;
		TXT_TO_DOUBLE("lastdiffacc", field, row->lastdiffacc);

		MODIFYDATEFLDPOINTERS(markersummary_free, res, i, row, ok);
		if (!ok)
			break;

		markersummary_root = add_to_ktree(markersummary_root, item, cmp_markersummary);
		markersummary_userid_root = add_to_ktree(markersummary_userid_root, item, cmp_markersummary_userid);
		k_add_head(markersummary_store, item);

		tick();
	}
	if (!ok)
		k_add_head(markersummary_free, item);

	PQclear(res);

	if (ok) {
		LOGDEBUG("%s(): built", __func__);
		LOGWARNING("%s(): loaded %d markersummary records", __func__, n);
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
		old_wm_item = find_workmarkers(workinfoidend, true, '\0');
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

		upd = "update workmarkers set expirydate=$1 where markerid=$2"
			" and expirydate=$3";
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
		w_item = find_workinfo(workinfoidend, NULL);
		if (!w_item)
			goto rollback;
		w_item = find_workinfo(workinfoidstart, NULL);
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

		row->poolinstance = strdup(poolinstance);
		LIST_MEM_ADD(workmarkers_free, poolinstance);
		row->workinfoidend = workinfoidend;
		row->workinfoidstart = workinfoidstart;
		row->description = strdup(description);
		LIST_MEM_ADD(workmarkers_free, description);
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

	K_WLOCK(workmarkers_free);
	if (!ok) {
		if (wm_item) {
			DATA_WORKMARKERS(row, wm_item);
			if (row->poolinstance) {
				if (row->poolinstance != EMPTY) {
					LIST_MEM_SUB(workmarkers_free,
						     row->poolinstance);
					free(row->poolinstance);
				}
				row->poolinstance = NULL;
			}
			if (row->description) {
				if (row->description != EMPTY) {
					LIST_MEM_SUB(workmarkers_free,
						     row->description);
					free(row->description);
				}
				row->description = NULL;
			}
			k_add_head(workmarkers_free, wm_item);
		}
	}
	else {
		if (old_wm_item) {
			workmarkers_root = remove_from_ktree(workmarkers_root,
							     old_wm_item,
							     cmp_workmarkers);
			workmarkers_workinfoid_root = remove_from_ktree(workmarkers_workinfoid_root,
									old_wm_item,
									cmp_workmarkers_workinfoid);
			copy_tv(&(oldworkmarkers->expirydate), cd);
			workmarkers_root = add_to_ktree(workmarkers_root,
							old_wm_item,
							cmp_workmarkers);
			workmarkers_workinfoid_root = add_to_ktree(workmarkers_workinfoid_root,
								   old_wm_item,
								   cmp_workmarkers_workinfoid);
		}
		if (wm_item) {
			workmarkers_root = add_to_ktree(workmarkers_root,
							wm_item,
							cmp_workmarkers);
			workmarkers_workinfoid_root = add_to_ktree(workmarkers_workinfoid_root,
								   wm_item,
								   cmp_workmarkers_workinfoid);
			k_add_head(workmarkers_store, wm_item);
		}
	}
	K_WUNLOCK(workmarkers_free);

	return ok;
}

bool workmarkers_fill(PGconn *conn)
{
	ExecStatusType rescode;
	PGresult *res;
	K_ITEM *item;
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
	for (i = 0; i < n; i++) {
		item = k_unlink_head(workmarkers_free);
		DATA_WORKMARKERS(row, item);

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

		PQ_GET_FLD(res, i, "status", field, ok);
		if (!ok)
			break;
		TXT_TO_STR("status", field, row->status);

		HISTORYDATEFLDS(res, i, row, ok);
		if (!ok)
			break;

		workmarkers_root = add_to_ktree(workmarkers_root, item, cmp_workmarkers);
		workmarkers_workinfoid_root = add_to_ktree(workmarkers_workinfoid_root,
							   item, cmp_workmarkers_workinfoid);
		k_add_head(workmarkers_store, item);

		tick();
	}
	if (!ok)
		k_add_head(workmarkers_free, item);

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

		upd = "update marks set expirydate=$1 where workinfoid=$2"
			" and expirydate=$3";
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
		row->poolinstance = strdup(poolinstance);
		LIST_MEM_ADD(marks_free, poolinstance);
		row->workinfoid = workinfoid;
		row->description = strdup(description);
		LIST_MEM_ADD(marks_free, description);
		row->extra = strdup(extra);
		LIST_MEM_ADD(marks_free, extra);
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
			DATA_MARKS(row, m_item);
			if (row->poolinstance) {
				if (row->poolinstance != EMPTY) {
					LIST_MEM_SUB(marks_free, row->poolinstance);
					free(row->poolinstance);
				}
				row->poolinstance = NULL;
			}
			if (row->description) {
				if (row->description != EMPTY) {
					LIST_MEM_SUB(marks_free, row->description);
					free(row->description);
				}
				row->description = NULL;
			}
			if (row->extra) {
				if (row->extra != EMPTY) {
					LIST_MEM_SUB(marks_free, row->extra);
					free(row->extra);
				}
				row->extra = NULL;
			}
			k_add_head(marks_free, m_item);
		}
	}
	else {
		if (old_m_item) {
			marks_root = remove_from_ktree(marks_root, old_m_item, cmp_marks);
			copy_tv(&(oldmarks->expirydate), cd);
			marks_root = add_to_ktree(marks_root, old_m_item, cmp_marks);
		}
		if (m_item) {
			marks_root = add_to_ktree(marks_root, m_item, cmp_marks);
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
	for (i = 0; i < n; i++) {
		item = k_unlink_head(marks_free);
		DATA_MARKS(row, item);

		if (everyone_die) {
			ok = false;
			break;
		}

		PQ_GET_FLD(res, i, "poolinstance", field, ok);
		if (!ok)
			break;
		TXT_TO_PTR("poolinstance", field, row->poolinstance);

		PQ_GET_FLD(res, i, "workinfoid", field, ok);
		if (!ok)
			break;
		TXT_TO_BIGINT("workinfoid", field, row->workinfoid);

		PQ_GET_FLD(res, i, "description", field, ok);
		if (!ok)
			break;
		TXT_TO_PTR("description", field, row->description);

		PQ_GET_FLD(res, i, "extra", field, ok);
		if (!ok)
			break;
		TXT_TO_PTR("extra", field, row->extra);

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

		marks_root = add_to_ktree(marks_root, item, cmp_marks);
		k_add_head(marks_store, item);

		tick();
	}
	if (!ok)
		k_add_head(marks_free, item);

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
