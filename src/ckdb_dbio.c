/*
 * Copyright 1995-2014 Andrew Smith
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

/* Whatever the current paymentaddresses are, replace them with this one
 * Code allows for zero, one or more current payment address
 *  even though there currently can only be zero or one */
K_ITEM *paymentaddresses_set(PGconn *conn, int64_t userid, char *payaddress,
				char *by, char *code, char *inet, tv_t *cd,
				K_TREE *trf_root)
{
	ExecStatusType rescode;
	bool conned = false;
	PGresult *res;
	K_TREE_CTX ctx[1];
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
		// Change the expiry on all the old ones
		pa.userid = userid;
		pa.expirydate.tv_sec = DATE_S_EOT;
		pa.payaddress[0] = '\0';
		INIT_PAYMENTADDRESSES(&look);
		look.data = (void *)(&pa);
		// Tree order is expirydate desc
		old = find_after_in_ktree(paymentaddresses_root, &look,
					  cmp_paymentaddresses, ctx);
		while (old) {
			this = old;
			DATA_PAYMENTADDRESSES(thispa, this);
			if (thispa->userid != userid)
				break;
			old = next_in_ktree(ctx);
			/* Tree remove+add below doesn't matter since
			 * this test will avoid reprocessing */
			if (CURRENT(&(thispa->expirydate))) {
				paymentaddresses_root = remove_from_ktree(paymentaddresses_root, this,
									  cmp_paymentaddresses);
				copy_tv(&(thispa->expirydate), cd);
				paymentaddresses_root = add_to_ktree(paymentaddresses_root, this,
								     cmp_paymentaddresses);
			}
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

bool payments_fill(PGconn *conn)
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
							       cmp_optioncontrol);
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

K_ITEM *optioncontrol_add(PGconn *conn, char *optionname, char *optionvalue,
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
		free(row->transactiontree);
		row->transactiontree = NULL;
		free(row->merklehash);
		row->merklehash = NULL;
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
		row->transactiontree = NULL;
		free(row->merklehash);
		row->merklehash = NULL;
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
		" from workinfo where expirydate=$1 and"
		" ((workinfoid>=$2 and workinfoid<=$3) or"
		"  workinfoid in (select workinfoid from blocks) )";
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
		// We only need to know if the workmarker is ready
		wm_item = find_workmarkers(shares->workinfoid);
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
		// We only need to know if the workmarker is ready
		wm_item = find_workmarkers(shareerrors->workinfoid);
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
		wm_item = find_workmarkers(workinfoid);
		K_RUNLOCK(workmarkers_free);
		if (wm_item) {
			char *tmp;
			DATA_WORKMARKERS(wm, wm_item);
			LOGERR("%s(): attempt to update sharesummary "
			       "with %s %"PRId64"/%"PRId64"/%s createdate %s"
			       " but ready workmarkers %"PRId64" exists",
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
	K_ITEM *item;
	int n, i, par = 0;
	SHARESUMMARY *row;
	char *params[2];
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
			free(row->workername);
			row->workername = NULL;
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
			blocks_root = remove_from_ktree(blocks_root, old_b_item, cmp_blocks);
			copy_tv(&(oldblocks->expirydate), cd);
			blocks_root = add_to_ktree(blocks_root, old_b_item, cmp_blocks);
		}
		blocks_root = add_to_ktree(blocks_root, b_item, cmp_blocks);
		k_add_head(blocks_store, b_item);
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
			blocks_root = remove_from_ktree(blocks_root, old_b_item, cmp_blocks);
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

bool miningpayouts_add(PGconn *conn, char *username, char *height,
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

bool miningpayouts_fill(PGconn *conn)
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

bool auths_add(PGconn *conn, char *poolinstance, char *username,
		char *workername, char *clientid, char *enonce1,
		char *useragent, char *preauth, char *by, char *code,
		char *inet, tv_t *cd, bool igndup, K_TREE *trf_root,
		bool addressuser, USERS **users, WORKERS **workers)
{
	ExecStatusType rescode;
	bool conned = false;
	PGresult *res;
	K_TREE_CTX ctx[1];
	K_ITEM *a_item, *u_item, *w_item;
	char cd_buf[DATE_BUFSIZ];
	AUTHS *row;
	char *ins;
	char *params[8 + HISTORYDATECOUNT];
	int n, par = 0;
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

		if (conned)
			PQfinish(conn);

		if (!igndup) {
			tv_to_buf(cd, cd_buf, sizeof(cd_buf));
			LOGERR("%s(): Duplicate auths ignored %s/%s/%s",
				__func__, poolinstance, workername, cd_buf);
		}

		/* Let them mine, that's what matters :)
		 *  though this would normally only be during a reload */
		return true;
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
	ok = true;
unparam:
	PQclear(res);
	for (n = 0; n < par; n++)
		free(params[n]);
unitem:
	if (conned)
		PQfinish(conn);
	K_WLOCK(auths_free);
	if (!ok)
		k_add_head(auths_free, a_item);
	else {
		auths_root = add_to_ktree(auths_root, a_item, cmp_auths);
		k_add_head(auths_store, a_item);
	}
	K_WUNLOCK(auths_free);

	return ok;
}

bool auths_fill(PGconn *conn)
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

bool userstats_add_db(PGconn *conn, USERSTATS *row)
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

// This is to RAM. The summariser calls the DB I/O functions for userstats
bool userstats_add(char *poolinstance, char *elapsed, char *username,
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

// TODO: data selection - only require ?
bool userstats_fill(PGconn *conn)
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

bool marks_fill(PGconn *conn)
{
	ExecStatusType rescode;
	PGresult *res;
	K_ITEM *item;
	int n, i;
	MARKS *row;
	char *field;
	char *sel;
	int fields = 5;
	bool ok;

	LOGDEBUG("%s(): select", __func__);

	// TODO: limit how far back
	sel = "select "
		"poolinstance,workinfoid,description,marktype,status"
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
