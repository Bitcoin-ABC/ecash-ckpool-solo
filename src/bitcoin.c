/*
 * Copyright 2014-2015 Con Kolivas
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#include "config.h"

#include <string.h>

#include "ckpool.h"
#include "libckpool.h"
#include "bitcoin.h"

static const char *b58chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/* Take a bitcoin address and do some sanity checks on it, then send it to
 * bitcoind to see if it's a valid address */
bool validate_address(connsock_t *cs, const char *address)
{
	json_t *val, *res_val, *valid_val;
	char rpc_req[128];
	bool ret = false;
	int len, i, j;

	if (unlikely(!address)) {
		LOGWARNING("Null address passed to validate_address");
		return ret;
	}
	len = strlen(address);
	if (len < 27 || len > 36) {
		LOGWARNING("Invalid address length %d passed to validate_address", len);
		return ret;
	}
	for (i = 0; i < len; i++) {
		char c = address[i];
		bool found = false;

		for (j = 0; j < 58; j++) {
			if (c == b58chars[j]) {
				found = true;
				break;
			}
		}
		if (!found) {
			LOGNOTICE("Invalid char %.1s passed to validate_address", &c);
			return ret;
		}
	}

	snprintf(rpc_req, 128, "{\"method\": \"validateaddress\", \"params\": [\"%s\"]}\n", address);
	val = json_rpc_call(cs, rpc_req);
	if (!val) {
		LOGERR("Failed to get valid json response to validate_address");
		return ret;
	}
	res_val = json_object_get(val, "result");
	if (!res_val) {
		LOGERR("Failed to get result json response to validate_address");
		goto out;
	}
	valid_val = json_object_get(res_val, "isvalid");
	if (!valid_val) {
		LOGERR("Failed to get isvalid json response to validate_address");
		goto out;
	}
	if (!json_is_true(valid_val))
		LOGDEBUG("Bitcoin address %s is NOT valid", address);
	else {
		LOGDEBUG("Bitcoin address %s IS valid", address);
		ret = true;
	}
out:
	if (val)
		json_decref(val);
	return ret;
}

/* Distill down a set of transactions into an efficient tree arrangement for
 * stratum messages and fast work assembly. */
static bool gbt_merkle_bins(gbtbase_t *gbt, json_t *transaction_arr)
{
	int i, j, binleft, binlen;
	json_t *arr_val;
	uchar *hashbin;

	dealloc(gbt->txn_data);
	dealloc(gbt->txn_hashes);
	gbt->transactions = 0;
	gbt->merkles = 0;
	gbt->transactions = json_array_size(transaction_arr);
	binlen = gbt->transactions * 32 + 32;
	hashbin = alloca(binlen + 32);
	memset(hashbin, 0, 32);
	binleft = binlen / 32;
	if (gbt->transactions) {
		int len = 1, ofs = 0;
		const char *txn;

		for (i = 0; i < gbt->transactions; i++) {
			arr_val = json_array_get(transaction_arr, i);
			txn = json_string_value(json_object_get(arr_val, "data"));
			if (!txn) {
				LOGWARNING("json_string_value fail - cannot find transaction data");
				return false;
			}
			len += strlen(txn);
		}

		gbt->txn_data = ckzalloc(len + 1);
		gbt->txn_hashes = ckzalloc(gbt->transactions * 65 + 1);
		memset(gbt->txn_hashes, 0x20, gbt->transactions * 65); // Spaces

		for (i = 0; i < gbt->transactions; i++) {
			char binswap[32];
			const char *hash;

			arr_val = json_array_get(transaction_arr, i);
			hash = json_string_value(json_object_get(arr_val, "hash"));
			txn = json_string_value(json_object_get(arr_val, "data"));
			len = strlen(txn);
			memcpy(gbt->txn_data + ofs, txn, len);
			ofs += len;
#if 0
			/* In case we ever want to be a gbt poolproxy */
			if (!hash) {
				char *txn_bin;
				int txn_len;

				txn_len = len / 2;
				txn_bin = ckalloc(txn_len);
				hex2bin(txn_bin, txn, txn_len);
				/* This is needed for pooled mining since only
				 * transaction data and not hashes are sent */
				gen_hash(txn_bin, hashbin + 32 + 32 * i, txn_len);
				continue;
			}
#endif
			if (!hex2bin(binswap, hash, 32)) {
				LOGERR("Failed to hex2bin hash in gbt_merkle_bins");
				return false;
			}
			memcpy(gbt->txn_hashes + i * 65, hash, 64);
			bswap_256(hashbin + 32 + 32 * i, binswap);
		}
	}
	if (binleft > 1) {
		while (42) {
			uchar merklebin[32];

			if (binleft == 1)
				break;
			memcpy(merklebin, hashbin + 32, 32);
			__bin2hex(&gbt->merklehash[gbt->merkles][0], merklebin, 32);
			LOGDEBUG("MH%d %s",gbt->merkles, &gbt->merklehash[gbt->merkles][0]);
			gbt->merkles++;
			if (binleft % 2) {
				memcpy(hashbin + binlen, hashbin + binlen - 32, 32);
				binlen += 32;
				binleft++;
			}
			for (i = 32, j = 64; j < binlen; i += 32, j += 64)
				gen_hash(hashbin + j, hashbin + i, 64);
			binleft /= 2;
			binlen = binleft * 32;
		}
	}
	LOGINFO("Stored %d transactions", gbt->transactions);
	return true;
}

static const char *gbt_req = "{\"method\": \"getblocktemplate\", \"params\": [{\"capabilities\": [\"coinbasetxn\", \"workid\", \"coinbase/append\"]}]}\n";

/* Request getblocktemplate from bitcoind already connected with a connsock_t
 * and then summarise the information to the most efficient set of data
 * required to assemble a mining template, storing it in a gbtbase_t structure */
bool gen_gbtbase(connsock_t *cs, gbtbase_t *gbt)
{
	json_t *transaction_arr, *coinbase_aux, *res_val, *val, *array;
	const char *previousblockhash;
	char hash_swap[32], tmp[32];
	uint64_t coinbasevalue;
	const char *target;
	const char *flags;
	const char *bits;
	int version;
	int curtime;
	int height;
	int i;
	bool ret = false;

	val = json_rpc_call(cs, gbt_req);
	if (!val) {
		LOGWARNING("Failed to get valid json response to getblocktemplate");
		return ret;
	}
	res_val = json_object_get(val, "result");
	if (!res_val) {
		LOGWARNING("Failed to get result in json response to getblocktemplate");
		goto out;
	}

	previousblockhash = json_string_value(json_object_get(res_val, "previousblockhash"));
	target = json_string_value(json_object_get(res_val, "target"));
	transaction_arr = json_object_get(res_val, "transactions");
	version = json_integer_value(json_object_get(res_val, "version"));
	curtime = json_integer_value(json_object_get(res_val, "curtime"));
	bits = json_string_value(json_object_get(res_val, "bits"));
	height = json_integer_value(json_object_get(res_val, "height"));
	coinbasevalue = json_integer_value(json_object_get(res_val, "coinbasevalue"));
	coinbase_aux = json_object_get(res_val, "coinbaseaux");
	flags = json_string_value(json_object_get(coinbase_aux, "flags"));

	if (unlikely(!previousblockhash || !target || !version || !curtime || !bits || !coinbase_aux || !flags)) {
		LOGERR("JSON failed to decode GBT %s %s %d %d %s %s", previousblockhash, target, version, curtime, bits, flags);
		goto out;
	}

	gbt->json = json_object();

	hex2bin(hash_swap, previousblockhash, 32);
	swap_256(tmp, hash_swap);
	__bin2hex(gbt->prevhash, tmp, 32);
	json_object_set_new_nocheck(gbt->json, "prevhash", json_string_nocheck(gbt->prevhash));

	strncpy(gbt->target, target, 65);
	json_object_set_new_nocheck(gbt->json, "target", json_string_nocheck(gbt->target));

	hex2bin(hash_swap, target, 32);
	bswap_256(tmp, hash_swap);
	gbt->diff = diff_from_target((uchar *)tmp);
	json_object_set_new_nocheck(gbt->json, "diff", json_real(gbt->diff));

	gbt->version = version;
	json_object_set_new_nocheck(gbt->json, "version", json_integer(version));

	gbt->curtime = curtime;
	json_object_set_new_nocheck(gbt->json, "curtime", json_integer(curtime));

	snprintf(gbt->ntime, 9, "%08x", curtime);
	json_object_set_new_nocheck(gbt->json, "ntime", json_string_nocheck(gbt->ntime));

	snprintf(gbt->bbversion, 9, "%08x", version);
	json_object_set_new_nocheck(gbt->json, "bbversion", json_string_nocheck(gbt->bbversion));

	snprintf(gbt->nbit, 9, "%s", bits);
	json_object_set_new_nocheck(gbt->json, "nbit", json_string_nocheck(gbt->nbit));

	gbt->coinbasevalue = coinbasevalue;
	json_object_set_new_nocheck(gbt->json, "coinbasevalue", json_integer(coinbasevalue));

	gbt->height = height;
	json_object_set_new_nocheck(gbt->json, "height", json_integer(height));

	gbt->flags = strdup(flags);
	json_object_set_new_nocheck(gbt->json, "flags", json_string_nocheck(gbt->flags));

	gbt_merkle_bins(gbt, transaction_arr);
	json_object_set_new_nocheck(gbt->json, "transactions", json_integer(gbt->transactions));
	if (gbt->transactions) {
		json_object_set_new_nocheck(gbt->json, "txn_data", json_string_nocheck(gbt->txn_data));
		json_object_set_new_nocheck(gbt->json, "txn_hashes", json_string_nocheck(gbt->txn_hashes));
	}
	json_object_set_new_nocheck(gbt->json, "merkles", json_integer(gbt->merkles));
	if (gbt->merkles) {
		array = json_array();
		for (i = 0; i < gbt->merkles; i++)
			json_array_append_new(array, json_string_nocheck(&gbt->merklehash[i][0]));
		json_object_set_new_nocheck(gbt->json, "merklehash", array);
	}
	ret = true;

out:
	json_decref(val);
	return ret;
}

void clear_gbtbase(gbtbase_t *gbt)
{
	dealloc(gbt->flags);
	dealloc(gbt->txn_data);
	dealloc(gbt->txn_hashes);
	json_decref(gbt->json);
	gbt->json = NULL;
	memset(gbt, 0, sizeof(gbtbase_t));
}

static const char *blockcount_req = "{\"method\": \"getblockcount\"}\n";

/* Request getblockcount from bitcoind, returning the count or -1 if the call
 * fails. */
int get_blockcount(connsock_t *cs)
{
	json_t *val, *res_val;
	int ret = -1;

	val = json_rpc_call(cs, blockcount_req);
	if (!val) {
		LOGWARNING("Failed to get valid json response to getblockcount");
		return ret;
	}
	res_val = json_object_get(val, "result");
	if (!res_val) {
		LOGWARNING("Failed to get result in json response to getblockcount");
		goto out;
	}
	ret = json_integer_value(res_val);
out:
	json_decref(val);
	return ret;
}

/* Request getblockhash from bitcoind for height, writing the value into *hash
 * which should be at least 65 bytes long since the hash is 64 chars. */
bool get_blockhash(connsock_t *cs, int height, char *hash)
{
	json_t *val, *res_val;
	const char *res_ret;
	char rpc_req[128];
	bool ret = false;

	sprintf(rpc_req, "{\"method\": \"getblockhash\", \"params\": [%d]}\n", height);
	val = json_rpc_call(cs, rpc_req);
	if (!val) {
		LOGWARNING("Failed to get valid json response to getblockhash");
		return ret;
	}
	res_val = json_object_get(val, "result");
	if (!res_val) {
		LOGWARNING("Failed to get result in json response to getblockhash");
		goto out;
	}
	res_ret = json_string_value(res_val);
	if (!res_ret || !strlen(res_ret)) {
		LOGWARNING("Got null string in result to getblockhash");
		goto out;
	}
	strncpy(hash, res_ret, 65);
	ret = true;
out:
	json_decref(val);
	return ret;
}

static const char *bestblockhash_req = "{\"method\": \"getbestblockhash\"}\n";

/* Request getbestblockhash from bitcoind. bitcoind 0.9+ only */
bool get_bestblockhash(connsock_t *cs, char *hash)
{
	json_t *val, *res_val;
	const char *res_ret;
	bool ret = false;

	val = json_rpc_call(cs, bestblockhash_req);
	if (!val) {
		LOGWARNING("Failed to get valid json response to getbestblockhash");
		return ret;
	}
	res_val = json_object_get(val, "result");
	if (!res_val) {
		LOGWARNING("Failed to get result in json response to getbestblockhash");
		goto out;
	}
	res_ret = json_string_value(res_val);
	if (!res_ret || !strlen(res_ret)) {
		LOGWARNING("Got null string in result to getbestblockhash");
		goto out;
	}
	strncpy(hash, res_ret, 65);
	ret = true;
out:
	json_decref(val);
	return ret;
}

bool submit_block(connsock_t *cs, char *params)
{
	json_t *val, *res_val;
	int len, retries = 0;
	const char *res_ret;
	bool ret = false;
	char *rpc_req;

	len = strlen(params) + 64;
retry:
	rpc_req = ckalloc(len);
	sprintf(rpc_req, "{\"method\": \"submitblock\", \"params\": [\"%s\"]}\n", params);
	val = json_rpc_call(cs, rpc_req);
	dealloc(rpc_req);
	if (!val) {
		LOGWARNING("Failed to get valid json response to submitblock");
		if (++retries < 5)
			goto retry;
		return ret;
	}
	res_val = json_object_get(val, "result");
	if (!res_val) {
		LOGWARNING("Failed to get result in json response to submitblock");
		if (++retries < 5) {
			json_decref(val);
			goto retry;
		}
		goto out;
	}
	if (!json_is_true(res_val)) {
		res_ret = json_string_value(res_val);
		if (res_ret && strlen(res_ret)) {
			LOGWARNING("SUBMIT BLOCK RETURNED: %s", res_ret);
			goto out;
		}
	}
	LOGWARNING("BLOCK ACCEPTED!");
	ret = true;
out:
	json_decref(val);
	return ret;
}
