/*
 * Copyright 2014-2017 Con Kolivas
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#ifndef STRATIFIER_H
#define STRATIFIER_H

void parse_remote_txns(ckpool_t *ckp, const json_t *val);
#define parse_upstream_txns(ckp, val) parse_remote_txns(ckp, val)
void parse_upstream_auth(ckpool_t *ckp, json_t *val);
void parse_upstream_workinfo(ckpool_t *ckp, json_t *val);
void parse_upstream_block(ckpool_t *ckp, json_t *val);
void parse_upstream_reqtxns(ckpool_t *ckp, json_t *val);
char *stratifier_stats(ckpool_t *ckp, void *data);
void stratifier_add_recv(ckpool_t *ckp, json_t *val);
void *stratifier(void *arg);

#endif /* STRATIFIER_H */
