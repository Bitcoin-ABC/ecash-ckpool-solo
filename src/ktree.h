/*
 * Copyright 1995-2015 Andrew Smith
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#ifndef ___KTREE_H
#define ___KTREE_H

#include "klist.h"
#include "libckpool.h"

#define quithere(status, fmt, ...) \
	quitfrom(status, __FILE__, __func__, __LINE__, fmt, ##__VA_ARGS__)

#define KTREE_FFL " - from %s %s() line %d"
#define KTREE_FFL_HERE __FILE__, __func__, __LINE__
#define KTREE_FFL_PASS file, func, line
#define KTREE_FFL_ARGS  __maybe_unused const char *file, \
			__maybe_unused const char *func, \
			__maybe_unused const int line

#define cmp_t int32_t

#define CMP_STR(a,b) strcmp((a),(b))
#define CMP_INT(a,b) ((a)-(b))
#define CMP_BIG_Z(a,b) (((a) < (b)) ? -1 : 1)
#define CMP_BIG(a,b) (((a) == (b)) ? 0 : CMP_BIG_Z(a,b))
#define CMP_TV(a,b) (((a).tv_sec == (b).tv_sec) ? CMP_BIG((a).tv_usec,(b).tv_usec) : \
						  CMP_BIG_Z((a).tv_sec,(b).tv_sec))
#define CMP_BIGINT CMP_BIG
#define CMP_DOUBLE CMP_BIG

typedef struct knode
{
	bool	isNil;
	bool	red;
	struct	knode	*parent;
	struct	knode	*left;
	struct	knode	*right;
	K_ITEM	*data;
	long	test;
} K_NODE;

typedef struct ktree
{
	K_NODE	*root;
	cmp_t (*cmp_funct)(K_ITEM *, K_ITEM *);
} K_TREE;

typedef void *K_TREE_CTX;

extern K_TREE *_new_ktree(cmp_t (*cmp_funct)(K_ITEM *, K_ITEM *), KTREE_FFL_ARGS);
#define new_ktree(_cmp_funct) _new_ktree(_cmp_funct, KLIST_FFL_HERE)
extern void _dump_ktree(K_TREE *tree, char *(*dsp_funct)(K_ITEM *), KTREE_FFL_ARGS);
#define dump_ktree(_tree, _dsp_funct) _dump_ktree(_tree, _dsp_funct, KLIST_FFL_HERE)
extern void _dsp_ktree(K_LIST *list, K_TREE *tree, char *filename, char *msg, KTREE_FFL_ARGS);
#define dsp_ktree(_list, _tree, _filename, _msg) _dsp_ktree(_list, _tree, _filename, _msg, KLIST_FFL_HERE)
extern K_ITEM *_first_in_ktree(K_TREE *tree, K_TREE_CTX *ctx, KTREE_FFL_ARGS);
#define first_in_ktree(_tree, _ctx) _first_in_ktree(_tree, _ctx, KLIST_FFL_HERE)
extern K_ITEM *_last_in_ktree(K_TREE *tree, K_TREE_CTX *ctx, KTREE_FFL_ARGS);
#define last_in_ktree(_tree, _ctx) _last_in_ktree(_tree, _ctx, KLIST_FFL_HERE)
extern K_ITEM *_next_in_ktree(K_TREE_CTX *ctx, KTREE_FFL_ARGS);
#define next_in_ktree(_ctx) _next_in_ktree(_ctx, KLIST_FFL_HERE)
extern K_ITEM *_prev_in_ktree(K_TREE_CTX *ctx, KTREE_FFL_ARGS);
#define prev_in_ktree(_ctx) _prev_in_ktree(_ctx, KLIST_FFL_HERE)
extern void _add_to_ktree(K_TREE *tree, K_ITEM *data, KTREE_FFL_ARGS);
#define add_to_ktree(_tree, _data) _add_to_ktree(_tree, _data, KLIST_FFL_HERE)
extern K_ITEM *_find_in_ktree(K_TREE *tree, K_ITEM *data, K_TREE_CTX *ctx, KTREE_FFL_ARGS);
#define find_in_ktree(_tree, _data, _ctx) _find_in_ktree(_tree, _data, _ctx, KLIST_FFL_HERE)
extern K_ITEM *_find_after_in_ktree(K_TREE *ktree, K_ITEM *data, K_TREE_CTX *ctx, KTREE_FFL_ARGS);
#define find_after_in_ktree(_ktree, _data, _ctx) _find_after_in_ktree(_ktree, _data, _ctx, KLIST_FFL_HERE)
extern K_ITEM *_find_before_in_ktree(K_TREE *ktree, K_ITEM *data, K_TREE_CTX *ctx, KTREE_FFL_ARGS);
#define find_before_in_ktree(_ktree, _data, _ctx) _find_before_in_ktree(_ktree, _data, _ctx, KLIST_FFL_HERE)
extern void _remove_from_ktree(K_TREE *tree, K_ITEM *data, K_TREE_CTX *ctx, KTREE_FFL_ARGS);
extern void _remove_from_ktree_free(K_TREE *tree, K_ITEM *data, KTREE_FFL_ARGS);
#define remove_from_ktree(_tree, _data) _remove_from_ktree_free(_tree, _data, KLIST_FFL_HERE)
extern void _free_ktree(K_TREE *tree, void (*free_funct)(void *), KTREE_FFL_ARGS);
#define free_ktree(_tree, _free_funct) do { \
		_free_ktree(_tree, _free_funct, KLIST_FFL_HERE); \
		_tree = NULL; \
	} while (0)

#endif
