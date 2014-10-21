/*
 * Copyright 1995-2014 Andrew Smith
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#include "ktree.h"

static const int dbg = 0;
#define DBG	if (dbg != 0) printf

#define FAIL(fmt, ...) do \
	{ \
		quithere(1, fmt KTREE_FFL, ##__VA_ARGS__, KTREE_FFL_PASS); \
	} while (0);

#define RED_RED         true
#define RED_BLACK       false

#define Yo true
#define No false

static K_TREE nil[1] = { { Yo, RED_BLACK, NULL, NULL, NULL, NULL, 0 } };

K_TREE *_new_ktree(KTREE_FFL_ARGS)
{
	K_TREE *ktree = (K_TREE *)malloc(sizeof(*ktree));

	if (ktree == NULL)
		FAIL("%s", "OOM");

	ktree->isNil = Yo;
	ktree->red = RED_BLACK;
	ktree->parent = nil;
	ktree->left = nil;
	ktree->right = nil;
	ktree->data = NULL;
	ktree->test = 0;

	return ktree;
}

static K_TREE *new_data(K_ITEM *data, KTREE_FFL_ARGS)
{
	K_TREE *ktree = (K_TREE *)malloc(sizeof(*ktree));

	if (ktree == NULL)
		FAIL("%s", "OOM");

	ktree->isNil = No;
	ktree->red = RED_RED;
	ktree->parent = nil;
	ktree->left = nil;
	ktree->right = nil;
	ktree->data = data;
	ktree->test = 0;

	return ktree;
}

static int bCount = 0;
static long bTestValue = 0;
static long nilTestValue = 0;
static long lrpTestValue = 0;

static long testValue = 1231230L;

static long getTestValue()
{
	return ++testValue;
}

static void show_ktree(K_TREE *root, char *path, int pos, char *(*dsp_funct)(K_ITEM *))
{
	char col;

	if (root->isNil == Yo)
		return;

	if (root->left->isNil == No)
	{
		path[pos] = 'L';
		path[pos+1] = '\0';
		show_ktree(root->left, path, pos+1, dsp_funct);
	}

	path[pos] = '\0';

	switch(root->red)
	{
	case RED_RED:
		col = 'R';
		break;
	case RED_BLACK:
		col = 'B';
		break;
	}

	printf(" %c %s=%s\n", col, path, dsp_funct(root->data));

	if (root->right->isNil == No)
	{
		path[pos] = 'R';
		path[pos+1] = '\0';
		show_ktree(root->right, path, pos+1, dsp_funct);
	}
}

void _dump_ktree(K_TREE *root, char *(*dsp_funct)(K_ITEM *), KTREE_FFL_ARGS)
{
	char buf[42424];

	printf("dump:\n");
	if (root->isNil == No)
	{
		buf[0] = 'T';
		buf[1] = '\0';
		show_ktree(root, buf, 1, dsp_funct);
	}
	else
		printf(" Empty ktree\n");
}

void _dsp_ktree(K_LIST *list, K_TREE *root, char *filename, char *msg, KTREE_FFL_ARGS)
{
	K_TREE_CTX ctx[1];
	K_ITEM *item;
	FILE *stream;
	struct tm tm;
	time_t now_t;
	char stamp[128];

	if (!list->dsp_func)
		FAIL("%s", "NULLDSP NULL dsp_func");

	now_t = time(NULL);
	localtime_r(&now_t, &tm);
	snprintf(stamp, sizeof(stamp),
			"[%d-%02d-%02d %02d:%02d:%02d]",
			tm.tm_year + 1900,
			tm.tm_mon + 1,
			tm.tm_mday,
			tm.tm_hour,
			tm.tm_min,
			tm.tm_sec);

	stream = fopen(filename, "ae");
	if (!stream)
	{
		fprintf(stderr, "%s %s() failed to open '%s' (%d) %s",
				stamp, __func__, filename, errno, strerror(errno));
		return;
	}

	if (msg)
		fprintf(stream, "%s %s\n", stamp, msg);
	else
		fprintf(stream, "%s Dump of ktree '%s':\n", stamp, list->name);

	if (root->isNil == No)
	{
		item = first_in_ktree(root, ctx);
		while (item)
		{
			list->dsp_func(item, stream);
			item = next_in_ktree(ctx);
		}
		fprintf(stream, "End\n\n");
	}
	else
		fprintf(stream, "Empty ktree\n\n");

	fclose(stream);
}

static int nilTest(K_TREE *node, char *msg, int depth, int count, K_TREE *nil2, KTREE_FFL_ARGS)
{
	if (node->isNil == Yo || node == nil2)
	{
		if (node == nil2 && node->isNil == No)
			FAIL("NIL2NOTNIL '%s' depth=%d count=%d", msg, depth, count);

		if (node != nil && node != nil2)
			FAIL("NOTNILNIL2 '%s' depth=%d count=%d", msg, depth, count);

		if (node->red == RED_RED)
			FAIL("NIRED '%s' depth=%d count=%d", msg, depth, count);

		if (node != nil2 && node->parent != NULL)
			FAIL("NILPARENT '%s' depth=%d count=%d", msg, depth, count);

		if (node != nil2 && node->left != NULL)
			FAIL("NILLEFT '%s' depth=%d count=%d", msg, depth, count);

		if (node == nil2 && node->left != nil)
			FAIL("NIL2LEFT '%s' depth=%d count=%d", msg, depth, count);

		if (node != nil2 && node->right != NULL)
			FAIL("NILRIGHT '%s' depth=%d count=%d", msg, depth, count);

		if (node == nil2 && node->right != nil)
			FAIL("NIL2RIGHT '%s' depth=%d count=%d", msg, depth, count);

		if (node->data != NULL)
			FAIL("NIDATA '%s' depth=%d count=%d", msg, depth, count);
	}
	else
	{
		count++;

		if (node->parent == NULL)
			FAIL("NOPAR '%s' depth=%d count=%d", msg, depth, count);

		if (node->left == NULL)
			FAIL("NOLEFT '%s' depth=%d count=%d", msg, depth, count);

		if (node->right == NULL)
			FAIL("NORIGHT '%s' depth=%d count=%d", msg, depth, count);

		if (node->data == NULL)
			FAIL("NODATA '%s' depth=%d count=%d", msg, depth, count);

		if (node->test != nilTestValue)
			node->test = nilTestValue;
		else
			FAIL("NILTESTVALUE '%s' depth=%d count=%d", msg, depth, count);

		count = nilTest(node->left, msg, depth+1, count, nil2, KTREE_FFL_PASS);
		count = nilTest(node->right, msg, depth+1, count, nil2, KTREE_FFL_PASS);
	}

	return(count);
}

static void bTest(K_TREE *root, K_TREE *cur, char *msg, int count, KTREE_FFL_ARGS)
{
	if (cur->red != RED_RED)
		count++;
	else
	{
		if (cur->left->red == RED_RED)
			FAIL("CURLR '%s' count=%d", msg, count);

		if (cur->right->red == RED_RED)
			FAIL("CURRR '%s' count=%d", msg, count);
	}

	if (cur->isNil == Yo)
	{
		if (bCount == 0)
			bCount = count;

		if (count != bCount)
			FAIL("BCOUNT '%s' count=%d bCount=%d", msg, count, bCount);
	}
	else
	{
		if (cur->test != bTestValue)
			cur->test = bTestValue;
		else
			FAIL("BTESTVALUE '%s' count=%d", msg, count);

		bTest(root, cur->left, msg, count, KTREE_FFL_PASS);
		bTest(root, cur->right, msg, count, KTREE_FFL_PASS);
	}
}

static void bTestInit(K_TREE *root, char *msg, KTREE_FFL_ARGS)
{
	bCount = 0;
	bTestValue = getTestValue();
	bTest(root, root, msg, 0, KTREE_FFL_PASS);
}

static void lrpTest(K_TREE *top, char *msg, KTREE_FFL_ARGS)
{
	if (top->test != lrpTestValue)
		top->test = lrpTestValue;
	else
		FAIL("LRPTESTVALUE '%s'", msg);

	if (top->left->isNil == No)
	{
		if (top->left->parent != top)
			FAIL("LRPTESTL '%s'", msg);

		lrpTest(top->left, msg, KTREE_FFL_PASS);
	}

	if (top->right->isNil == No)
	{
		if (top->right->parent != top)
			FAIL("LRPTESTR '%s'", msg);

		lrpTest(top->right, msg, KTREE_FFL_PASS);
	}
}

static __maybe_unused void check_ktree(K_TREE *root, char *msg, K_TREE *nil2, int debugNil, int debugLRP, int debugColor, KTREE_FFL_ARGS)
{
	if (root->isNil == Yo)
		return;

	if (debugNil)
	{
		nilTestValue = getTestValue();
		nilTest(root, msg, 1, 0, nil2, KTREE_FFL_PASS);
	}

	if (debugLRP && root->isNil == No)
	{
		lrpTestValue = getTestValue();
		lrpTest(root, msg, KTREE_FFL_PASS);
	}

	if (debugColor && root->isNil == No)
		bTestInit(root, msg, KTREE_FFL_PASS);
}

K_ITEM *_first_in_ktree(K_TREE *root, K_TREE_CTX *ctx, KTREE_FFL_ARGS)
{
	if (root->isNil == No)
	{
		while (root->left->isNil == No)
			root = root->left;

		*ctx = root;
		return(root->data);
	}

	*ctx = NULL;
	return(NULL);
}

K_ITEM *_last_in_ktree(K_TREE *root, K_TREE_CTX *ctx, KTREE_FFL_ARGS)
{
	if (root->isNil == No)
	{
		while (root->right->isNil == No)
			root = root->right;

		*ctx = root;
		return(root->data);
	}

	*ctx = NULL;
	return(NULL);
}

K_ITEM *_next_in_ktree(K_TREE_CTX *ctx, KTREE_FFL_ARGS)
{
	K_TREE *parent;
	K_TREE *ktree = (K_TREE *)(*ctx);

	if (ktree->isNil == No)
	{
		if (ktree->right->isNil == No)
			return(first_in_ktree(ktree->right, ctx));
		else
		{
			parent = ktree->parent;
			while (parent->isNil == No && ktree == parent->right)
			{
				ktree = parent;
				parent = parent->parent;
			}
			if (parent->isNil == No)
			{
				*ctx = parent;
				return(parent->data);
			}
		}
	}

	*ctx = NULL;
	return(NULL);
}

K_ITEM *_prev_in_ktree(K_TREE_CTX *ctx, KTREE_FFL_ARGS)
{
	K_TREE *parent;
	K_TREE *ktree = (K_TREE *)(*ctx);

	if (ktree->isNil == No)
	{
		if (ktree->left->isNil == No)
			return(last_in_ktree(ktree->left, ctx));
		else
		{
			parent = ktree->parent;
			while (parent->isNil == No && ktree == parent->left)
			{
				ktree = parent;
				parent = parent->parent;
			}
			if (parent->isNil == No)
			{
				*ctx = parent;
				return(parent->data);
			}
		}
	}

	*ctx = NULL;
	return(NULL);
}

static K_TREE *left_rotate(K_TREE *root, K_TREE *about)
{
	K_TREE *rotate;

	rotate = about->right;
	about->right = rotate->left;

	if (rotate->left->isNil == No)
		rotate->left->parent = about;

	rotate->parent = about->parent;

	if (about->parent->isNil == Yo)
		root = rotate;
	else
	{
		if (about == about->parent->left)
			about->parent->left = rotate;
		else
			about->parent->right = rotate;
	}

	rotate->left = about;
	about->parent = rotate;

	return(root);
}

static K_TREE *right_rotate(K_TREE *root, K_TREE *about)
{
	K_TREE *rotate;

	rotate = about->left;
	about->left = rotate->right;

	if (rotate->right->isNil == No)
		rotate->right->parent = about;

	rotate->parent = about->parent;

	if (about->parent->isNil == Yo)
		root = rotate;
	else
		if (about == about->parent->right)
			about->parent->right = rotate;
		else
			about->parent->left = rotate;

	rotate->right = about;
	about->parent = rotate;

	return(root);
}

K_TREE *_add_to_ktree(K_TREE *root, K_ITEM *data, cmp_t (*cmp_funct)(K_ITEM *, K_ITEM *), KTREE_FFL_ARGS)
{
	K_TREE *ktree;
	K_TREE *x, *y;
	K_TREE *pp;
	cmp_t cmp;

	if (root == NULL)
		FAIL("%s", "ADDNULL add ktree is NULL");

//check_ktree(root, ">add", NULL, 1, 1, 1, KTREE_FFL_PASS);

	if (root->parent != nil && root->parent != NULL)
		FAIL("%s", "ADDROOT add root isn't the root");

	ktree = new_data(data, KTREE_FFL_PASS);

	if (root->isNil == Yo)
	{
		if (root != nil)
			free(root);

		root = ktree;
	}
	else
	{
		x = root;
		y = nil;
		while (x->isNil == No)
		{
			y = x;
			if ((cmp = (*cmp_funct)(ktree->data, x->data)) < 0)
				x = x->left;
			else
				x = x->right;
		}
		ktree->parent = y;
		if (cmp < 0)
			y->left = ktree;
		else
			y->right = ktree;

		x = ktree;
		while (x != root && x->parent->red == RED_RED)
		{
			pp = x->parent->parent;
			if (x->parent == pp->left)
			{
				y = pp->right;
				if (y->red == RED_RED)
				{
					x->parent->red = RED_BLACK;
					y->red = RED_BLACK;
					pp->red = RED_RED;
					x = pp;
				}
				else
				{
					if (x == x->parent->right)
					{
						x = x->parent;
						root = left_rotate(root, x);
						pp = x->parent->parent;
					}
					x->parent->red = RED_BLACK;
					pp->red = RED_RED;
					root = right_rotate(root, pp);
				}
			}
			else
			{
				y = pp->left;
				if (y->red == RED_RED)
				{
					x->parent->red = RED_BLACK;
					y->red = RED_BLACK;
					pp->red = RED_RED;
					x = pp;
				}
				else
				{
					if (x == x->parent->left)
					{
						x = x->parent;
						root = right_rotate(root, x);
						pp = x->parent->parent;
					}
					x->parent->red = RED_BLACK;
					pp->red = RED_RED;
					root = left_rotate(root, pp);
				}
			}
		}
	}
	root->red = RED_BLACK;

//check_ktree(root, "<add", NULL, 1, 1, 1, KTREE_FFL_PASS);

	return(root);
}

K_ITEM *_find_in_ktree(K_TREE *ktree, K_ITEM *data, cmp_t (*cmp_funct)(K_ITEM *, K_ITEM *), K_TREE_CTX *ctx, KTREE_FFL_ARGS)
{
	cmp_t cmp = -1;

	if (ktree == NULL)
		FAIL("%s", "FINDNULL find ktree is NULL");

	while (ktree->isNil == No && cmp != 0)
	{
		if ((cmp = (*cmp_funct)(ktree->data, data)))
		{
			if (cmp > 0)
				ktree = ktree->left;
			else
				ktree = ktree->right;
		}
	}

	if (ktree->isNil == No)
	{
		*ctx = ktree;
		return(ktree->data);
	}
	else
	{
		*ctx = NULL;
		return(NULL);
	}
}

K_ITEM *_find_after_in_ktree(K_TREE *ktree, K_ITEM *data, cmp_t (*cmp_funct)(K_ITEM *, K_ITEM *), K_TREE_CTX *ctx, KTREE_FFL_ARGS)
{
	K_TREE *old = NULL;
	cmp_t cmp = -1, oldcmp = -1;

	if (ktree == NULL)
		FAIL("%s", "FINDNULL find_after ktree is NULL");

	while (ktree->isNil == No && cmp != 0)
	{
		if ((cmp = (*cmp_funct)(ktree->data, data)))
		{
			old = ktree;
			oldcmp = cmp;
			if (cmp > 0)
				ktree = ktree->left;
			else
				ktree = ktree->right;
		}
	}

	if (ktree->isNil == No)
	{
		*ctx = ktree;
		return next_in_ktree(ctx);
	}
	else
	{
		if (old)
		{
			if (oldcmp > 0)
			{
				*ctx = old;
				return(old->data);
			}

			*ctx = old;
			return next_in_ktree(ctx);
		}

		*ctx = NULL;
		return(NULL);
	}
}

K_ITEM *_find_before_in_ktree(K_TREE *ktree, K_ITEM *data, cmp_t (*cmp_funct)(K_ITEM *, K_ITEM *), K_TREE_CTX *ctx, KTREE_FFL_ARGS)
{
	K_TREE *old = NULL;
	cmp_t cmp = 1, oldcmp = 1;

	if (ktree == NULL)
		FAIL("%s", "FINDNULL find_before ktree is NULL");

	while (ktree->isNil == No && cmp != 0)
	{
		if ((cmp = (*cmp_funct)(ktree->data, data)))
		{
			old = ktree;
			oldcmp = cmp;
			if (cmp > 0)
				ktree = ktree->left;
			else
				ktree = ktree->right;
		}
	}

	if (ktree->isNil == No)
	{
		*ctx = ktree;
		return prev_in_ktree(ctx);
	}
	else
	{
		if (old)
		{
			if (oldcmp < 0)
			{
				*ctx = old;
				return(old->data);
			}

			*ctx = old;
			return prev_in_ktree(ctx);
		}

		*ctx = NULL;
		return(NULL);
	}
}

static K_TREE *removeFixup(K_TREE *root, K_TREE *fix)
{
	K_TREE *w = NULL;

	while (fix != root && fix->red != RED_RED)
	{
		if (fix == fix->parent->left)
		{
			w = fix->parent->right;
			if (w->red == RED_RED)
			{
				w->red = RED_BLACK;
				fix->parent->red = RED_RED;
				root = left_rotate(root, fix->parent);
				w = fix->parent->right;
			}

			if (w->left->red != RED_RED && w->right->red != RED_RED)
			{
				w->red = RED_RED;
				fix = fix->parent;
			}
			else
			{
				if (w->right->red != RED_RED)
				{
					w->left->red = RED_BLACK;
					w->red = RED_RED;
					root = right_rotate(root, w);
					w = fix->parent->right;
				}

				w->red = fix->parent->red;
				fix->parent->red = RED_BLACK;
				w->right->red = RED_BLACK;
				root = left_rotate(root, fix->parent);
				fix = root;
			}
		}
		else
		{
			w = fix->parent->left;
			if (w->red == RED_RED)
			{
				w->red = RED_BLACK;
				fix->parent->red = RED_RED;
				root = right_rotate(root, fix->parent);
				w = fix->parent->left;
			}

			if (w->right->red != RED_RED && w->left->red != RED_RED)
			{
				w->red = RED_RED;
				fix = fix->parent;
			}
			else
			{
				if (w->left->red != RED_RED)
				{
					w->right->red = RED_BLACK;
					w->red = RED_RED;
					root = left_rotate(root, w);
					w = fix->parent->left;
				}

				w->red = fix->parent->red;
				fix->parent->red = RED_BLACK;
				w->left->red = RED_BLACK;
				root = right_rotate(root, fix->parent);
				fix = root;
			}
		}
	}

	fix->red = RED_BLACK;

	return root;
}

// Does this work OK when you remove the last element in the ktree?
// It should return the root as 'nil'
K_TREE *_remove_from_ktree(K_TREE *root, K_ITEM *data, cmp_t (*cmp_funct)(K_ITEM *, K_ITEM *), K_TREE_CTX *ctx, KTREE_FFL_ARGS)
{
	K_TREE_CTX tmpctx[1];
	K_TREE *found;
	K_ITEM *fdata;
	K_TREE *x, *y, *nil2;
	// cmp_t cmp;
	int yred;

//check_ktree(root, ">remove", NULL, 1, 1, 1, KTREE_FFL_PASS);

	if (root == NULL)
		FAIL("%s", "REMNULL remove ktree is NULL");

	if (root->isNil == Yo)
	{
		*ctx = NULL;
		return(root);
	}

	if (root->parent->isNil == No)
		FAIL("%s", "REMROOT remove root isn't the root");

	fdata = find_in_ktree(root, data, cmp_funct, ctx);

	if (fdata == NULL)
		return(root);

	if (cmp_funct(fdata, data) != 0)
		FAIL("%s", "BADFIND cmp(found, remove) != 0");

	found = *ctx;

	x = nil;
	y = nil;

	if (found->left->isNil == Yo || found->right->isNil == Yo)
		y = found;
	else
	{
		*tmpctx = found;
		next_in_ktree(tmpctx);
		y = *tmpctx;
	}

	yred = y->red;

	if (y->left->isNil == No && y->right->isNil == No)
		FAIL("%s", "REMBADY remove error");

	if (y->left->isNil == Yo)
		x = y->right;
	else
		x = y->left;

	if (x != nil)
		nil2 = NULL;
	else
	{
		nil2 = new_ktree();
		x = nil2;
	}

	x->parent = y->parent;

	if (x->parent->isNil == Yo)
		root = x;
	else
	{
		if (x->parent->left == y)
			x->parent->left = x;
		else
			x->parent->right = x;
	}

	if (y != found)
	{
		if (root == found)
			root = y;

		if (x == found)
			x = y;

		y->red = found->red;
		y->parent = found->parent;

		if (y->parent->isNil == No)
		{
			if (y->parent->left == found)
				y->parent->left = y;
			else
				y->parent->right = y;
		}

		y->left = found->left;
		if (y->left->isNil == No || y->left == nil2)
			y->left->parent = y;

		y->right = found->right;
		if (y->right->isNil == No || y->right == nil2)
			y->right->parent = y;
	}

	if (yred != RED_RED)
		root = removeFixup(root, x);

	if (nil2 != NULL)
	{
		if (nil2->parent->isNil == No && nil2->parent->left == nil2)
			nil2->parent->left = nil;

		if (nil2->parent->isNil == No && nil2->parent->right == nil2)
			nil2->parent->right = nil;

		if (root == nil2)
			root = nil;

/*
if (dbg != 0)
{
 if (nil2->left != nil)
 {
DBG("@remove nil2->left wasn't nil!!!\n");
 }
 if (nil2->right != nil)
 {
DBG("@remove nil2->right wasn't nil!!!\n");
 }
 cmp = 0;
 fdata = first_in_ktree(root, tmpctx);;
 while (fdata != NULL)
 {
	cmp++;
	x = *tmpctx;
	if (x == nil2)
	{
DBG("@remove found nil2 in ktree %f!!!\n", cmp);
	}
	else
		if (x->left == nil2)
		{
DBG("@remove found nil2 in ktree(left) %f!!!\n", cmp);
		}
		else
			if (x->right == nil2)
			{
DBG("@remove found nil2 in ktree(right) %f!!!\n", cmp);
			}

	fdata = next_in_ktree(tmpctx);;
 }
}
*/
		free(nil2);
	}

/*
if (dbg != 0)
{
 cmp = 0;
 fdata = first_in_ktree(root, tmpctx);;
 while (fdata != NULL)
 {
	if (cmp_funct(fdata, root->data) < 0)
		cmp--;
	else
		cmp++;

	fdata = next_in_ktree(tmpctx);;
 }
 if (cmp < -10 || cmp > 10)
 {
DBG("@remove after balance=%f :(\n", cmp);
 }
}
*/


//check_ktree(root, "<remove", NULL, 1, 1, 1, KTREE_FFL_PASS);

	return root;
}

static void free_ktree_sub(K_TREE *ktree, void (*free_funct)(void *))
{
	if (ktree != NULL && ktree != nil)
	{
		if (ktree->data != NULL && free_funct)
			(*free_funct)(ktree->data);

		free_ktree_sub(ktree->left, free_funct);
		free_ktree_sub(ktree->right, free_funct);

		free(ktree);
	}
}

K_TREE *_free_ktree(K_TREE *ktree, void (*free_funct)(void *), KTREE_FFL_ARGS)
{
	if (ktree == NULL)
		FAIL("%s", "FREENULL free NULL ktree");

	if (ktree->parent != NULL && ktree->parent != nil)
		FAIL("%s", "FREENOTROOT free ktree not root");

	free_ktree_sub(ktree, free_funct);

	return(nil);
}
