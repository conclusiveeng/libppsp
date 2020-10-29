/*
 * Copyright (c) 2020 Conclusive Engineering Sp. z o.o.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#include "mt.h"
#include "debug.h"
#include "peer.h"
#include "sha1.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * returns rounded order of 32-bit variable
 * simplified log2() function
 */
INTERNAL_LINKAGE
int
order2(uint32_t val)
{
  int o;
  int bits;
  int32_t b;

  o = -1;
  bits = 0;
  for (b = 31; b >= 0; b--) {
    if (val & (1 << b)) {
      if (o == -1) {
	o = b;
      }
      bits++;
    }
  }

  if (bits > 1) {
    o++;
  } /* increase order of the "val" if there are other bits on the right
               side of the most important bit */

  return o;
}

/*
 * builds tree with "num_chunks" number of chunks
 * returns:
 * 	pointer to root node of the new created tree
 * 	as "**ret" parameter - pointer to new created tree - 0 index of the leaf
 *
 */
INTERNAL_LINKAGE
struct node *
build_tree(int num_chunks, struct node **ret)
{
  int x;
  int l;
  int si;
  int h;
  int first_idx;
  int nc;
  int left;
  int right;
  int parent;
  int root_idx;
  struct node *rot;
  struct node *tt;

  d_printf("num_chunks: %d\n", num_chunks);

  h = order2(num_chunks); /* "h" - height of the tree */
  nc = 1 << h;            /* if there are for example only 7 chunks - create tree with 8
                             leaves */
  d_printf("order2(%d): %d\n", num_chunks, h);
  d_printf("num_chunks(orig): %d  after_correction: %d\n", num_chunks, nc);

  /* list the tree */
#if 1
  for (l = 1; l <= h + 1; l++) {                        /* goes level by level from bottom up to highest level */
    first_idx = (1 << (l - 1)) - 1;                     /* first index on the given level starting
                                                           from left: 0, 1, 3, 7, 15, etc */
    for (si = first_idx; si < 2 * nc; si += (1 << l)) { /* si - sibling index */
      d_printf("%d ", si);
    }
    d_printf("%s", "\n");
  }
#endif

  /* allocate array of "struct node" */
  tt = malloc(2 * nc * sizeof(struct node));

  /* initialize array of struct node */
  for (x = 0; x < 2 * nc; x++) {
    tt[x].number = x;
    tt[x].chunk = NULL;
    tt[x].left = tt[x].right = tt[x].parent = NULL;
    tt[x].state = INITIALIZED;
  }

  d_printf("%s", "\nbuilding tree - linking nodes\n\n");
  /* build the tree by linking nodes */
  for (l = 1; l <= h; l++) {
    first_idx = (1 << (l - 1)) - 1;
    for (si = first_idx; si < 2 * nc; si += (2 << l)) {
      left = si;
      right = (si | (1 << l));
      parent = (left + right) / 2;
      /* d_printf("pair %d-%d will have parent: %d\n", left, right, parent); */
      tt[left].parent = &tt[parent];  /* parent for left node */
      tt[right].parent = &tt[parent]; /* parent for right node */

      tt[parent].left = &tt[left];   /* left child of the parent */
      tt[parent].right = &tt[right]; /* right child of the parent */
    }
    /* d_printf("%s", "\n"); */
  }

  *ret = tt; /* return just created tree */

  root_idx = (1 << h) - 1;
  d_printf("root node: %d\n", root_idx);

  rot = &tt[root_idx];
  return rot;
}

/*
 * extends the tree by order (8 ->16, 16->32, 32->64, etc)
 * in params:
 * 	orig_tree - pointer to original tree for extending
 * 	orig_num_chunks - number of leaves of original tree
 * out params:
 * 	ret - pointer to index [0] of he new created tree
 */
INTERNAL_LINKAGE
struct node *
extend_tree(struct node *orig_tree, int orig_num_chunks, struct node **ret)
{
  int x;
  int l;
  int si;
  int h;
  int nc;
  int left;
  int right;
  int parent;
  int root_idx;
  int root_idx_012;
  int root_idx_456;
  struct node *rot;
  struct node *tt;
  struct node min;
  struct node max;

  d_printf("extending tree - num_chunks: %d => %d\n", orig_num_chunks, orig_num_chunks * 2);

  h = order2(orig_num_chunks);
  nc = 1 << h;
  d_printf("order2(%d): %d\n", orig_num_chunks, h);
  d_printf("num_chunks(orig): %d  after_correction: %d\n", orig_num_chunks, nc);

  /* list the tree */
#if 0
	for (l = 1; l <= h + 1; l++) {		/* go through levels of the tree starting from bottom */
		int first_idx = (1 << (l - 1)) -1;  /* first index to show on given level: 0, 1, 3, 7, 15 */
		for (si = first_idx; si < 2 * nc; si += (1 << l)) {	/* si - sibling index */
			d_printf("%d ", si);
		}
		d_printf("%s", "\n");
	}
#endif

  /* allocate array of nodes for the new tree (2 times more of the leaves than
   * original tree */
  tt = malloc(2 * 2 * nc * sizeof(struct node));
  *ret = tt; /* return pointer to index [0] of the new tree */

  /* initialize the nodes of the new tree */
#if 1
  for (x = 0; x < 2 * 2 * nc; x++) {
    tt[x].number = x;
    tt[x].chunk = NULL;
    tt[x].left = tt[x].right = tt[x].parent = NULL;
    tt[x].state = INITIALIZED;
  }
#endif

  /* copy SHA hashes of the original tree */
  for (x = 0; x < nc; x++) {
    memcpy(tt[x].sha, orig_tree[x].sha, 20);
  }

  /* compute height and number of leaves for the new created tree */
  h++;
  nc = 2 * nc;

  /* find extreme left and right nodes for old tree */
  interval_min_max(&orig_tree[(1 << (h - 1)) - 1], &min, &max); /* for example: 0-14 */

  /* linking nodes */
  for (l = 1; l <= h; l++) {
    int first_idx = (1 << (l - 1)) - 1;
    for (si = first_idx; si < 2 * nc; si += (2 << l)) {
      left = si;
      right = (si | (1 << l));
      parent = (left + right) / 2;
      tt[left].parent = &tt[parent];
      tt[right].parent = &tt[parent];
      tt[parent].left = &tt[left];
      tt[parent].right = &tt[right];
    }
  }

  /* link both trees */
  root_idx_012 = (1 << (h - 1)) - 1;
  root_idx_456 = root_idx_012 + (1 << h);

  root_idx = (1 << h) - 1;

  tt[root_idx_012].parent = &tt[root_idx]; /* parent for left node */
  tt[root_idx_456].parent = &tt[root_idx]; /* parent for right node */

  tt[root_idx].left = &tt[root_idx_012];  /* left child of the parent */
  tt[root_idx].right = &tt[root_idx_456]; /* right child of the parent */

  tt[root_idx].number = root_idx;

  free(orig_tree);

  d_printf("extend root node: %d  %d\n", root_idx, tt[root_idx].number);

  rot = &tt[root_idx];
  return rot;
}

INTERNAL_LINKAGE
int
update_chunk(struct node *t, unsigned int cn, struct chunk *c)
{
  return 0;
}

/*
 * print tree - root node at top, leaves at bottom
 */
INTERNAL_LINKAGE
void
show_tree_root_based(struct node *t)
{
  int l;
  int si;
  int nl;
  int h;
  int ti;
  int first_idx;
  int center;
  int sp;
  struct node min;
  struct node max;

  d_printf("print the tree starting from root node: %d\n", t->number);

  ti = t->number;
  interval_min_max(t, &min, &max);
  d_printf("min: %d   max: %d\n", min.number, max.number);
  nl = (max.number - min.number) / 2 + 1; /* number of leaves in given subtree */
  h = order2(nl) + 1;

  first_idx = ti;

  /* justification */
#if 1
  center = (nl * (2 + 2)) / 2;
  for (l = h; l >= 1; l--) {
    int is = 1 << l;            /* how many spaces has to be inserted between values on
                                   given level */
    int iw = 1 << (h - l);      /* number of nodes to print on given level */
    int m = iw * (2 + is) - is; /*  */
    /* d_printf("center: %d  iw: %d  m: %d  is: %d\n", center, iw, m, is); */
    for (sp = 0; sp < (center - m / 2); sp++) {
      d_printf("%s", " "); /* insert (center - m/2) spaces first */
    }
    for (si = first_idx; si <= max.number; si += (1 << l)) {
      d_printf("%2d", si);
      for (sp = 0; sp < is; sp++) {
	d_printf("%s", " "); /* add a few spaces */
      }
    }
    first_idx -= (1 << (l - 2));
    d_printf("%s", "\n");
  }
#endif
}

/*
 * find uncle for node "n" in tree with root "t"
 */
INTERNAL_LINKAGE
struct node *
find_uncle(struct node *t, struct node *n)
{
  struct node *p;
  struct node *gp;
  struct node *u;

  p = n->parent;
  if (p == NULL) {
    return NULL;
  }
  gp = p->parent;
  if (gp == NULL) {
    return NULL;
  }

  if (p == gp->right) { /* if parent is right child of grandparent - then uncle is
                         left child of the grandparent */
    u = gp->left;
  }
  if (p == gp->left) { /* if parent is left child of grandparent - then uncle is
                        right child of the grandparent */
    u = gp->right;
  }

  d_printf("node: %d   parent: %d  grandparent: %d  uncle: %d\n", n->number, p->number, gp->number, u->number);

  return u;
}

INTERNAL_LINKAGE
struct node *
find_sibling(struct node *n)
{
  struct node *p;
  struct node *s;

  p = n->parent;
  if (p == NULL) {
    return NULL;
  }

  if (n == p->left) { /* if node 'n' is left child of parent - then sibling is
                       right child of parent */
    s = p->right;
  }
  if (n == p->right) { /* if node 'n' is right child of parent - then sibling is
                        left child of parent */
    s = p->left;
  }

  d_printf("node: %d   parent: %d  sibling: %d\n", n->number, p->number, s->number);

  return s;
}

/*
 * looks for min and max index going through the tree - extremely left and right
 *
 */
INTERNAL_LINKAGE
void
list_interval(struct node *i)
{
  struct node *c;
  struct node *min;
  struct node *max;

  c = i;
  while (c->left != NULL) {
    c = c->left;
  }
  min = c;

  c = i;
  while (c->right != NULL) {
    c = c->right;
  }
  max = c;

  d_printf("root: %d  interval  min: %d  max: %d\n", i->number, min->number, max->number);
}

/*
 * for given node find min and max child node numbers
 */
INTERNAL_LINKAGE
void
interval_min_max(struct node *i, struct node *min, struct node *max)
{
  struct node *c;

  if (i == NULL) {
    abort();
  }
  c = i;
  while (c->left != NULL) {
    c = c->left;
  }

  memcpy(min, c, sizeof(struct node));

  c = i;
  while (c->right != NULL) {
    c = c->right;
  }

  memcpy(max, c, sizeof(struct node));

  d_printf("root: %d  interval  min: %d  max: %d\n", i->number, min->number, max->number);
}

/*
 * dump array of tree
 * in params:
 * 	t - pointer to array of tree
 * 	l - number of leaves
 */
INTERNAL_LINKAGE
void
dump_tree(struct node *t, int l)
{
  char shas[40 + 1];
  int x;
  int y;
  int s;

  memset(shas, 0, sizeof(shas));
  d_printf("%s", "dump tree\n");
  for (x = 0; x < 2 * l; x++) {
    s = 0;
    for (y = 0; y < 20; y++) {
      s += sprintf(shas + s, "%02x", t[x].sha[y] & 0xff);
    }
    d_printf("[%3d]  %d  %s\n", t[x].number, t[x].state, shas);
  }
  d_printf("%s", "\n");
}

/*
 * dump array of chunks
 * in params:
 * 	t - pointer to array of tree
 * 	l - number of leaves
 *
 */
INTERNAL_LINKAGE
void
dump_chunk_tab(struct chunk *c, int l)
{
  char buf[40 + 1];
  int x;
  int y;

  d_printf("%s l: %d\n", __func__, l);
  for (x = 0; x < l; x++) {
    int s = 0;
    for (y = 0; y < 20; y++) {
      s += sprintf(buf + s, "%02x", c[x].sha[y] & 0xff);
    }
    buf[40] = '\0';
    d_printf("chunk[%3d]  off: %8lu  len: %8u  sha: %s  state: %s\n", x, c[x].offset, c[x].len, buf,
             c[x].state == CH_EMPTY ? "EMPTY" : "ACTIVE");
  }
}

INTERNAL_LINKAGE
void
update_sha(struct node *t, int num_chunks)
{
  char sha_parent[40 + 1];
  char zero[20];
  uint8_t concat[80 + 1];
  unsigned char digest[20 + 1];
  int h;
  int nc;
  int l;
  int si;
  int y;
  int s;
  int left;
  int right;
  int parent;
  SHA1Context context;

  memset(zero, 0, sizeof(zero));

  h = order2(num_chunks); /* "h" - height of the tree */
  nc = 1 << h;

  for (l = 1; l <= h; l++) {                            /* go through levels of the tree starting from
                                                           bottom of the tree */
    int first_idx = (1 << (l - 1)) - 1;                 /* first index on given level starting
                                                           from left: 0, 1, 3, 7, 15, etc */
    for (si = first_idx; si < 2 * nc; si += (2 << l)) { /* si - sibling index */
      left = si;
      right = (si | (1 << l));
      parent = (left + right) / 2;

      /* check if both children are empty */
      if ((memcmp(zero, t[left].sha, sizeof(zero)) == 0) && (memcmp(zero, t[right].sha, sizeof(zero)) == 0)) {
	memcpy(t[parent].sha, zero, 20);
      } else {
	memcpy(concat, t[left].sha, 20);
	memcpy(concat + 20, t[right].sha, 20);

	/* calculate SHA1 for concatenated both SHA (left and right) */
	SHA1Reset(&context);
	SHA1Input(&context, concat, 40);
	SHA1Result(&context, digest);

	/* copy generated SHA hash to parent node */
	memcpy(t[parent].sha, digest, 20);
      }
      /* generate ASCII SHA for parent node */
      if (debug) {
	s = 0;
	for (y = 0; y < 20; y++) {
	  s += sprintf(sha_parent + s, "%02x", digest[y] & 0xff);
	}
	sha_parent[40] = '\0';
	d_printf(" p[%d]: %s\n", t[parent].number, sha_parent);
      }
      t[parent].state = ACTIVE;
    }
    d_printf("%s", "\n");
  }
}
