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
#include "log.h"
#include "sha1.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * @brief return rounded order of 32-bit variable, similar to log2()
 *
 * @param val 32-bit variable to get order of
 * @return int order of the variable
 */
int
mt_order2(uint32_t val)
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
struct node *
mt_build_tree(int num_chunks, struct node **ret)
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
	struct node *root_node;
	struct node *tree;

	//   DEBUG("num_chunks: %d", num_chunks);

	h = mt_order2(num_chunks); // "h" - height of the tree
	nc = 1 << h;               // if there are for example only 7 chunks - create tree with 8 leaves
	//   DEBUG("order2(%d): %d", num_chunks, h);
	//   DEBUG("num_chunks(orig): %d  after_correction: %d", num_chunks, nc);

	/* DEBUG: list the tree */
	//   for (l = 1; l <= h + 1; l++) {                        /* goes level by level from
	//   bottom up to highest level */
	//     first_idx = (1 << (l - 1)) - 1;                     /* first index on the given level
	//     starting
	//                                                            from left: 0, 1, 3, 7, 15, etc
	//                                                            */
	//     for (si = first_idx; si < 2 * nc; si += (1 << l)) { /* si - sibling index */
	//       DEBUG("%d ", si);
	//     }
	//   }

	/* allocate array of "struct node" */
	tree = malloc(2 * nc * sizeof(struct node));

	/* initialize array of struct node */
	for (x = 0; x < 2 * nc; x++) {
		tree[x].number = x;
		tree[x].chunk = NULL;
		tree[x].left = tree[x].right = tree[x].parent = NULL;
		tree[x].state = INITIALIZED;
	}

	/* build the tree by linking nodes */
	for (l = 1; l <= h; l++) {
		int first_idx = (1 << (l - 1)) - 1;
		for (si = first_idx; si < 2 * nc; si += (2 << l)) {
			left = si;
			right = (si | (1 << l));
			parent = (left + right) / 2;
			/* d_printf("pair %d-%d will have parent: %d\n", left, right, parent); */
			tree[left].parent = &tree[parent];  /* parent for left node */
			tree[right].parent = &tree[parent]; /* parent for right node */

			tree[parent].left = &tree[left];   /* left child of the parent */
			tree[parent].right = &tree[right]; /* right child of the parent */
		}
	}

	*ret = tree; /* return just created tree */

	root_idx = (1 << h) - 1;
	//   DEBUG("root node: %d", root_idx);

	root_node = &tree[root_idx];
	return root_node;
}

/*
 * print tree - root node at top, leaves at bottom
 */
void
mt_show_tree_root_based(struct node *t)
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

	DEBUG("print the tree starting from root node: %d", t->number);

	ti = t->number;
	mt_interval_min_max(t, &min, &max);
	DEBUG("min: %d max: %d", min.number, max.number);
	nl = (max.number - min.number) / 2 + 1; /* number of leaves in given subtree */
	h = mt_order2(nl) + 1;

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
			DEBUG("%s", " "); /* insert (center - m/2) spaces first */
		}
		for (si = first_idx; si <= max.number; si += (1 << l)) {
			DEBUG("%2d", si);
			for (sp = 0; sp < is; sp++) {
				DEBUG("%s", " "); /* add a few spaces */
			}
		}
		first_idx -= (1 << (l - 2));
	}
#endif
}

struct node *
mt_find_sibling(struct node *n)
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

	DEBUG("node: %d   parent: %d  sibling: %d", n->number, p->number, s->number);

	return s;
}

/*
 * for given node find min and max child node numbers
 */
void
mt_interval_min_max(struct node *i, struct node *min, struct node *max)
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

	DEBUG("root: %d  interval  min: %d  max: %d", i->number, min->number, max->number);
}

/*
 * dump array of tree
 * in params:
 * 	t - pointer to array of tree
 * 	l - number of leaves
 */
void
mt_dump_tree(struct node *t, int l)
{
	char shas[40 + 1];
	int x;
	int y;
	int s;

	memset(shas, 0, sizeof(shas));
	for (x = 0; x < 2 * l; x++) {
		s = 0;
		for (y = 0; y < 20; y++) {
			s += sprintf(shas + s, "%02x", t[x].sha[y] & 0xff);
		}
		DEBUG("[%3d]  %d  %s", t[x].number, t[x].state, shas);
	}
}

/*
 * dump array of chunks
 * in params:
 * 	t - pointer to array of tree
 * 	l - number of leaves
 *
 */
void
mt_dump_chunk_tab(struct chunk *c, int l)
{
	char buf[40 + 1];
	int x;
	int y;

	DEBUG("l: %d", l);
	for (x = 0; x < l; x++) {
		int s = 0;
		for (y = 0; y < 20; y++) {
			s += sprintf(buf + s, "%02x", c[x].sha[y] & 0xff);
		}
		buf[40] = '\0';
		if (c[x].state != CH_EMPTY) {
			DEBUG("chunk[%3d]  off: %8lu  len: %8u  sha: %s  state: %s", x, c[x].offset, c[x].len, buf,
			      c[x].state == CH_EMPTY ? "EMPTY" : "ACTIVE");
		}
	}
}

void
mt_update_sha(struct node *t, int num_chunks)
{
	char sha_parent[40 + 1];
	char zero[20];
	uint8_t concat[80 + 1];
	unsigned char digest[20 + 1];
	int h;
	int nc;
	int l;
	int si;
	int left;
	int right;
	int parent;
	SHA1Context context;

	memset(zero, 0, sizeof(zero));

	h = mt_order2(num_chunks); /* "h" - height of the tree */
	nc = 1 << h;

	for (l = 1; l <= h; l++) {                                  /* go through levels of the tree starting from
		                                                       bottom of the tree */
		int first_idx = (1 << (l - 1)) - 1;                 /* first index on given level starting
		                                                       from left: 0, 1, 3, 7, 15, etc */
		for (si = first_idx; si < 2 * nc; si += (2 << l)) { /* si - sibling index */
			left = si;
			right = (si | (1 << l));
			parent = (left + right) / 2;

			/* check if both children are empty */
			if ((memcmp(zero, t[left].sha, sizeof(zero)) == 0)
			    && (memcmp(zero, t[right].sha, sizeof(zero)) == 0)) {
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
			/* DEBUG: print ASCI SHA for parent node */
			//       int y;
			//       int s = 0;
			//       for (y = 0; y < 20; y++) {
			// 	s += sprintf(sha_parent + s, "%02x", digest[y] & 0xff);
			//       }
			//       sha_parent[40] = '\0';
			//       DEBUG(" p[%d]: %s", t[parent].number, sha_parent);

			t[parent].state = ACTIVE;
		}
	}
}
