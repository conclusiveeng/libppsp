#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <libgen.h>

#include "mt.h"
#include "sha1.h"
#include "ppspp_protocol.h"
#include "net.h"
#include "peer.h"

extern char *optarg;
extern int optind, opterr, optopt;
struct node *tree, *root8, *root16, *root32;
struct chunk *tab_chunk;
struct peer remote_peer;


/*
 * returns rounded order of 32-bit variable
 * simplified log2() function
 */
int order2 (uint32_t val)
{
	int o, bits;
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

	if (bits > 1) o++;		// jesli poza calkiem lewym bitem sa na prawo od niego inne bity - zwieksz rzad wielkosci zwracanej w return

	return o;
}


/*
 * builds tree with "num_chunks" number of chunks
 * returns:
 * 	pointer to root node of the new created tree
 * 	as "**ret" parameter - pointer to new created tree - 0 index of the leaf
 *
 */
struct node * build_tree (int num_chunks, struct node **ret)
{
	int x, l, si, h, first_idx, nc;
	int left, right, parent, root_idx;
	struct node *rot, *tt;

	printf("num_chunks: %u\n", num_chunks);

	h = order2(num_chunks);							/* "h" - height of the tree */
	nc = 1 << h;								/* if there are for example only 7 chunks - create tree with 8 leaves */
	printf("order2(%u): %u\n", num_chunks, h);
	printf("num_chunks(orig): %u  after_correction: %u\n", num_chunks, nc);

	/* list the tree */
#if 1
	for (l = 1; l <= h + 1; l++) {		/* goes level by level from bottom up to highest level */
		first_idx = (1 << (l - 1)) -1;  /* first index on the given level starting from left: 0, 1, 3, 7, 15, etc */
		for (si = first_idx; si < 2 * nc; si += (1 << l)) {   /* si - sibling index */
			printf("%u ", si);
		}
		printf("\n");
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

	printf("\nbuilding tree - linking nodes\n\n");
	/* build the tree by linking nodes */
	for (l = 1; l <= h; l++) {
		first_idx = (1 << (l - 1)) -1;
		for (si = first_idx; si < 2 * nc; si += (2 << l)) {
			left = si;
			right = (si | (1 << l));
			parent = (left + right) / 2;
			/* printf("pair %u-%u will have parent: %u\n", left, right, parent); */
			tt[left].parent = &tt[parent];			/* parent for left node */
			tt[right].parent = &tt[parent];			/* parent for right node */

			tt[parent].left = &tt[left];			/* left child of the parent */
			tt[parent].right = &tt[right];			/* right child of the parent */
		}
		/* printf("\n"); */
	}

	*ret = tt;							/* return just created tree */

	root_idx = (1 << h) - 1;
	printf("root node: %u\n", root_idx);

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
struct node * extend_tree (struct node *orig_tree, int orig_num_chunks, struct node **ret)
{
	int x, l, si, h, first_idx, nc;
	int left, right, parent, root_idx;
	int root_idx_012, root_idx_456;
	struct node *rot, *tt;
	struct node min, max;

	printf("extending tree - num_chunks: %u => %u\n", orig_num_chunks, orig_num_chunks * 2);

	h = order2(orig_num_chunks);
	nc = 1 << h;
	printf("order2(%u): %u\n", orig_num_chunks, h);
	printf("num_chunks(orig): %u  after_correction: %u\n", orig_num_chunks, nc);


// ok to dobrze listuje drzewko (tylko listuje)
#if 0
	for (l = 1; l <= h + 1; l++) {		// idz po poziomach drzewa od dolu- "l" level
		first_idx = (1 << (l - 1)) -1;  // pierwszy index na danym poziomie od lewej: 0, 1, 3, 7, 15, etc
		for (si = first_idx; si < 2 * nc; si += (1 << l)) {   //si - sibling index
			printf("%u ", si);
		}
		printf("\n");
	}
#endif

	/* allocate array of nodes for the new tree (2 times more of the leaves than original tree */
	tt = malloc(2 * 2 * nc * sizeof(struct node));
	*ret = tt;			/* return pointer to index [0] of the new tree */

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
	for (x = 0; x < nc; x++)
		memcpy(tt[x].sha, orig_tree[x].sha, 20);

	/* compute height and number of leaves for the new created tree */
	h++;
	nc = 2 * nc;

	/* find extreme left and right nodes for old tree */
	interval_min_max(&orig_tree[(1 << (h - 1)) - 1], &min, &max);		/* for example: 0-14 */

	/* linking nodes */
	for (l = 1; l <= h; l++) {
		first_idx = (1 << (l - 1)) -1;
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

	tt[root_idx_012].parent = &tt[root_idx];			/* parent for left node */
	tt[root_idx_456].parent = &tt[root_idx];			/* parent for right node */

	tt[root_idx].left = &tt[root_idx_012];				/* left child of the parent */
	tt[root_idx].right = &tt[root_idx_456];				/* right child of the parent */

	tt[root_idx].number = root_idx;

	free(orig_tree);

	printf("extend root node: %u  %u\n", root_idx, tt[root_idx].number);

	rot = &tt[root_idx];
	return rot;
}


int update_chunk (struct node *t, unsigned int cn, struct chunk *c)
{
	return 0;
}


/*
 * print tree - root node at top, leaves at bottom
 */
void show_tree_root_based (struct node *t)
{
	int l, si, nl, h, ti, first_idx;
	int center, iw, m, sp, is;
	struct node min, max;

	printf("print the tree starting from root node: %u\n", t->number);

	ti = t->number;
	interval_min_max(t, &min, &max);
	printf("min: %u   max: %u\n", min.number, max.number);
	nl = (max.number - min.number) / 2 + 1;		/* number of leaves in given subtree */
	h = order2(nl) + 1;

	first_idx = ti;

	printf("\n\n");

	/* justification */
#if 1
	first_idx = ti;

	center = (nl * (2 + 2)) / 2;
	for (l = h; l >= 1; l--) {
		is = 1 << l;			/* how many spaces has to be inserted between values on given level */
		iw = 1 << (h - l);		/* number of nodes to print on given level */
		m = iw * (2 + is) - is;		/*  */
		//printf("center: %u  iw: %u  m: %u  is: %u\n", center, iw, m, is);
		for (sp = 0; sp < (center - m/2); sp++) printf(" ");			/* insert (center - m/2) spaces first */
		for (si = first_idx; si <= max.number; si += (1 << l)) {
			printf("%2u", si);
			for (sp = 0; sp < is; sp++) printf(" ");			/* add a few spaces */
		}
		first_idx -= (1 << (l - 2));
		printf("\n");
	}
#endif
}


/*
 * find uncle for node "n" in tree with root "t"
 */
struct node * find_uncle (struct node *t, struct node *n)
{
	struct node *p, *gp, *u;

	p = n->parent;
	if (p == NULL)
		return NULL;
	gp = p->parent;
	if (gp == NULL)
		return NULL;

	if (p == gp->right)		/* if parent is right child of grandparent - then uncle is left child of the grandparent */
		u = gp->left;
	if (p == gp->left)		/* if parent is left child of grandparent - then uncle is right child of the grandparent */
		u = gp->right;

	printf("node: %u   parent: %u  grandparent: %u  uncle: %u\n", n->number, p->number, gp->number, u->number);

	return u;
}


// metoda iteracyjna (a nie rekurencyjna)
// znajduje minimalny i maxymalny index - schodzac calkiem w lewo w dol od korzenia i calekiem w prawo
// ta proc chyba nie jest juz potrzebna
void list_interval (struct node *i)
{
	struct node *c, *min, *max;

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

	printf("root: %u  interval  min: %u  max: %u\n", i->number, min->number, max->number);
}


/*
 * for given node find min and max child node numbers
 */
void interval_min_max (struct node *i, struct node *min, struct node *max)
{
	struct node *c;

	c = i;
	while (c->left != NULL)
		c = c->left;

	memcpy(min, c, sizeof(struct node));

	c = i;
	while (c->right != NULL)
		c = c->right;

	memcpy(max, c, sizeof(struct node));

	printf("root: %u  interval  min: %u  max: %u\n", i->number, min->number, max->number);
}


/*
 * dump array of tree
 * in params:
 * 	t - pointer to array of tree
 * 	l - number of leaves
 */
void dump_tree (struct node *t, int l)
{
	char shas[40 + 1];
	int x, y, s;

	memset(shas, 0, sizeof(shas));
	printf("dump tree\n");
	for (x = 0; x < 2 * l; x++) {
		s = 0;
		for (y = 0; y < 20; y++)
			s += sprintf(shas + s, "%02x", t[x].sha[y] & 0xff);
		printf("[%3u]  %u  %s\n", t[x].number, t[x].state, shas);
	}
	printf("\n");
}


/*
 * dump array of chunks
 * in params:
 * 	t - pointer to array of tree
 * 	l - number of leaves
 *
 */
void dump_chunk_tab (struct chunk *c, int l)
{
	char buf[40 + 1];
	int x, y, s;

	printf("%s l: %u\n", __func__, l);
	for (x = 0; x < l; x++) {
		s = 0;
		for (y = 0; y < 20; y++) {
			s += sprintf(buf + s, "%02x", c[x].sha[y] & 0xff);
		}
		buf[40] = '\0';
		printf("chunk[%3u]  off: %8lu  len: %8u  sha: %s  state: %s\n", x, c[x].offset, c[x].len, buf, c[x].state == CH_EMPTY ? "EMPTY" : "ACTIVE" );
	}
}


void update_sha (struct node *t, int num_chunks)
{
	char sha_left[40 + 1], sha_right[40 + 1], sha_parent[40 + 1];
	uint8_t concat[80 + 1];
	unsigned char digest[20 + 1];
	int h, nc, l, si, first_idx, y, s, left, right, parent;
	SHA1Context context;

	printf("%s\n", __func__);

	h = order2(num_chunks);							/* "h" - height of the tree */
	nc = 1 << h;

	for (l = 1; l <= h; l++) {		/* go through levels of the tree starting from bottom of the tree */
		first_idx = (1 << (l - 1)) -1;  /* first index on given level starting from left: 0, 1, 3, 7, 15, etc */
		for (si = first_idx; si < 2 * nc; si += (2 << l)) {   /* si - sibling index */
			left = si;
			right = (si | (1 << l));
			parent = (left + right) / 2;

			/* generate ASCII SHA for left node */
			s = 0;
			for (y = 0; y < 20; y++)
				s += sprintf(sha_left + s, "%02x", t[left].sha[y] & 0xff);
			sha_left[40] = '\0';
			//printf(" l: %s\n", sha_left);

			/* generate ASCII SHA for right node */
			s = 0;
			for (y = 0; y < 20; y++)
				s += sprintf(sha_right + s, "%02x", t[right].sha[y] & 0xff);
			//printf(" r: %s\n", sha_right);
			sha_right[40] = '\0';

			snprintf((char *)concat, sizeof(concat), "%s%s", sha_left, sha_right);
			//printf(" +: %s\n", concat);

			/* calculate SHA1 for concatenated string of both SHA (left and right) */
			SHA1Reset(&context);
			SHA1Input(&context, concat, 80);
			SHA1Result(&context, digest);

			/* copy generated SHA hash to parent node */
			memcpy(t[parent].sha, digest, 20);

			/* generate ASCII SHA for parent node */
			s = 0;
			for (y = 0; y < 20; y++)
				s += sprintf(sha_parent + s, "%02x", digest[y] & 0xff);
			//printf(" p: %s\n", sha_parent);
			sha_parent[40] = '\0';

			t[parent].state = ACTIVE;
		}
		printf("\n");
	}
}


int main (int argc, char *argv[])
{
	char *fname1, *fname, *fname2, *buf;
	unsigned char digest[20 + 1];
	int fd, r, opt, chunk_size;
	uint64_t x, nc, nl, c ,rd;
	struct stat stat;
	SHA1Context context;
	struct node *ret, *ret2;

	chunk_size = 1024;
	fname = NULL;
	while ((opt = getopt(argc, argv, "f:s:")) != -1) {
		switch (opt) {
			case 'f':				/* filename */
				fname1 = optarg;
				break;
			case 's':				/* chunk size [bytes] */
				chunk_size = atoi(optarg);
				break;
			default:
				break;
		}
	}

	if (fname1 != NULL) {
		fname2 = strdup(fname1);
		fname = basename(fname2);		/* skip any "./" */
	}

	root8 = build_tree(8, &ret);			/* 8 - number of leaves */
	ret2 = ret;

	root16 = extend_tree(ret2, 8, &ret);		/* extend array: 8 => 16 */
	ret2 = ret;

	root32 = extend_tree(ret2, 16, &ret);		/* extend array: 16 => 32 */
	ret2 = ret;

	root32 = extend_tree(ret2, 32, &ret);		/* 32 => 64 */
	ret2 = ret;

#if 0
	u = find_uncle(root, tab_tree[9]);		/* uncle: 3 */
	if (u == NULL)
		printf("no uncle\n");
#endif

	list_interval(&ret[7]);				/* starting from 7 - should be: 0-30 */

	show_tree_root_based(&ret[7]);
	show_tree_root_based(&ret[15]);

#if 0
	x = 0;
	size = 64;
	while ((x < 30) && (size < 33554432)) {
		ret2 = ret;
		printf("\n\n\nsize: %u\n", size);
		root32 = extend_tree(ret2, size, &ret);		/* 32 => 64,  64 => 128, etc*/
		printf("root32: %u\n", root32->number);
		//show_tree_root_based(root32);
		size *= 2;
		getc(stdin);
		x++;
	}
#endif

	/* example of computing SHA1 for given file */
	if (fname != NULL) {
		fd = open(fname, O_RDONLY);
		if (fd < 0) {
			printf("error opening file1: %s\n", fname);
			exit(1);
		}
		fstat(fd, &stat);

		buf = malloc(chunk_size);

		nc = stat.st_size / chunk_size;
		if ((stat.st_size - stat.st_size / chunk_size * chunk_size) > 0)
			nc++;
		printf("ilosc chunkow [%u]: %lu\n", chunk_size, nc);

		/* compute number of leaves - it is not the same as numbe of chunks */
		nl = 1 << (order2(nc));

		/* allocate array of chunks which will be linked to leaves later*/
		tab_chunk = malloc(nl * sizeof(struct chunk));
		memset(tab_chunk, 0, nl * sizeof(struct chunk));

		/* initialize array of chunks */
		for (x = 0; x < nl; x++)
			tab_chunk[x].state = CH_EMPTY;

		root8 = build_tree(nc, &ret);

		/* compute SHA hash for every chunk form given file */
		rd = 0;
		c = 0;
		while (rd < (uint64_t) stat.st_size) {
			r = read(fd, buf, chunk_size);

			SHA1Reset(&context);
			SHA1Input(&context, (uint8_t *)buf, r);
			SHA1Result(&context, digest);

			tab_chunk[c].state = CH_ACTIVE;
			tab_chunk[c].offset = c * chunk_size;
			tab_chunk[c].len = r;
			memcpy(tab_chunk[c].sha, digest, 20);
			memcpy(ret[2 * c].sha, digest, 20);
			ret[2 * c].state = ACTIVE;
			rd += r;
			c++;
		}
		close(fd);

		/* link array of chunks to leaves */
		for (x = 0; x < nl; x++) {
			ret[x * 2].chunk = &tab_chunk[x];
			tab_chunk[x].node = &ret[x * 2];
		}

		/* print the tree for given file */
		show_tree_root_based(&ret[root8->number]);

		dump_chunk_tab(tab_chunk, nl);

		update_sha(ret, nl);
		dump_tree(ret, nl);

		remote_peer.tree = ret;
		remote_peer.nl = nl;
		remote_peer.nc = nc;
		remote_peer.type = SEEDER;
		remote_peer.start_chunk = 0;
		remote_peer.end_chunk = nc - 1;
		remote_peer.chunk_size = chunk_size;
		memcpy(remote_peer.fname, fname, strlen(fname));
		remote_peer.fname_len = strlen(fname);
		remote_peer.file_size = stat.st_size;

		proto_test(&remote_peer);
	} else { /* leecher */
		remote_peer.tree = NULL;
		remote_peer.nl = 0;
		remote_peer.nc = 0;
		remote_peer.type = LEECHER;
		memset(remote_peer.fname, 0, sizeof(remote_peer.fname));
		remote_peer.fname_len = 0;
		remote_peer.file_size = 0;

		proto_test(&remote_peer);
	}

	free(fname2);
	free(buf);
	free(tab_chunk);

	return 0;
}
