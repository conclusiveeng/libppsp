#ifndef _MT_H_
#define _MT_H_

#include <stdint.h>

struct chunk {
	uint64_t offset;				/* offset in file where chunk begins [bytes] */
	uint32_t len;					/* length of the chunk */
	char sha[20 + 1];
	struct node *node;
	enum { CH_EMPTY = 0, CH_ACTIVE } state;
};

struct node {
	int number;					/* number of the node */
	struct node *left, *right, *parent;		/* if parent == NULL - it is root node of the tree */
	struct chunk *chunk;				/* pointer to chunk */
	char sha[20 + 1];
	enum { EMPTY = 0, INITIALIZED, ACTIVE } state;
};


int order2 (uint32_t val);
struct node * build_tree (int num_chunks, struct node **ret);
struct node * extend_tree (struct node *orig_tree, int num_chunks, struct node **ret);
int update_chunk (struct node *t, unsigned int cn, struct chunk *c);
void show_tree_root_based (struct node *t);
struct node * find_uncle (struct node *t, struct node *n);
void list_interval (struct node *i);
void interval_min_max (struct node *i, struct node *min, struct node *max);
void dump_tree (struct node *t, int l);
void dump_tree_raw (struct node **t, int l);
void dump_chunk_tab (struct chunk *c, int l);
void verify_tree1 (struct node *t, int l);
void verify_tree2 (struct node *t, struct node *array);
void update_sha (struct node *t, int num_chunks);

#endif
