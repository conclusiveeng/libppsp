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


int order2 (uint32_t);
struct node * build_tree (int, struct node **);
struct node * extend_tree (struct node *, int, struct node **);
int update_chunk (struct node *, unsigned int, struct chunk *);
void show_tree_root_based (struct node *);
struct node * find_uncle (struct node *, struct node *);
void list_interval (struct node *);
void interval_min_max (struct node *, struct node *, struct node *);
void dump_tree (struct node *, int);
void dump_tree_raw (struct node **, int);
void dump_chunk_tab (struct chunk *, int);
void verify_tree1 (struct node *, int);
void verify_tree2 (struct node *, struct node *);
void update_sha (struct node *, int);

#endif
