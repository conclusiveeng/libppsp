#ifndef _MT_H_
#define _MT_H_

//#include "types.h"

struct chunk {
	unsigned long int offset;				// offset w pliku w bajtach do poczaktu tego chunka
	unsigned long int len;					// dlugosc tego chunka
	char sha[20];
	struct node *node;
	enum { CH_EMPTY = 0, CH_ACTIVE } state;
};
 

struct node {
	int number;					// numer wezla
	struct node *left, *right, *parent;		// jesli parent == NULL - to jest to korzen drzwea
	struct chunk *chunk;				// tylko wezly typu liscie maja swoje chunki - figure 2. rfc7574: c0, c1, c2, c3, c4, ...
	char sha[20];
	enum { EMPTY = 0, INITIALIZED, ACTIVE } state;
#if DEBUG
	int l, si;					// tylko dla debuggingu  weryfikacja poziomu (l: 1...l) na ktorym jest wezel i jego index (si: 0..si-1) na danym poziomie
#endif	
};




int order2 (unsigned int val);
void traverse_ex1 (struct node *t);
void traverse_ex2 (struct node *t);
void traverse_ex3 (struct node *t);
struct node * build_tree (struct chunk *a[], int num_chunks, struct node **ret);
struct node * extend_tree (struct chunk *a[], struct node *orig_tree, int num_chunks, struct node **ret);
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
