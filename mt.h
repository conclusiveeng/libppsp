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


#ifndef _MT_H_
#define _MT_H_

#include <stdint.h>

struct chunk {
	uint64_t offset;				/* offset in file where chunk begins [bytes] */
	uint32_t len;					/* length of the chunk */
	char sha[20 + 1];
	struct node *node;
	enum {
		CH_EMPTY = 0,
		CH_ACTIVE
	} state;
	enum {
		CH_NO = 0,
		CH_YES
	} downloaded;
};

struct node {
	int number;					/* number of the node */
	struct node *left, *right, *parent;		/* if parent == NULL - it is root node of the tree */
	struct chunk *chunk;				/* pointer to chunk */
	char sha[20 + 1];
	enum {
		EMPTY = 0,
		INITIALIZED,
		ACTIVE
	} state;
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

#endif /* _MT_H_ */
