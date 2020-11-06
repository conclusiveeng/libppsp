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

enum chunk_state { CH_EMPTY = 0, CH_ACTIVE };

enum chunk_downloaded { CH_NO = 0, CH_YES };

struct chunk {
  uint64_t offset; /* offset in file where chunk begins [bytes] */
  uint32_t len;    /* length of the chunk */
  char sha[20 + 1];
  struct node *node;
  enum chunk_state state;
  enum chunk_downloaded downloaded;
};

enum node_state {
  EMPTY = 0,
  INITIALIZED,
  ACTIVE,
  SENT /* seeder already sent this sha to leecher */
};
struct node {
  int number;                         /* number of the node */
  struct node *left, *right, *parent; /* if parent == NULL - it is root node of the tree */
  struct chunk *chunk;                /* pointer to chunk */
  char sha[20 + 1];
  enum node_state state;
};

int order2(uint32_t /*val*/);
struct node *build_tree(int /*num_chunks*/, struct node ** /*ret*/);
void show_tree_root_based(struct node * /*t*/);
struct node *find_sibling(struct node * /*n*/);
void interval_min_max(struct node * /*i*/, struct node * /*min*/, struct node * /*max*/);
void dump_tree(struct node * /*t*/, int /*l*/);
void dump_chunk_tab(struct chunk * /*c*/, int /*l*/);
void update_sha(struct node * /*t*/, int /*num_chunks*/);

#endif /* _MT_H_ */
