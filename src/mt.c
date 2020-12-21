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

#include <math.h>
#include <stdlib.h>
#include <string.h>
#include "sha1.h"
#include "internal.h"
#include "log.h"

#undef DEBUG
#define DEBUG(fmt, ...)

size_t
pg_tree_calc_height(size_t n_chunks)
{

	return (ceil(log2(n_chunks)) + 1);
}

void
pg_tree_init_nodes(struct node *array, size_t start_idx, size_t count)
{
	size_t i;

	for (i = start_idx; i < start_idx + count; i++) {
		array[i].number = i;
		array[i].chunk = NULL;
		array[i].left = array[i].right = array[i].parent = NULL;
		array[i].state = INITIALIZED;
	}
}

void
pg_tree_link_nodes(struct node *node_array, size_t height)
{
	uint32_t level;
	uint32_t si;
	uint32_t left;
	uint32_t right;
	uint32_t parent;
	size_t node_count = (1u << height) - 1;

	for (level = 0; level < height - 1; level++) {
		/* DEBUG("building level %d", l); */
		uint32_t first_idx = (1u << level) - 1;
		for (si = first_idx; si < node_count; si += (2u << (level + 1))) {
			left = si;
			right = (si | (1u << (level + 1)));
			parent = (left + right) / 2;
			/* DEBUG("pair %d-%d will have parent: %d", left, right, parent); */
			node_array[left].parent = &node_array[parent];  /* parent for left node */
			node_array[right].parent = &node_array[parent]; /* parent for right node */

			node_array[parent].left = &node_array[left];   /* left child of the parent */
			node_array[parent].right = &node_array[right]; /* right child of the parent */
		}
	}
}

struct node *
pg_tree_create(int n_chunks)
{
	size_t height;
	size_t node_count;

	struct node *tree;

	height = pg_tree_calc_height(n_chunks);
	node_count = (1u << height) - 1;

	tree = malloc(node_count * sizeof(struct node));
	pg_tree_init_nodes(tree, 0, node_count);
	pg_tree_link_nodes(tree, height);

	return (tree);
}

struct node *
pg_tree_get_root(struct node *tree)
{
	struct node *node = tree;

	while (node->parent != NULL)
		node = node->parent;

	return (node);
}

size_t
pg_tree_get_height(struct node *tree)
{
	struct node *node = pg_tree_get_root(tree);
	return (pg_tree_get_node_height(node));
}

size_t
pg_tree_get_node_height(struct node *node)
{
	size_t height = 1;

	while (node->left != NULL) {
		node = node->left;
		height++;
	}

	return (height);
}

size_t
pg_tree_get_chunk_count(struct node *tree)
{
	struct node *root = pg_tree_get_root(tree);
	struct node *first_node = pg_tree_get_first_node(root);
	size_t leaves_count = pg_tree_get_leaves_count(root);
	size_t idx = leaves_count - 1;
	struct node *node = &first_node[2 * idx];
	uint8_t zero[20];

	while (idx > 0) {
		if (node->chunk && node->chunk->state == CH_EMPTY) {
			idx--;
			node = &first_node[2 * idx];
			continue;
		}

		if (memcmp(node->sha, zero, 20) == 0) {
			idx--;
			node = &first_node[2 * idx];
			continue;
		} else
			break;
	}

	return (idx + 1);
}

size_t
pg_tree_gen_peak_nodes(struct node *tree, struct node ***retp)
{
	size_t chunk_count = pg_tree_get_chunk_count(tree);
	size_t peak_size = __builtin_popcount(chunk_count);
	size_t idx;
	size_t result_idx = 0;
	struct node *node = pg_tree_get_chunk_node(tree, chunk_count - 1);
	struct node **result;

	result = calloc(peak_size, sizeof(struct node **));

	for (idx = 1; idx <= chunk_count; idx = idx << 1u) {
		if (!(chunk_count & idx)) {
			node = node->parent;
			continue;
		}

		if (node->parent) {
			node = node->parent;
			result[result_idx] = node->left;
		} else
			peak_size--;

		result_idx++;
	}

	*retp = result;
	return (peak_size);
}

size_t
pg_tree_gen_uncle_nodes(struct node *node, struct node ***retp)
{
	struct node *root = pg_tree_get_root(node);
	struct node **uncle_nodes;
	struct node *cur_node = node;
	size_t node_height = pg_tree_get_node_height(node);
	size_t root_height = pg_tree_get_node_height(root);
	size_t uncle_nodes_size = root_height - node_height;
	size_t chunk_count = pg_tree_get_chunk_count(root);
	struct node *last_chunk = pg_tree_get_chunk_node(root, chunk_count - 1);
	size_t i;

	uncle_nodes = calloc(uncle_nodes_size, sizeof(struct node **));

	for (i = 0; i < uncle_nodes_size; i++) {
		cur_node = pg_tree_find_sibling_node(cur_node);
		if (cur_node->number > last_chunk->number) {
			*retp = uncle_nodes;
			return (i);
		}
		uncle_nodes[i] = cur_node;
		cur_node = cur_node->parent;
	}

	*retp = uncle_nodes;
	return (uncle_nodes_size);
}

size_t
pg_tree_gen_uncle_peak_nodes(struct node *node, struct node ***retp)
{
	struct node **peak_nodes;
	struct node **uncle_nodes;
	struct node **result;
	size_t peak_size = pg_tree_gen_peak_nodes(node, &peak_nodes);
	size_t uncle_size = pg_tree_gen_uncle_nodes(node, &uncle_nodes);
	size_t result_size;
	size_t uncle_idx;
	size_t result_idx;

	for (uncle_idx = 0; uncle_idx < uncle_size; uncle_idx++) {
		if (pg_tree_is_within_node(uncle_nodes[uncle_idx], peak_nodes, peak_size))
			break;
	}

	result_size = peak_size + uncle_idx;
	result = calloc(result_size, sizeof(struct node **));

	for (result_idx = 0; result_idx < result_size; result_idx++) {
		if (result_idx < uncle_idx)
			result[result_idx] = uncle_nodes[result_idx];
		else
			result[result_idx] = peak_nodes[result_idx - uncle_idx];
	}

	*retp = result;
	free(peak_nodes);
	free(uncle_nodes);
	return (result_size);
}

bool
pg_tree_is_within_node(struct node *node, struct node **set, size_t set_size)
{
	size_t i;
	struct node *min_node;
	struct node *max_node;
	int start;
	int end;

	pg_tree_node_interval(node, &min_node, &max_node);
	start = min_node->number;
	end = max_node->number;

	for (i = 0; i < set_size; i++) {
		pg_tree_node_interval(set[i], &min_node, &max_node);
		if (min_node->number >= start && max_node->number <= end)
			return (true);
	}

	return (false);
}

size_t
pg_tree_get_leaves_count(struct node *tree)
{
	size_t height = pg_tree_get_height(tree);

	return (1u << (height - 1));
}

struct node *
pg_tree_get_first_node(struct node *tree)
{

	return (&tree[-tree->number]);
}

struct node *
pg_tree_get_chunk_node(struct node *tree, size_t idx)
{
	struct node *node = pg_tree_get_first_node(tree);

	return (&node[2 * idx]);
}

struct node *
pg_tree_get_node(struct node *tree, size_t idx)
{
	struct node *node = pg_tree_get_first_node(tree);

	return (&node[idx]);
}

struct node *
pg_tree_grow(struct node *old_tree, size_t n_chunks)
{

	uint32_t old_height;
	uint32_t height;
	uint32_t old_node_count;
	uint32_t node_count;
	struct node *tree;
	size_t cur_chunk_count = pg_tree_get_leaves_count(old_tree);

	if (cur_chunk_count >= n_chunks)
		return (pg_tree_get_first_node(old_tree));

	old_height = pg_tree_calc_height(cur_chunk_count);
	old_node_count = (1 << old_height) - 1;
	height = pg_tree_calc_height(n_chunks);
	node_count = (1 << height) - 1;

	tree = realloc(old_tree, node_count * sizeof(struct node));
	pg_tree_init_nodes(tree, old_node_count,node_count - old_node_count);
	pg_tree_link_nodes(tree, height);

	return (tree);
}

/*
 * print tree - root node at top, leaves at bottom
 */
void
pg_tree_show(struct node *tree)
{
	int level;
	int si;
	size_t n_leaves;
	size_t height;
	int first_idx;
	size_t center;
	unsigned int sp;
	struct node *min;
	struct node *max;
	struct node *root;

	root = pg_tree_get_root(tree);
	DEBUG("print the tree starting from root node: %d", root->number);

	pg_tree_node_interval(root, &min, &max);
	DEBUG("min: %d max: %d", min->number, max->number);
	n_leaves = (max->number - min->number) / 2 + 1; /* number of leaves in given subtree */
	height = pg_tree_calc_height(n_leaves) + 1;

	first_idx = root->number;

	/* justification */
	center = (n_leaves * (2 + 2)) / 2;
	for (level = height; level >= 1; level--) {
		unsigned int is = 1 << level;            /* how many spaces has to be inserted between values on
		                               given level */
		int iw = 1 << (height - level);      /* number of nodes to print on given level */
		int m = iw * (2 + is) - is; /*  */
		/* d_printf("center: %d  iw: %d  m: %d  is: %d\n", center, iw, m, is); */
		for (sp = 0; sp < (center - m / 2); sp++) {
			DEBUG("%s", " "); /* insert (center - m/2) spaces first */
		}
		for (si = first_idx; si <= max->number; si += (1 << level)) {
			DEBUG("%2d", si);
			for (sp = 0; sp < is; sp++) {
				DEBUG("%s", " "); /* add a few spaces */
			}
		}
		first_idx -= (1 << (level - 2));
	}
}

struct node *
pg_tree_find_sibling_node(struct node *node)
{
	struct node *parent;
	struct node *sibling;

	parent = node->parent;
	if (parent == NULL)
		return NULL;

	sibling = node == parent->left ? parent->right : parent->left;

	DEBUG("node: %d, parent: %d, sibling: %d", node->number, parent->number,
	    sibling->number);

	return (sibling);
}

/*
 * for given node find min and max child node numbers
 */
void
pg_tree_node_interval(struct node *node, struct node **min, struct node **max)
{
	struct node *current;

	if (node == NULL)
		abort();

	current = node;
	while (current->left != NULL)
		current = current->left;

	*min = current;

	current = node;
	while (current->right != NULL)
		current = current->right;

	*max = current;

	DEBUG("root: %d, interval min: %d, max: %d", node->number,
	    (*min)->number, (*max)->number);
}

struct node *
pg_tree_interval_to_node(struct node *tree, size_t min, size_t max)
{
	struct node *min_node = pg_tree_get_chunk_node(tree, min);
	struct node *max_node = pg_tree_get_chunk_node(tree, max);

	while (min_node != max_node) {
		min_node = min_node->parent;
		max_node = max_node->parent;
	}

	return (min_node);
}

void
pg_tree_update_sha(struct node *tree)
{
	char zero[20];
	uint8_t concat[80 + 1];
	unsigned char digest[20 + 1];
	struct node *node;
	size_t height;
	size_t node_count;
	size_t level;
	size_t si;
	size_t left;
	size_t right;
	size_t parent;
	SHA1Context context;

	memset(zero, 0, sizeof(zero));

	node = pg_tree_get_first_node(tree);
	height = pg_tree_get_height(node);
	node_count = (1u << height) - 1;

	for (level = 0; level < height - 1; level++) {
		uint32_t first_idx = (1u << level) - 1;
		for (si = first_idx; si < node_count; si += (2u << (level + 1))) {
			left = si;
			right = (si | (1u << (level + 1)));
			parent = (left + right) / 2;

			/* check if both children are empty */
			if ((memcmp(zero, node[left].sha, sizeof(zero)) == 0)
			    && (memcmp(zero, node[right].sha, sizeof(zero)) == 0)) {
				memcpy(node[parent].sha, zero, 20);
			} else {
				memcpy(concat, node[left].sha, 20);
				memcpy(concat + 20, node[right].sha, 20);

				/* calculate SHA1 for concatenated both SHA (left and right) */
				SHA1Reset(&context);
				SHA1Input(&context, concat, 40);
				SHA1Result(&context, digest);

				/* copy generated SHA hash to parent node */
				memcpy(node[parent].sha, digest, 20);
			}

			node[parent].state = ACTIVE;
		}
	}
}
