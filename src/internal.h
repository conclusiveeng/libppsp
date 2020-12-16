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

#ifndef PEREGRINE_INTERNAL_H
#define PEREGRINE_INTERNAL_H

#include <stdint.h>
#include <stdbool.h>
#include <sys/queue.h>
#include <peregrine/peregrine.h>
#include "eventloop.h"

#ifndef __unused
#define __unused __attribute__((unused))
#endif

struct msg;
struct pg_context;
struct pg_swarm;
struct pg_peer;
struct pg_peer_swarm;

typedef bool (*pg_bitmap_scan_func_t)(uint64_t start, uint64_t end, bool value,
    void *arg);

enum pg_bitmap_scan_mode
{
	BITMAP_SCAN_0,
	BITMAP_SCAN_1,
	BITMAP_SCAN_BOTH
};

enum pg_peer_swarm_state
{
	PEERSWARM_CREATED,
	PEERSWARM_HANDSHAKE,
	PEERSWARM_WAIT_HAVE,
	PEERSWARM_WAIT_FIRST_INTEGRITY,
	PEERSWARM_READY
};

struct pg_bitmap
{
	uint64_t size;
	uint8_t *data;
};

struct pg_buffer
{
	struct pg_peer *peer;
	void *storage;
	size_t used;
	size_t allocated;
	uint32_t channel_id;
	TAILQ_ENTRY(pg_buffer) entry;
};

struct pg_protocol_options
{
	uint8_t version;
	uint8_t minimum_version;
	uint8_t content_prot_method;
	uint8_t merkle_hash_func;
	uint8_t live_signature_alg;
	uint8_t chunk_addr_method;
	uint64_t live_disc_wind;
	uint8_t supported_msgs_len;
	void *supported_msgs; // for now we ignore this field
	uint32_t chunk_size;
};

struct pg_file
{
	struct pg_context *context;
	const char *path;
	char hash[41];    /* textual representation of sha1 for a file */
	uint8_t sha[20];
	uint64_t file_size;
	size_t chunk_size;
	uint32_t nl;             /* number of leaves */
	uint32_t nc;             /* number of chunks */
	struct chunk *tab_chunk; /* array of chunks for this file */
	struct node *tree;       /* tree of the file */
	struct node *tree_root;  /* pointer to root node of the tree */
	int fd;
	void *mmap_handle;

	SLIST_ENTRY(pg_file) entry;
};

/**
 * @brief peregrine peer structure - main communication object
 *
 */
struct pg_peer
{
	struct pg_context *context;
	struct sockaddr_storage addr;
	uint64_t fetched_chunks;
	uint64_t sent_chunks;
	LIST_HEAD(, pg_peer_swarm) swarms;
	LIST_ENTRY(pg_peer) entry;
};

struct pg_swarm
{
	struct pg_context *context;
	struct pg_file *file;
	struct pg_bitmap *have_bitmap;
	uint64_t base_delay;
	uint64_t nc;
	uint64_t fetched_chunks;
	uint64_t sent_chunks;
	uint8_t swarm_id[20];
	uint16_t swarm_id_len;

	LIST_HEAD(, pg_peer_swarm) peers;
	LIST_ENTRY(pg_swarm) entry;
};

struct pg_peer_swarm
{
	struct pg_peer *peer;
	struct pg_swarm *swarm;
	struct pg_protocol_options options;
	struct pg_bitmap *have_bitmap;
	struct pg_bitmap *request_bitmap;
	struct pg_bitmap *want_bitmap;
	struct pg_bitmap *sent_bitmap;
	struct pg_buffer *buffer;
	enum pg_peer_swarm_state state;
	bool choked;
	uint32_t dst_channel_id;
	uint32_t src_channel_id;

	LIST_ENTRY(pg_peer_swarm) peer_entry;
	LIST_ENTRY(pg_peer_swarm) swarm_entry;
};

/* file being downloaded */
struct pg_download
{
	struct pg_context *context;
	char hash[256];
	int out_fd;
	LIST_HEAD(, pg_peer) peers; // peers we download from
	/* other download state: downloaded chunks, known chunks, etc */
	LIST_ENTRY(pg_download) entry;
};

/* instance */
struct pg_context
{
	int sock_fd;
	int sock_fd_write;
	struct sockaddr_storage addr;
	struct pg_context_options options;
	struct pg_eventloop *eventloop;
	bool tx_active;
	bool can_send;

	LIST_HEAD(, pg_peer) peers;
	LIST_HEAD(, pg_swarm) swarms;
	SLIST_HEAD(, pg_file) files;
	LIST_HEAD(, pg_download) downloads;
	TAILQ_HEAD(, pg_block) io;
	TAILQ_HEAD(, pg_buffer) tx_queue;
	TAILQ_HEAD(, pg_buffer) tx_data_queue;
};

enum chunk_state
{
	CH_EMPTY = 0,
	CH_ACTIVE
};

enum chunk_downloaded
{
	CH_NO = 0,
	CH_YES
};

struct chunk
{
	uint64_t offset; /* offset in file where chunk begins [bytes] */
	uint32_t len;    /* length of the chunk */
	char sha[20 + 1];
	struct node *node;
	enum chunk_state state;
	enum chunk_downloaded downloaded;
};

enum node_state
{
	EMPTY = 0,
	INITIALIZED,
	ACTIVE,
	SENT /* seeder already sent this sha to leecher */
};

struct node
{
	int number;                         /* number of the node */
	struct node *left, *right, *parent; /* if parent == NULL - it is root node of the tree */
	struct chunk *chunk;                /* pointer to chunk */
	uint8_t sha[20];
	enum node_state state;
	LIST_ENTRY(node) entry;
};

struct pg_bitmap *pg_bitmap_create(uint64_t size);
void pg_bitmap_resize(struct pg_bitmap *bmp, uint64_t new_size);
void pg_bitmap_free(struct pg_bitmap *bmp);
void pg_bitmap_set(struct pg_bitmap *bmp, uint64_t position);
void pg_bitmap_set_range(struct pg_bitmap *bmp, uint64_t start, uint64_t end, bool value);
void pg_bitmap_clear(struct pg_bitmap *bmp, uint64_t position);
void pg_bitmap_fill(struct pg_bitmap *bmp, bool value);
bool pg_bitmap_get(struct pg_bitmap *bmp, uint64_t position);
void pg_bitmap_scan(struct pg_bitmap *bmp, enum pg_bitmap_scan_mode mode,
    pg_bitmap_scan_func_t fn, void *arg);

ssize_t pg_handle_message(struct pg_peer *peer, uint32_t chid, struct msg *msg);
int pg_send_have(struct pg_peer_swarm *ps);
int pg_send_handshake(struct pg_peer_swarm *ps);
int pg_send_integrity(struct pg_peer_swarm *ps, uint32_t block);
int pg_send_data(struct pg_peer_swarm *ps, uint64_t chunk);

struct pg_peer_swarm *pg_peerswarm_create(struct pg_peer *peer, struct pg_swarm *swarm,
    struct pg_protocol_options *options, uint32_t src_channel_id, uint32_t dst_channel_id);
void pg_peerswarm_destroy(struct pg_peer_swarm *ps);
void pg_peerswarm_request(struct pg_peer_swarm *ps);
struct pg_swarm *pg_swarm_create(struct pg_context *ctx, struct pg_file *file);
struct pg_peer_swarm *pg_find_peerswarm_by_id(struct pg_peer *peer, uint8_t *swarm_id, size_t id_len);
struct pg_peer_swarm *pg_find_peerswarm_by_channel(struct pg_peer *peer, uint32_t channel_id);

size_t pg_tree_calc_height(size_t n_chunks);
void pg_tree_init_nodes(struct node *node_array, size_t start_idx, size_t count);
void pg_tree_link_nodes(struct node *node_array, size_t height);
struct node *pg_tree_create(int n_chunks);
struct node *pg_tree_get_root(struct node *tree);
size_t pg_tree_get_height(struct node *tree);
size_t pg_tree_get_node_height(struct node *node);
struct node *pg_tree_get_first_node(struct node *tree);
struct node *pg_tree_get_chunk_node(struct node *tree, size_t idx);
struct node *pg_tree_get_node(struct node *tree, size_t idx);
size_t pg_tree_get_chunk_count(struct node *tree);
size_t pg_tree_get_leaves_count(struct node *tree);
size_t pg_tree_gen_peak_nodes(struct node *tree, struct node ***retp);
size_t pg_tree_gen_uncle_nodes(struct node *node, struct node ***retp);
size_t pg_tree_gen_uncle_peak_nodes(struct node *node, struct node ***retp);
bool pg_tree_is_within_node(struct node *node, struct node **set, size_t set_size);
struct node *pg_tree_grow(struct node *old_tree, size_t n_chunks);
void pg_tree_node_interval(struct node *node, struct node **min, struct node **max);
struct node *pg_tree_interval_to_node(struct node * tree, size_t min, size_t max);
struct node *pg_tree_find_sibling_node(struct node *node);
void pg_tree_show(struct node *tree);
void pg_tree_update_sha(struct node *tree);
bool pg_verify_node(struct node *node);
bool pg_verify_tree(struct node *tree);

int pg_sockaddr_cmp(const struct sockaddr *s1, const struct sockaddr *s2);
void pg_sockaddr_copy(struct sockaddr_storage *dest, const struct sockaddr *src);
const char *pg_sockaddr_to_str(struct sockaddr *sa);
struct pg_file *pg_context_file_by_sha(struct pg_context *ctx, const char *sha);
struct pg_file *pg_file_by_sha(struct pg_context *ctx, const uint8_t *sha);
const char *pg_hexdump(const uint8_t *buf, size_t len);
uint32_t pg_new_channel_id(void);

void pg_socket_enqueue_tx(struct pg_context *ctx, struct pg_buffer *block);
void pg_socket_suspend_tx(struct pg_context *ctx);

struct pg_buffer *pg_buffer_create(struct pg_peer *peer, uint32_t channel_id);
void pg_buffer_free(struct pg_buffer *buffer);
void *pg_buffer_advance(struct pg_buffer *buffer, size_t len);
void *pg_buffer_ptr(struct pg_buffer *buffer);
size_t pg_buffer_size_left(struct pg_buffer *buffer);
size_t pg_buffer_enqueue(struct pg_buffer *buffer);
size_t pg_buffer_enqueue_data(struct pg_buffer *buffer);
void pg_buffer_reset(struct pg_buffer *buffer);

int pg_file_read_chunks(struct pg_file *file, uint64_t chunk, uint64_t count, void *buf);
int pg_file_write_chunks(struct pg_file *file, uint64_t chunk, uint64_t count, void *buf);

void pg_emit_event(struct pg_event *event);

void *xmalloc(size_t length);
void *xcalloc(size_t nelems, size_t length);
void *xrealloc(void *ptr, size_t length);

#endif /* PEREGRINE_INTERNAL_H */