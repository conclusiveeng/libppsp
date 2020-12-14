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
#include "peregrine/socket.h"

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

/* shared file */
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
	LIST_HEAD(, pg_peer_swarm) swarms;
	LIST_ENTRY(pg_peer) entry;
};

struct pg_swarm
{
	struct pg_context *context;
	struct pg_file *file;
	struct pg_bitmap *have_bitmap;
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
	struct pg_bitmap *integrity_bitmap;
	struct pg_buffer *buffer;
	enum pg_peer_swarm_state state;
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
	struct sockaddr_storage addr;
	struct pg_context_options options;

	LIST_HEAD(, pg_peer) peers;
	LIST_HEAD(, pg_swarm) swarms;
	SLIST_HEAD(, pg_file) files;
	LIST_HEAD(, pg_download) downloads;
	TAILQ_HEAD(, pg_block) io;
	TAILQ_HEAD(, pg_buffer) tx_queue;
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
	char sha[20 + 1];
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

struct pg_peer_swarm *pg_peerswarm_create(struct pg_peer *peer, struct pg_swarm *swarm,
    struct pg_protocol_options *options, uint32_t src_channel_id, uint32_t dst_channel_id);
void pg_peerswarm_destroy(struct pg_peer_swarm *ps);
void pg_peerswarm_request(struct pg_peer_swarm *ps);
struct pg_swarm *pg_swarm_create(struct pg_context *ctx, struct pg_file *file);
struct pg_peer_swarm *pg_find_peerswarm_by_id(struct pg_peer *peer, uint8_t *swarm_id, size_t id_len);
struct pg_peer_swarm *pg_find_peerswarm_by_channel(struct pg_peer *peer, uint32_t channel_id);

int mt_order2(uint32_t /*val*/);
struct node *mt_build_tree(int /*num_chunks*/, struct node ** /*ret*/);
void mt_show_tree_root_based(struct node * /*t*/);
struct node *mt_find_sibling(struct node * /*n*/);
void mt_interval_min_max(struct node * /*i*/, struct node * /*min*/, struct node * /*max*/);
void mt_dump_tree(struct node * /*t*/, int /*l*/);
void mt_dump_chunk_tab(struct chunk * /*c*/, int /*l*/);
void mt_update_sha(struct node * /*t*/, int /*num_chunks*/);
int mt_verify_node(struct node *);

int pg_sockaddr_cmp(const struct sockaddr *s1, const struct sockaddr *s2);
void pg_sockaddr_copy(struct sockaddr_storage *dest, const struct sockaddr *src);
const char *pg_sockaddr_to_str(struct sockaddr *sa);
struct pg_file *pg_context_file_by_sha(struct pg_context *ctx, const char *sha);
struct pg_file *pg_file_by_sha(struct pg_context *ctx, const uint8_t *sha);
const char *pg_hexdump(const uint8_t *buf, size_t len);
const char *pg_swarm_to_str(struct pg_swarm *swarm);
const char *pg_peer_to_str(struct pg_peer *peer);
uint32_t pg_new_channel_id(void);

void pg_socket_enqueue_tx(struct pg_context *ctx, struct pg_buffer *block);
void pg_socket_suspend_tx(struct pg_context *ctx);

struct pg_buffer *pg_buffer_create(struct pg_peer *peer, uint32_t channel_id);
void pg_buffer_free(struct pg_buffer *buffer);
void *pg_buffer_advance(struct pg_buffer *buffer, size_t len);
void *pg_buffer_ptr(struct pg_buffer *buffer);
size_t pg_buffer_size_left(struct pg_buffer *buffer);
size_t pg_buffer_enqueue(struct pg_buffer *buffer);
void pg_buffer_reset(struct pg_buffer *buffer);

int pg_file_read_chunks(struct pg_file *file, uint64_t chunk, uint64_t count, void *buf);
int pg_file_write_chunks(struct pg_file *file, uint64_t chunk, uint64_t count, void *buf);

#endif //PEREGRINE_INTERNAL_H
