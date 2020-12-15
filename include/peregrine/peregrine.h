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

#ifndef LIBPEREGRINE_PEREGRINE_H
#define LIBPEREGRINE_PEREGRINE_H

#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>

/**
 * @file peregrine.h
 */

#define PG_CHUNK_SIZE	1024

struct pg_context;
struct pg_peer;
struct pg_swarm;
struct pg_file;
struct pg_event;

typedef bool (*pg_swarm_iter_fn_t)(struct pg_swarm *swarm, void *arg);
typedef bool (*pg_peer_iter_fn_t)(struct pg_peer *peer, void *arg);
typedef void (*pg_context_event_fn_t)(struct pg_event *event, void *arg);
typedef void (*pg_file_dir_add_func_t)(struct pg_file *file, const char *dname);

/**
 *
 */
enum pg_content_protection_method
{
	CONTENT_PROTECTION_NONE = 0,
	CONTENT_PROTECTION_MERKLE_HASH = 1,
	CONTENT_PROTECTION_SIGN_ALL = 2,
	CONTENT_PROTECTION_UNIFIED_MERKLE_HASH = 3,
};

enum pg_merkle_hash_func
{
	MERKLE_HASH_SHA1 = 0,		/**< SHA1 hashes */
	MERKLE_HASH_SHA224 = 1,		/**< SHA224 hashes */
	MERKLE_HASH_SHA256 = 2,		/**< SHA256 hashes */
	MERKLE_HASH_SHA384 = 3,		/**< SHA384 hashes */
	MERKLE_HASH_SHA512 = 4,		/**< SHA512 hashes */
	MERKLE_HASH_INVALID = 255
};

enum pg_chunk_addressing_method
{
	LIVE_SIGNATURE_32BIT_BIN = 0,	/**< 32-bit bin addressing */
	LIVE_SIGNATURE_64BIT_BYTE = 1,	/**< 64-bit byte range addressing */
	LIVE_SIGNATURE_32BIT_CHUNK = 2,	/**< 32-bit chunk range addressing */
	LIVE_SIGNATURE_64BIT_BIN = 3,	/**< 64-bit bin addressing */
	LIVE_SIGNATURE_64BIT_CHUNK = 4,	/**< 64-bit chunk range addressing */
};

enum pg_event_type
{
	EVENT_UNKNOWN = 0,
	EVENT_PEER_ADDED,
	EVENT_PEER_REMOVED,
	EVENT_PEER_JOINED_SWARM,
	EVENT_PEER_LEFT_SWARM,
};

/**
 * Event structure.
 *
 * This structure is used by the library to communicate various events
 * back to the user.
 */
struct pg_event
{
	struct pg_context *ctx;
	struct pg_peer *peer;
	struct pg_swarm *swarm;
	enum pg_event_type type;
};

/**
 * Configurable options for peregrine context.
 */
struct pg_context_options
{
	struct sockaddr *listen_addr;
	socklen_t listen_addr_len;
	const char *working_dir;
	pg_context_event_fn_t event_fn;
	void *fn_arg;
	enum pg_content_protection_method content_protection_method;
	enum pg_merkle_hash_func merkle_hash_func;
	enum pg_chunk_addressing_method chunk_addressing_method;
};

/**
 * Create a new peregrine context.
 *
 * @param options Context options
 * @param ctxp Pointer where returned context handle will be stored
 * @return 0 on success, -1 on error
 */
int pg_context_create(struct pg_context_options *options, struct pg_context **ctxp);

/**
 * Return file descriptor associated with the context event loop.
 *
 * This file descriptor can be used by an external event loop to
 * determine when @ref pg_context_step needs to be called.
 *
 * @param ctx Context handle
 * @return File descriptor number
 */
int pg_context_get_fd(struct pg_context *ctx);

/**
 * Perform one interation of the internal event loop.
 *
 * @param ctx
 * @return
 */
int pg_context_step(struct pg_context *ctx);

/**
 * Run the internal event loop.
 *
 * @param ctx Context handle
 * @return 0 when shut down gracefully, otherwise -1
 */
int pg_context_run(struct pg_context *ctx);

/**
 * Add new peer.
 *
 * @param ctx Context handle
 * @param sa Peer address
 * @param peerp Pointer where returned peer handle will be stored
 * @return 0 on success, -1 on error
 */
int pg_add_peer(struct pg_context *ctx, struct sockaddr *sa, struct pg_peer **peerp);

/**
 * Iterate over known swarms.
 *
 * @param ctx Context handle
 * @param fn
 * @param arg
 * @return
 */
bool pg_swarm_iterate(struct pg_context *ctx, pg_swarm_iter_fn_t fn, void *arg);

/**
 * Return swarm ID from the swarm handle.
 *
 * This function allocates storage for the hash and returns pointer to it.
 * Such pointer can be freed with @ref free function.
 *
 * @param swarm Swarm handle
 * @param hash Pointer where hash
 * @return
 */
size_t pg_swarm_get_id(struct pg_swarm *swarm, uint8_t **hash);

/**
 * Return total number of bytes in a swarm content.
 *
 * When this information is not available (eg. not computed yet), returns 0.
 *
 * @param swarm Swarm handle
 * @return
 */
uint64_t pg_swarm_get_content_size(struct pg_swarm *swarm);

/**
 * Return total number of chunks in a swarm content.
 *
 * @param swarm Swarm handle
 * @return
 */
uint64_t pg_swarm_get_total_chunks(struct pg_swarm *swarm);

/**
 * Return number of chunks received in a swarm.
 *
 * @param swarm Swarm handle
 * @return
 */
uint64_t pg_swarm_get_received_chunks(struct pg_swarm *swarm);
uint64_t pg_swarm_get_sent_chunks(struct pg_swarm *swarm);
const char *pg_swarm_to_str(struct pg_swarm *swarm);

bool pg_peer_iterate(struct pg_context *ctx, pg_peer_iter_fn_t fn, void *arg);
struct sockaddr *pg_peer_get_address(struct pg_peer *peer);
const char *pg_peer_to_str(struct pg_peer *peer);

void pg_file_generate_sha1(struct pg_context *context);
struct pg_file *pg_file_add_file(struct pg_context *context, const uint8_t *sha1, const char *path);
int pg_file_add_directory(struct pg_context *context, const char *dname, pg_file_dir_add_func_t fn);
void pg_file_list_sha1(struct pg_context *context);
const uint8_t *pg_file_get_sha(struct pg_file *file);
const char *pg_file_get_path(struct pg_file *file);

uint8_t *pg_parse_sha1(const char *str);

#endif /* LIBPEREGRINE_PEREGRINE_H */
