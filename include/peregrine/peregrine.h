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

/**
 * @file peregrine.h
 * @author Conclusive Engineerg
 * @brief libperegrine public API
 * @version 0.4
 * @date 2020-12-15
 * 
 * @copyright Copyright (c) 2020 Conclusive Engineering Sp. z o.o.
 * 
 */

#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>

struct pg_context;
struct pg_peer;
struct pg_swarm;
struct pg_file;
struct pg_event;

/**
 * @brief Callback function pointer type used while iterating swarms
 * 
 */
typedef bool (*pg_swarm_iter_fn_t)(struct pg_swarm *swarm, void *arg);
/**
 * @brief  Callback function pointer type used while iterating peers
 * 
 */
typedef bool (*pg_peer_iter_fn_t)(struct pg_peer *peer, void *arg);
/**
 * @brief Callback function pointer type used on event loop routine
 * 
 */
typedef void (*pg_context_event_fn_t)(struct pg_event *event, void *arg);

/**
 * @brief Callback function pointer type used while adding files directory
 * 
 */
typedef void (*pg_file_dir_add_func_t)(struct pg_file *file, const char *dname);

/**
 * @brief PPSPP Content protection method protocol option.
 */
enum pg_content_protection_method
{
	CONTENT_PROTECTION_NONE = 0,			/**< No protection method */
	CONTENT_PROTECTION_MERKLE_HASH = 1,		/**< Merkle hash tree */
	CONTENT_PROTECTION_SIGN_ALL = 2,		/**< All data transferred are signed with private key and checked with public key  */
	CONTENT_PROTECTION_UNIFIED_MERKLE_HASH = 3,	/**< Used in live streaming mode when tree has dynamic root hash */
};

/**
 * @brief PPSPP Merkle tree hash function protocol option
 */
enum pg_merkle_hash_func
{
	MERKLE_HASH_SHA1 = 0,		/**< SHA1 hashes */
	MERKLE_HASH_SHA224 = 1,		/**< SHA224 hashes */
	MERKLE_HASH_SHA256 = 2,		/**< SHA256 hashes */
	MERKLE_HASH_SHA384 = 3,		/**< SHA384 hashes */
	MERKLE_HASH_SHA512 = 4,		/**< SHA512 hashes */
	MERKLE_HASH_INVALID = 255
};

/**
 * @brief PPSPP Chunk addressing method
 */
enum pg_chunk_addressing_method
{
	LIVE_SIGNATURE_32BIT_BIN = 0,	/**< 32-bit bin addressing */
	LIVE_SIGNATURE_64BIT_BYTE = 1,	/**< 64-bit byte range addressing */
	LIVE_SIGNATURE_32BIT_CHUNK = 2,	/**< 32-bit chunk range addressing */
	LIVE_SIGNATURE_64BIT_BIN = 3,	/**< 64-bit bin addressing */
	LIVE_SIGNATURE_64BIT_CHUNK = 4,	/**< 64-bit chunk range addressing */
};

/**
 * @brief Peregrine event handler event type

 */
enum pg_event_type
{
	EVENT_UNKNOWN = 0,		/**< Unused  */
	EVENT_PEER_ADDED,		/**< New peer was added  */
	EVENT_PEER_REMOVED,		/**< Peer was removed  */
	EVENT_PEER_JOINED_SWARM, 	/**< Peer joined swarm  */
	EVENT_PEER_LEFT_SWARM,		/**< Peer left the swarm  */
	EVENT_SWARM_ADDED,		/**< New swarm was added */
	EVENT_SWARM_REMOVED,		/**< Swarm was removed */
	EVENT_SWARM_FINISHED,		/**< Finished swarm download activities */
	EVENT_SWARM_FINISHED_ALL	/**< Finished all download activities */
};

/**
 * @brief Event structure.
 *
 * This structure is used by the library to communicate various events
 * back to the user.
 */
struct pg_event
{
	struct pg_context *ctx;		/**< Peregrine context handle */
	struct pg_peer *peer;		/**< Peregrine peer handle  */
	struct pg_swarm *swarm;		/**< Peregrine swarm handle  */
	enum pg_event_type type;	/**< Event loop type  */
};

/**
 *  @brief Configurable options for peregrine context.
 *
 *  This options perserve global configuration options for peregrine runtime.
 */
struct pg_context_options
{
	struct sockaddr *listen_addr;					/**< Peer listening address  */
	socklen_t listen_addr_len;					/**< Peer listening address length  */
	const char *working_dir;					/**< Peregrine working directory path  */
	pg_context_event_fn_t event_fn;					/**< Peregrine event loop callback handle  */
	void *fn_arg;							/**< Peregrine event loop callback arguments */
	enum pg_content_protection_method content_protection_method;	/**< PPSPP selected content protection method */
	enum pg_merkle_hash_func merkle_hash_func;			/**< PPSPP selected merkle tree hash protection function  */
	enum pg_chunk_addressing_method chunk_addressing_method;	/**< PPSPP chunk addressing method  */
	int chunk_size;
};

/**
 * @brief Create a new peregrine context handle.
 *
 * @param options Peregrine context options
 * @param ctxp Pointer where returned context handle will be stored
 * @return int 0 on success, -1 on error
 */
int pg_context_create(struct pg_context_options *options, struct pg_context **ctxp);

/**
 * @brief Return file descriptor associated with the context event loop.
 *
 * This file descriptor can be used by an external event loop to
 * determine when @ref pg_context_step needs to be called.
 *
 * @param ctx Context handle
 * @return int file descriptor number
 */
int pg_context_get_fd(struct pg_context *ctx);

/**
 * @brief Perform one interation of the internal event loop.
 *
 * @param ctx Context handle
 * @return int 0 on success, -1 on error
 */
int pg_context_step(struct pg_context *ctx);

/**
 *  @brief Run the internal event loop.
 *
 * @param ctx Context handle
 * @return 0 when shut down gracefully, otherwise -1
 */
int pg_context_run(struct pg_context *ctx);

/**
 * @brief Add new peer.
 *
 * @param ctx Context handle
 * @param sa Peer address structure
 * @param peerp Pointer where returned peer handle will be stored
 * @return int 0 on success, -1 on error
 */
int pg_add_peer(struct pg_context *ctx, struct sockaddr *sa, struct pg_peer **peerp);

/**
 * @brief Iterate over known swarms.
 *
 * @param ctx Context handle
 * @param fn Callback function called on each swarm
 * @param arg Callback additional arguments
 * @return bool true when all elements are iterated, false is callback function stopped iteration
 */
bool pg_swarm_iterate(struct pg_context *ctx, pg_swarm_iter_fn_t fn, void *arg);

/**
 * @brief Get swarm ID from the swarm handle.
 *
 * This function allocates storage for the hash and returns pointer to it.
 * Such pointer can be freed with free function.
 *
 * @param swarm Swarm handle
 * @param hash Pointer where hash should be stored
 * @return size_t size of returned hash
 */
size_t pg_swarm_get_id(struct pg_swarm *swarm, uint8_t **hash);

/**
 * @brief Return total number of bytes in a swarm content.
 *
 * When this information is not available (eg. not computed yet), returns 0.
 *
 * @param swarm Swarm handle
 * @return uint64_t total number of stored bytes in a swarm
 */
uint64_t pg_swarm_get_content_size(struct pg_swarm *swarm);

/**
 * @brief Return total number of chunks in a swarm content.
 *
 * @param swarm Swarm handle
 * @return uint64_t total number of chunks for a swarm
 */
uint64_t pg_swarm_get_total_chunks(struct pg_swarm *swarm);

/**
 * @brief Return number of chunks received in a swarm.
 *
 * @param swarm Swarm handle
 * @return uint64_t total number of chunks received by swarm
 */
uint64_t pg_swarm_get_received_chunks(struct pg_swarm *swarm);

/**
 * @brief Return number of chunks sent from a swarm
 * 
 * @param swarm swarm handle
 * @return uint64_t total number of chunks sent from swarm
 */
uint64_t pg_swarm_get_sent_chunks(struct pg_swarm *swarm);

/**
 * @brief Return Swarm ID in human readable form
 * 
 * @param swarm Swarm handle
 * @return const char* string containing hexadecimal representation of Swarm ID
 */
const char *pg_swarm_to_str(struct pg_swarm *swarm);

/**
 * @brief Iterate over known peers
 * 
 * @param ctx Context handle
 * @param fn Callback function called on each peer
 * @param arg Additional arguments passed to callback function
 * @return true when function iterated overall elements
 * @return false when iteration was interrupted by the callback function
 */
bool pg_peer_iterate(struct pg_context *ctx, pg_peer_iter_fn_t fn, void *arg);

/**
 * @brief Return peer address structure for selected peer
 * 
 * @param peer Peer handle
 * @return struct sockaddr* structure with peer address
 */
struct sockaddr *pg_peer_get_address(struct pg_peer *peer);

/**
 * @brief Return total number of chunks received from peer
 * 
 * @param peer Peer handle
 * @return uint64_t total number of chunks received 
 */
uint64_t pg_peer_get_received_chunks(struct pg_peer *peer);

/**
 * @brief Return total number of chunks send by peer
 * 
 * @param peer Peer handle
 * @return uint64_t total number of chunks sent
 */
uint64_t pg_peer_get_sent_chunks(struct pg_peer *peer);

/**
 * @brief Return human readable representation of peer address
 * Eg. Peer addres 127.0.0.1:47856
 *
 * @param peer Peer handle
 * @return const char* string peer address
 */
const char *pg_peer_to_str(struct pg_peer *peer);

/**
 * @brief Generate SHA1 sums for all files added to peregrine context
 * This is required operation after adding files to peregrine in seeder mode.
 * 
 * @param context Context handle
 */
void pg_file_generate_sha1(struct pg_context *context);

/**
 * @brief Add single file to peregrine context
 * 
 * @param context Context handle
 * @param sha1 If sha1 is provided the file will be received by peregrine
 * @param path If path is provided then the file can be sent by peregrine
 * @return struct pg_file* pointer to added file
 */
struct pg_file *pg_file_add_file(struct pg_context *context, const uint8_t *sha1, const char *path);

/**
 * @brief Add files from provided directory to peregrine context
 * 
 * @param context Context handle
 * @param dname Path to directory where the files are stored
 * @param fn Callback function called for each file to store (optional)
 * @return int 0 on success, -1 on error
 */
int pg_file_add_directory(struct pg_context *context, const char *dname, pg_file_dir_add_func_t fn);

/**
 * @brief Prints files stored in the context to debug output
 * Prints file path, sha1 and number of chunks
 * 
 * @param context Context handle
 */
void pg_file_list_sha1(struct pg_context *context);

/**
 * @brief Returns SHA1 of provided file
 * 
 * @param file File handle
 * @return const uint8_t* SHA1 of the file 
 */
const uint8_t *pg_file_get_sha(struct pg_file *file);

/**
 * @brief Returns path to provided file
 * 
 * @param file File handle
 * @return const char* string path to the file
 */
const char *pg_file_get_path(struct pg_file *file);

/**
 * @brief Parse hexadecimal SHA1 to binary form and return it
 * 
 * @param str HEX string with SHA1 to parse (required 40 characters string)
 * @return uint8_t* binary form of the SHA1
 */
uint8_t *pg_parse_sha1(const char *str);

#endif /* LIBPEREGRINE_PEREGRINE_H */
