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
 */

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
	MERKLE_HASH_SHA1 = 0,
	MERKLE_HASH_SHA224 = 1,
	MERKLE_HASH_SHA256 = 2,
	MERKLE_HASH_SHA384 = 3,
	MERKLE_HASH_SHA512 = 4,
	MERKLE_HASH_INVALID = 255
};

enum pg_chunk_addressing_method
{
	LIVE_SIGNATURE_32BIT_BIN = 0,
	LIVE_SIGNATURE_64BIT_BYTE = 1,
	LIVE_SIGNATURE_32BIT_CHUNK = 2,
	LIVE_SIGNATURE_64BIT_BIN = 3,
	LIVE_SIGNATURE_64BIT_CHUNK = 4,
};

struct pg_context_options
{
	struct sockaddr *listen_addr;
	socklen_t listen_addr_len;
	const char *working_dir;
	enum pg_content_protection_method content_protection_method;
	enum pg_merkle_hash_func merkle_hash_func;
	enum pg_chunk_addressing_method chunk_addressing_method;
	void (*add_fd)(struct pg_context *ctx, void *arg, int fd, int events);
	void (*mod_fd)(struct pg_context *ctx, void *arg, int fd, int events);
	void (*del_fd)(struct pg_context *ctx, void *arg, int fd);
	void *arg;
};

#endif /* LIBPEREGRINE_PEREGRINE_H */
