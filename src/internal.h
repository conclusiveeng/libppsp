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

#include "peregrine/socket.h"
#include <stdint.h>
#include <peregrine/mt.h>

struct pg_bitmap
{
	uint64_t size;
	uint8_t *data;
};

struct chunk {
	uint64_t offset; /* offset in file where chunk begins [bytes] */
	uint32_t len;    /* length of the chunk */
	char sha[20 + 1];
	struct node *node;
	enum chunk_state state;
	enum chunk_downloaded downloaded;
};

struct node {
	int number;                         /* number of the node */
	struct node *left, *right, *parent; /* if parent == NULL - it is root node of the tree */
	struct chunk *chunk;                /* pointer to chunk */
	char sha[20 + 1];
	enum node_state state;
};

struct msg_handshake {
	uint32_t src_channel_id;
	uint8_t protocol_options[];
} __attribute__((packed));

struct msg_handshake_opt {
	uint8_t code;
	uint8_t value[];
} __attribute__((packed));

/**
 * @brief Additional handshake structure used for replying to others peer handshake.
 *
 */
struct msg_handshake_reply {
	uint32_t dst_channel_id;
	uint8_t f_handshake_type;
	uint32_t src_channel_id;
	uint8_t f_version;
	uint8_t version;
	uint8_t f_min_version;
	uint8_t min_version;
	uint8_t f_content_prot_method;
	uint8_t content_prot_method;
	uint8_t f_merkle_hash_func;
	uint8_t merkle_hash_func;
	uint8_t f_chunk_addr_method;
	uint8_t chunk_addr_method;
	uint8_t end_opt;
} __attribute__((packed));

struct msg_have {
	uint32_t start_chunk;
	uint32_t end_chunk;
} __attribute__((packed));

struct msg_data {
	uint32_t start_chunk;
	uint32_t end_chunk;
	uint64_t timestamp;
	uint8_t data[];
} __attribute__((packed));

struct msg_ack {
	uint32_t start_chunk;
	uint32_t end_chunk;
	uint64_t sample;
};

struct msg_integrity {
	uint32_t start_chunk;
	uint32_t end_chunk;
	uint8_t hash[20];
} __attribute__((packed));

struct msg_signed_integrity {
	uint32_t start_chunk;
	uint32_t end_chunk;
	uint64_t timestamp;
	uint8_t signature[];
} __attribute__((packed));

struct msg_request {
	uint32_t start_chunk;
	uint32_t end_chunk;
} __attribute__((packed));

struct msg_cancel {
	uint32_t start_chunk;
	uint32_t end_chunk;
} __attribute__((packed));

struct msg_pex_resv4 {
	in_addr_t ip_address;
	uint16_t port;
} __attribute__((packed));

struct msg {
	uint8_t message_type;
	union {
		struct msg_handshake handshake;
		struct msg_have have;
		struct msg_data data;
		struct msg_ack ack;
		struct msg_integrity integrity;
		struct msg_pex_resv4 pex_resv4;
		struct msg_signed_integrity signed_integrity;
		struct msg_request request;
		struct msg_cancel cancel;
	};
} __attribute__((packed));

struct msg_frame {
	uint32_t channel_id;
	struct msg msg;
};


#endif //PEREGRINE_INTERNAL_H
