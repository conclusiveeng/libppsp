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

#ifndef _PEER_HANDLER_H_
#define _PEER_HANDLER_H_

#include "peregrine_socket.h"
#include <stddef.h>
#include <stdint.h>

enum ppspp_protocol_options_headers {
	F_VERSION = 0,
	F_MINIMUM_VERSION,
	F_SWARM_ID,
	F_CONTENT_PROT_METHOD,
	F_MERKLE_HASH_FUNC,
	F_LIVE_SIGNATURE_ALG,
	F_CHUNK_ADDR_METHOD,
	F_LIVE_DISC_WIND,
	F_SUPPORTED_MSGS,
	F_CHUNK_SIZE,
	F_END_OPTION = 255
};

/*
 Message types in PPSPP/LIBSWIFT
        +----------+------------------+
        | Msg Type | Description      |
        +----------+------------------+
        | 0        | HANDSHAKE        |
        | 1        | DATA             |
        | 2        | ACK              |
        | 3        | HAVE             |
        | 4        | INTEGRITY        |
        | 5        | PEX_RESv4        |
        | 6        | PEX_REQ          |
        | 7        | SIGNED_INTEGRITY |
        | 8        | REQUEST          |
        | 9        | CANCEL           |
        | 10       | CHOKE            |
        | 11       | UNCHOKE          |
        | 12       | PEX_RESv6        |
        | 13       | PEX_REScert      |
        | 14-254   | Unassigned       |
        | 255      | Reserved         |
        +----------+------------------+
*/

enum peregrine_message_type {
	MSG_HANDSHAKE = 0,
	MSG_DATA,
	MSG_ACK,
	MSG_HAVE,
	MSG_INTEGRITY,
	MSG_PEX_RESV4,
	MSG_PEX_REQ,
	MSG_SIGNED_INTEGRITY,
	MSG_REQUEST,
	MSG_CANCEL,
	MSG_CHOKE,
	MSG_UNCHOKE,
	MSG_PEX_RESV6,
	MSG_PEX_RESCERT,
	MSG_RESERVED = 255
};

enum pg_handshake_option {
	HANDSHAKE_OPT_VERSION = 0,
	HANDSHAKE_OPT_MIN_VERSION = 1,
	HANDSHAKE_OPT_SWARM_ID = 2,
	HANDSHAKE_OPT_CONTENT_INTEGRITY = 3,
	HANDSHAKE_OPT_MERKLE_HASH_FUNC = 4,
	HANDSHAKE_OPT_LIVE_SIGNATURE_ALGO = 5,
	HANDSHAKE_OPT_CHUNK_ADDRESSING_METHOD = 6,
	HANDSHAKE_OPT_LIVE_DISCARD_WINDOW = 7,
	HANDSHAKE_OPT_SUPPORTED_MESSAGE = 8,
	HANDSHAKE_OPT_CHUNK_SIZE = 9,
	HANDSHAKE_OPT_END = 255
};

enum ppspp_handshake_type { HANDSHAKE_INIT = 0, HANDSHAKE_CLOSE, HANDSHAKE_ERROR };

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

ssize_t pg_handle_message(struct pg_peer *peer, struct msg *msg);

#endif
