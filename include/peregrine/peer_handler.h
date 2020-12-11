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

#include "socket.h"
#include <stddef.h>
#include <stdint.h>

enum ppspp_handshake_type { HANDSHAKE_INIT = 0, HANDSHAKE_CLOSE, HANDSHAKE_ERROR };

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

struct msg;

ssize_t pg_handle_message(struct pg_peer *peer, struct msg *msg);

#endif
