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

#ifndef _PROTO_HELPER_H_
#define _PROTO_HELPER_H_

#include "peer_handler.h"
#include <netinet/in.h>
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
enum ppspp_message_type {
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

enum ppspp_handshake_type { HANDSHAKE_INIT = 0, HANDSHAKE_CLOSE, HANDSHAKE_ERROR };

struct msg_handshake {
  uint32_t dst_channel_id;
  uint8_t f_handshake_type;
  uint32_t src_channel_id;
  uint8_t f_version;
  uint8_t version;
  uint8_t f_min_version;
  uint8_t min_version;
  uint8_t f_swarm_id;
  uint16_t swarm_id_len; // Hash has always 20 bytes
  uint8_t swarm_id[20];  //
  uint8_t f_content_prot_method;
  uint8_t content_prot_method;
  uint8_t f_merkle_hash_func;
  uint8_t merkle_hash_func;
  uint8_t f_live_signature_alg;
  uint8_t live_signature_alg;
  uint8_t f_chunk_addr_method;
  uint8_t chunk_addr_method;
  //   uint8_t f_live_disc_wind; // Live discard window is not used currently
  //   uint32_t live_disc_wind;
  //   uint8_t f_supported_msg;
  //   uint8_t supported_msg_len;
  //   uint8_t supported_msg;
  uint8_t f_chunk_size;
  uint32_t chunk_size;
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
  uint32_t end_chunk;
  uint8_t hash[256];
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

void proto_print_protocol_options(struct ppspp_protocol_options *proto_options);
enum ppspp_handshake_type proto_parse_handshake(char *ptr, uint32_t *dest_chan_id, uint32_t *src_chan_id,
                                                struct ppspp_protocol_options *proto_options, uint32_t *bytes_parsed);
int proto_prepare_handshake(struct peregrine_peer *peer, size_t response_buffer_size, char *response);
int proto_prepare_have(struct peregrine_peer *peer, size_t response_buffer_size, char *response);

size_t pack_have(void *dptr, uint32_t start_chunk, uint32_t end_chunk);
size_t pack_data(void *dptr, uint32_t start_chunk, uint32_t end_chunk, uint64_t timestamp);
size_t pack_ack(void *dptr, uint32_t start_chunk, uint32_t end_chunk, uint64_t sample);
size_t pack_integrity(void *dptr, uint32_t end_chunk, uint8_t *hash);
size_t pack_signed_integrity(void *dptr, uint32_t start_chunk, uint32_t end_chunk, int64_t timestamp,
                             uint8_t *signature, size_t siglen);
size_t pack_request(void *dptr, uint32_t start_chunk, uint32_t end_chunk);
size_t pack_cancel(void *dptr, uint32_t start_chunk, uint32_t end_chunk);
size_t pack_dest_chan(void *dptr, uint32_t dst_channel_id);
size_t pack_pex_resv4(void *dptr, in_addr_t ip_address, uint16_t port);
// size_t pack_pex_req(void *dptr);

#endif /* _PPSPP_PROTOCOL_H_ */
