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

#ifndef _PPSPP_PROTOCOL_H_
#define _PPSPP_PROTOCOL_H_

#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>

struct peer;
struct in_addr;

/* handshake protocol options */
enum proto_options {
  VERSION = 0,
  MINIMUM_VERSION,
  SWARM_ID,
  CONTENT_PROT_METHOD,
  MERKLE_HASH_FUNC,
  LIVE_SIGNATURE_ALG,
  CHUNK_ADDR_METHOD,
  LIVE_DISC_WIND,
  SUPPORTED_MSGS,
  CHUNK_SIZE,
  FILE_SIZE,
  FILE_NAME,
  FILE_HASH,
  END_OPTION = 255
};

enum message {
  HANDSHAKE = 0,
  DATA,
  ACK,
  HAVE,
  INTEGRITY,
  PEX_RESV4,
  PEX_REQ,
  SIGNED_INTEGRITY,
  REQUEST,
  CANCEL,
  CHOKE,
  UNCHOKE,
  PEX_RESV6,
  PEX_RESCERT
};

enum handshake_type { HANDSHAKE_INIT = 1, HANDSHAKE_FINISH, HANDSHAKE_ERROR };

struct proto_opt_str {
  uint8_t version;
  uint8_t minimum_version;
  uint16_t swarm_id_len;
  uint8_t *swarm_id;
  uint8_t content_prot_method;
  uint8_t merkle_hash_func;
  uint8_t live_signature_alg;
  uint8_t chunk_addr_method;
  uint8_t live_disc_wind[8];
  uint8_t supported_msgs_len;
  uint8_t supported_msgs[256];
  uint32_t chunk_size;
  uint64_t file_size;
  uint8_t file_name[256];
  uint8_t file_name_len;
  uint8_t sha_demanded[20];
  uint32_t opt_map; /* bitmap - which of the fields above have any data */
};

struct msg_handshake {
  uint32_t src_channel_id;
  uint8_t protocol_options[];
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

// tylko do testow - dla odwrocenia wysylania danych - tzn wysylania od konca -
// tak jak to robi swift
struct integrity_temp {
  uint32_t start_chunk;
  uint32_t end_chunk;
  uint8_t sha[20];
};

int make_handshake_options(uint8_t * /*ptr*/, struct proto_opt_str * /*pos*/);
int make_handshake_request(char * /*ptr*/, uint32_t /*dest_chan_id*/, uint32_t /*src_chan_id*/, uint8_t * /*opts*/,
                           int /*opt_len*/);
int swift_make_handshake_have(char * /*ptr*/, uint32_t /*dest_chan_id*/, uint32_t /*src_chan_id*/, uint8_t * /*opts*/,
                              int /*opt_len*/, struct peer * /*peer*/);
int make_handshake_finish(char * /*ptr*/, struct peer * /*peer*/);
int make_request(char * /*ptr*/, uint32_t /*dest_chan_id*/, uint32_t /*start_chunk*/, uint32_t /*end_chunk*/,
                 struct peer * /*peer*/);
int make_pex_resp(char * /*ptr*/, struct peer * /*peer*/, struct peer * /*we*/);
int swift_make_integrity(char *, struct peer *, struct peer *);
int swift_make_integrity_reverse(char * /*ptr*/, struct peer * /*peer*/, struct peer * /*we*/);
int swift_make_data(char * /*ptr*/, struct peer * /*peer*/);
int swift_make_data_no_chanid(char * /*ptr*/, struct peer * /*peer*/);
int swift_make_have_ack(char * /*ptr*/, struct peer * /*peer*/);
int dump_options(uint8_t *ptr, struct peer * /*peer*/);
int swift_dump_options(uint8_t *ptr, struct peer * /*peer*/);
int dump_handshake_request(char * /*ptr*/, int /*req_len*/, struct peer * /*peer*/);
int swift_dump_handshake_request(char * /*ptr*/, int /*req_len*/, struct peer * /*peer*/);
int swift_seeder_dump_handshake_have(char *, int, struct peer *);
int swift_dump_handshake_have(char * /*ptr*/, int /*resp_len*/, struct peer * /*peer*/);
int swift_dump_request(char * /*ptr*/, int /*req_len*/, struct peer * /*peer*/);
int swift_dump_integrity(char * /*ptr*/, int /*req_len*/, struct peer * /*peer*/);
int swift_dump_have_ack(char * /*ptr*/, int /*ack_len*/, struct peer * /*peer*/);
uint8_t message_type(const char * /*ptr*/);
uint8_t handshake_type(char * /*ptr*/);

uint16_t count_handshake(char * /*ptr*/, uint16_t /*n*/, uint8_t /*skip_hdr*/);

#endif /* _PPSPP_PROTOCOL_H_ */
