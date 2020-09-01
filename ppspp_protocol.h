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

#include "mt.h"
#include "peer.h"


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

enum handshake_type {
	HANDSHAKE_INIT = 1,
	HANDSHAKE_FINISH,
	HANDSHAKE_ERROR
};

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
	uint32_t opt_map;				/* bitmap - which of the fields above have any data */
};

struct ppsp_msg_handshake
{
	uint32_t src_channel_id;
	uint8_t protocol_options[];
} __attribute__((packed));

struct ppsp_msg_have
{
	uint32_t start_chunk;
	uint32_t end_chunk;
} __attribute__((packed));

struct ppsp_msg_data
{
	uint32_t start_chunk;
	uint32_t end_chunk;
	uint64_t timestamp;
	uint8_t data[];
} __attribute__((packed));

struct ppsp_msg_ack
{
	uint32_t start_chunk;
	uint32_t end_chunk;
	uint64_t sample;
};

struct ppsp_msg_integrity
{
	uint32_t end_chunk;
	uint8_t hash[256];
} __attribute__((packed));

struct ppsp_msg_pex_resv4
{
	in_addr_t ip_address;
	uint16_t port;
} __attribute__((packed));

struct ppsp_msg_signed_integrity
{
	uint32_t start_chunk;
	uint32_t end_chunk;
	uint64_t timestamp;
	uint8_t signature[];
} __attribute__((packed));

struct ppsp_msg_request
{
	uint32_t start_chunk;
	uint32_t end_chunk;
} __attribute__((packed));

struct ppsp_msg_cancel
{
	uint32_t start_chunk;
	uint32_t end_chunk;
} __attribute__((packed));

struct ppsp_msg
{
	uint8_t message_type;
	union {
		struct ppsp_msg_handshake handshake;
		struct ppsp_msg_have have;
		struct ppsp_msg_data data;
		struct ppsp_msg_ack ack;
		struct ppsp_msg_integrity integrity;
		struct ppsp_msg_pex_resv4 pex_resv4;
		struct ppsp_msg_signed_integrity signed_integrity;
		struct ppsp_msg_request request;
		struct ppsp_msg_cancel cancel;
	};
} __attribute__((packed));

// tylko do testow - dla odwrocenia wysylania danych - tzn wysylania od konca - tak jak to robi swift
struct integrity_temp {
	uint32_t start_chunk;
	uint32_t end_chunk;
	uint8_t sha[20];
};

static inline size_t
ppspp_pack_dest_chan(void *dptr, uint32_t dst_channel_id)
{
	uint32_t *chan_id = dptr;

	*chan_id = dst_channel_id;
	return (sizeof(*chan_id));
}

static inline size_t
ppspp_pack_handshake(void *dptr, uint32_t src_channel_id, uint8_t *options, size_t optlen)
{
	struct ppsp_msg *msg = dptr;

	msg->message_type = HANDSHAKE;
	msg->handshake.src_channel_id = src_channel_id;
	memcpy(msg->handshake.protocol_options, options, optlen);

	return (sizeof(uint8_t) + sizeof(msg->handshake));
}

static inline size_t
ppspp_pack_have(void *dptr, uint32_t start_chunk, uint32_t end_chunk)
{
	struct ppsp_msg *msg = dptr;

	msg->message_type = HAVE;
	msg->have.start_chunk = htonl(start_chunk);
	msg->have.end_chunk = htonl(end_chunk);

	return (sizeof(uint8_t) + sizeof(msg->have));
}

static inline size_t
ppspp_pack_data(void *dptr, uint32_t start_chunk, uint32_t end_chunk, uint64_t timestamp)
{
	struct ppsp_msg *msg = dptr;

	msg->message_type = DATA;
	msg->data.start_chunk = htonl(start_chunk);
	msg->data.end_chunk = htonl(end_chunk);
	msg->data.timestamp = timestamp;

	return (sizeof(uint8_t) + sizeof(msg->data));
}

static inline int
ppspp_pack_ack(void *dptr, uint32_t start_chunk, uint32_t end_chunk,
    uint64_t sample)
{
	struct ppsp_msg *msg = dptr;

	msg->message_type = ACK;
	msg->ack.start_chunk = htonl(start_chunk);
	msg->ack.end_chunk = htonl(end_chunk);
	msg->ack.sample = sample;

	return (sizeof(uint8_t) + sizeof(msg->ack));
}

static inline size_t
ppspp_pack_integrity(void *dptr, uint32_t end_chunk, uint8_t *hash)
{
	struct ppsp_msg *msg = dptr;

	msg->message_type = INTEGRITY;
	msg->integrity.end_chunk = htonl(end_chunk);
	memcpy(msg->integrity.hash, hash, sizeof(msg->integrity.hash));

	return (sizeof(uint8_t) + sizeof(msg->integrity));
}

static inline size_t
ppspp_pack_pex_resv4(void *dptr, in_addr_t ip_address, uint16_t port)
{
	struct ppsp_msg *msg = dptr;

	msg->message_type = PEX_RESV4;
	msg->pex_resv4.ip_address = ip_address;
	msg->pex_resv4.port = port;

	return (sizeof(uint8_t) + sizeof(msg->pex_resv4));
}

static inline size_t
ppspp_pack_pex_req(void *dptr)
{
	struct ppsp_msg *msg = dptr;

	msg->message_type = PEX_REQ;

	return (sizeof(uint8_t));
}

static inline size_t
ppspp_pack_signed_integrity(void *dptr, uint32_t start_chunk, uint32_t end_chunk,
    int64_t timestamp, uint8_t *signature, size_t siglen)
{
	struct ppsp_msg *msg = dptr;

	msg->message_type = SIGNED_INTEGRITY;
	msg->signed_integrity.start_chunk = htonl(start_chunk);
	msg->signed_integrity.end_chunk = htonl(end_chunk);
	msg->signed_integrity.timestamp = timestamp;
	memcpy(msg->signed_integrity.signature, signature, siglen);

	return (sizeof(uint8_t) + sizeof(msg->signed_integrity) + siglen);
}

static inline size_t
ppspp_pack_request(void *dptr, uint32_t start_chunk, uint32_t end_chunk)
{
	struct ppsp_msg *msg = dptr;

	msg->message_type = REQUEST;
	msg->request.start_chunk = htonl(start_chunk);
	msg->request.end_chunk = htonl(end_chunk);

	return (sizeof(uint8_t) + sizeof(msg->request));
}

static inline size_t
ppspp_pack_cancel(void *dptr, uint32_t start_chunk, uint32_t end_chunk)
{
	struct ppsp_msg *msg = dptr;

	msg->message_type = CANCEL;
	msg->cancel.start_chunk = htonl(start_chunk);
	msg->cancel.end_chunk = htonl(end_chunk);

	return (sizeof(uint8_t) + sizeof(msg->cancel));
}

int ppspp_make_handshake_options (char *, struct proto_opt_str *);
int ppspp_make_handshake_request (char *, uint32_t, uint32_t, char *, int);
int ppspp_make_handshake_have (char *, uint32_t, uint32_t, char *, int, struct peer *);
int ppspp_make_handshake_finish (char *, struct peer *);
int ppspp_make_request (char *, uint32_t, uint32_t, uint32_t, struct peer*);
int ppspp_make_pex_resp (char *, struct peer *, struct peer *);
int ppspp_make_integrity (char *, struct peer *, struct peer *);
int ppspp_make_integrity_reverse (char *, struct peer *, struct peer *);
int ppspp_make_data (char *, struct peer *);
int ppspp_make_data_no_chanid (char *, struct peer *);
int ppspp_make_have_ack (char *, struct peer *);
int ppspp_dump_options (char *ptr, struct peer *);
int ppspp_dump_handshake_request (char *, int, struct peer *);
int ppspp_seeder_dump_handshake_have (char *, int, struct peer *);
int ppspp_dump_handshake_have (char *, int, struct peer *);
int ppspp_dump_request (char *, int, struct peer *);
int ppspp_dump_pex_resp (char *, int, struct peer *, int);
int ppspp_dump_integrity (char *, int, struct peer *);
int ppspp_dump_ack (char *, int, struct peer *);
int ppspp_dump_have_ack (char *, int, struct peer *);
uint8_t ppspp_message_type (const char *);
uint8_t ppspp_handshake_type (char *);
uint16_t ppspp_count_handshake (char *, uint16_t, uint8_t);

#endif /* _PPSPP_PROTOCOL_H_ */
