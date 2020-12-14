//
// Created by jakub on 11.12.2020.
//

#ifndef LIBPEREGRINE_PROTO_H
#define LIBPEREGRINE_PROTO_H

#include "internal.h"

#define MSG_LENGTH(_type)	(sizeof(uint8_t) + sizeof(struct _type))
#define OPT_LENGTH(_size)	(sizeof(struct msg_handshake_opt) + (_size))

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

enum pg_handshake_option
{
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

struct msg_handshake
{
	uint32_t src_channel_id;
	uint8_t protocol_options[];
} __attribute__((packed));

struct msg_handshake_opt
{
	uint8_t code;
	uint8_t value[];
} __attribute__((packed));

struct msg_have
{
	uint32_t start_chunk;
	uint32_t end_chunk;
} __attribute__((packed));

struct msg_data
{
	uint32_t start_chunk;
	uint32_t end_chunk;
	uint64_t timestamp;
	uint8_t data[];
} __attribute__((packed));

struct msg_ack
{
	uint32_t start_chunk;
	uint32_t end_chunk;
	uint64_t sample;
};

struct msg_integrity
{
	uint32_t start_chunk;
	uint32_t end_chunk;
	uint8_t hash[20];
} __attribute__((packed));

struct msg_signed_integrity
{
	uint32_t start_chunk;
	uint32_t end_chunk;
	uint64_t timestamp;
	uint8_t signature[];
} __attribute__((packed));

struct msg_request
{
	uint32_t start_chunk;
	uint32_t end_chunk;
} __attribute__((packed));

struct msg_cancel
{
	uint32_t start_chunk;
	uint32_t end_chunk;
} __attribute__((packed));

struct msg_pex_req
{
} __attribute__((packed));

struct msg_choke
{
} __attribute__((packed));

struct msg_unchoke
{
} __attribute__((packed));

struct msg_pex_resv4
{
	in_addr_t ip_address;
	uint16_t port;
} __attribute__((packed));

struct msg
{
	uint8_t message_type;
	union
	{
		struct msg_handshake handshake;
		struct msg_have have;
		struct msg_data data;
		struct msg_ack ack;
		struct msg_integrity integrity;
		struct msg_pex_req pex_req;
		struct msg_pex_resv4 pex_resv4;
		struct msg_signed_integrity signed_integrity;
		struct msg_request request;
		struct msg_cancel cancel;
	};
} __attribute__((packed));

struct msg_frame
{
	uint32_t channel_id;
	struct msg msg;
};

void pack_handshake(struct pg_buffer *buf, uint32_t src_channel_id);
void pack_handshake_opt(struct pg_buffer *buf, uint8_t code, void *data, size_t len);
void pack_handshake_opt_u8(struct pg_buffer *buf, uint8_t code, uint8_t value);
void pack_handshake_opt_u32(struct pg_buffer *buf, uint8_t code, uint32_t value);
void pack_handshake_opt_end(struct pg_buffer *buf);
void pack_have(struct pg_buffer *buf, uint32_t start_chunk, uint32_t end_chunk);
void pack_data(struct pg_buffer *buf, uint32_t start_chunk, uint32_t end_chunk, uint64_t timestamp);
void pack_ack(struct pg_buffer *buf, uint32_t start_chunk, uint32_t end_chunk, uint64_t sample);
void pack_integrity(struct pg_buffer *buf, uint32_t start_chunk, uint32_t end_chunk,
    const uint8_t *hash);
void pack_signed_integrity(struct pg_buffer *buf, uint32_t start_chunk, uint32_t end_chunk,
    int64_t timestamp, uint8_t *signature, size_t siglen);
void pack_request(struct pg_buffer *buf, uint32_t start_chunk, uint32_t end_chunk);
void pack_cancel(struct pg_buffer *buf, uint32_t start_chunk, uint32_t end_chunk);
void pack_dest_chan(struct pg_buffer *buf, uint32_t dst_channel_id);
void pack_pex_resv4(struct pg_buffer *buf, in_addr_t ip_address, uint16_t port);
void pack_pex_req(struct pg_buffer *buf);

#endif //LIBPEREGRINE_PROTO_H
