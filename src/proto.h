//
// Created by jakub on 11.12.2020.
//

#ifndef LIBPEREGRINE_PROTO_H
#define LIBPEREGRINE_PROTO_H

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

struct msg_handshake {
	uint32_t src_channel_id;
	uint8_t protocol_options[];
} __attribute__((packed));

struct msg_handshake_opt {
	uint8_t code;
	uint8_t value[];
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

#endif //LIBPEREGRINE_PROTO_H
