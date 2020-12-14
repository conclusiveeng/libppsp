#include <sys/param.h>
#include <sys/types.h>
#include <sys/endian.h>
#include <stdlib.h>
#include <string.h>
#include "internal.h"
#include "proto.h"
#include "log.h"

void
pack_dest_chan(struct pg_buffer *buf, uint32_t dst_channel_id)
{
	uint32_t *chan_id = pg_buffer_advance(buf, sizeof(*chan_id));

	*chan_id = htobe32(dst_channel_id);
}

void
pack_handshake(struct pg_buffer *buf, uint32_t src_channel_id)
{
	struct msg *msg = pg_buffer_advance(buf, MSG_LENGTH(msg_handshake));

	msg->message_type = MSG_HANDSHAKE;
	msg->handshake.src_channel_id = htobe32(src_channel_id);
}

void
pack_handshake_opt(struct pg_buffer *buf, uint8_t code, void *data, size_t len)
{
	struct msg_handshake_opt *opt;

	opt = pg_buffer_advance(buf, OPT_LENGTH(len));
	opt->code = code;
	memcpy(opt->value, data, len);
}

void
pack_handshake_opt_u8(struct pg_buffer *buf, uint8_t code, uint8_t value)
{
	struct msg_handshake_opt *opt = pg_buffer_advance(buf, OPT_LENGTH(sizeof(value)));

	opt->code = code;
	opt->value[0] = value;
}

void
pack_handshake_opt_u32(struct pg_buffer *buf, uint8_t code, uint32_t value)
{
	struct msg_handshake_opt *opt = pg_buffer_advance(buf, OPT_LENGTH(sizeof(value)));

	opt->code = code;
	memcpy(opt->value, &value, sizeof(uint32_t));
}

void
pack_handshake_opt_end(struct pg_buffer *buf)
{
	struct msg_handshake_opt *opt = pg_buffer_advance(buf, OPT_LENGTH(0));

	opt->code = HANDSHAKE_OPT_END;
}

void
pack_have(struct pg_buffer *buf, uint32_t start_chunk, uint32_t end_chunk)
{
	struct msg *msg = pg_buffer_advance(buf, MSG_LENGTH(msg_have));

	msg->message_type = MSG_HAVE;
	msg->have.start_chunk = htobe32(start_chunk);
	msg->have.end_chunk = htobe32(end_chunk);
}

void
pack_data(struct pg_buffer *buf, uint32_t start_chunk, uint32_t end_chunk, uint64_t timestamp)
{
	struct msg *msg = pg_buffer_advance(buf, MSG_LENGTH(msg_data));

	msg->message_type = MSG_DATA;
	msg->data.start_chunk = htobe32(start_chunk);
	msg->data.end_chunk = htobe32(end_chunk);
	msg->data.timestamp = htobe64(timestamp);
}

void
pack_ack(struct pg_buffer *buf, uint32_t start_chunk, uint32_t end_chunk, uint64_t sample)
{
	struct msg *msg = pg_buffer_advance(buf, MSG_LENGTH(msg_ack));

	msg->message_type = MSG_ACK;
	msg->ack.start_chunk = htobe32(start_chunk);
	msg->ack.end_chunk = htobe32(end_chunk);
	msg->ack.sample = sample;
}

void
pack_integrity(struct pg_buffer *buf, uint32_t start_chunk, uint32_t end_chunk,
    const uint8_t *hash)
{
	struct msg *msg = pg_buffer_advance(buf, MSG_LENGTH(msg_integrity));

	msg->message_type = MSG_INTEGRITY;
	msg->integrity.start_chunk = htobe32(start_chunk);
	msg->integrity.end_chunk = htobe32(end_chunk);
	memcpy(msg->integrity.hash, hash, sizeof(msg->integrity.hash));
}

void
pack_signed_integrity(struct pg_buffer *buf, uint32_t start_chunk, uint32_t end_chunk,
    int64_t timestamp, uint8_t *signature, size_t siglen)
{
	struct msg *msg = pg_buffer_advance(buf, MSG_LENGTH(msg_signed_integrity) + siglen);

	msg->message_type = MSG_SIGNED_INTEGRITY;
	msg->signed_integrity.start_chunk = htobe32(start_chunk);
	msg->signed_integrity.end_chunk = htobe32(end_chunk);
	msg->signed_integrity.timestamp = timestamp;
	memcpy(msg->signed_integrity.signature, signature, siglen);
}

void
pack_request(struct pg_buffer *buf, uint32_t start_chunk, uint32_t end_chunk)
{
	struct msg *msg = pg_buffer_advance(buf, MSG_LENGTH(msg_request));

	msg->message_type = MSG_REQUEST;
	msg->request.start_chunk = htobe32(start_chunk);
	msg->request.end_chunk = htobe32(end_chunk);
}

void
pack_cancel(struct pg_buffer *buf, uint32_t start_chunk, uint32_t end_chunk)
{
	struct msg *msg = pg_buffer_advance(buf, MSG_LENGTH(msg_cancel));

	msg->message_type = MSG_CANCEL;
	msg->cancel.start_chunk = htonl(start_chunk);
	msg->cancel.end_chunk = htonl(end_chunk);
}

void
pack_pex_resv4(struct pg_buffer *buf, in_addr_t ip_address, uint16_t port)
{
	struct msg *msg = pg_buffer_advance(buf, MSG_LENGTH(msg_pex_resv4));

	msg->message_type = MSG_PEX_RESV4;
	msg->pex_resv4.ip_address = ip_address;
	msg->pex_resv4.port = port;
}

void
pack_pex_req(struct pg_buffer *buf)
{
	struct msg *msg = pg_buffer_advance(buf, sizeof(uint8_t));

	msg->message_type = MSG_PEX_REQ;
}
