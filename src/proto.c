#include <stdlib.h>
#include <string.h>
#include "internal.h"
#include "log.h"

size_t
pack_handshake(void *dptr, uint32_t src_channel_id)
{
	struct msg *msg = dptr;

	msg->message_type = MSG_HANDSHAKE;
	msg->handshake.src_channel_id = htobe32(src_channel_id);

	return (sizeof(uint8_t) + sizeof(msg->handshake));
}

size_t
pack_handshake_opt(void *dptr, uint8_t code, void *data, size_t len)
{
	struct msg_handshake_opt *opt = dptr;

	opt->code = code;
	memcpy(opt->value, data, len);
	return (sizeof(uint8_t) + len);
}

size_t
pack_handshake_opt_u8(void *dptr, uint8_t code, uint8_t value)
{
	struct msg_handshake_opt *opt = dptr;

	opt->code = code;
	opt->value[0] = value;

	return (sizeof(uint8_t) * 2);
}

size_t
pack_handshake_opt_end(void *dptr)
{
	struct msg_handshake_opt *opt = dptr;

	opt->code = HANDSHAKE_OPT_END;

	return (sizeof(uint8_t));
}

size_t
pack_have(void *dptr, uint32_t start_chunk, uint32_t end_chunk)
{
	struct msg *msg = dptr;

	msg->message_type = MSG_HAVE;
	msg->have.start_chunk = htobe32(start_chunk);
	msg->have.end_chunk = htobe32(end_chunk);

	return (sizeof(uint8_t) + sizeof(msg->have));
}

size_t
pack_data(void *dptr, uint32_t start_chunk, uint32_t end_chunk, uint64_t timestamp)
{
	struct msg *msg = dptr;

	msg->message_type = MSG_DATA;
	msg->data.start_chunk = htobe32(start_chunk);
	msg->data.end_chunk = htobe32(end_chunk);
	msg->data.timestamp = htobe64(timestamp);

	return (sizeof(uint8_t) + sizeof(msg->data));
}

size_t
pack_ack(void *dptr, uint32_t start_chunk, uint32_t end_chunk, uint64_t sample)
{
	struct msg *msg = dptr;

	msg->message_type = MSG_ACK;
	msg->ack.start_chunk = htobe32(start_chunk);
	msg->ack.end_chunk = htobe32(end_chunk);
	msg->ack.sample = sample;

	return (sizeof(uint8_t) + sizeof(msg->ack));
}

size_t
pack_integrity(void *dptr, uint32_t end_chunk, uint8_t *hash)
{
	struct msg *msg = dptr;

	msg->message_type = MSG_INTEGRITY;
	msg->integrity.end_chunk = htobe32(end_chunk);
	memcpy(msg->integrity.hash, hash, sizeof(msg->integrity.hash));

	return (sizeof(uint8_t) + sizeof(msg->integrity));
}

size_t
pack_signed_integrity(void *dptr, uint32_t start_chunk, uint32_t end_chunk, int64_t timestamp, uint8_t *signature,
                      size_t siglen)
{
	struct msg *msg = dptr;

	msg->message_type = MSG_SIGNED_INTEGRITY;
	msg->signed_integrity.start_chunk = htobe32(start_chunk);
	msg->signed_integrity.end_chunk = htobe32(end_chunk);
	msg->signed_integrity.timestamp = timestamp;
	memcpy(msg->signed_integrity.signature, signature, siglen);

	return (sizeof(uint8_t) + sizeof(msg->signed_integrity) + siglen);
}

size_t
pack_request(void *dptr, uint32_t start_chunk, uint32_t end_chunk)
{
	struct msg *msg = dptr;

	msg->message_type = MSG_REQUEST;
	msg->request.start_chunk = htobe32(start_chunk);
	msg->request.end_chunk = htobe32(end_chunk);

	return (sizeof(uint8_t) + sizeof(msg->request));
}

size_t
pack_cancel(void *dptr, uint32_t start_chunk, uint32_t end_chunk)
{
	struct msg *msg = dptr;

	msg->message_type = MSG_CANCEL;
	msg->cancel.start_chunk = htonl(start_chunk);
	msg->cancel.end_chunk = htonl(end_chunk);

	return (sizeof(uint8_t) + sizeof(msg->cancel));
}

size_t
pack_dest_chan(void *dptr, uint32_t dst_channel_id)
{
	uint32_t *chan_id = dptr;

	*chan_id = htobe32(dst_channel_id);
	return (sizeof(*chan_id));
}

size_t
pack_pex_resv4(void *dptr, in_addr_t ip_address, uint16_t port)
{
	struct msg *msg = dptr;

	msg->message_type = MSG_PEX_RESV4;
	msg->pex_resv4.ip_address = ip_address;
	msg->pex_resv4.port = port;

	return (sizeof(uint8_t) + sizeof(msg->pex_resv4));
}

size_t
pack_pex_req(void *dptr)
{
	struct msg *msg = dptr;

	msg->message_type = MSG_PEX_REQ;

	return (sizeof(uint8_t));
}
