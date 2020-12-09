#include "proto_helper.h"
#include "log.h"
#include "peer_handler.h"
#include <string.h>

void
proto_print_protocol_options(struct ppspp_protocol_options *proto_options)
{
  char buffer[256];
  PEREGRINE_DEBUG("VERSION IS: %d", proto_options->version);
  PEREGRINE_DEBUG("MININUM VERSION IS: %d", proto_options->minimum_version);
  PEREGRINE_DEBUG("SWARM_ID_LEN: %u", proto_options->swarm_id_len);
  dbgutil_str2hex((char *)proto_options->swarm_id, proto_options->swarm_id_len, buffer, 256);
  PEREGRINE_DEBUG("SWARM_ID: %s", buffer);
  PEREGRINE_DEBUG("CONTENT PROTOCOL METHOD: %d", proto_options->content_prot_method);
  PEREGRINE_DEBUG("CHUNK ADDR METHOD: %d", proto_options->chunk_addr_method);
  PEREGRINE_DEBUG("MERKLE HASH FUNC: %d", proto_options->merkle_hash_func);
  PEREGRINE_DEBUG("LIVE SIGNATURE ALG: %d", proto_options->live_signature_alg);
  PEREGRINE_DEBUG("LIVE DISCARD WINDOW: %u", proto_options->live_disc_wind);
  PEREGRINE_DEBUG("SUPPORTED MESSAGES LEN: %d", proto_options->supported_msgs_len);
  PEREGRINE_DEBUG("CHUNK SIZE: %u", proto_options->chunk_size);
}

enum ppspp_handshake_type
proto_parse_handshake(char *ptr, uint32_t *dest_chan_id, uint32_t *src_chan_id,
                      struct ppspp_protocol_options *proto_options, uint32_t *bytes_parsed)
{
  // FIXME: Maybe 'struct msg_handshake' could be use for parsing
  //  Descritpion can be found at section 8.4 of https://tools.ietf.org/rfc/rfc7574.txt
  uint8_t *msg_ptr = (uint8_t *)ptr;
  enum ppspp_handshake_type ret = HANDSHAKE_ERROR;

  *dest_chan_id = be32toh(*(uint32_t *)msg_ptr);
  msg_ptr += sizeof(uint32_t);
  if (*msg_ptr != MSG_HANDSHAKE) {
    PEREGRINE_ERROR("[PEER] Wrong HANDSHAKE message format. Should be %u, actual value: %u", 0, *msg_ptr);
    *bytes_parsed = (char *)msg_ptr - ptr;
    return HANDSHAKE_ERROR;
  }
  msg_ptr += sizeof(uint8_t);
  *src_chan_id = be32toh(*(uint32_t *)msg_ptr);
  msg_ptr += sizeof(uint32_t);

  // Peer wants to initiate connection
  if ((*dest_chan_id == 0x0) && (*src_chan_id != 0x0)) {
    ret = HANDSHAKE_INIT;
  }
  // Peer wants to close connection
  if ((*dest_chan_id != 0x0) && (*src_chan_id == 0x0)) {
    // Don't parse handshake if it's close request!
    *bytes_parsed = (char *)msg_ptr - ptr;
    return HANDSHAKE_CLOSE;
  }

  // Parse peer options send with handshake
  if (*msg_ptr == F_VERSION) {
    msg_ptr += sizeof(uint8_t);
    proto_options->version = *msg_ptr;
    msg_ptr += sizeof(uint8_t);
  }

  if (*msg_ptr == F_MINIMUM_VERSION) {
    msg_ptr += sizeof(uint8_t);
    proto_options->minimum_version = *msg_ptr;
    msg_ptr += sizeof(uint8_t);
  }

  if (*msg_ptr == F_SWARM_ID) {
    msg_ptr += sizeof(uint8_t);
    proto_options->swarm_id_len = be16toh(*((uint16_t *)msg_ptr) & 0xffff);
    msg_ptr += sizeof(uint16_t);
    memcpy(proto_options->swarm_id, msg_ptr, proto_options->swarm_id_len);
    msg_ptr += proto_options->swarm_id_len;
  }

  if (*msg_ptr == F_CONTENT_PROT_METHOD) {
    msg_ptr += sizeof(uint8_t);
    proto_options->content_prot_method = *msg_ptr;
    msg_ptr += sizeof(uint8_t);
  }

  if (*msg_ptr == F_MERKLE_HASH_FUNC) {
    msg_ptr += sizeof(uint8_t);
    proto_options->merkle_hash_func = *msg_ptr;
    msg_ptr += sizeof(uint8_t);
  }

  if (*msg_ptr == F_LIVE_SIGNATURE_ALG) {
    msg_ptr += sizeof(uint8_t);
    proto_options->live_signature_alg = *msg_ptr;
    msg_ptr += sizeof(uint8_t);
  }

  if (*msg_ptr == F_CHUNK_ADDR_METHOD) {
    msg_ptr += sizeof(uint8_t);
    proto_options->chunk_addr_method = *msg_ptr;
    msg_ptr += sizeof(uint8_t);
  }

  if (*msg_ptr == F_LIVE_DISC_WIND) {
    msg_ptr += sizeof(uint8_t);
    switch (proto_options->chunk_addr_method) {
    case 0:
    case 2:
      proto_options->live_disc_wind = be32toh(*(uint32_t *)msg_ptr);
      msg_ptr += sizeof(uint32_t);
      break;
    case 1:
    case 3:
    case 4:
      proto_options->live_disc_wind = be64toh(*(uint64_t *)msg_ptr);
      msg_ptr += sizeof(uint64_t);
      break;
    default:
      *bytes_parsed = (char *)msg_ptr - ptr;
      return HANDSHAKE_ERROR;
    }
  }

  if (*msg_ptr == F_SUPPORTED_MSGS) {
    msg_ptr += sizeof(uint8_t);
    proto_options->supported_msgs_len = *msg_ptr;
    msg_ptr += sizeof(uint8_t);
    // WARN: For now we ignore this field of protocol options - normally here we should parse the bitmap of supported
    // messages
    msg_ptr += proto_options->supported_msgs_len;
  }

  if (*msg_ptr == F_CHUNK_SIZE) {
    msg_ptr += sizeof(uint8_t);
    proto_options->chunk_size = be32toh(*(uint32_t *)msg_ptr);
    msg_ptr += sizeof(uint32_t);
  }

  if ((*msg_ptr & 0xff) == F_END_OPTION) {
    msg_ptr += sizeof(uint8_t);
  } else {
    PEREGRINE_ERROR("[PEER] Should be END_OPTION(0xff) but it is: d[%td]: %d", (char *)msg_ptr - ptr, *msg_ptr & 0xff);
    return HANDSHAKE_ERROR;
  }

  *bytes_parsed = (char *)msg_ptr - ptr;
  PEREGRINE_DEBUG("[PEER] parsed %td bytes", *bytes_parsed);
  return ret;
}

int
proto_prepare_handshake(struct peregrine_peer *peer, size_t response_buffer_size, char *response)
{
  size_t response_size;
  struct msg_handshake proto_handshake;
  proto_handshake.dst_channel_id = htobe32(peer->dst_channel_id);
  proto_handshake.f_handshake_type = MSG_HANDSHAKE;
  proto_handshake.src_channel_id = htobe32(peer->src_channel_id);
  proto_handshake.f_version = F_VERSION;
  proto_handshake.version = 1;
  proto_handshake.f_min_version = F_MINIMUM_VERSION;
  proto_handshake.min_version = 1;
  proto_handshake.f_swarm_id = F_SWARM_ID;
  proto_handshake.swarm_id_len = htobe16(peer->protocol_options.swarm_id_len & 0xffff);
  memcpy(proto_handshake.swarm_id, peer->protocol_options.swarm_id, 20); // Respond with same swarm id
  proto_handshake.f_content_prot_method = F_CONTENT_PROT_METHOD;
  proto_handshake.content_prot_method = 1;
  proto_handshake.f_merkle_hash_func = F_MERKLE_HASH_FUNC;
  proto_handshake.merkle_hash_func = 0;
  proto_handshake.f_live_signature_alg = F_LIVE_SIGNATURE_ALG;
  proto_handshake.live_signature_alg = peer->protocol_options.live_signature_alg;
  proto_handshake.f_chunk_addr_method = F_CHUNK_ADDR_METHOD;
  proto_handshake.chunk_addr_method = 2;
  // Live discard window and supported messages bitmap are currently omitted from handshake currently
  //
  //   proto_handshake.f_live_disc_wind = F_LIVE_DISC_WIND;
  //   proto_handshake.live_disc_wind = peer->protocol_options.live_disc_wind;
  //   proto_handshake.f_supported_msg = F_SUPPORTED_MSGS;
  //   proto_handshake.supported_msg_len = 1; // bitmap of supported messages consists of 1 bytes
  //   proto_handshake.supported_msg = 0xff;  // bitmap of supported messages
  //
  // Live discard window and supported messages bitmap are currently omitted from handshake currently
  proto_handshake.f_chunk_size = F_CHUNK_SIZE;
  proto_handshake.chunk_size = htobe32(1024);
  proto_handshake.end_opt = F_END_OPTION;

  response_size = sizeof(struct msg_handshake);
  if (response_size <= response_buffer_size) {
    memcpy(response, &proto_handshake, response_size);
    return response_size;
  }

  return 0;
}

int
proto_prepare_handshake_replay(struct peregrine_peer *peer, size_t response_buffer_size, char *response)
{
  size_t response_size;
  struct msg_handshake_reply proto_handshake;
  proto_handshake.dst_channel_id = htobe32(peer->dst_channel_id);
  proto_handshake.f_handshake_type = MSG_HANDSHAKE;
  proto_handshake.src_channel_id = htobe32(peer->src_channel_id);
  proto_handshake.f_version = F_VERSION;
  proto_handshake.version = 1;
  proto_handshake.f_min_version = F_MINIMUM_VERSION;
  proto_handshake.min_version = 1;
  proto_handshake.f_content_prot_method = F_CONTENT_PROT_METHOD;
  proto_handshake.content_prot_method = 1;
  proto_handshake.f_merkle_hash_func = F_MERKLE_HASH_FUNC;
  proto_handshake.merkle_hash_func = 0;
  proto_handshake.f_chunk_addr_method = F_CHUNK_ADDR_METHOD;
  proto_handshake.chunk_addr_method = 2;
  proto_handshake.end_opt = F_END_OPTION;

  response_size = sizeof(struct msg_handshake_reply);
  if (response_size <= response_buffer_size) {
    memcpy(response, &proto_handshake, response_size);
    return response_size;
  }

  return 0;
}

int
proto_prepare_have(struct peregrine_peer *peer, size_t response_buffer_size, char *response)
{

  uint32_t bit = 31; /* starting bit for scanning of bits */
  uint32_t it = 0;   /* iterator */
  uint32_t val = 0;
  uint32_t offset = 0;

  //     /* alloc memory for HAVE cache */
  //   peer->have_cache = malloc(1024 * sizeof(struct have_cache));
  //   peer->num_have_cache = 0;

  while (it < 32) {
    if (peer->file->nc & (1 << bit)) { /* if the bit on position "b" is set? */
      PEREGRINE_INFO("HAVE: %u..%u", val, val + (1 << bit) - 1);

      offset += pack_have(response + offset, val, val + (1 << bit) - 1);
      PEREGRINE_INFO("OFFSET: %d", offset);
      PEREGRINE_INFO("VALUE: %d", val);

      //       /* add HAVE header + data */
      //       *d = HAVE;
      //       d++;

      //       *(uint32_t *)d = htobe32(v);
      //       d += sizeof(uint32_t);
      //       peer->have_cache[peer->num_have_cache].start_chunk = val;

      //       *(uint32_t *)d = htobe32(v + (1 << b) - 1);
      //       d += sizeof(uint32_t);
      //       peer->have_cache[peer->num_have_cache].end_chunk = val + (1 << bit) - 1;

      val = val + (1 << bit);
      //       peer->num_have_cache++;
    }
    it++;
    bit--;
  }
  return offset;
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

// size_t
// pack_pex_req(void *dptr)
// {
//   struct msg *msg = dptr;

//   msg->message_type = MSG_EX_REQ;

//   return (sizeof(uint8_t));
// }
