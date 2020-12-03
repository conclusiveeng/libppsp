#include "peer_handler.h"
#include "include/peregrine_socket.h"
#include "log.h"
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>

uint8_t
parse_message_type(const char *ptr)
{
  const struct msg *msg = (const struct msg *)&ptr[4];
  return (msg->message_type);
}

enum ppspp_handshake_type
parse_handshake(char *ptr, uint32_t *dest_chan_id, uint32_t *src_chan_id, struct ppspp_protocol_options *proto_options)
{
  //  Descritpion can be found at section 8.4 of https://tools.ietf.org/rfc/rfc7574.txt
  uint8_t *msg_ptr = (uint8_t *)ptr;
  enum ppspp_handshake_type ret = HANDSHAKE_ERROR;

  *dest_chan_id = be32toh(*(uint32_t *)msg_ptr);
  msg_ptr += sizeof(uint32_t);
  if (*msg_ptr != MSG_HANDSHAKE) {
    PEREGRINE_ERROR("[PEER] Wrong HANDSHAKE message format. Should be %u, actual value: %u", 0, *msg_ptr);
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
    proto_options->swarm_id = be32toh(*(uint32_t *)msg_ptr);
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

  PEREGRINE_DEBUG("[PEER] parsed %td bytes", (char *)msg_ptr - ptr);
  return ret;
}

void
print_handshake(struct ppspp_protocol_options *proto_options)
{
  PEREGRINE_DEBUG("VERSION IS: %d", proto_options->version);
  PEREGRINE_DEBUG("MININUM VERSION IS: %d", proto_options->minimum_version);
  PEREGRINE_DEBUG("SWARM_ID_LEN: %u", proto_options->swarm_id_len);
  PEREGRINE_DEBUG("SWARM_ID: %u", proto_options->swarm_id);
  PEREGRINE_DEBUG("CONTENT PROTOCOL METHOD: %d", proto_options->content_prot_method);
  PEREGRINE_DEBUG("CHUNK ADDR METHOD: %d", proto_options->chunk_addr_method);
  PEREGRINE_DEBUG("MERKLE HASH FUNC: %d", proto_options->merkle_hash_func);
  PEREGRINE_DEBUG("LIVE SIGNATURE ALG: %d", proto_options->live_signature_alg);
  PEREGRINE_DEBUG("LIVE DISCARD WINDOW: %u", proto_options->live_disc_wind);
  PEREGRINE_DEBUG("SUPPORTED MESSAGES LEN: %d", proto_options->supported_msgs_len);
  PEREGRINE_DEBUG("CHUNK SIZE: %u", proto_options->chunk_size);
}

int
peer_handle_request(struct peregrine_context *ctx, struct peregrine_peer *peer, char *input_data, size_t input_size,
                    char *response_buffer, size_t response_size)
{
  PEREGRINE_DEBUG("CTX %d", ctx->sock_fd);
  PEREGRINE_DEBUG("PEER: %s", peer->str_addr);
  uint32_t src_channel_id = 0;
  uint32_t dst_channel_id = 0;

  if (input_size == 4) {
    // KEEPALIVE message it's safe to ignore
    response_buffer = NULL;
    src_channel_id = be32toh(*(uint32_t *)input_data);
    PEREGRINE_DEBUG("CHANNEL_ID KEEPALIVE: %ul", src_channel_id);
    return 0;
  }

  if (parse_message_type(input_data) == MSG_HANDSHAKE) {
    PEREGRINE_DEBUG("[PEER] Got HANDSHAKE message");

    if (parse_handshake(input_data, &dst_channel_id, &src_channel_id, &peer->protocol_options) == HANDSHAKE_INIT) {
      PEREGRINE_DEBUG("[PEER] Got HANDSHAKE_INIT message");
      PEREGRINE_DEBUG("SRC_CHAN: %u, DST_CHAN: %u", src_channel_id, dst_channel_id);
      print_handshake(&peer->protocol_options);
      peer->to_remove = 0;
      return 0;
    }

    if (parse_handshake(input_data, &dst_channel_id, &src_channel_id, &peer->protocol_options) == HANDSHAKE_CLOSE) {
      PEREGRINE_DEBUG("[PEER] Got HANDSHAKE_FINISH message");
      // peer wants to close the connection
      peer->to_remove = 1;
      return 0;
    }
  }

  memcpy(response_buffer, input_data, response_size);
  return 100;
}
