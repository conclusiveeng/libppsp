#include "peer_handler.h"
#include "include/peregrine_socket.h"
#include "log.h"
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>

void
print_dbg_protocol_options(struct ppspp_protocol_options *proto_options)
{
  char buffer[256];
  PEREGRINE_DEBUG("VERSION IS: %d", proto_options->version);
  PEREGRINE_DEBUG("MININUM VERSION IS: %d", proto_options->minimum_version);
  PEREGRINE_DEBUG("SWARM_ID_LEN: %u", proto_options->swarm_id_len);
  dbgutil_str2hex(proto_options->swarm_id, proto_options->swarm_id_len, buffer, 256);
  PEREGRINE_DEBUG("SWARM_ID: %s", buffer);
  PEREGRINE_DEBUG("CONTENT PROTOCOL METHOD: %d", proto_options->content_prot_method);
  PEREGRINE_DEBUG("CHUNK ADDR METHOD: %d", proto_options->chunk_addr_method);
  PEREGRINE_DEBUG("MERKLE HASH FUNC: %d", proto_options->merkle_hash_func);
  PEREGRINE_DEBUG("LIVE SIGNATURE ALG: %d", proto_options->live_signature_alg);
  PEREGRINE_DEBUG("LIVE DISCARD WINDOW: %u", proto_options->live_disc_wind);
  PEREGRINE_DEBUG("SUPPORTED MESSAGES LEN: %d", proto_options->supported_msgs_len);
  PEREGRINE_DEBUG("CHUNK SIZE: %u", proto_options->chunk_size);
}

uint8_t
parse_message_type(const char *ptr)
{
  const struct msg *msg = (const struct msg *)&ptr[4];
  return (msg->message_type);
}

enum ppspp_handshake_type
parse_handshake(char *ptr, uint32_t *dest_chan_id, uint32_t *src_chan_id, struct ppspp_protocol_options *proto_options,
                uint8_t *bytes_parsed)
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
response_handshake(struct peregrine_peer *peer, size_t response_buffer_size, char *response)
{
  size_t response_size;
  struct msg_handshake proto_handshake;
  proto_handshake.dst_channel_id = htobe32(peer->src_channel_id); // peer->src_channel_id; // Cross channel
  proto_handshake.src_channel_id = htobe32(peer->dst_channel_id); // peer->dst_channel_id;
  proto_handshake.f_handshake_type = MSG_HANDSHAKE;
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

  // Should we send also HAVE message, with what we've got?
  return 0;
}

int
peer_handle_request(struct peregrine_context *ctx, struct peregrine_peer *peer, char *input_data, size_t input_size,
                    char *response_buffer, size_t max_response_size)
{
  PEREGRINE_DEBUG("CTX %d", ctx->sock_fd);
  PEREGRINE_DEBUG("PEER: %s", peer->str_addr);
  uint32_t src_channel_id = 0;
  uint32_t dst_channel_id = 0;
  uint8_t bytes_done = 0;

  if (input_size == 4) {
    // KEEPALIVE message it's safe to ignore
    response_buffer = NULL;
    src_channel_id = be32toh(*(uint32_t *)input_data);
    PEREGRINE_DEBUG("CHANNEL_ID KEEPALIVE: %ul", src_channel_id);
    return 0;
  }

  if (parse_message_type(input_data) == MSG_HANDSHAKE) {
    PEREGRINE_DEBUG("[PEER] Got HANDSHAKE message");

    if (parse_handshake(input_data, &dst_channel_id, &src_channel_id, &peer->protocol_options, &bytes_done)
        == HANDSHAKE_CLOSE) {
      PEREGRINE_DEBUG("[PEER] Got HANDSHAKE_FINISH message");
      // peer wants to close the connection
      peer->to_remove = 1;
      return 0;
    }

    if (parse_handshake(input_data, &dst_channel_id, &src_channel_id, &peer->protocol_options, &bytes_done)
        == HANDSHAKE_INIT) {
      PEREGRINE_DEBUG("[PEER] Got HANDSHAKE_INIT message");
      peer->src_channel_id = src_channel_id;
      peer->dst_channel_id = 8; // Choosen by hand
      print_dbg_protocol_options(&peer->protocol_options);
      peer->to_remove = 0;

      size_t resp = response_handshake(peer, max_response_size, response_buffer);
      PEREGRINE_DEBUG("Resp size: %d", resp);

      return resp;
    }
  }
  if (parse_message_type(input_data) == MSG_DATA) {
    PEREGRINE_DEBUG("GOT MSG_DATA");
    return 0;
  }
  if (parse_message_type(input_data) == MSG_ACK) {
    PEREGRINE_DEBUG("GOT MSG_ACK");
    return 0;
  }
  if (parse_message_type(input_data) == MSG_HAVE) {
    PEREGRINE_DEBUG("GOT MSG_HAVE");
    return 0;
  }
  if (parse_message_type(input_data) == MSG_INTEGRITY) {
    PEREGRINE_DEBUG("GOT MSG_INTEGRITY");
    return 0;
  }
  if (parse_message_type(input_data) == MSG_PEX_RESV4) {
    PEREGRINE_DEBUG("GOT MSG_PEX_RESV4");
    return 0;
  }
  if (parse_message_type(input_data) == MSG_PEX_REQ) {
    PEREGRINE_DEBUG("GOT MSG_PEX_REQ");
    return 0;
  }
  if (parse_message_type(input_data) == MSG_SIGNED_INTEGRITY) {
    PEREGRINE_DEBUG("GOT MSG_SIGNED_INTEGRITY");
    return 0;
  }
  if (parse_message_type(input_data) == MSG_REQUEST) {
    PEREGRINE_DEBUG("GOT MSG_REQUEST");
    return 0;
  }
  if (parse_message_type(input_data) == MSG_CANCEL) {
    PEREGRINE_DEBUG("GOT MSG_CANCEL");
    return 0;
  }
  if (parse_message_type(input_data) == MSG_CHOKE) {
    PEREGRINE_DEBUG("GOT MSG_CHOKE");
    return 0;
  }
  if (parse_message_type(input_data) == MSG_UNCHOKE) {
    PEREGRINE_DEBUG("GOT MSG_UNCHOKE");
    return 0;
  }
  if (parse_message_type(input_data) == MSG_PEX_RESV6) {
    PEREGRINE_DEBUG("GOT MSG_PEX_RESV6");
    return 0;
  }
  if (parse_message_type(input_data) == MSG_PEX_RESCERT) {
    PEREGRINE_DEBUG("GOT MSG_PEX_RESCERT");
    return 0;
  }

  PEREGRINE_DEBUG("READ %d, PARSED: %d", input_size, bytes_done);
  if (input_size == bytes_done) {
    return 0;
  }

  // memcpy(response_buffer, input_data, response_size);
  return 100;
}
