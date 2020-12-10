#include "peer_handler.h"
#include "log.h"
#include "peregrine_socket.h"
#include "proto_helper.h"
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>

ssize_t pg_handle_message(struct peregrine_peer *peer, struct msg *msg);
ssize_t pg_handle_handshake(struct peregrine_peer *peer, struct msg *msg);
ssize_t pg_handle_data(struct peregrine_peer *peer, struct msg *msg);
ssize_t pg_handle_ack(struct peregrine_peer *peer, struct msg *msg);
ssize_t pg_handle_have(struct peregrine_peer *peer, struct msg *msg);
ssize_t pg_handle_integrity(struct peregrine_peer *peer, struct msg *msg);
ssize_t pg_handle_pex_resv4(struct peregrine_peer *peer, struct msg *msg);
ssize_t pg_handle_pex_req(struct peregrine_peer *peer, struct msg *msg);
ssize_t pg_handle_signed_integrity(struct peregrine_peer *peer, struct msg *msg);
ssize_t pg_handle_request(struct peregrine_peer *peer, struct msg *msg);
ssize_t pg_handle_cancel(struct peregrine_peer *peer, struct msg *msg);
ssize_t pg_handle_choke(struct peregrine_peer *peer, struct msg *msg);
ssize_t pg_handle_unchoke(struct peregrine_peer *peer, struct msg *msg);

struct peregrine_frame_handler {
  enum peregrine_message_type type;
  ssize_t (*handler)(struct peregrine_peer *, struct msg *);
};

static const struct peregrine_frame_handler frame_handlers[] = { { MSG_HANDSHAKE, pg_handle_handshake },
                                                                 { MSG_DATA, pg_handle_data },
                                                                 { MSG_ACK, pg_handle_ack },
                                                                 { MSG_HAVE, pg_handle_have },
                                                                 { MSG_INTEGRITY, pg_handle_integrity },
                                                                 { MSG_PEX_RESV4, pg_handle_pex_resv4 },
                                                                 { MSG_PEX_REQ, pg_handle_pex_req },
                                                                 { MSG_SIGNED_INTEGRITY, pg_handle_signed_integrity },
                                                                 { MSG_REQUEST, pg_handle_request },
                                                                 { MSG_CANCEL, pg_handle_cancel },
                                                                 { MSG_CHOKE, pg_handle_choke },
                                                                 { MSG_UNCHOKE, pg_handle_unchoke },
                                                                 { MSG_RESERVED, NULL } };

void
print_dbg_protocol_options(struct ppspp_protocol_options *proto_options)
{
  char buffer[256];
  DEBUG("VERSION IS: %d", proto_options->version);
  DEBUG("MININUM VERSION IS: %d", proto_options->minimum_version);
  DEBUG("SWARM_ID_LEN: %u", proto_options->swarm_id_len);
  dbgutil_str2hex(proto_options->swarm_id, proto_options->swarm_id_len, buffer, 256);
  DEBUG("SWARM_ID: %s", buffer);
  DEBUG("CONTENT PROTOCOL METHOD: %d", proto_options->content_prot_method);
  DEBUG("CHUNK ADDR METHOD: %d", proto_options->chunk_addr_method);
  DEBUG("MERKLE HASH FUNC: %d", proto_options->merkle_hash_func);
  DEBUG("LIVE SIGNATURE ALG: %d", proto_options->live_signature_alg);
  DEBUG("LIVE DISCARD WINDOW: %u", proto_options->live_disc_wind);
  DEBUG("SUPPORTED MESSAGES LEN: %d", proto_options->supported_msgs_len);
  DEBUG("CHUNK SIZE: %u", proto_options->chunk_size);
}

ssize_t
pg_handle_message(struct peregrine_peer *peer, struct msg *msg)
{
  const struct peregrine_frame_handler *handler;

  for (handler = &frame_handlers[0]; handler->handler != NULL; handler++) {
    if (handler->type == msg->message_type) {
      return (handler->handler(peer, msg));
    }
  }

  return (-1);
}

ssize_t
pg_handle_handshake(struct peregrine_peer *peer, struct msg *msg)
{
  struct msg_handshake_opt *opt;
  struct ppspp_protocol_options options;
  int pos = 0;

  DEBUG("handshake: peer=%p", peer);

  for (;;) {
    opt = (struct msg_handshake_opt *)&msg->handshake.protocol_options[pos];

    switch (opt->code) {
    case HANDSHAKE_OPT_VERSION:
      options.version = opt->value[0];
      pos += sizeof(opt) + sizeof(uint8_t);
      DEBUG("handshake: version = %d\n", options.version);
      break;

    case HANDSHAKE_OPT_MIN_VERSION:
      options.minimum_version = opt->value[0];
      pos += sizeof(opt) + sizeof(uint8_t);
      DEBUG("handshake: minimum_version = %d\n", options.version);
      break;

    case HANDSHAKE_OPT_SWARM_ID:
      options.swarm_id_len = be16toh(*(uint16_t *)opt->value);
      memcpy(&options.swarm_id, &opt->value[sizeof(uint16_t)], options.swarm_id_len);
      pos += sizeof(opt) + options.swarm_id_len;
      DEBUG("handshake: minimum_version = %d\n", options.minimum_version);
      break;

    case HANDSHAKE_OPT_MERKLE_HASH_FUNC:
      options.merkle_hash_func = opt->value[0];
      pos += sizeof(opt) + sizeof(uint8_t);
      DEBUG("handshake: merkle_hash_func = %d\n", options.merkle_hash_func);
      break;

    case HANDSHAKE_OPT_LIVE_SIGNATURE_ALGO:
      options.live_signature_alg = opt->value[0];
      pos += sizeof(opt) + sizeof(uint8_t);
      DEBUG("handshake: live_signature_alg = %d\n", options.live_signature_alg);
      break;

    case HANDSHAKE_OPT_CHUNK_SIZE:
      options.chunk_size = be32toh(*(uint32_t *)opt->value);
      pos += sizeof(opt) + sizeof(uint32_t);
      DEBUG("handshake: chunk_size = %d\n", options.chunk_size);
      break;

    case HANDSHAKE_OPT_END:
      goto done;
    }
  }

done:
  return -1;
}

ssize_t
pg_handle_data(struct peregrine_peer *peer, struct msg *msg)
{
}

ssize_t
pg_handle_ack(struct peregrine_peer *peer, struct msg *msg)
{
}

ssize_t
pg_handle_have(struct peregrine_peer *peer, struct msg *msg)
{
}

ssize_t
pg_handle_integrity(struct peregrine_peer *peer, struct msg *msg)
{
}

ssize_t
pg_handle_pex_resv4(struct peregrine_peer *peer, struct msg *msg)
{
}

ssize_t
pg_handle_pex_req(struct peregrine_peer *peer, struct msg *msg)
{
  uint32_t bytes_done = 0;
  uint32_t remote_channel_id = 0;
  size_t resp = 0;
  DEBUG("[PEER] Got REQUEST message");
  if (msg->message_type == MSG_REQUEST) {
    bytes_done += sizeof(msg->message_type);
    DEBUG("[PEER] REQUEST start chunk: %d, end chunk: %d", msg->request.start_chunk, msg->request.end_chunk);
    bytes_done += sizeof(struct msg_request);
    peer->seeder_request_start_chunk = msg->request.start_chunk;
    peer->seeder_request_end_chunk = msg->request.end_chunk;
  }

  //   // It's possible that PEX_REQ is attached to the message
  //   if ((input_size - bytes_done) == sizeof(msg->message_type)) {
  //     msg = (const struct msg *)&input[bytes_done];
  //     if (msg->message_type == MSG_PEX_REQ) {
  //       peer->seeder_pex_request = 1;
  //       bytes_done += sizeof(msg->message_type);
  //     }
  //   }

  return 0;
}

ssize_t
pg_handle_signed_integrity(struct peregrine_peer *peer, struct msg *msg)
{
}

ssize_t
pg_handle_request(struct peregrine_peer *peer, struct msg *msg)
{
}

ssize_t
pg_handle_cancel(struct peregrine_peer *peer, struct msg *msg)
{
}

ssize_t
pg_handle_choke(struct peregrine_peer *peer, struct msg *msg)
{
}

ssize_t
pg_handle_unchoke(struct peregrine_peer *peer, struct msg *msg)
{
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
    ERROR("[PEER] Wrong HANDSHAKE message format. Should be %u, actual value: %u", 0, *msg_ptr);
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
    ERROR("[PEER] Should be END_OPTION(0xff) but it is: d[%td]: %d", (char *)msg_ptr - ptr, *msg_ptr & 0xff);
    return HANDSHAKE_ERROR;
  }

  *bytes_parsed = (char *)msg_ptr - ptr;
  DEBUG("[PEER] parsed %td bytes", *bytes_parsed);
  return ret;
}

int
prepare_handshake(struct peregrine_peer *peer, size_t response_buffer_size, char *response)
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

#if 0
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

  // FIXME: Here we should have sendto
  response_size = sizeof(struct msg_handshake);
  if (response_size <= response_buffer_size) {
    memcpy(response, &proto_handshake, response_size);
    return response_size;
  }

#endif

  return 0;
}

int
prepare_have(struct peregrine_peer *peer, size_t response_buffer_size, char *response)
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
      INFO("HAVE: %u..%u", val, val + (1 << bit) - 1);

      offset += pack_have(response + offset, val, val + (1 << bit) - 1);
      INFO("OFFSET: %d", offset);
      INFO("VALUE: %d", val);

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

int
peer_handle_request(struct peregrine_context *ctx, struct peregrine_peer *peer, char *input_data, size_t input_size,
                    char *response_buffer, size_t max_response_size)
{
  DEBUG("CTX %d", ctx->sock_fd);
  DEBUG("PEER: %s", peer->str_addr);

  uint32_t src_channel_id = 0;
  uint32_t dst_channel_id = 0;
  uint8_t bytes_done = 0;

  if (input_size == 4) {
    // KEEPALIVE message it's safe to ignore
    response_buffer = NULL;
    src_channel_id = be32toh(*(uint32_t *)input_data);
    DEBUG("CHANNEL_ID KEEPALIVE: %ul", src_channel_id);
    return 0;
  }

  //    MESSAGE_HANDSHAKE
  DEBUG("[PEER] Got HANDSHAKE message");

  if (parse_handshake(input_data, &dst_channel_id, &src_channel_id, &peer->protocol_options, &bytes_done)
      == HANDSHAKE_CLOSE) {
    DEBUG("[PEER] Got HANDSHAKE_FINISH message");
    // peer wants to close the connection
    peer->to_remove = 1;
    return 0;
  }

  if (parse_handshake(input_data, &dst_channel_id, &src_channel_id, &peer->protocol_options, &bytes_done)
      == HANDSHAKE_INIT) {
    DEBUG("[PEER] Got HANDSHAKE_INIT message");
    peer->src_channel_id = src_channel_id;
    peer->dst_channel_id = 8; // Choosen by hand
    print_dbg_protocol_options(&peer->protocol_options);
    peer->to_remove = 0;

    size_t resp = prepare_handshake(peer, max_response_size, response_buffer);
    DEBUG("Resp size: %d", resp);

    return resp;
  }
  return 0;
}

// /*
//  * generate set of HAVE messages basing on that if given bit in number of chunks
//  * is set or not if set - make proper HAVE subrange in other words - make HAVE
//  * cache
//  */
// int
// prepare_handshake_have(struct peregrine_peer *peer, size_t response_buffer_size, char *response)
// {
//   /* char *ptr, uint32_t dest_chan_id, uint32_t src_chan_id, uint8_t *opts, int opt_len,
//                        struct peer *peer */
//   char *d;
//   int ret;
//   int len;
//   uint32_t b;
//   uint32_t i;
//   uint32_t v;
//   uint32_t nc;

//   /* serialize HANDSHAKE header and options */
//   // len = make_handshake_request(ptr, dest_chan_id, src_chan_id, opts, opt_len);
//   len = prepare_handshake(peer, response_buffer_size, response);

//   /* alloc memory for HAVE cache */
//   peer->have_cache = malloc(1024 * sizeof(struct have_cache));
//   peer->num_have_cache = 0;

//   d = ptr + len;
//   nc = peer->file_list_entry->end_chunk - peer->file_list_entry->start_chunk + 1;

//   b = 31; /* starting bit for scanning of bits */
//   i = 0;  /* iterator */
//   v = 0;
//   while (i < 32) {
//     if (nc & (1 << b)) { /* if the bit on position "b" is set? */
//       d_printf("HAVE: %u..%u\n", v, v + (1 << b) - 1);

//       /* add HAVE header + data */
//       *d = HAVE;
//       d++;

//       *(uint32_t *)d = htobe32(v);
//       d += sizeof(uint32_t);
//       peer->have_cache[peer->num_have_cache].start_chunk = v;

//       *(uint32_t *)d = htobe32(v + (1 << b) - 1);
//       d += sizeof(uint32_t);
//       peer->have_cache[peer->num_have_cache].end_chunk = v + (1 << b) - 1;

//       v = v + (1 << b);
//       peer->num_have_cache++;
//     }
//     i++;
//     b--;
//   }

//   d_printf("num_have_cache: %d\n", peer->num_have_cache);

//   ret = d - ptr;
//   d_printf("%s: returning %d bytes\n", __func__, ret);

//   return ret;
// }
