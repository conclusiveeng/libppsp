#include "peer_handler.h"
#include "file.h"
#include "log.h"
#include "peregrine_socket.h"
#include "proto_helper.h"
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>

uint8_t
parse_message_type(const char *ptr)
{
  const struct msg *msg = (const struct msg *)&ptr[4];
  return (msg->message_type);
}

int
peer_handle_handshake(struct peregrine_context *ctx, struct peregrine_peer *peer, char *input,
                      size_t max_response_size, char *response_buffer, uint32_t *bytes_parsed)
{
  uint32_t src_channel_id = 0;
  uint32_t dst_channel_id = 0;
  uint32_t bytes_done = 0;
  size_t resp = 0;
  PEREGRINE_DEBUG("[PEER] Got HANDSHAKE message");

  enum ppspp_handshake_type handshake_type
      = proto_parse_handshake(input, &dst_channel_id, &src_channel_id, &peer->protocol_options, &bytes_done);

  if (handshake_type == HANDSHAKE_CLOSE) {
    PEREGRINE_DEBUG("[PEER] Got HANDSHAKE_FINISH message");
    // peer wants to close the connection
    peer->to_remove = 1;
  } else if (handshake_type == HANDSHAKE_INIT) {
    PEREGRINE_DEBUG("[PEER] Got HANDSHAKE_INIT message");
    peer->src_channel_id = src_channel_id;
    peer->dst_channel_id = 8; // Choosen by hand
    peer->to_remove = 0;
    proto_print_protocol_options(&peer->protocol_options);

    resp = proto_prepare_handshake(peer, max_response_size, response_buffer);
    PEREGRINE_DEBUG("HANDSHAKE: %d bytes", resp);
    peer->file = peregrine_file_find(ctx, peer->protocol_options.swarm_id);
    if (peer->file) {
      PEREGRINE_DEBUG("Remote peer selected file: %s", peer->file->path);
      resp += proto_prepare_have(peer, max_response_size - resp, response_buffer + resp);
      PEREGRINE_DEBUG("Sending HANDSHAKE + HAVE %d bytes", resp);
    } else {
      PEREGRINE_ERROR("Remote peer asked for not existing file!");
      // Skip sending HAVE message
    }
  }
  *bytes_parsed = bytes_done;
  return resp;
}

int
peer_handle_request(struct peregrine_context *ctx, struct peregrine_peer *peer, char *input_data, size_t input_size,
                    char *response_buffer, size_t max_response_size)
{
  uint32_t src_channel_id = 0;
  uint32_t bytes_done = 0;
  size_t resp = 0;
  PEREGRINE_DEBUG("CTX %d", ctx->sock_fd);

  if (input_size == 4) {
    // KEEPALIVE message it's safe to ignore
    response_buffer = NULL;
    src_channel_id = be32toh(*(uint32_t *)input_data);
    PEREGRINE_DEBUG("CHANNEL_ID KEEPALIVE: %ul", src_channel_id);
    return 0;
  }
  PEREGRINE_INFO("PEER %s SRC:%d DEST:%d", peer->str_addr, peer->src_channel_id, peer->dst_channel_id);

  switch (parse_message_type(input_data)) {
  case MSG_HANDSHAKE:
    resp = peer_handle_handshake(ctx, peer, input_data, max_response_size, response_buffer, &bytes_done);
    break;
  case MSG_DATA:
    PEREGRINE_DEBUG("GOT MSG_DATA");
    break;
  case MSG_ACK:
    PEREGRINE_DEBUG("GOT MSG_ACK");
    break;
  case MSG_HAVE:
    PEREGRINE_DEBUG("GOT MSG_HAVE");
    break;
  case MSG_INTEGRITY:
    PEREGRINE_DEBUG("GOT MSG_INTEGRITY");
    break;
  case MSG_PEX_RESV4:
    PEREGRINE_DEBUG("GOT MSG_PEX_RESV4");
    break;
  case MSG_PEX_REQ:
    PEREGRINE_DEBUG("GOT MSG_PEX_REQ");
    break;
  case MSG_SIGNED_INTEGRITY:
    PEREGRINE_DEBUG("GOT MSG_SIGNED_INTEGRITY");
    break;
  case MSG_REQUEST:
    PEREGRINE_DEBUG("GOT MSG_REQUEST");
    break;
  case MSG_CANCEL:
    PEREGRINE_DEBUG("GOT MSG_CANCEL");
    break;
  case MSG_CHOKE:
    PEREGRINE_DEBUG("GOT MSG_CHOKE");
    break;
  case MSG_UNCHOKE:
    PEREGRINE_DEBUG("GOT MSG_UNCHOKE");
    break;
  case MSG_PEX_RESV6:
    PEREGRINE_DEBUG("GOT MSG_PEX_RESV6");
    break;
  case MSG_PEX_RESCERT:
    PEREGRINE_DEBUG("GOT MSG_PEX_RESCERT");
    break;
  default:
    break;
  }

  PEREGRINE_DEBUG("READ %d, PARSED: %d RESP: %d", input_size, bytes_done, resp);
  return resp;
}
