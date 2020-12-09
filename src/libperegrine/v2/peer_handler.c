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

    if (proto_parse_handshake(input_data, &dst_channel_id, &src_channel_id, &peer->protocol_options, &bytes_done)
        == HANDSHAKE_CLOSE) {
      PEREGRINE_DEBUG("[PEER] Got HANDSHAKE_FINISH message");
      // peer wants to close the connection
      peer->to_remove = 1;
      return 0;
    }

    if (proto_parse_handshake(input_data, &dst_channel_id, &src_channel_id, &peer->protocol_options, &bytes_done)
        == HANDSHAKE_INIT) {
      PEREGRINE_DEBUG("[PEER] Got HANDSHAKE_INIT message");
      peer->src_channel_id = src_channel_id;
      peer->dst_channel_id = 8; // Choosen by hand
      proto_print_protocol_options(&peer->protocol_options);
      peer->to_remove = 0;

      size_t resp = proto_prepare_handshake(peer, max_response_size, response_buffer);
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
