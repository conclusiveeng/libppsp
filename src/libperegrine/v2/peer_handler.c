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
peer_handle_handshake(struct peregrine_context *ctx, struct peregrine_peer *peer, char *input, size_t input_size,
                      size_t max_response_size, char *response_buffer, uint32_t *bytes_parsed)
{
  uint32_t remote_channel_id = 0;
  uint32_t local_channel_id = 0;
  uint32_t bytes_done = 0;
  size_t resp = 0;
  PEREGRINE_DEBUG("[PEER] Got HANDSHAKE message");

  enum ppspp_handshake_type handshake_type
      = proto_parse_handshake(input, &local_channel_id, &remote_channel_id, &peer->protocol_options, &bytes_done);

  if (handshake_type == HANDSHAKE_CLOSE) {
    PEREGRINE_DEBUG("[PEER] Got HANDSHAKE_FINISH message");
    // peer wants to close the connection
    peer->to_remove = 1;
    // FIXME: Should we send something here?
    resp = 0;
  } else {
    if (peer->handshake_send == 0) {
      // A new leecher want's to cooperate
      peer->to_remove = 0;
      peer->handshake_send = 1;
      peer->dst_channel_id = remote_channel_id;
      peer->src_channel_id = rand() % 65535 + 1;
      PEREGRINE_DEBUG("PEER %s SRC:%d DEST:%d", peer->str_addr, peer->src_channel_id, peer->dst_channel_id);
      resp = proto_prepare_handshake(peer, max_response_size, response_buffer);
      peer->file = peregrine_file_find(ctx, peer->protocol_options.swarm_id);
      if (peer->file) {
	PEREGRINE_DEBUG("Remote peer selected file: %s", peer->file->path);
	resp += proto_prepare_have(peer, max_response_size - resp, response_buffer + resp);
	PEREGRINE_DEBUG("Sending HANDSHAKE + HAVE %d bytes", resp);
	if (peer->seeder_data_bmp == NULL) {
	  peer->seeder_data_bmp = malloc(2 * peer->file->nl / 8);
	  memset(peer->seeder_data_bmp, 0, 2 * peer->file->nl / 8);
	} else {
	  peer->seeder_data_bmp = realloc(peer->seeder_data_bmp, 2 * peer->file->nl / 8);
	  memset(peer->seeder_data_bmp, 0, 2 * peer->file->nl / 8);
	}
      }
    }
    if (peer->handshake_send == 1) {
      // We've got replay to our handshake
      PEREGRINE_INFO("Got replay to handshake");
      PEREGRINE_INFO("PEER %s SRC:%d DEST:%d", peer->str_addr, peer->src_channel_id, peer->dst_channel_id);
      resp = proto_prepare_handshake_replay(peer, max_response_size, response_buffer);
      peer->file = peregrine_file_find(ctx, peer->protocol_options.swarm_id);
      if (peer->file) {
	PEREGRINE_DEBUG("Remote peer selected file: %s", peer->file->path);
	resp += proto_prepare_have(peer, max_response_size - resp, response_buffer + resp);
	PEREGRINE_DEBUG("Sending HANDSHAKE + HAVE %d bytes", resp);
	if (peer->seeder_data_bmp == NULL) {
	  peer->seeder_data_bmp = malloc(2 * peer->file->nl / 8);
	  memset(peer->seeder_data_bmp, 0, 2 * peer->file->nl / 8);
	} else {
	  peer->seeder_data_bmp = realloc(peer->seeder_data_bmp, 2 * peer->file->nl / 8);
	  memset(peer->seeder_data_bmp, 0, 2 * peer->file->nl / 8);
	}
      }
    }
  }
  *bytes_parsed = bytes_done;
  return resp;
}

size_t
peer_make_integrity_reverse(struct peregrine_context *ctx, struct peregrine_peer *peer, size_t max_response_size,
                            char *response_buffer)
{
  peer->seeder_current_chunk = peer->seeder_request_start_chunk;
  do {

    if (peer->seeder_data_bmp[peer->seeder_current_chunk / 8] & (1 << (peer->seeder_current_chunk % 8))) {
      PEREGRINE_DEBUG("DATA %lu already sent - skipping", peer->seeder_current_chunk);
      peer->seeder_current_chunk++;
    }

    //     n = make_integrity_reverse(response_buffer, peer);

    peer->seeder_current_chunk++;
  } while (peer->seeder_current_chunk <= peer->seeder_request_end_chunk);
  return 0;
}

int
peer_handle_request_msg(struct peregrine_context *ctx, struct peregrine_peer *peer, char *input, size_t input_size,
                        size_t max_response_size, char *response_buffer, uint32_t *bytes_parsed)
{
  uint32_t bytes_done = 0;
  uint32_t remote_channel_id = 0;
  size_t resp = 0;
  PEREGRINE_DEBUG("[PEER] Got REQUEST message");
  bytes_done += proto_unpack_channel_id(input, &remote_channel_id);
  const struct msg *msg = (const struct msg *)&input[bytes_done];

  if (msg->message_type == MSG_REQUEST) {
    bytes_done += sizeof(msg->message_type);
    PEREGRINE_DEBUG("[PEER] REQUEST start chunk: %d, end chunk: %d", msg->request.start_chunk, msg->request.end_chunk);
    bytes_done += sizeof(struct msg_request);
    peer->seeder_request_start_chunk = msg->request.start_chunk;
    peer->seeder_request_end_chunk = msg->request.end_chunk;
  }

  // It's possible that PEX_REQ is attached to the message
  if ((input_size - bytes_done) == sizeof(msg->message_type)) {
    msg = (const struct msg *)&input[bytes_done];
    if (msg->message_type == MSG_PEX_REQ) {
      peer->seeder_pex_request = 1;
      bytes_done += sizeof(msg->message_type);
    }
  }

  resp = peer_make_integrity_reverse(ctx, peer, max_response_size, response_buffer);

  *bytes_parsed = bytes_done;
  return resp;
}

int
peer_handle_request(struct peregrine_context *ctx, struct peregrine_peer *peer, char *input_data, size_t input_size,
                    char *response_buffer, size_t max_response_size)
{
  uint32_t remote_channel_id = 0;
  uint32_t bytes_done = 0;
  uint32_t bytes_done_overall = 0;
  size_t resp = 0;
  PEREGRINE_DEBUG("CTX %d", ctx->sock_fd);

  if (input_size == 4) {
    // KEEPALIVE message it's safe to ignore
    response_buffer = NULL;
    remote_channel_id = be32toh(*(uint32_t *)input_data);
    PEREGRINE_DEBUG("CHANNEL_ID KEEPALIVE: %ul", remote_channel_id);
    return 0;
  }
  PEREGRINE_INFO("PEER %s SRC:%d DEST:%d", peer->str_addr, peer->src_channel_id, peer->dst_channel_id);

  switch (parse_message_type(input_data)) {
  case MSG_HANDSHAKE:
    resp = peer_handle_handshake(ctx, peer, input_data, input_size, max_response_size, response_buffer, &bytes_done);
    bytes_done_overall += bytes_done;
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
    // This is rather not possible as it's just msg_type field, usually attached to MSG_REQUEST
    PEREGRINE_DEBUG("GOT MSG_PEX_REQ");
    break;
  case MSG_SIGNED_INTEGRITY:
    PEREGRINE_DEBUG("GOT MSG_SIGNED_INTEGRITY");
    break;
  case MSG_REQUEST:
    resp += peer_handle_request_msg(ctx, peer, input_data + bytes_done_overall, input_size, max_response_size,
                                    response_buffer, &bytes_done);
    bytes_done_overall += bytes_done;
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

  PEREGRINE_DEBUG("READ %d, PARSED: %d RESP: %d", input_size, bytes_done_overall, resp);
  return resp;
}
