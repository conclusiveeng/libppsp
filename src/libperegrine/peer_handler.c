#include "peer_handler.h"
#include "include/peregrine_socket.h"
#include "log.h"
#include "ppspp_protocol.h"
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>

int
peer_handle_request(struct peregrine_context *ctx, struct peregrine_peer *peer, char *input_data, size_t input_size,
                    char *response_buffer, size_t response_size)
{
  PEREGRINE_DEBUG("CTX %d", ctx->sock_fd);
  PEREGRINE_DEBUG("PEER: %s", peer->str_addr);

  if (input_size == 4) {
    // KEEPALIVE message it's safe to ignore
    response_buffer = NULL;
    return 0;
  }

  if (message_type(input_data) == HANDSHAKE) {
    PEREGRINE_DEBUG("[PEER] Got HANDSHAKE message");

    if (handshake_type(input_data) == HANDSHAKE_INIT) {
      PEREGRINE_DEBUG("[PEER] Got HANDSHAKE_INIT message");
      peer->to_remove = 0;
      return 0;
    }

    if (handshake_type(input_data) == HANDSHAKE_FINISH) {
      PEREGRINE_DEBUG("[PEER] Got HANDSHAKE_FINISH message");
      // peer wants to close the connection
      peer->to_remove = 1;
      return 0;
    }
  }

  memcpy(response_buffer, input_data, response_size);
  return 100;
}
