#include "peer_handler.h"
#include "include/peregrine_socket.h"
#include "log.h"
#include <string.h>

int
peer_handle_request(struct peregrine_context *ctx, struct peregrine_peer *peer, char *input_data,
                    char *response_buffer, size_t response_size)
{
  PEREGRINE_DEBUG("CTX %d", ctx->sock_fd);
  PEREGRINE_DEBUG("PEER: %s", peer->str_addr);

  strncpy(response_buffer, input_data, response_size);
  return response_size;
}
