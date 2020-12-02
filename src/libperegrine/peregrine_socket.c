#include "peregrine_socket.h"
#include "log.h"
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <unistd.h>

void
str_to_hex(char *in, size_t in_size, char *out, size_t out_size)
{
  char *ptr_in = in;
  const char *hex = "0123456789ABCDEF";
  char *ptr_out = out;
  for (; ptr_in < in + in_size; ptr_out += 3, ptr_in++) {
    ptr_out[0] = hex[(*ptr_in >> 4) & 0xF];
    ptr_out[1] = hex[*ptr_in & 0xF];
    ptr_out[2] = ':';
    if (ptr_out + 3 - out > (long)out_size) {
      // Truncate instead of overflow...
      break;
    }
  }
  out[ptr_out - out - 1] = 0;
}

int
peregrine_socket_setup(unsigned long local_port, struct peregrine_context *ctx)
{
  // Crete server socket
  ctx->sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (ctx->sock_fd < 0) {
    PEREGRINE_ERROR("Failed to open socket: %s", strerror(errno));
    return 1;
  }

  // This will allow to setup multiple servers on the same port, use with caution!
  //   int opt_val = 1;
  //   setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &opt_val, sizeof(opt_val));

  // Bind server socket
  ctx->ctx_peer.peer_addr.sin_family = AF_INET;
  ctx->ctx_peer.peer_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  ctx->ctx_peer.peer_addr.sin_port = htons(local_port);
  if (bind(ctx->sock_fd, (struct sockaddr *)(&ctx->ctx_peer.peer_addr), sizeof(ctx->ctx_peer.peer_addr)) < 0) {
    PEREGRINE_ERROR("Failed to bind socket: %s", strerror(errno));
    return 1;
  }

  snprintf(ctx->ctx_peer.str_addr, PEER_STR_ADDR, "%s:%d", inet_ntoa(ctx->ctx_peer.peer_addr.sin_addr),
           ntohs(ctx->ctx_peer.peer_addr.sin_port));
  PEREGRINE_INFO("Setup socket at: %s", ctx->ctx_peer.str_addr);
  ctx->ctx_peer.context = ctx;

  LIST_INIT(&ctx->peers);
  LIST_INIT(&ctx->files);
  LIST_INIT(&ctx->downloads);

  return 0;
}

struct peregrine_peer *
find_existing_peer_or_null(struct peregrine_context *ctx, struct peregrine_peer *searched_peer)
{
  struct peregrine_peer *peer_ptr;
  peer_ptr = LIST_FIRST(&ctx->peers);
  while (peer_ptr != NULL) {
    if (memcmp(&searched_peer->peer_addr, &peer_ptr->peer_addr, sizeof(peer_ptr->peer_addr)) == 0) {
      return peer_ptr;
    }
    peer_ptr = LIST_NEXT(peer_ptr, ptrs);
  }
  return NULL;
}

int
peregrine_socket_add_peer_from_connection(struct peregrine_context *ctx, const struct sockaddr_in *peer_sockaddr,
                                          struct peregrine_peer **peer)
{
  struct peregrine_peer *new_peer = malloc(sizeof(struct peregrine_peer));

  new_peer->peer_addr.sin_family = AF_INET;
  memcpy((void *)&new_peer->peer_addr, (void *)peer_sockaddr, sizeof(struct sockaddr_in));

  struct peregrine_peer *existing_peer = find_existing_peer_or_null(ctx, new_peer);
  if (existing_peer) {
    *peer = existing_peer;
    PEREGRINE_DEBUG("Peer %s already known.", existing_peer->str_addr);
    return 0;
  }
  snprintf(new_peer->str_addr, PEER_STR_ADDR, "%s:%d", inet_ntoa(new_peer->peer_addr.sin_addr),
           ntohs(new_peer->peer_addr.sin_port));
  new_peer->context = ctx;
  PEREGRINE_DEBUG("Added new peer at: %s", new_peer->str_addr);
  LIST_INSERT_HEAD(&ctx->peers, new_peer, ptrs);
  *peer = new_peer;

  return 0;
}

int
peregrine_socket_add_peer_from_cli(struct peregrine_context *ctx, char *in_buffer, struct peregrine_peer **peer)
{
  if (strncmp("add", in_buffer, strlen("add")) == 0) {
    strtok(in_buffer, ",");
    char *host = strtok(NULL, ",");
    char *port = strtok(NULL, ",");

    if ((host == NULL) || (port == NULL)) {
      PEREGRINE_ERROR("Host or port input it incorrect. Format is 'add,host,port'");
      return 1;
    }

    struct peregrine_peer *new_peer = malloc(sizeof(struct peregrine_peer));
    new_peer->peer_addr.sin_family = AF_INET;

    if (inet_aton(host, &new_peer->peer_addr.sin_addr) == 0) {
      PEREGRINE_ERROR("Invalid remote address '%s'", host);
      free(new_peer);
      return 1;
    }

    unsigned long peer_port = strtoul(port, NULL, 0);
    if (peer_port < 1 || peer_port > 65535) {
      PEREGRINE_ERROR("Invalid remote port '%s'", port);
      free(new_peer);
      return 1;
    }
    new_peer->peer_addr.sin_port = htons(peer_port);

    struct peregrine_peer *existing_peer = find_existing_peer_or_null(ctx, new_peer);
    if (existing_peer) {
      *peer = existing_peer;
      PEREGRINE_DEBUG("Peer %s already known.", existing_peer->str_addr);
      return 0;
    }
    snprintf(new_peer->str_addr, PEER_STR_ADDR, "%s:%d", inet_ntoa(new_peer->peer_addr.sin_addr),
             ntohs(new_peer->peer_addr.sin_port));
    new_peer->context = ctx;
    PEREGRINE_DEBUG("Added new peer from CLI at: %s", new_peer->str_addr);
    LIST_INSERT_HEAD(&ctx->peers, new_peer, ptrs);
    *peer = new_peer;
  }

  return 0;
}

void
peregrine_socket_loop(struct peregrine_context *ctx)
{
  ssize_t bytes;
  char input_buffer[BUFSIZE];
  char input_buffer_hex[BUFSIZE];
  char output_buffer[BUFSIZE];
  struct pollfd fds[3];
  struct sockaddr_in client_addr;
  socklen_t client_addr_len;
  struct peregrine_peer *new_peer = NULL;

  /* Descriptor zero is stdin */
  fds[0].fd = 0;
  fds[1].fd = ctx->sock_fd;
  fds[0].events = POLLIN | POLLPRI;
  fds[1].events = POLLIN | POLLPRI;

  while (1) {
    int ret = poll(fds, 2, -1);

    if (ret < 0) {
      PEREGRINE_ERROR("Poll returned error: %s", strerror(errno));
      break;
    }
    if (ret > 0) {
      if (fds[0].revents & (POLLERR | POLLHUP | POLLNVAL)) {
	PEREGRINE_ERROR("Poll indicated stdin error");
	break;
      }
      if (fds[1].revents & (POLLERR | POLLHUP | POLLNVAL)) {
	PEREGRINE_ERROR("Poll indicated socket error");
	break;
      }

      /* Check if there is any input on stdin */
      if (fds[0].revents & (POLLIN | POLLPRI)) {
	bytes = read(0, output_buffer, sizeof(output_buffer));
	if (bytes < 0) {
	  PEREGRINE_ERROR("stdin error: %s", strerror(errno));
	  break;
	}
	new_peer = NULL;
	output_buffer[strcspn(output_buffer, "\n")] = 0;
	PEREGRINE_INFO("[CLI] GOT: '%.*s'", (int)bytes, output_buffer);

	// Each peer will be added only once, if it was added before it will just skip it.

	if (peregrine_socket_add_peer_from_cli(ctx, output_buffer, &new_peer) < 0) {
	  PEREGRINE_ERROR("[CLI] There was an error while adding new peer from CLI.");
	}
      }

      /* Check if there is any data on ours socket */
      if (fds[1].revents & (POLLIN | POLLPRI)) {
	new_peer = NULL;
	bzero(&client_addr, sizeof(client_addr));
	client_addr_len = sizeof(client_addr);
	bytes = recvfrom(ctx->sock_fd, input_buffer, sizeof(input_buffer) - 1, 0, (struct sockaddr *)&client_addr,
	                 &client_addr_len);
	if (bytes < 0) {
	  PEREGRINE_ERROR("Error - recvfrom error: %s", strerror(errno));
	  break;
	}

	// Each peer will be added only once, if it was added before it will just skip it.
	if (peregrine_socket_add_peer_from_connection(ctx, &client_addr, &new_peer) < 0) {
	  PEREGRINE_ERROR("[SRV] There was an error while adding new peer from connection!");
	  break;
	}

	PEREGRINE_DEBUG("[SRV] Received from peer %s", new_peer->str_addr);
	if (bytes > 0) {
	  input_buffer[strcspn(input_buffer, "\n")] = 0;
	  str_to_hex(input_buffer, bytes, input_buffer_hex, bytes);
	  PEREGRINE_DEBUG("[SRV] %s Received 0x:'%.*s'", new_peer->str_addr, (int)bytes, input_buffer_hex);
	  PEREGRINE_DEBUG("[SRV] %s Received   :'%.*s'", new_peer->str_addr, (int)bytes, input_buffer);
	}

	// FIXME: Handle the input data instead of just sending back
	PEREGRINE_INFO("[SRV] Will send to: %s", new_peer->str_addr);
	bytes = sendto(ctx->sock_fd, input_buffer, bytes, 0, (struct sockaddr *)&new_peer->peer_addr,
	               sizeof(new_peer->peer_addr));
	if (bytes < 0) {
	  PEREGRINE_ERROR("Error - sendto error: %s", strerror(errno));
	  break;
	}
      }
    }
  }
  PEREGRINE_ERROR("Something bad happend. We shouldn't exit the program loop.");
}

void
peregrine_socket_finish(struct peregrine_context *ctx)
{
  while (!LIST_EMPTY(&ctx->peers)) {
    struct peregrine_peer *peer = LIST_FIRST(&ctx->peers);
    LIST_REMOVE(peer, ptrs);
    free(peer);
  }

  if (ctx->sock_fd != -1) {
    close(ctx->sock_fd);
  }
}
