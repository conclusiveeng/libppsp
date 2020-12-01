#include "peregrine_socket.h"
#include "log.h"
#include "seeder.h"
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
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
peregrine_socket_setup(unsigned long local_port, struct peregrine_peer *peer)
{
  // Crete server socket
  peer->sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (peer->sock_fd < 0) {
    PEREGRINE_ERROR("Failed to open socket: %s", strerror(errno));
    return 1;
  }

  // This will allow to setup multiple servers on the same port, use with caution!
  //   int opt_val = 1;
  //   setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &opt_val, sizeof(opt_val));

  // Bind server socket
  peer->peer_addr.sin_family = AF_INET;
  peer->peer_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  peer->peer_addr.sin_port = htons(local_port);
  if (bind(peer->sock_fd, (struct sockaddr *)(&peer->peer_addr), sizeof(peer->peer_addr)) < 0) {
    PEREGRINE_ERROR("Failed to bind socket: %s", strerror(errno));
    return 1;
  }

  snprintf(peer->str_addr, PEER_STR_ADDR, "%s:%d", inet_ntoa(peer->peer_addr.sin_addr),
           ntohs(peer->peer_addr.sin_port));
  PEREGRINE_INFO("Setup socket at: %s", peer->str_addr);

  return 0;
}

int
peregrine_socket_add_peer(const unsigned long port, const char *host, struct peregrine_peer *peer)
{
  peer->peer_addr.sin_family = AF_INET;
  peer->peer_addr.sin_port = htons(port);
  if (inet_aton(host, &peer->peer_addr.sin_addr) == 0) {
    PEREGRINE_ERROR("Invalid remote address '%s'", host);
    return 1;
  }
  snprintf(peer->str_addr, PEER_STR_ADDR, "%s:%lu", host, port);
  peer->sock_fd = -1;

  PEREGRINE_INFO("Setup new peer at: %s", peer->str_addr);

  return 0;
}

int
peregrine_socket_add_peer_from_connection(const struct sockaddr_in *peer_sockaddr, struct peregrine_peer *peer)
{
  memcpy((void *)&peer->peer_addr, (void *)peer_sockaddr, sizeof(struct sockaddr_in));
  snprintf(peer->str_addr, PEER_STR_ADDR, "%s:%d", inet_ntoa(peer->peer_addr.sin_addr),
           ntohs(peer->peer_addr.sin_port));

  PEREGRINE_INFO("Added new peer at: %s", peer->str_addr);

  return 0;
}

int
peregrine_socket_add_peer_from_cli(char *in_buffer, struct peregrine_peer *peer)
{
  if (strncmp("add", in_buffer, strlen("add")) == 0) {
    strtok(in_buffer, ",");
    char *host = strtok(NULL, ",");
    char *port = strtok(NULL, ",");

    peer->peer_addr.sin_family = AF_INET;

    if ((host == NULL) || (port == NULL)) {
      PEREGRINE_ERROR("Host or port input it incorrect. Format is 'add,host,port'");
    }

    if (host != NULL) {
      if (inet_aton(host, &peer->peer_addr.sin_addr) == 0) {
	PEREGRINE_ERROR("Invalid remote address '%s'", host);
	return 1;
      }
    }

    if (port != NULL) {
      unsigned long peer_port = strtoul(port, NULL, 0);
      if (peer_port < 1 || peer_port > 65535) {
	PEREGRINE_ERROR("Invalid remote port '%s'", port);
	return 1;
      }
      peer->peer_addr.sin_port = htons(peer_port);
    }

    snprintf(peer->str_addr, PEER_STR_ADDR, "%s:%d", inet_ntoa(peer->peer_addr.sin_addr),
             ntohs(peer->peer_addr.sin_port));
    PEREGRINE_INFO("Added new peer from CLI at: %s", peer->str_addr);
  }

  return 0;
}

void
peregrine_socket_loop(struct peregrine_peer *peer, struct peregrine_peer *initial_peer)
{
  ssize_t bytes;
  char input_buffer[BUFSIZE];
  char input_buffer_hex[BUFSIZE];
  char output_buffer[BUFSIZE];
  struct pollfd fds[3];
  struct sockaddr_in client_addr;
  socklen_t client_addr_len;

  /* Descriptor zero is stdin */
  fds[0].fd = 0;
  fds[1].fd = peer->sock_fd;
  fds[0].events = POLLIN | POLLPRI;
  fds[1].events = POLLIN | POLLPRI;

  while (1) {
    //     if (initial_peer != NULL) {
    //       PEREGRINE_INFO("[SRV] Will send to: %s", initial_peer->str_addr);

    //       strcpy(output_buffer, "HELLO!");
    //       bytes = 8;

    //       bytes = sendto(peer->sock_fd, output_buffer, bytes, 0, (struct sockaddr *)&initial_peer->peer_addr,
    //                      sizeof(initial_peer->peer_addr));
    //       if (bytes < 0) {
    // 	PEREGRINE_ERROR("Error - sendto error: %s", strerror(errno));
    // 	break;
    //       }
    //     }
    int ret = poll(fds, 2, -1);

    if (ret < 0) {
      PEREGRINE_ERROR("Poll returned error: %s", strerror(errno));
      break;
    }
    if (ret > 0) {

      /* Regardless of requested events, poll() can always return these */
      if (fds[0].revents & (POLLERR | POLLHUP | POLLNVAL)) {
	PEREGRINE_ERROR("Poll indicated stdin error");
	break;
      }
      if (fds[1].revents & (POLLERR | POLLHUP | POLLNVAL)) {
	PEREGRINE_ERROR("Poll indicated socket error");
	break;
      }

      // Check if there is any input on stdin
      if (fds[0].revents & (POLLIN | POLLPRI)) {
	bytes = read(0, output_buffer, sizeof(output_buffer));
	if (bytes < 0) {
	  PEREGRINE_ERROR("stdin error: %s", strerror(errno));
	  break;
	}
	PEREGRINE_INFO("[CLI] GOT: '%.*s'", (int)bytes, output_buffer);
	struct peregrine_peer new_peer;
	peregrine_socket_add_peer_from_cli(output_buffer, &new_peer);
      }

      // Check if there is any data on ours socket
      if (fds[1].revents & (POLLIN | POLLPRI)) {
	struct peregrine_peer new_peer;

	bzero(&client_addr, sizeof(client_addr));
	client_addr_len = sizeof(client_addr);
	bytes = recvfrom(peer->sock_fd, input_buffer, sizeof(input_buffer) - 1, 0, (struct sockaddr *)&client_addr,
	                 &client_addr_len);
	if (bytes < 0) {
	  PEREGRINE_ERROR("Error - recvfrom error: %s", strerror(errno));
	  break;
	}

	// Potentially, new client just connected to us.
	peregrine_socket_add_peer_from_connection(&client_addr, &new_peer);
	PEREGRINE_DEBUG("[SRV] Received from peer %s", new_peer.str_addr);
	if (bytes > 0) {
	  input_buffer[strcspn(input_buffer, "\n")] = 0;
	  str_to_hex(input_buffer, bytes, input_buffer_hex, bytes);
	  PEREGRINE_DEBUG("[SRV] %s Received 0x:'%.*s'", new_peer.str_addr, (int)bytes, input_buffer_hex);
	  PEREGRINE_DEBUG("[SRV] %s Received   :'%.*s'", new_peer.str_addr, (int)bytes, input_buffer);
	}

	PEREGRINE_INFO("[SRV] Will send to: %s", new_peer.str_addr);
	bytes = sendto(peer->sock_fd, input_buffer, bytes, 0, (struct sockaddr *)&new_peer.peer_addr,
	               sizeof(new_peer.peer_addr));
	if (bytes < 0) {
	  PEREGRINE_ERROR("Error - sendto error: %s", strerror(errno));
	  break;
	}
      }
    }
  }
}

void
peregrine_socket_finish(struct peregrine_peer *peer)
{
  if (peer->sock_fd != -1) {
    close(peer->sock_fd);
  }
}
