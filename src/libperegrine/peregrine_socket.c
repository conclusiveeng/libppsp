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
peregrine_socket_setup_server(unsigned long local_port, struct peregrine_server *server)
{
  // Crete server socket
  server->server_sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (server->server_sock_fd < 0) {
    PEREGRINE_ERROR("Failed to open socket: %s\n", strerror(errno));
    return 1;
  }

  // This will allow to setup multiple servers on the same port, use with caution!
  //   int opt_val = 1;
  //   setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &opt_val, sizeof(opt_val));

  // Bind server socket
  server->server_addr.sin_family = AF_INET;
  server->server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  server->server_addr.sin_port = htons(local_port);
  if (bind(server->server_sock_fd, (struct sockaddr *)(&server->server_addr), sizeof(server->server_addr)) < 0) {
    PEREGRINE_ERROR("Failed to bind socket: %s\n", strerror(errno));
    return 1;
  }

  PEREGRINE_INFO("Setup seeder server at: %s:%d", inet_ntoa(server->server_addr.sin_addr),
                 ntohs(server->server_addr.sin_port));

  return 0;
}

int
peregrine_socket_setup_client(const unsigned long port, const char *host, struct peregrine_client *client)
{
  // Setup connection details to seeder (remote server)
  client->remote_peer.peer_addr.sin_family = AF_INET;
  client->remote_peer.peer_addr.sin_port = htons(port);
  if (inet_aton(host, &client->remote_peer.peer_addr.sin_addr) == 0) {
    PEREGRINE_ERROR("Invalid remote address '%s'\n", host);
    return 1;
  }
  snprintf(client->remote_peer.str_addr, PEER_STR_ADDR, "%s:%lu", host, port);

  // Setup leecher connection details - use random port (internal peregrine client)
  client->local_peer.peer_addr.sin_family = AF_INET;
  client->local_peer.peer_addr.sin_addr.s_addr = INADDR_ANY;
  client->local_peer.peer_addr.sin_port = 0; // Get first free random port number.

  // Create leecher socket (internal peregrine client)
  client->local_peer.peer_sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (client->local_peer.peer_sock_fd < 0) {
    PEREGRINE_ERROR("Failed to open socket: %s\n", strerror(errno));
    return 1;
  }

  if (bind(client->local_peer.peer_sock_fd, (struct sockaddr *)&client->local_peer.peer_addr,
           sizeof(client->local_peer.peer_addr))
      < 0) {
    PEREGRINE_ERROR("Failed to bind socket: %s\n", strerror(errno));
    return 1;
  }

  // Get assigned port number
  socklen_t len = sizeof(client->local_peer.peer_addr);
  if (getsockname(client->local_peer.peer_sock_fd, (struct sockaddr *)&client->local_peer.peer_addr, &len) == -1) {
    PEREGRINE_ERROR("Error while getsockname: %s\n", strerror(errno));
    return 1;
  }

  snprintf(client->local_peer.str_addr, PEER_STR_ADDR, "%s:%d", inet_ntoa(client->local_peer.peer_addr.sin_addr),
           ntohs(client->local_peer.peer_addr.sin_port));

  PEREGRINE_INFO("Setup internal client at: %s", client->local_peer.str_addr);

  return 0;
}

void
peregrine_socket_loop(struct peregrine_server *server, struct peregrine_client *client)
{
  ssize_t bytes;
  char input_buffer[BUFSIZE];
  char input_buffer_hex[BUFSIZE];
  char output_buffer[BUFSIZE];
  struct pollfd fds[3];
  struct sockaddr_in client_addr;
  socklen_t client_addr_len;
  char client_str_addr[PEER_STR_ADDR];
  int received_from_client = 0;

  /* Descriptor zero is stdin */
  fds[0].fd = 0;
  fds[1].fd = server->server_sock_fd;
  fds[2].fd = client->local_peer.peer_sock_fd;
  fds[0].events = POLLIN | POLLPRI;
  fds[1].events = POLLIN | POLLPRI;
  fds[2].events = POLLIN | POLLPRI;

  while (1) {
    int ret = poll(fds, 3, -1);

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
	// Don't send newline characters when on CLI operation
	output_buffer[strcspn(output_buffer, "\n")] = 0;
	PEREGRINE_INFO("[CLI] Sending: '%.*s'", (int)bytes, output_buffer);

	// This is for test purposes :
	//     At the beggining of the application running the stdio stream should be directed to remote server socket
	//     - seeder, this way we initiate connection(from perspective of 2nd application)
	//     After the connetion is initialized - remote server has our address, we change the communication,
	//     to point to remote client(from perspective of 1st application)
	//     After those operation we will be able to cross communicate between 2nd application (as client) to
	//     1st application (as server).

	if (received_from_client == 1) {
	  PEREGRINE_INFO("[CLI] Will send to: %s", client_str_addr);
	  bytes = sendto(server->server_sock_fd, output_buffer, bytes, 0, (struct sockaddr *)&client_addr,
	                 sizeof(client_addr));
	} else {
	  PEREGRINE_INFO("[CLI] Will send to: %s", client->remote_peer.str_addr);
	  bytes = sendto(client->local_peer.peer_sock_fd, output_buffer, bytes, 0,
	                 (struct sockaddr *)&client->remote_peer.peer_addr, sizeof(client->remote_peer.peer_addr));
	}

	if (bytes < 0) {
	  PEREGRINE_ERROR("Error - sendto error: %s", strerror(errno));
	  break;
	}
      }

      // Check if there is any data on the server (seeder) socket
      if (fds[1].revents & (POLLIN | POLLPRI)) {
	// Potentially, new client just connected to us.
	bzero(&client_addr, sizeof(client_addr));
	client_addr_len = sizeof(client_addr);
	bytes = recvfrom(server->server_sock_fd, input_buffer, sizeof(input_buffer) - 1, 0,
	                 (struct sockaddr *)&client_addr, &client_addr_len);
	if (bytes < 0) {
	  PEREGRINE_ERROR("Error - recvfrom error: %s", strerror(errno));
	  break;
	}

	snprintf(client_str_addr, PEER_STR_ADDR, "%s:%d", inet_ntoa(client_addr.sin_addr),
	         ntohs(client_addr.sin_port));
	PEREGRINE_DEBUG("[SRV] Received from peer %s", client_str_addr);

	if (bytes > 0) {
	  str_to_hex(input_buffer, bytes, input_buffer_hex, bytes);
	  PEREGRINE_DEBUG("[SRV] %s Received 0x:'%.*s'", client_str_addr, (int)bytes, input_buffer_hex);
	  PEREGRINE_DEBUG("[SRV] %s Received   :'%.*s'", client_str_addr, (int)bytes, input_buffer);
	}

	received_from_client = 1;
      }

      // Check if there is any data on the client (leecher) socket
      if (fds[2].revents & (POLLIN | POLLPRI)) {
	bzero(&client_addr, sizeof(client_addr));
	client_addr_len = sizeof(client_addr);
	bytes = recvfrom(client->local_peer.peer_sock_fd, input_buffer, sizeof(input_buffer) - 1, 0,
	                 (struct sockaddr *)&client_addr, &client_addr_len);
	if (bytes < 0) {
	  PEREGRINE_ERROR("Error - recvfrom error: %s", strerror(errno));
	  break;
	}

	snprintf(client_str_addr, PEER_STR_ADDR, "%s:%d", inet_ntoa(client_addr.sin_addr),
	         ntohs(client_addr.sin_port));
	PEREGRINE_DEBUG("[CLT] Received from peer %s", client_str_addr);

	if (bytes > 0) {
	  str_to_hex(input_buffer, bytes, input_buffer_hex, bytes);
	  PEREGRINE_INFO("[CLT] %s Received 0x:'%.*s'", client_str_addr, (int)bytes, input_buffer_hex);
	  PEREGRINE_INFO("[CLT] %s Received   :'%.*s'", client_str_addr, (int)bytes, input_buffer);
	}
      }
    }
  }
}

void
peregrine_socket_finish(struct peregrine_server *server, struct peregrine_client *client)
{
  close(client->local_peer.peer_sock_fd);
  close(server->server_sock_fd);
}
