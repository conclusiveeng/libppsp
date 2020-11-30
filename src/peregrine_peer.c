#include "libperegrine/log.h"
#include "peregrine_socket.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int debug;

int
main(int argc, char const *argv[])
{
  struct peregrine_server server;
  struct peregrine_client client;
  unsigned long local_port;
  unsigned long remote_port;
  const char *remote_host;

  if (argc < 4) {
    printf("Usage: %s <local seeder port> <remote seeder host> <remote seeder port>\n", argv[0]);
    return 1;
  }
  local_port = strtoul(argv[1], NULL, 0);
  if (local_port < 1 || local_port > 65535) {
    PEREGRINE_ERROR("Invalid local port '%s'\n", argv[1]);
    return 1;
  }
  remote_port = strtoul(argv[3], NULL, 0);
  if (remote_port < 1 || remote_port > 65535) {
    PEREGRINE_ERROR("Invalid remote port '%s'\n", argv[3]);
    return 1;
  }
  remote_host = argv[2];

  if (peregrine_socket_setup_server(local_port, &server) < 0) {
    PEREGRINE_ERROR("Error while seting up server!");
    return 1;
  }

  peregrine_socket_setup_client(remote_port, remote_host, &client);

  peregrine_socket_loop(&server, &client);

  peregrine_socket_finish(&server, &client);

  return 0;
}
