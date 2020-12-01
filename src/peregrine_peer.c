#include "libperegrine/log.h"
#include "peregrine_socket.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int debug;

int
main(int argc, char const *argv[])
{
  struct peregrine_peer our_peer;
  struct peregrine_peer *other_peer = NULL;
  unsigned long local_port;

  if (argc < 2) {
    printf("Usage: %s <local seeder port> <remote seeder host> <remote seeder port>\n", argv[0]);
    return 1;
  }
  local_port = strtoul(argv[1], NULL, 0);
  if (local_port < 1 || local_port > 65535) {
    PEREGRINE_ERROR("Invalid local port '%s'\n", argv[1]);
    return 1;
  }

  //   if (argc > 2) {
  //     unsigned long  remote_port = strtoul(argv[3], NULL, 0);
  //     if (remote_port < 1 || remote_port > 65535) {
  //       PEREGRINE_ERROR("Invalid remote port '%s'\n", argv[3]);
  //       return 1;
  //     }
  //     const char *remote_host = argv[2];

  //     other_peer = malloc(sizeof(struct peregrine_peer));
  //     peregrine_socket_add_peer(remote_port, remote_host, other_peer);
  //     PEREGRINE_INFO("Added initial peer!");
  //   }

  if (peregrine_socket_setup(local_port, &our_peer) < 0) {
    PEREGRINE_ERROR("Error while seting up server!");
    return 1;
  }

  peregrine_socket_loop(&our_peer, other_peer);

  if (other_peer) {
    free(other_peer);
  }

  peregrine_socket_finish(&our_peer);

  return 0;
}
