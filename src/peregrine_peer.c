#include "libperegrine/v2/log.h"
#include "peregrine_socket.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int debug;

int
main(int argc, char const *argv[])
{
  struct peregrine_context context;
  unsigned long local_port;

  if (argc < 3) {
    printf("Usage: %s <local port> <work directory> \n", argv[0]);
    return 1;
  }
  local_port = strtoul(argv[1], NULL, 0);
  if (local_port < 1 || local_port > 65535) {
    PEREGRINE_ERROR("Invalid local port '%s'\n", argv[1]);
    return 1;
  }

  if (peregrine_socket_setup(local_port, (char *)argv[2], &context) < 0) {
    PEREGRINE_ERROR("Error while seting up server!");
    return 1;
  }

  peregrine_socket_loop(&context);

  peregrine_socket_finish(&context);

  return 0;
}
