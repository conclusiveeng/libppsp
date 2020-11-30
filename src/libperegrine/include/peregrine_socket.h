/*
 * Copyright (c) 2020 Conclusive Engineering Sp. z o.o.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _PEREGRINE_SOCKET_H_
#define _PEREGRINE_SOCKET_H_

#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/socket.h>

#define BUFSIZE       1500
#define PEER_STR_ADDR 32

struct peregrine_server {
  int server_sock_fd;
  struct sockaddr_in server_addr;
};

struct peregrine_peer {
  int peer_sock_fd;
  char str_addr[PEER_STR_ADDR];
  struct sockaddr_in peer_addr;
};

struct peregrine_client {
  struct peregrine_peer local_peer;  // it's local leecher peer (running in current process)
  struct peregrine_peer remote_peer; // it's remote server/seeder peer (external process)
};

int peregrine_socket_setup_server(unsigned long local_port, struct peregrine_server *server);
int peregrine_socket_setup_client(unsigned long port, const char *host, struct peregrine_client *client);
void peregrine_socket_loop(struct peregrine_server *server, struct peregrine_client *client);
void peregrine_socket_finish(struct peregrine_server *server, struct peregrine_client *client);

#endif
