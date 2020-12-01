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
struct peregrine_peer {
  int sock_fd;
  char str_addr[PEER_STR_ADDR];
  struct sockaddr_in peer_addr;
};

int peregrine_socket_setup(unsigned long local_port, struct peregrine_peer *peer);
void peregrine_socket_loop(struct peregrine_peer *peer, struct peregrine_peer *initial_peer);
int peregrine_socket_add_peer(unsigned long port, const char *host, struct peregrine_peer *peer);
int peregrine_socket_add_peer_from_cli(char *in_buffer, struct peregrine_peer *peer);
int peregrine_socket_add_peer_from_connection(const struct sockaddr_in *peer_sockaddr, struct peregrine_peer *peer);
void peregrine_socket_finish(struct peregrine_peer *peer);

#endif
