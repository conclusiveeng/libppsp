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
#include <stdio.h>
#include <sys/queue.h>
#include <sys/socket.h>

#define BUFSIZE       1500
#define PEER_STR_ADDR 32
#define CHUNK_SIZE    1024
/* protocol options for peer send with HANDSHAKE */
struct ppspp_protocol_options {
  uint8_t version;
  uint8_t minimum_version;
  uint16_t swarm_id_len;
  uint8_t swarm_id[20];
  uint8_t content_prot_method;
  uint8_t merkle_hash_func;
  uint8_t live_signature_alg;
  uint8_t chunk_addr_method;
  uint64_t live_disc_wind;
  uint8_t supported_msgs_len;
  uint32_t supported_msgs; // for now we ignore this field
  uint32_t chunk_size;
};

// /* shared file */
// struct peregrine_file {
//   struct peregrine_context *context;
//   const char *name;
//   int fd;
//   char hash[256];
//   /* other file state, maybe mmap() handle, etc */
//   LIST_ENTRY(peregrine_file) ptrs;
// };

/* shared file */
struct peregrine_file {
  struct peregrine_context *context;
  char path[1024]; /* full path to file: directory name + file name */
  char sha[41];    /* textual representation of sha1 for a file */
  uint64_t file_size;
  uint32_t nl;             /* number of leaves */
  uint32_t nc;             /* number of chunks */
  struct chunk *tab_chunk; /* array of chunks for this file */
  struct node *tree;       /* tree of the file */
  struct node *tree_root;  /* pointer to root node of the tree */
  int fd;
  uint32_t start_chunk;
  uint32_t end_chunk;

  SLIST_ENTRY(peregrine_file) ptrs;
};

/* known peer */
struct peregrine_peer {
  struct peregrine_context *context;

  int sock_fd;
  char str_addr[PEER_STR_ADDR];
  struct sockaddr_in peer_addr;
  /* other peer state: known files cache, etc */
  LIST_ENTRY(peregrine_peer) ptrs;
  uint8_t to_remove;
  uint8_t handshake_send;
  struct ppspp_protocol_options protocol_options;
  uint32_t src_channel_id;
  uint32_t dst_channel_id;
  struct peregrine_file *file;
};

/* file being downloaded */
struct peregrine_download {
  struct peregrine_context *context;
  char hash[256];
  int out_fd;
  LIST_HEAD(peregrine_download_peers, peregrine_peer) peers; // peers we download from
  /* other download state: downloaded chunks, known chunks, etc */
  LIST_ENTRY(peregrine_download) ptrs;
};

/* instance */
struct peregrine_context {
  int sock_fd;
  uint32_t swarm_id;
  struct peregrine_peer ctx_peer;
  char work_dir[BUFSIZ];
  LIST_HEAD(peregrine_peers, peregrine_peer) peers;
  SLIST_HEAD(peregrine_files, peregrine_file) files;
  LIST_HEAD(peregrine_downloads, peregrine_download) downloads;
  /* other instance state */
};

int peregrine_socket_setup(unsigned long local_port, char *work_dir, struct peregrine_context *ctx);
void peregrine_socket_loop(struct peregrine_context *ctx);
int peregrine_socket_add_peer_from_cli(struct peregrine_context *ctx, char *in_buffer, struct peregrine_peer **peer);
int peregrine_socket_add_peer_from_connection(struct peregrine_context *ctx, const struct sockaddr_in *peer_sockaddr,
                                              struct peregrine_peer **peer);
void peregrine_socket_finish(struct peregrine_context *ctx);

#endif
