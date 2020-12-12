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
#include <sys/queue.h>
#include <sys/socket.h>

#define BUFSIZE       1500
#define CHUNK_SIZE    1024

struct pg_context;

struct pg_context_options
{
	struct sockaddr *listen_addr;
	socklen_t listen_addr_len;
	void (*add_fd)(struct pg_context *ctx, void *arg, int fd, int events);
	void (*mod_fd)(struct pg_context *ctx, void *arg, int fd, int events);
	void (*del_fd)(struct pg_context *ctx, void *arg, int fd);
	void *arg;
};

int pg_context_create(struct pg_context_options *options, struct pg_context **ctxp);
int pg_context_add_directory(struct pg_context *ctx, const char *directory);
struct pg_file *pg_context_add_file(struct pg_context *ctx, const char *path);
int pg_context_destroy(struct pg_context *ctx);
int pg_handle_fd_read(struct pg_context *ctx, int fd);
int pg_handle_fd_write(struct pg_context *ctx, int fd);
int pg_add_peer(struct pg_context *ctx, struct sockaddr *sa);

#endif
