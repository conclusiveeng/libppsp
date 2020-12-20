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

#include <sys/param.h>
#include <sys/types.h>
#include <endian.h>
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include "internal.h"
#include "eventloop.h"
#include "proto.h"
#include "log.h"

#define FRAME_LENGTH	1500

static bool pg_handle_fd_read(void *arg);

static struct pg_peer *
pg_find_peer(struct pg_context *ctx, const struct sockaddr *saddr)
{
	struct pg_peer *peer;

	LIST_FOREACH(peer, &ctx->peers, entry) {
		if (pg_sockaddr_cmp((struct sockaddr *)&peer->addr, saddr) == 0)
			return (peer);
	}

	return (NULL);
}

static struct pg_peer *
pg_find_or_add_peer(struct pg_context *ctx, const struct sockaddr *saddr)
{
	struct pg_peer *peer;
	struct pg_event event;

	peer = pg_find_peer(ctx, saddr);
	if (peer != NULL)
		return (peer);

	peer = calloc(1, sizeof(*peer));
	peer->context = ctx;
	pg_sockaddr_copy(&peer->addr, saddr);

	LIST_INIT(&peer->swarms);
	LIST_INSERT_HEAD(&ctx->peers, peer, entry);

	event.type = EVENT_PEER_ADDED;
	event.ctx = ctx;
	event.peer = peer;
	pg_emit_event(&event);

	return (peer);
}

int
pg_context_create(struct pg_context_options *options, struct pg_context **ctxp)
{
	struct pg_context *ctx;

	ctx = calloc(1, sizeof(*ctx));
	ctx->options = *options;
	ctx->eventloop = pg_eventloop_create();

	ctx->sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (ctx->sock_fd < 0) {
		ERROR("Failed to open socket: %s", strerror(errno));
		return (-1);
	}

	if (bind(ctx->sock_fd, options->listen_addr, options->listen_addr_len) != 0) {
		ERROR("Failed to bind: %s", strerror(errno));
		return (-1);
	}

	/* Add the initial socket in read mode */
	pg_eventloop_add_fd(ctx->eventloop, ctx->sock_fd, pg_handle_fd_read,
	    EVENTLOOP_FD_READABLE, ctx);

	LIST_INIT(&ctx->peers);
	LIST_INIT(&ctx->downloads);
	SLIST_INIT(&ctx->files);
	TAILQ_INIT(&ctx->io);
	*ctxp = ctx;
	return (0);
}

int
pg_context_get_fd(struct pg_context *ctx)
{
	return (pg_eventloop_get_fd(ctx->eventloop));
}

int
pg_context_step(struct pg_context *ctx)
{
	return (pg_eventloop_step(ctx->eventloop));
}

int
pg_context_run(struct pg_context *ctx)
{
	return (pg_eventloop_run(ctx->eventloop));
}

void
pg_socket_enqueue_tx(struct pg_context *ctx, struct pg_buffer *buffer)
{
	DEBUG("enqueue_tx: peer=%s length=%d", pg_peer_to_str(buffer->peer), buffer->used);

	if (sendto(ctx->sock_fd, buffer->storage, buffer->used, 0,
	    (struct sockaddr *)&buffer->peer->addr, sizeof(struct sockaddr_in)) < 0) {
		ERROR("sendto: peer=%s error=%s", pg_peer_to_str(buffer->peer),
		      strerror(errno));
	}
}

int
pg_context_destroy(struct pg_context *ctx)
{
	struct pg_peer *peer;
	struct pg_file *file;

	LIST_FOREACH(peer, &ctx->peers, entry) {
		LIST_REMOVE(peer, entry);
		free(peer);
	}

	while (!SLIST_EMPTY(&ctx->files)) {
		file = SLIST_FIRST(&ctx->files);
		SLIST_REMOVE_HEAD(&ctx->files, entry);
		free(file);
	}

	return (0);
}

static int
peregrine_handle_frame(struct pg_context *ctx, const struct sockaddr *client,
    const uint8_t *frame, size_t len)
{
	struct pg_peer *peer;
	struct msg *msg;
	uint32_t channel_id;
	size_t pos;
	ssize_t ret;

	channel_id = be32toh(*(uint32_t *)frame);
	peer = pg_find_or_add_peer(ctx, client);

	if (len == 4) {
		DEBUG("keep-alive received");
		return (0);
	}

	for (pos = 4; pos < len;) {
		msg = (struct msg *)&frame[pos];
		ret = pg_handle_message(peer, channel_id, msg, len - pos);
		if (ret < 0)
			break;

		pos += ret;
	}

	return (0);
}

static bool
pg_handle_fd_read(void *arg)
{
	struct pg_context *ctx = arg;
	struct sockaddr_storage client_addr;
	socklen_t client_addr_len = sizeof(struct sockaddr_storage);
	uint8_t frame[FRAME_LENGTH];
	ssize_t ret;

	DEBUG("ctx=%p fd=%d", ctx, ctx->sock_fd);

	for (;;) {
		ret = recvfrom(ctx->sock_fd, frame, sizeof(frame), MSG_DONTWAIT, (struct sockaddr *)&client_addr,
		               &client_addr_len);

		if (ret == 0)
			return (true);

		if (ret < 0) {
			if (errno == EWOULDBLOCK)
				return (true);

			return (false);
		}

		peregrine_handle_frame(ctx, (struct sockaddr *)&client_addr, frame, ret);
	}
}

void
pg_emit_event(struct pg_event *event)
{
	struct pg_context *ctx = event->ctx;

	if (ctx->options.event_fn == NULL)
		return;

	ctx->options.event_fn(event, ctx->options.fn_arg);
}

int
pg_add_peer(struct pg_context *ctx, struct sockaddr *sa, struct pg_peer **peerp)
{
	struct pg_peer *peer;
	struct pg_swarm *swarm;
	struct pg_protocol_options options = { .chunk_size = 1024 };

	DEBUG("add peer %s into context %p", pg_sockaddr_to_str(sa), ctx);

	peer = pg_find_or_add_peer(ctx, sa);
	if (peer == NULL)
		return (-1);

	/* Try to connect to all known swarms? */
	LIST_FOREACH(swarm, &ctx->swarms, entry) {
		if (!pg_find_peerswarm_by_id(peer, swarm->swarm_id, swarm->swarm_id_len))
			pg_peerswarm_create(peer, swarm, &options, pg_new_channel_id(), 0);
	}

	if (peerp != NULL)
		*peerp = peer;

	return (0);
}
