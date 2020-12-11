#include "peregrine/peregrine_socket.h"
#include "peregrine/file.h"
#include "peregrine/log.h"
#include "peregrine/peer_handler.h"
#include "peregrine/utils.h"
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <unistd.h>
#include "internal.h"

static struct pg_peer *
pg_find_peer(struct pg_context *ctx, const struct sockaddr *saddr)
{
	struct pg_peer *peer;

	LIST_FOREACH(peer, &ctx->peers, ptrs)
	{
		if (pg_sockaddr_cmp((struct sockaddr *)&peer->addr, saddr) == 0)
			return (peer);
	}

	return (NULL);
}

static struct pg_peer *
pg_find_or_add_peer(struct pg_context *ctx, const struct sockaddr *saddr)
{
	struct pg_peer *peer;

	peer = pg_find_peer(ctx, saddr);
	if (peer != NULL)
		return (peer);

	peer = calloc(1, sizeof(*peer));
	peer->context = ctx;
	pg_sockaddr_copy(&peer->addr, saddr);

	return (peer);
}

int
pg_context_create(struct sockaddr *sa, socklen_t salen, struct pg_context **ctxp)
{
	struct pg_context *ctx;

	ctx = calloc(1, sizeof(*ctx));

	ctx->sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (ctx->sock_fd < 0) {
		ERROR("Failed to open socket: %s", strerror(errno));
		return (-1);
	}

	if (bind(ctx->sock_fd, sa, salen) != 0) {
		ERROR("Failed to bind: %s", strerror(errno));
		return (-1);
	}

	LIST_INIT(&ctx->peers);
	LIST_INIT(&ctx->downloads);
	SLIST_INIT(&ctx->files);
	TAILQ_INIT(&ctx->io);

	*ctxp = ctx;
	return (0);
}

int
pg_context_add_directory(struct pg_context *ctx, const char *directory)
{
	pg_file_add_directory(ctx, directory);
	pg_file_generate_sha1(ctx);
	pg_file_list_sha1(ctx);

	return (0);
}

struct pg_file*
pg_context_add_file(struct pg_context *ctx, const char *path)
{
	return (pg_file_add_file(ctx, path));
}

int
pg_context_destroy(struct pg_context *ctx) {
	struct pg_peer *peer;
	struct pg_download *download;
	struct pg_file *file;
	struct pg_block *block;

	LIST_FOREACH(peer, &ctx->peers, ptrs) {
		LIST_REMOVE(peer, ptrs);
		free(peer);
	}

	LIST_FOREACH(download, &ctx->downloads, entry) {
		LIST_REMOVE(download, entry);
		free(download);
	}

	while (!SLIST_EMPTY(&ctx->files)) {
		file = SLIST_FIRST(&ctx->files);
		SLIST_REMOVE_HEAD(&ctx->files, entry);
		free(file);
	}

	TAILQ_FOREACH(block, &ctx->io, entry) {
		TAILQ_REMOVE(&ctx->io, block, entry);
		free(block);
	}

	return (0);
}

int
pg_context_get_fd(struct pg_context *ctx)
{
	return (ctx->sock_fd);
}

static int
peregrine_handle_frame(struct pg_context *ctx, const struct sockaddr *client, const uint8_t *frame, size_t len)
{
	struct pg_peer *peer;
	struct msg *msg;
	uint32_t channel_id;
	size_t pos;
	ssize_t ret;

	channel_id = ((uint32_t *)frame)[0];
	peer = pg_find_or_add_peer(ctx, client);

	if (len == 4) {
		DEBUG("keep-alive received");
		return 0;
	}

	for (pos = 4; pos < len;) {
		msg = (struct msg *)&frame[pos];
		ret = pg_handle_message(peer, msg);
		if (ret < 0)
			break;

		pos += ret;
	}

	return (0);
}

int
pg_handle_fd_read(struct pg_context *ctx)
{
	struct sockaddr_storage client_addr;
	socklen_t client_addr_len;
	uint8_t frame[BUFSIZE];
	ssize_t ret;
	ssize_t pos = 0;

	DEBUG("ctx=%p fd=%d", ctx, ctx->sock_fd);

	for (;;) {
		ret = recvfrom(ctx->sock_fd, frame, sizeof(frame), MSG_DONTWAIT, (struct sockaddr *)&client_addr,
		               &client_addr_len);

		if (ret == 0)
			return (0);

		if (ret < 0)
			return (-1);

		peregrine_handle_frame(ctx, (struct sockaddr *)&client_addr, frame, ret);
	}
}

int
pg_handle_fd_write(struct pg_context *ctx)
{
	struct pg_block *block;
	struct msg_frame *msgf;
	uint8_t frame[sizeof(struct msg_data) + 1500];
	size_t chunk_size;
	size_t frame_size;
	off_t offset;

	DEBUG("ctx=%p fd=%d", ctx, ctx->sock_fd);

	for (;;) {
		block = TAILQ_FIRST(&ctx->io);
		if (block == NULL)
			break;

		msgf = (struct msg_frame *)frame;
		msgf->channel_id = block->peer->dst_channel_id;
		msgf->msg.message_type = MSG_DATA;
		msgf->msg.data.start_chunk = block->chunk_num;
		msgf->msg.data.end_chunk = block->chunk_num;
		msgf->msg.data.timestamp = 0; /* ??? */

		chunk_size = block->peer->protocol_options.chunk_size;
		frame_size = sizeof(msgf->channel_id) + sizeof(msgf->msg.data) + chunk_size;
		offset = chunk_size * block->chunk_num;

		if (pread(block->file->fd, &msgf->msg.data, chunk_size, offset) < 0) {
			ERROR("cannot read from file %s: %s", block->file->path, strerror(errno));
			continue;
		}

		if (sendto(ctx->sock_fd, frame, frame_size, MSG_DONTWAIT, (struct sockaddr *)&block->peer->addr,
		           sizeof(struct sockaddr_in))
		    < 0) {
			if (errno == EWOULDBLOCK)
				break;
		}

		TAILQ_REMOVE(&ctx->io, block, entry);
	}
}

int
pg_add_peer(struct pg_context *ctx, struct sockaddr *sa)
{
	if (pg_find_or_add_peer(ctx, sa) == NULL)
		return (-1);

	return (0);
}
