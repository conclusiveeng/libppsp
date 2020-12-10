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
#include "peregrine_socket.h"
#include "file.h"
#include "log.h"
#include "peer_handler.h"
#include "utils.h"

static struct peregrine_peer *
pg_find_peer(struct peregrine_context *ctx, const struct sockaddr *saddr)
{
	struct peregrine_peer *peer;

	LIST_FOREACH(peer, &ctx->peers, ptrs) {
		if (pg_sockaddr_cmp((struct sockaddr *)&peer->addr, saddr) == 0)
			return (peer);
	}

	return (NULL);
}

static struct peregrine_peer *
pg_find_or_add_peer(struct peregrine_context *ctx, const struct sockaddr *saddr)
{
	struct peregrine_peer *peer;

	peer = pg_find_peer(ctx, saddr);
	if (peer != NULL)
		return (peer);

	peer = calloc(1, sizeof(*peer));
	peer->context = ctx;
	pg_sockaddr_copy(&peer->addr, saddr);

	return (peer);
}

int
pg_context_create(struct sockaddr *sa, socklen_t salen, struct peregrine_context **ctxp)
{
	struct peregrine_context *ctx;

	ctx = calloc(1, sizeof(*ctx));

	ctx->sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (ctx->sock_fd < 0) {
		ERROR("Failed to open socket: %s", strerror(errno));
		return (-1);
	}

	if (bind(ctx->sock_fd, sa, salen) != 0) {

	}

	LIST_INIT(&ctx->peers);
	LIST_INIT(&ctx->downloads);
	SLIST_INIT(&ctx->files);
	TAILQ_INIT(&ctx->io);

	return (0);
}

int
pg_context_destroy(struct peregrine_context *ctx)
{

}


static int
peregrine_handle_frame(struct peregrine_context *ctx, const struct sockaddr *client, const uint8_t *frame, size_t len)
{
	struct peregrine_peer *peer;
    struct msg *msg;
    uint32_t channel_id;
    size_t pos;
    ssize_t ret;

    channel_id = ((uint32_t *)frame)[0];
    peer = pg_find_or_add_peer(ctx, client);

    for (;;) {
        msg = (struct msg *)&frame[pos];

	ret = pg_handle_message(peer, msg);
	if (ret < 0)
		break;

	pos += ret;
    }
}

int
pg_handle_fd_read(struct peregrine_context *ctx)
{
    struct sockaddr_storage client_addr;
    socklen_t client_addr_len;
    uint8_t frame[BUFSIZE];
    ssize_t ret;
    ssize_t pos = 0;

    for (;;) {
        ret = recvfrom(ctx->sock_fd, frame, sizeof(frame), MSG_DONTWAIT,
	    (struct sockaddr *)&client_addr, &client_addr_len);

        if (ret == 0)
        	return (0);

        if (ret < 0)
        	return (-1);

        for (;;) {
            pos += peregrine_handle_frame(ctx, (struct sockaddr *)&client_addr, frame, ret);
            if (pos >= ret)
            	break;
        }
    }
}

int
pg_handle_fd_write(struct peregrine_context *ctx)
{

}

int
pg_add_peer(struct peregrine_context *ctx, struct sockaddr *sa)
{
	if (pg_find_or_add_peer(ctx, sa) == NULL)
		return (-1);

	return (0);
}
