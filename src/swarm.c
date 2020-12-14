//
// Created by jakub on 12.12.2020.
//

#include <sys/param.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "internal.h"
#include "proto.h"
#include "log.h"

struct pg_swarm_scan_state
{
	struct pg_peer_swarm *ps;
	uint64_t collected;
	uint64_t budget;
};

struct pg_peer_swarm *
pg_find_peerswarm_by_id(struct pg_peer *peer, uint8_t *swarm_id, size_t id_len)
{
	struct pg_peer_swarm *ps;

	LIST_FOREACH(ps, &peer->swarms, peer_entry) {
		if (memcmp(ps->swarm->swarm_id, swarm_id, id_len) == 0)
			return (ps);
	}

	return (NULL);
}

struct pg_peer_swarm *
pg_find_peerswarm_by_channel(struct pg_peer *peer, uint32_t channel_id)
{
	struct pg_peer_swarm *ps;

	LIST_FOREACH(ps, &peer->swarms, peer_entry) {
		if (ps->src_channel_id == channel_id)
			return (ps);
	}

	return (NULL);
}

static bool
pg_peerswarm_request_find_fn(uint64_t start, uint64_t end, bool value, void *arg)
{
	struct pg_swarm_scan_state *state = arg;
	uint64_t count = MIN(end - start + 1, state->budget);

	DEBUG("requesting %d blocks @ %d", count, start);

	state->collected += count;
	pg_bitmap_set_range(state->ps->request_bitmap, start, start + count, true);
	pack_request(state->ps->buffer, start, start + count);
	return (state->collected <= state->budget);
}

void
pg_peerswarm_request(struct pg_peer_swarm *ps)
{
	struct pg_swarm_scan_state state;

	switch (ps->state) {
	case PEERSWARM_WAIT_HAVE:
		/*
		 * We have completed the handshake but we don't know the payload size yet.
		 *
		 * We request first block and wait for peak hashes to be send by the seeder,
		 * which we will then use to calculate content size.
		 */
		DEBUG("requesting first block from peer %s in swarm %s",
		    pg_peer_to_str(ps->peer), pg_swarm_to_str(ps->swarm));

		pack_request(ps->buffer, 0, 0);
		pg_buffer_enqueue(ps->buffer);
		ps->state = PEERSWARM_READY;
		break;

	case PEERSWARM_READY:
		DEBUG("trying to request blocks from peer %s in swarm %s",
		    pg_peer_to_str(ps->peer), pg_swarm_to_str(ps->swarm));

		state.ps = ps;
		state.collected = 0;
		state.budget = 10;

		pg_bitmap_scan(ps->request_bitmap, BITMAP_SCAN_0, pg_peerswarm_request_find_fn, &state);
		pg_buffer_enqueue(ps->buffer);
		break;
	}


}

struct pg_peer_swarm *
pg_peerswarm_create(struct pg_peer *peer, struct pg_swarm *swarm,
    struct pg_protocol_options *options, uint32_t src_channel_id,
    uint32_t dst_channel_id)
{
	struct pg_peer_swarm *ps;

	DEBUG("peer=%s, swarm=%s, dst_channel_id=%d", pg_peer_to_str(peer),
	      pg_swarm_to_str(swarm), dst_channel_id);

	ps = calloc(1, sizeof(struct pg_peer_swarm));
	ps->peer = peer;
	ps->swarm = swarm;
	ps->src_channel_id = src_channel_id;
	ps->dst_channel_id = dst_channel_id;
	ps->have_bitmap = pg_bitmap_create(swarm->file->nc);
	ps->request_bitmap = pg_bitmap_create(swarm->file->nc);
	ps->options = *options;
	ps->buffer = pg_buffer_create(peer, ps->dst_channel_id);
	LIST_INSERT_HEAD(&peer->swarms, ps, peer_entry);
	LIST_INSERT_HEAD(&swarm->peers, ps, swarm_entry);

	pg_send_handshake(ps);
	pg_send_have(ps);
	pg_peerswarm_request(ps);

	return (ps);
}


void
pg_peerswarm_destroy(struct pg_peer_swarm *ps)
{

}

struct pg_swarm *
pg_swarm_create(struct pg_context *ctx, struct pg_file *file)
{
	struct pg_peer *peer;
	struct pg_swarm *swarm;
	struct pg_protocol_options options = { .chunk_size = 1024 };

	swarm = calloc(1, sizeof(*swarm));
	swarm->context = ctx;
	swarm->file = file;
	swarm->nc = file->nc;
	swarm->have_bitmap = pg_bitmap_create(file->nc);
	swarm->swarm_id_len = sizeof(file->sha);
	memcpy(swarm->swarm_id, file->sha, sizeof(file->sha));
	LIST_INSERT_HEAD(&ctx->swarms, swarm, entry);
	DEBUG("created swarm %s", pg_swarm_to_str(swarm));

	/* Poke all known peers for this swarm */
	LIST_FOREACH(peer, &ctx->peers, entry) {
		pg_peerswarm_create(peer, swarm, &options, pg_new_channel_id(), 0);
	}

	return (swarm);
}

int
pg_swarm_request(struct pg_swarm *swarm)
{
	struct pg_peer_swarm *ps;

	DEBUG("trying to request blocks in swarm %s", pg_swarm_to_str(swarm));

	LIST_FOREACH(ps, &swarm->peers, swarm_entry) {
		pg_peerswarm_request(ps);
	}

	return (0);
}
