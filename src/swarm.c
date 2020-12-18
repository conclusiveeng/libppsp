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
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "internal.h"
#include "proto.h"
#include "log.h"

struct pg_swarm_scan_state
{
	struct pg_peer_swarm *ps;
	uint64_t min;
	uint64_t max;
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
pg_peerswarm_request_find_fn(uint64_t start, uint64_t end, bool value __unused, void *arg)
{
	struct pg_swarm_scan_state *state = arg;
	uint64_t count = MIN(end - start + 1, state->budget);

	DEBUG("requesting %d blocks @ %d", count, start);

	state->collected += count;
	pg_bitmap_set_range(state->ps->want_bitmap, start, start + count, true);
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

		pg_bitmap_set(ps->want_bitmap, 0);
		pack_request(ps->buffer, 0, 0);
		/* Here we could send PEX_Req */
		pg_buffer_enqueue(ps->buffer);
		ps->state = PEERSWARM_WAIT_FIRST_DATA;
		break;

	case PEERSWARM_WAIT_FIRST_DATA:
		DEBUG("waiting for first block from peer %s in swarm %s",
		      pg_peer_to_str(ps->peer), pg_swarm_to_str(ps->swarm));
		break;

	case PEERSWARM_READY:
		DEBUG("trying to request blocks from peer %s in swarm %s",
		    pg_peer_to_str(ps->peer), pg_swarm_to_str(ps->swarm));

		state.ps = ps;
		state.collected = 0;
		state.budget = 10;

		pg_bitmap_scan(ps->want_bitmap, BITMAP_SCAN_0, pg_peerswarm_request_find_fn, &state);
		pg_buffer_enqueue(ps->buffer);
		break;
	}


}

static bool
pg_peerswarm_timer_scan_fn(uint64_t start, uint64_t end, bool value __unused, void *arg)
{
	struct pg_peer_swarm *ps = arg;
	uint64_t i;

	end = MIN(end, start + 32);

	for (i = start; i <= end; i++) {
		pg_send_integrity(ps, i);
		pg_send_data(ps, i);
		pg_bitmap_set_range(ps->request_bitmap, start, end, false);
	}

	return (true);
}

static bool
pg_peerswarm_timer(void *arg)
{
	struct pg_peer_swarm *ps = arg;

	pg_bitmap_scan(ps->request_bitmap, BITMAP_SCAN_1, pg_peerswarm_timer_scan_fn, ps);
	return (true);
}

struct pg_peer_swarm *
pg_peerswarm_create(struct pg_peer *peer, struct pg_swarm *swarm,
    struct pg_protocol_options *options, uint32_t src_channel_id,
    uint32_t dst_channel_id)
{
	struct pg_peer_swarm *ps;
	struct pg_event event;

	DEBUG("peer=%s, swarm=%s, dst_channel_id=0x%08x", pg_peer_to_str(peer),
	    pg_swarm_to_str(swarm), dst_channel_id);

	ps = calloc(1, sizeof(struct pg_peer_swarm));
	ps->peer = peer;
	ps->swarm = swarm;
	ps->src_channel_id = src_channel_id;
	ps->dst_channel_id = dst_channel_id;
	ps->have_bitmap = pg_bitmap_create(swarm->file->nc);
	ps->request_bitmap = pg_bitmap_create(swarm->file->nc);
	ps->want_bitmap = pg_bitmap_create(swarm->file->nc);
	ps->sent_bitmap = pg_bitmap_create(swarm->file->nl * 2);
	ps->options = *options;
	ps->buffer = pg_buffer_create(peer, ps->dst_channel_id);
	LIST_INSERT_HEAD(&peer->swarms, ps, peer_entry);
	LIST_INSERT_HEAD(&swarm->peers, ps, swarm_entry);

	pg_send_handshake(ps);
	/* If we are leecher we can't send any HAVE in the HANDSHAKE, otherwise libswift will stop responding */
	if (dst_channel_id != 0) {
		pg_send_have(ps);
	} else {
		/* Normally pg_send_have would do that, but we don't send it */
		pg_buffer_enqueue(ps->buffer);
	}
	pg_peerswarm_request(ps);

	event.ctx = peer->context;
	event.peer = peer;
	event.swarm = swarm;
	event.type = EVENT_PEER_JOINED_SWARM;
	pg_emit_event(&event);

	pg_eventloop_add_timer(ps->peer->context->eventloop, 10, pg_peerswarm_timer, ps);

	return (ps);
}


void
pg_peerswarm_destroy(struct pg_peer_swarm *ps)
{
	struct pg_event ev;

	ev.ctx = ps->peer->context;
	ev.peer = ps->peer;
	ev.swarm = ps->swarm;
	ev.type = EVENT_PEER_LEFT_SWARM;
	pg_emit_event(&ev);
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
	swarm->fetched_chunks = swarm->nc;
	swarm->swarm_id_len = sizeof(file->sha);
	memcpy(swarm->swarm_id, file->sha, sizeof(file->sha));
	pg_bitmap_fill(swarm->have_bitmap, true);
	LIST_INSERT_HEAD(&ctx->swarms, swarm, entry);
	DEBUG("created swarm %s", pg_swarm_to_str(swarm));

	/* Poke all known peers for this swarm */
	LIST_FOREACH(peer, &ctx->peers, entry) {
		pg_peerswarm_create(peer, swarm, &options, pg_new_channel_id(), 0);
	}

	return (swarm);
}

bool
pg_swarm_iterate(struct pg_context *ctx, pg_swarm_iter_fn_t fn, void *arg)
{
	struct pg_swarm *swarm;

	LIST_FOREACH(swarm, &ctx->swarms, entry) {
		if (!fn(swarm, arg))
			return (false);
	}

	return (true);
}

size_t
pg_swarm_get_id(struct pg_swarm *swarm, uint8_t **hash)
{
	uint8_t *ret;

	ret = xmalloc(swarm->swarm_id_len);
	memcpy(ret, swarm->swarm_id, swarm->swarm_id_len);

	if (hash)
		*hash = ret;

	return (swarm->swarm_id_len);
}

uint64_t
pg_swarm_get_content_size(struct pg_swarm *swarm)
{
	return (0);
}

uint64_t
pg_swarm_get_total_chunks(struct pg_swarm *swarm)
{
	return (swarm->nc);
}

uint64_t
pg_swarm_get_received_chunks(struct pg_swarm *swarm)
{
	return (swarm->fetched_chunks);
}

uint64_t
pg_swarm_get_sent_chunks(struct pg_swarm *swarm)
{
	return (swarm->sent_chunks);
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
