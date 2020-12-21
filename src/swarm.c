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
#include <inttypes.h>
#include <stdlib.h>
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

static void
pg_peerswarm_request_range(struct pg_peer_swarm *ps, uint64_t start, uint64_t count)
{
	struct pg_rx_range_timeout *range;

	DEBUG("requesting %d blocks @ %d", count, start);

	pg_bitmap_set_range(ps->want_bitmap, start, start + count - 1, true);
	range = pg_peerswarm_create_range_timeout(start, start + count - 1);
	TAILQ_INSERT_TAIL(&ps->timeout_queue, range, entry);
	pack_request(ps->buffer, start, start + count - 1);

}

struct pg_rx_range_timeout *
pg_peerswarm_create_range_timeout(size_t start_chunk, size_t end_chunk)
{
	struct pg_rx_range_timeout *range;

	range = calloc(1, sizeof(*range));
	range->start = start_chunk;
	range->end = end_chunk;
	range->requested_at = pg_get_timestamp();

	return (range);
}

void
pg_peerswarm_request(struct pg_peer_swarm *ps)
{
	struct pg_swarm_scan_state state;
	struct pg_rx_range_timeout *range;
	uint64_t start;
	uint64_t count;

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
		range = pg_peerswarm_create_range_timeout(0, 0);
		TAILQ_INSERT_TAIL(&ps->timeout_queue, range, entry);

		/* Here we could send PEX_Req */
		pg_buffer_enqueue(ps->buffer);
		ps->state = PEERSWARM_WAIT_FIRST_DATA;
		ps->acked = 4;
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
		state.budget = 4;

		if (ps->acked >= state.budget) {
			pg_bitmap_find_first(ps->want_bitmap, state.budget, BITMAP_SCAN_0,
			    &start, &count);
			if (count == 0)
				return;

			pg_peerswarm_request_range(ps, start, count);
			pg_buffer_enqueue(ps->buffer);
			ps->acked = 0;
		}
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

static bool
pg_peerswarm_rx_req_timer_scan_fn(uint64_t start, uint64_t end,
    bool value __unused, void *arg)
{
	struct pg_peer_swarm *ps = arg;

	pg_bitmap_set_range(ps->want_bitmap, start, end, false);
	return (true);
}

static bool
pg_peerswarm_rx_req_timer(void *arg)
{
	struct pg_peer_swarm *ps = arg;
	struct pg_rx_range_timeout *range;
	uint64_t now;
	uint64_t elapsed_us;
	uint64_t req_timeout_us = 1000000;
	bool want_cleared = false;

	now = pg_get_timestamp();

	while (!TAILQ_EMPTY(&ps->timeout_queue)) {
		range = TAILQ_FIRST(&ps->timeout_queue);
		elapsed_us = now - range->requested_at;

		if (elapsed_us >= req_timeout_us) {
			want_cleared |= pg_bitmap_scan_range_limit(ps->have_bitmap,
			    range->start, range->end, 0, BITMAP_SCAN_0,
			    pg_peerswarm_rx_req_timer_scan_fn, ps);
			TAILQ_REMOVE(&ps->timeout_queue, range, entry);
		} else
			return (true);
	}

	if (want_cleared)
		pg_peerswarm_request(ps);

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
	TAILQ_INIT(&ps->timeout_queue);
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

	event.ctx = peer->context;
	event.peer = peer;
	event.swarm = swarm;
	event.type = EVENT_PEER_JOINED_SWARM;
	pg_emit_event(&event);

	pg_eventloop_add_timer(ps->peer->context->eventloop, 100, pg_peerswarm_timer, ps);
	pg_eventloop_add_timer(ps->peer->context->eventloop, 1000, pg_peerswarm_rx_req_timer, ps);

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

void
pg_swarm_finished(struct pg_swarm *swarm)
{
	struct pg_context *ctx = swarm->context;
	struct pg_peer_swarm *ps;
	struct pg_swarm *other_swarm;
	struct pg_event ev;
	bool finished_all = true;

	swarm->finished = true;

	INFO("finished downloading of swarm %s", pg_swarm_to_str(swarm));

	LIST_FOREACH(ps, &swarm->peers, swarm_entry)
	    pg_send_closing_handshake(ps);

	ev.ctx = ctx;
	ev.type = EVENT_SWARM_FINISHED;
	ev.swarm = swarm;
	ev.peer = NULL;
	pg_emit_event(&ev);

	LIST_FOREACH(other_swarm, &ctx->swarms, entry) {
		if (!other_swarm->finished)
			finished_all = false;
	}

	if (finished_all) {
		ev.type = EVENT_SWARM_FINISHED_ALL;
		ev.swarm = NULL;
		ev.peer = NULL;
		pg_emit_event(&ev);
	}
}

struct pg_swarm *
pg_swarm_create(struct pg_context *ctx, struct pg_file *file)
{
	struct pg_peer *peer;
	struct pg_swarm *swarm;
	struct pg_protocol_options options = { .chunk_size = ctx->options.chunk_size };

	swarm = calloc(1, sizeof(*swarm));
	swarm->context = ctx;
	swarm->file = file;
	swarm->nc = file->nc;
	swarm->have_bitmap = pg_bitmap_create(file->nc);
	swarm->fetched_chunks = swarm->nc;
	swarm->swarm_id_len = sizeof(file->sha);
	memcpy(swarm->swarm_id, file->sha, sizeof(file->sha));
	LIST_INSERT_HEAD(&ctx->swarms, swarm, entry);
	DEBUG("created swarm %s", pg_swarm_to_str(swarm));

	if (file->file_size != 0)
		pg_bitmap_fill(swarm->have_bitmap, true);

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
