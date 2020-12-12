//
// Created by jakub on 12.12.2020.
//

#include "internal.h"
#include "log.h"

struct pg_swarm_scan_state
{
	struct pg_peer_swarm *ps;
	uint64_t collected;
	uint64_t budget;
};

static bool
pg_swarm_request_find_fn(uint64_t start, uint64_t end, bool value, void *arg)
{
	uint64_t count = end - start + 1;


}

int
pg_swarm_request_from_peer(struct pg_peer_swarm *ps, uint64_t nblocks)
{
	struct pg_swarm_scan_state state;

	DEBUG("trying to request blocks from peer %s in swarm %s", pg_peer_to_str(ps->peer),
	    pg_swarm_to_str(ps->swarm));

	state.ps = ps;
	state.collected = 0;
	state.budget = nblocks;

	pg_bitmap_scan(ps->have_bitmap, BITMAP_SCAN_0, pg_swarm_request_find_fn, &state);
}

int
pg_swarm_request(struct pg_swarm *swarm)
{
	struct pg_peer_swarm *ps;

	DEBUG("trying to request blocks in swarm %s", pg_swarm_to_str(swarm));

	LIST_FOREACH(ps, &swarm->peers, swarm_entry) {
		pg_swarm_request_from_peer(ps);
	}

	return (0);
}
