#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/queue.h>
#include "internal.h"
#include "log.h"
#include "proto.h"

#define MAX_FRAME_SIZE	1400

struct pg_have_scan_state
{
	struct pg_peer_swarm *ps;
	uint8_t *response;
	size_t used;
};

struct pg_frame_handler
{
	enum peregrine_message_type type;
	ssize_t (*handler)(struct pg_peer *, uint32_t, struct msg *);
};

static ssize_t pg_handle_handshake(struct pg_peer *peer, uint32_t chid, struct msg *msg);
static ssize_t pg_handle_data(struct pg_peer *peer, uint32_t chid, struct msg *msg);
static ssize_t pg_handle_ack(struct pg_peer *peer, uint32_t chid, struct msg *msg);
static ssize_t pg_handle_have(struct pg_peer *peer, uint32_t chid, struct msg *msg);
static ssize_t pg_handle_integrity(struct pg_peer *peer, uint32_t chid, struct msg *msg);
static ssize_t pg_handle_pex_resv4(struct pg_peer *peer, uint32_t chid, struct msg *msg);
static ssize_t pg_handle_pex_req(struct pg_peer *peer, uint32_t chid, struct msg *msg);
static ssize_t pg_handle_signed_integrity(struct pg_peer *peer, uint32_t chid, struct msg *msg);
static ssize_t pg_handle_request(struct pg_peer *peer, uint32_t chid, struct msg *msg);
static ssize_t pg_handle_cancel(struct pg_peer *peer, uint32_t chid, struct msg *msg);
static ssize_t pg_handle_choke(struct pg_peer *peer, uint32_t chid, struct msg *msg);
static ssize_t pg_handle_unchoke(struct pg_peer *peer, uint32_t chid, struct msg *msg);

static const struct pg_frame_handler frame_handlers[] = {
	{ MSG_HANDSHAKE, pg_handle_handshake },
	{ MSG_DATA, pg_handle_data },
	{ MSG_ACK, pg_handle_ack },
	{ MSG_HAVE, pg_handle_have },
	{ MSG_INTEGRITY, pg_handle_integrity },
	{ MSG_PEX_RESV4, pg_handle_pex_resv4 },
	{ MSG_PEX_REQ, pg_handle_pex_req },
	{ MSG_SIGNED_INTEGRITY, pg_handle_signed_integrity },
	{ MSG_REQUEST, pg_handle_request },
	{ MSG_CANCEL, pg_handle_cancel },
	{ MSG_CHOKE, pg_handle_choke },
	{ MSG_UNCHOKE, pg_handle_unchoke },
	{ MSG_RESERVED, NULL }
};

ssize_t
pg_peer_send(struct pg_peer *peer, const void *buf, size_t len)
{
	DEBUG("send %d bytes to peer %p", len, peer);

	return (sendto(peer->context->sock_fd, buf, len, 0, (struct sockaddr *)&peer->addr,
	    sizeof(struct sockaddr_in)));
}

ssize_t
pg_handle_message(struct pg_peer *peer, uint32_t chid, struct msg *msg)
{
	const struct pg_frame_handler *handler;

	for (handler = &frame_handlers[0]; handler->handler != NULL; handler++) {
		if (handler->type == msg->message_type)
			return (handler->handler(peer, chid, msg));
	}

	return (-1);
}

static struct pg_swarm *
pg_find_swarm_by_id(struct pg_context *ctx, const uint8_t *swarm_id, size_t id_len)
{
	struct pg_swarm *s;
	struct pg_file *file;

	LIST_FOREACH(s, &ctx->swarms, entry) {
		if (memcmp(s->swarm_id, swarm_id, id_len) == 0)
			return (s);
	}

	/* Let's create a new swarm from a known file or stream */
	file = pg_context_file_by_sha(ctx, (const char *)swarm_id);
	if (file == NULL)
		return (NULL);

	s = calloc(1, sizeof(*s));
	s->file = file;
	s->context = ctx;
	s->have_bitmap = pg_bitmap_create(file->nc);
	s->nc = file->nc;
	pg_bitmap_fill(s->have_bitmap, true);
	memcpy(s->swarm_id, swarm_id, id_len);
	LIST_INSERT_HEAD(&ctx->swarms, s, entry);

	DEBUG("created new swarm %s", pg_swarm_to_str(s));

	return (s);
}

static struct pg_peer_swarm *
pg_find_peerswarm_by_id(struct pg_peer *peer, uint8_t *swarm_id, size_t id_len)
{
	struct pg_peer_swarm *ps;

	LIST_FOREACH(ps, &peer->swarms, entry) {
		if (memcmp(ps->swarm->swarm_id, swarm_id, id_len) == 0)
			return (ps);
	}

	return (NULL);
}

static struct pg_peer_swarm *
pg_find_peerswarm_by_channel(struct pg_peer *peer, uint32_t channel_id)
{
	struct pg_peer_swarm *ps;

	LIST_FOREACH(ps, &peer->swarms, entry) {
		if (ps->src_channel_id == channel_id)
			return (ps);
	}

	return (NULL);
}

static bool
pg_send_have_scan_fn(uint64_t start, uint64_t end, bool value, void *arg)
{
	struct pg_have_scan_state *state = arg;

	DEBUG("send_have: adding range % " PRIu64 "..%" PRIu64, start, end);

	/* prepare and send HAVE message */
	state->used += pack_have(state->response, start, end);
	if (state->used + sizeof(struct msg_have) > MAX_FRAME_SIZE) {
		pg_peer_send(state->ps->peer, state->response, state->used);
		state->used = pack_dest_chan(state->response, state->ps->dst_channel_id);
	}

	return (true);
}

static int
pg_send_have(struct pg_peer_swarm *ps)
{
	struct pg_have_scan_state state;
	uint8_t response[MAX_FRAME_SIZE];

	state.ps = ps;
	state.response = response;
	state.used = pack_dest_chan(response, ps->dst_channel_id);

	pg_bitmap_scan(ps->swarm->have_bitmap, BITMAP_SCAN_1, pg_send_have_scan_fn, &state);

	if (state.used != 4)
		pg_peer_send(ps->peer, state.response, state.used);

	return (0);
}

static int
pg_send_integrity(struct pg_peer_swarm *ps, uint32_t block)
{
	struct node *node, *sibling;
	struct node n_min, n_max;
	uint8_t response[MAX_FRAME_SIZE];
	size_t len;
	LIST_HEAD(, node) nodes;

	LIST_INIT(&nodes);

	/* Start with the leaf node */
	node = &ps->swarm->file->tree[block * 2];

	while (node != NULL) {
		if (node->state != SENT) {
			LIST_INSERT_HEAD(&nodes, node, entry);
			node->state = SENT;
		}

		sibling = mt_find_sibling(node);
		if (sibling != NULL && sibling->state != SENT) {
			LIST_INSERT_HEAD(&nodes, sibling, entry);
			sibling->state = SENT;
		}

		node = node->parent;
	}

	len = pack_dest_chan(response, ps->dst_channel_id);

	LIST_FOREACH(node, &nodes, entry) {
		mt_interval_min_max(node, &n_min, &n_max);
		len += pack_integrity(response + len, n_min.number / 2, n_max.number / 2, node->sha);
	}

	pg_peer_send(ps->peer, response, len);
}

static ssize_t
pg_handle_handshake(struct pg_peer *peer, uint32_t chid, struct msg *msg)
{
	struct pg_peer_swarm *ps;
	struct pg_swarm *swarm;
	struct msg_handshake_opt *opt;
	struct pg_protocol_options options;
	uint16_t swarm_id_len;
	uint8_t swarm_id[20];
	uint8_t response[sizeof(struct msg_handshake) + 1024];
	int pos = 0;
	size_t len;

	DEBUG("handshake: peer=%p", peer);

	options.chunk_size = 1024;

	for (;;) {
		opt = (struct msg_handshake_opt *)&msg->handshake.protocol_options[pos];

		switch (opt->code) {
		case HANDSHAKE_OPT_VERSION:
			options.version = opt->value[0];
			pos += sizeof(*opt) + sizeof(uint8_t);
			DEBUG("handshake: version = %d", options.version);
			break;

		case HANDSHAKE_OPT_MIN_VERSION:
			options.minimum_version = opt->value[0];
			pos += sizeof(*opt) + sizeof(uint8_t);
			DEBUG("handshake: minimum_version = %d", options.version);
			break;

		case HANDSHAKE_OPT_SWARM_ID:
			swarm_id_len = be16toh(*(uint16_t *)opt->value);
			memcpy(&swarm_id, &opt->value[sizeof(uint16_t)], swarm_id_len);
			pos += sizeof(*opt) + sizeof(uint16_t) + swarm_id_len;
			DEBUG("handshake: swarm_id_len = %d", swarm_id_len);
			DEBUG("handshake: swarm_id = %s", pg_hexdump(swarm_id, swarm_id_len));
			break;

		case HANDSHAKE_OPT_CONTENT_INTEGRITY:
			options.content_prot_method = opt->value[0];
			pos += sizeof(*opt) + sizeof(uint8_t);
			DEBUG("handshake: content_prot_method = %d", options.chunk_addr_method);
			break;

		case HANDSHAKE_OPT_MERKLE_HASH_FUNC:
			options.merkle_hash_func = opt->value[0];
			pos += sizeof(*opt) + sizeof(uint8_t);
			DEBUG("handshake: merkle_hash_func = %d", options.merkle_hash_func);
			break;

		case HANDSHAKE_OPT_LIVE_SIGNATURE_ALGO:
			options.live_signature_alg = opt->value[0];
			pos += sizeof(*opt) + sizeof(uint8_t);
			DEBUG("handshake: live_signature_alg = %d", options.live_signature_alg);
			break;

		case HANDSHAKE_OPT_CHUNK_ADDRESSING_METHOD:
			options.chunk_addr_method = opt->value[0];
			pos += sizeof(*opt) + sizeof(uint8_t);
			DEBUG("handshake: chunk_addressing_method = %d", options.chunk_addr_method);
			break;

		case HANDSHAKE_OPT_LIVE_DISCARD_WINDOW:
			pos += sizeof(*opt);
			switch (options.chunk_addr_method) {
			case 0:
			case 2:
				options.live_disc_wind = be32toh(*(uint32_t *)opt->value);
				pos += sizeof(uint32_t);
				break;
			case 1:
			case 3:
			case 4:
				options.live_disc_wind = be64toh(*(uint32_t *)opt->value);
				pos += sizeof(uint64_t);
				break;
			}
			DEBUG("handshake: live_disc_wind = %d", options.live_disc_wind);
			break;

		case HANDSHAKE_OPT_SUPPORTED_MESSAGE:
			options.supported_msgs_len = opt->value[0];
			pos += sizeof(*opt) + sizeof(uint8_t);

			options.supported_msgs = calloc(1, options.supported_msgs_len);
			memcpy(options.supported_msgs, &opt->value[1], options.supported_msgs_len);
			pos += options.supported_msgs_len;
			DEBUG("handshake: supported_msgs_len = %d", options.supported_msgs_len);
			break;

		case HANDSHAKE_OPT_CHUNK_SIZE:
			options.chunk_size = be32toh(*(uint32_t *)opt->value);
			pos += sizeof(*opt) + sizeof(uint32_t);
			DEBUG("handshake: chunk_size = %d", options.chunk_size);
			break;

		case HANDSHAKE_OPT_END:
			goto done;

		default:
			DEBUG("handshake: unknown option %d", opt->value[0]);
			pos++;
		}
	}

done:
	/* Check if we have a peer-swarm association with this ID already */
	ps = pg_find_peerswarm_by_id(peer, swarm_id, swarm_id_len);
	if (ps != NULL) {
		/* Error! Already member of this swarm */
		ERROR("handshake: already associated with swarm %s",
		    pg_hexdump(swarm_id, swarm_id_len));
		return (-1);
	}

	swarm = pg_find_swarm_by_id(peer->context, swarm_id, swarm_id_len);
	if (swarm == NULL) {
		/* Error! Cannot find or create swarm */
		ERROR("handshake: cannot find or create swarm %s",
		    pg_hexdump(swarm_id, swarm_id_len));
		return (-1);
	}

	// Handshake finish
	if (be32toh(chid) != 0 && be32toh(msg->handshake.src_channel_id) == 0) {
		ps->peer->to_remove = 1;
		return sizeof(struct msg) + sizeof(struct msg_handshake) + pos;
	}

	// HANDSHAKE INIT dst_channel_id = 0, src_channel_id != 0
	ps = calloc(1, sizeof(struct pg_peer_swarm));
	ps->peer = peer;
	ps->swarm = swarm;
	ps->src_channel_id = pg_new_channel_id();
	ps->dst_channel_id = be32toh(msg->handshake.src_channel_id);
	ps->request_bitmap = pg_bitmap_create(swarm->file->nc);
	ps->options = options;
	LIST_INSERT_HEAD(&peer->swarms, ps, entry);
	LIST_INSERT_HEAD(&swarm->peers, ps, entry);

	len = pack_dest_chan(response, ps->dst_channel_id);
	len += pack_handshake(response + len, ps->src_channel_id);
	len += pack_handshake_opt_u8(response + len, HANDSHAKE_OPT_VERSION, 1);
	len += pack_handshake_opt_u8(response + len, HANDSHAKE_OPT_MIN_VERSION, 1);
	len += pack_handshake_opt_u8(response + len, HANDSHAKE_OPT_CONTENT_INTEGRITY, 1);
	len += pack_handshake_opt_u8(response + len, HANDSHAKE_OPT_MERKLE_HASH_FUNC, 0);
	len += pack_handshake_opt_u8(response + len, HANDSHAKE_OPT_CHUNK_ADDRESSING_METHOD, 2);
	//len += pack_handshake_opt_u32(response + len, HANDSHAKE_OPT_CHUNK_SIZE, options.chunk_size);
	len += pack_handshake_opt_end(response + len);
	len += pack_have(response + len, 0, ps->swarm->nc - 1);
	pg_peer_send(peer, response, len);
	pg_send_have(ps);

	return sizeof(struct msg) + sizeof(struct msg_handshake) + pos;
}

static ssize_t
pg_handle_data(struct pg_peer *peer, uint32_t chid, struct msg *msg)
{
	struct pg_peer_swarm *ps;

	ps = pg_find_peerswarm_by_channel(peer, chid);
	if (ps == NULL) {
		WARN("data: cannot find channel id %d for peer %p", chid, peer);
		return (-1);
	}

	DEBUG("data: peer=%p, swarm=%s", peer, pg_swarm_to_str(ps->swarm));


}

static ssize_t
pg_handle_ack(struct pg_peer *peer, uint32_t chid, struct msg *msg)
{
	struct pg_peer_swarm *ps;

	ps = pg_find_peerswarm_by_channel(peer, chid);
	if (ps == NULL) {
		WARN("ack: cannot find channel id %d for peer %p", chid, peer);
		return (-1);
	}

	DEBUG("ack: peer=%p, swarm=%s", peer, pg_swarm_to_str(ps->swarm));

}

static ssize_t
pg_handle_have(struct pg_peer *peer, uint32_t chid, struct msg *msg)
{
	struct pg_peer_swarm *ps;

	ps = pg_find_peerswarm_by_channel(peer, chid);
	if (ps == NULL) {
		WARN("have: cannot find channel id %d for peer %p", chid, peer);
		return (-1);
	}

	DEBUG("have: peer=%p, swarm=%s", peer, pg_swarm_to_str(ps->swarm));
}

static ssize_t
pg_handle_integrity(struct pg_peer *peer, uint32_t chid, struct msg *msg)
{
	struct pg_peer_swarm *ps;

	ps = pg_find_peerswarm_by_channel(peer, chid);
	if (ps == NULL) {
		WARN("integrity: cannot find channel id %d for peer %p", chid, peer);
		return (-1);
	}

	DEBUG("integrity: peer=%p, swarm=%s", peer, pg_swarm_to_str(ps->swarm));
}

static ssize_t
pg_handle_pex_resv4(struct pg_peer *peer, uint32_t chid, struct msg *msg)
{
	DEBUG("pex_resv4: peer=%p", peer);
}

static ssize_t
pg_handle_pex_req(struct pg_peer *peer, uint32_t chid, struct msg *msg)
{
	struct pg_peer_swarm *otherps;
	struct pg_peer_swarm *ps;
	struct sockaddr_in *sin;
	uint8_t response[1400];
	size_t pos;

	ps = pg_find_peerswarm_by_channel(peer, chid);
	if (ps == NULL) {
		WARN("data: cannot find channel id %d for peer %p", chid, peer);
		return (-1);
	}

	DEBUG("pex_req: peer=%p, swarm=%s", peer, pg_swarm_to_str(ps->swarm));

	pos = pack_dest_chan(response, ps->dst_channel_id);

	/* Iterate through peers in the same swarm */
	LIST_FOREACH(otherps, &ps->swarm->peers, entry) {
		sin = (struct sockaddr_in *)&otherps->peer->addr;
		if (sin->sin_family != AF_INET)
			continue;

		pos += pack_pex_resv4(response + pos, sin->sin_addr.s_addr, sin->sin_port);
	}

	return (pos);
}

static ssize_t
pg_handle_signed_integrity(struct pg_peer *peer, uint32_t chid, struct msg *msg)
{
}

static ssize_t
pg_handle_request(struct pg_peer *peer, uint32_t chid, struct msg *msg)
{
	struct pg_peer_swarm *ps;
	struct pg_block *req;
	uint32_t i;
	uint32_t start_chunk = be32toh(msg->request.start_chunk);
	uint32_t end_chunk = be32toh(msg->request.end_chunk);

	ps = pg_find_peerswarm_by_channel(peer, chid);
	if (ps == NULL) {
		WARN("request: cannot find channel id %d for peer %p", chid, peer);
		return (-1);
	}

	DEBUG("request: peer=%p, swarm=%s, start=%u, end=%u", peer, pg_swarm_to_str(ps->swarm),
	    start_chunk, end_chunk);

	for (i = start_chunk; i <= end_chunk; i++) {
		req = calloc(1, sizeof(*req));
		req->ps = ps;
		req->file = ps->swarm->file;
		req->chunk_num = i;
		pg_send_integrity(ps, i);
		pg_socket_enqueue_tx(peer->context, req);
	}

	pg_bitmap_set_range(ps->request_bitmap, start_chunk, end_chunk, true);
	return (sizeof(msg->message_type) + sizeof(msg->request));
}

static ssize_t
pg_handle_cancel(struct pg_peer *peer, uint32_t chid, struct msg *msg)
{
	struct pg_peer_swarm *ps;

	ps = pg_find_peerswarm_by_channel(peer, chid);
	if (ps == NULL) {
		WARN("cancel: cannot find channel id %d for peer %p", chid, peer);
		return (-1);
	}

	DEBUG("cancel: peer=%p, swarm=%s", peer, pg_swarm_to_str(ps->swarm));
}

static ssize_t
pg_handle_choke(struct pg_peer *peer, uint32_t chid, struct msg *msg)
{
}

static ssize_t
pg_handle_unchoke(struct pg_peer *peer, uint32_t chid, struct msg *msg)
{
}
