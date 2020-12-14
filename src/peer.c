#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/queue.h>
#include "internal.h"
#include "log.h"
#include "proto.h"

#define MAX_FRAME_SIZE	1400

struct pg_frame_handler
{
	enum peregrine_message_type type;
	ssize_t (*handler)(struct pg_peer *, uint32_t, struct msg *);
};

static int pg_send_integrity(struct pg_peer_swarm *ps, uint32_t block);
static int pg_send_data(struct pg_peer_swarm *ps, uint64_t chunk);

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
	file = pg_file_by_sha(ctx, swarm_id);
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

static bool
pg_send_have_scan_fn(uint64_t start, uint64_t end, bool value, void *arg)
{
	struct pg_peer_swarm *ps = arg;

	DEBUG("send_have: adding range % " PRIu64 "..%" PRIu64, start, end);

	pack_have(ps->buffer, start, end);
	return (true);
}

int
pg_send_have(struct pg_peer_swarm *ps)
{
	DEBUG("send_have: peer=%s swarm=%s", pg_peer_to_str(ps->peer), pg_swarm_to_str(ps->swarm));

	pg_bitmap_scan(ps->swarm->have_bitmap, BITMAP_SCAN_1, pg_send_have_scan_fn, ps);
	pg_buffer_enqueue(ps->buffer);
	return (0);
}

static int
pg_ack_range(struct pg_peer_swarm *ps, uint64_t start, uint64_t end)
{

	pack_ack(ps->buffer, start, end, 0);
	pg_buffer_enqueue(ps->buffer);
	return (MSG_LENGTH(msg_ack));
}

static int
pg_send_integrity(struct pg_peer_swarm *ps, uint32_t block)
{
	struct node *node, *sibling;
	struct node n_min, n_max;
	LIST_HEAD(, node) nodes;

	LIST_INIT(&nodes);

	/* Start with the leaf node */
	node = &ps->swarm->file->tree[block * 2];

	while (node != NULL) {
		mt_interval_min_max(node, &n_min, &n_max);

		if (n_max.number / 2 > ps->swarm->nc)
			break;

		if (node->state != SENT)
			LIST_INSERT_HEAD(&nodes, node, entry);

		sibling = mt_find_sibling(node);
		if (sibling != NULL && sibling->state != SENT) {
			mt_interval_min_max(sibling, &n_min, &n_max);
			if (n_max.number / 2 > ps->swarm->nc) {
				node = node->parent;
				continue;
			}

			LIST_INSERT_HEAD(&nodes, sibling, entry);
		}

		node = node->parent;
	}

	if (!LIST_EMPTY(&nodes)) {
		LIST_FOREACH(node, &nodes, entry) {
			mt_interval_min_max(node, &n_min, &n_max);
			pack_integrity(ps->buffer, n_min.number / 2, n_max.number / 2, node->sha);
			node->state = SENT;
		}

		pg_buffer_enqueue(ps->buffer);
	}
	return (0);
}

static int
pg_send_data(struct pg_peer_swarm *ps, uint64_t chunk)
{
	void *ptr;
	uint64_t offset = ps->options.chunk_size * chunk;

	pack_data(ps->buffer, chunk, chunk, 0);
	ptr = pg_buffer_advance(ps->buffer, ps->options.chunk_size);

	pg_file_read_chunks(ps->swarm->file, chunk, 1, ptr);
	pg_buffer_enqueue(ps->buffer);
	return (0);
}

int
pg_send_handshake(struct pg_peer_swarm *ps)
{
	struct pg_buffer *buf = ps->buffer;
	struct {
		uint16_t length;
		uint8_t swarm_id[20];
	} swarm_id_opt;

	pack_handshake(buf, ps->src_channel_id);
	pack_handshake_opt_u8(buf, HANDSHAKE_OPT_VERSION, 1);
	pack_handshake_opt_u8(buf, HANDSHAKE_OPT_MIN_VERSION, 1);

	if (ps->dst_channel_id == 0) {
		swarm_id_opt.length = htobe16(ps->swarm->swarm_id_len);
		memcpy(&swarm_id_opt.swarm_id, ps->swarm->swarm_id, sizeof(swarm_id_opt.swarm_id));
		pack_handshake_opt(buf, HANDSHAKE_OPT_SWARM_ID, &swarm_id_opt,
		     sizeof(swarm_id_opt));
	}

	pack_handshake_opt_u8(buf, HANDSHAKE_OPT_CONTENT_INTEGRITY, 1);
	pack_handshake_opt_u8(buf, HANDSHAKE_OPT_MERKLE_HASH_FUNC, 0);
	pack_handshake_opt_u8(buf, HANDSHAKE_OPT_CHUNK_ADDRESSING_METHOD, 2);

#if 0
	/*
	 * Send chunk size if we're initiating the handshake.
	 *
	 * Apparently libswift doesn't like it.
	 * */
	if (ps->dst_channel_id == 0)
		pack_handshake_opt_u32(buf, HANDSHAKE_OPT_CHUNK_SIZE, ps->options.chunk_size);
#endif

	pack_handshake_opt_end(buf);
	return (0);
}

static ssize_t
pg_handle_handshake(struct pg_peer *peer, uint32_t chid, struct msg *msg)
{
	struct pg_peer_swarm *ps;
	struct pg_swarm *swarm;
	struct msg_handshake_opt *opt;
	struct pg_protocol_options options;
	uint16_t swarm_id_len = 20;
	uint8_t swarm_id[20];
	int pos = 0;

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
			pos += sizeof(*opt);
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

	if (chid != 0) {
		/* This is a handshake response */
		ps = pg_find_peerswarm_by_channel(peer, chid);
		if (ps == NULL) {

		}

		ps->state = PEERSWARM_WAIT_HAVE;
		ps->dst_channel_id = be32toh(msg->handshake.src_channel_id);
		ps->buffer->channel_id = ps->dst_channel_id;
		pg_buffer_reset(ps->buffer);

		return (MSG_LENGTH(msg_handshake) + pos);
	}

	swarm = pg_find_swarm_by_id(peer->context, swarm_id, swarm_id_len);
	if (swarm == NULL) {
		/* Error! Cannot find or create swarm */
		ERROR("handshake: cannot find or create swarm %s",
		    pg_hexdump(swarm_id, swarm_id_len));
		return (-1);
	}

	/* Closing handshake */
	if (msg->handshake.src_channel_id == 0) {
		pg_peerswarm_destroy(ps);
		return (MSG_LENGTH(msg_handshake) + pos);
	}

	/* Opening handshake, create peer-swarm relationship */
	pg_peerswarm_create(peer, swarm, &options, pg_new_channel_id(),
	    be32toh(msg->handshake.src_channel_id));

	return (MSG_LENGTH(msg_handshake) + pos);
}

static ssize_t
pg_handle_data(struct pg_peer *peer, uint32_t chid, struct msg *msg)
{
	struct pg_peer_swarm *ps;
	uint32_t start_chunk = be32toh(msg->data.start_chunk);
	uint32_t end_chunk = be32toh(msg->data.end_chunk);
	uint32_t len = end_chunk - start_chunk + 1;

	ps = pg_find_peerswarm_by_channel(peer, chid);
	if (ps == NULL) {
		WARN("data: cannot find channel id %d for peer %p", chid, peer);
		return (-1);
	}

	DEBUG("data: peer=%p, swarm=%s", peer, pg_swarm_to_str(ps->swarm));
	DEBUG("data: received %d chunks @ %d", len, start_chunk);

	pg_file_write_chunks(ps->swarm->file, start_chunk, len, msg->data.data);
	pg_bitmap_set_range(ps->swarm->have_bitmap, start_chunk, end_chunk, true);
	pg_ack_range(ps, start_chunk, end_chunk);
	pg_peerswarm_request(ps);

	return (MSG_LENGTH(msg_data) + len);
}

static ssize_t
pg_handle_ack(struct pg_peer *peer, uint32_t chid, struct msg *msg)
{
	struct pg_peer_swarm *ps;

	ps = pg_find_peerswarm_by_channel(peer, chid);
	if (ps == NULL) {
		WARN("ack: cannot find channel id 0x%08x for peer %p", chid, peer);
		return (-1);
	}

	DEBUG("ack: peer=%p, swarm=%s", peer, pg_swarm_to_str(ps->swarm));
	return (MSG_LENGTH(msg_ack));
}

static ssize_t
pg_handle_have(struct pg_peer *peer, uint32_t chid, struct msg *msg)
{
	struct pg_peer_swarm *ps;
	uint32_t start = be32toh(msg->have.start_chunk);
	uint32_t end = be32toh(msg->have.end_chunk);

	ps = pg_find_peerswarm_by_channel(peer, chid);
	if (ps == NULL) {
		WARN("have: cannot find channel id 0x%08x for peer %p", chid, peer);
		return (-1);
	}

	DEBUG("have: peer=%p, swarm=%s", peer, pg_swarm_to_str(ps->swarm));

	if (end > ps->swarm->nc) {
		DEBUG("have: updating swarm size to %u blocks", end + 1);
		ps->swarm->nc = end + 1;
		ps->swarm->file->nc = end + 1;
		pg_bitmap_resize(ps->swarm->have_bitmap, end + 1);
		pg_bitmap_resize(ps->have_bitmap, end + 1);
		pg_bitmap_resize(ps->request_bitmap, end + 1);
	}

	pg_bitmap_set_range(ps->have_bitmap, start, end, true);
	pg_peerswarm_request(ps);
	return (MSG_LENGTH(msg_have));
}

static ssize_t
pg_handle_integrity(struct pg_peer *peer, uint32_t chid, struct msg *msg)
{
	struct pg_peer_swarm *ps;

	ps = pg_find_peerswarm_by_channel(peer, chid);
	if (ps == NULL) {
		WARN("integrity: cannot find channel id 0x%08x for peer %p", chid, peer);
		return (-1);
	}

	DEBUG("integrity: peer=%p, swarm=%s", peer, pg_swarm_to_str(ps->swarm));

	if (ps->swarm->file->tree == NULL) {
		uint64_t order = mt_order2(
		    be32toh(msg->integrity.end_chunk) -
		    be32toh(msg->integrity.start_chunk)) + 1;

		DEBUG("integrity: creating merkle tree with order %d", order);

		ps->swarm->file->tree_root = mt_build_tree(1 << order, &ps->swarm->file->tree);
	}

	return (MSG_LENGTH(msg_integrity));
}

static ssize_t
pg_handle_pex_resv4(struct pg_peer *peer, uint32_t chid, struct msg *msg)
{
	struct sockaddr_in sin;

	DEBUG("pex_resv4: peer=%p", peer);

	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = msg->pex_resv4.ip_address;
	sin.sin_port = msg->pex_resv4.port;

	if (pg_add_peer(peer->context, (struct sockaddr *)&sin) != 0) {

	}

	return (MSG_LENGTH(msg_pex_resv4));
}

static ssize_t
pg_handle_pex_req(struct pg_peer *peer, uint32_t chid, struct msg *msg)
{
	struct pg_peer_swarm *otherps;
	struct pg_peer_swarm *ps;
	struct sockaddr_in *sin;

	ps = pg_find_peerswarm_by_channel(peer, chid);
	if (ps == NULL) {
		WARN("data: cannot find channel id 0x%08x for peer %p", chid, peer);
		return (-1);
	}

	DEBUG("pex_req: peer=%p, swarm=%s", peer, pg_swarm_to_str(ps->swarm));

	/* Iterate through peers in the same swarm */
	LIST_FOREACH(otherps, &ps->swarm->peers, swarm_entry) {
		sin = (struct sockaddr_in *)&otherps->peer->addr;
		if (sin->sin_family != AF_INET)
			continue;

		if (pg_sockaddr_cmp((struct sockaddr *)&ps->peer->addr,
		    (struct sockaddr *)&otherps->peer->addr) == 0)
			continue;

		pack_pex_resv4(ps->buffer, sin->sin_addr.s_addr, sin->sin_port);
	}

	pg_buffer_enqueue(ps->buffer);
	return (MSG_LENGTH(msg_pex_req));
}

static ssize_t
pg_handle_signed_integrity(struct pg_peer *peer, uint32_t chid, struct msg *msg)
{
	return (-1);
}

static ssize_t
pg_handle_request(struct pg_peer *peer, uint32_t chid, struct msg *msg)
{
	struct pg_peer_swarm *ps;
	uint32_t i;
	uint32_t start_chunk = be32toh(msg->request.start_chunk);
	uint32_t end_chunk = be32toh(msg->request.end_chunk);

	ps = pg_find_peerswarm_by_channel(peer, chid);
	if (ps == NULL) {
		WARN("request: cannot find channel id 0x%08x for peer %p", chid, peer);
		return (-1);
	}

	DEBUG("request: peer=%p, swarm=%s, start=%u, end=%u", peer, pg_swarm_to_str(ps->swarm),
	    start_chunk, end_chunk);

	for (i = start_chunk; i <= end_chunk; i++) {
		pg_send_integrity(ps, i);
		pg_send_data(ps, i);
	}

	pg_bitmap_set_range(ps->request_bitmap, start_chunk, end_chunk, true);
	return (MSG_LENGTH(msg_request));
}

static ssize_t
pg_handle_cancel(struct pg_peer *peer, uint32_t chid, struct msg *msg)
{
	struct pg_peer_swarm *ps;

	ps = pg_find_peerswarm_by_channel(peer, chid);
	if (ps == NULL) {
		WARN("cancel: cannot find channel id 0x%08x for peer %p", chid, peer);
		return (-1);
	}

	DEBUG("cancel: peer=%p, swarm=%s", peer, pg_swarm_to_str(ps->swarm));
	return (MSG_LENGTH(msg_cancel));
}

static ssize_t
pg_handle_choke(struct pg_peer *peer, uint32_t chid, struct msg *msg)
{
	struct pg_peer_swarm *ps;

	ps = pg_find_peerswarm_by_channel(peer, chid);
	if (ps == NULL) {
		WARN("choke: cannot find channel id 0x%08x for peer %p", chid, peer);
		return (-1);
	}

	DEBUG("choke: peer=%p, swarm=%s", peer, pg_swarm_to_str(ps->swarm));
	return (MSG_LENGTH(msg_choke));
}

static ssize_t
pg_handle_unchoke(struct pg_peer *peer, uint32_t chid, struct msg *msg)
{
	struct pg_peer_swarm *ps;

	ps = pg_find_peerswarm_by_channel(peer, chid);
	if (ps == NULL) {
		WARN("unchoke: cannot find channel id 0x%08x for peer %p", chid, peer);
		return (-1);
	}

	DEBUG("unchoke: peer=%p, swarm=%s", peer, pg_swarm_to_str(ps->swarm));
	return (MSG_LENGTH(msg_unchoke));
}
