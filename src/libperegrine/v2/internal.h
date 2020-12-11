//
// Created by jakub on 10.12.2020.
//

#ifndef PEREGRINE_INTERNAL_H
#define PEREGRINE_INTERNAL_H

struct ppspp_protocol_options
{
	uint8_t version;
	uint8_t minimum_version;
	uint16_t swarm_id_len;
	uint8_t swarm_id[20];
	uint8_t content_prot_method;
	uint8_t merkle_hash_func;
	uint8_t live_signature_alg;
	uint8_t chunk_addr_method;
	uint64_t live_disc_wind;
	uint8_t supported_msgs_len;
	void *supported_msgs; // for now we ignore this field
	uint32_t chunk_size;
};

struct peregrine_block
{
	struct peregrine_file *file;
	struct peregrine_peer *peer;
	uint32_t chunk_num;

	TAILQ_ENTRY(peregrine_block) entry;
};

/* shared file */
struct peregrine_file
{
	struct peregrine_context *context;
	char path[1024]; /* full path to file: directory name + file name */
	char sha[41];    /* textual representation of sha1 for a file */
	uint64_t file_size;
	uint32_t nl;             /* number of leaves */
	uint32_t nc;             /* number of chunks */
	struct chunk *tab_chunk; /* array of chunks for this file */
	struct node *tree;       /* tree of the file */
	struct node *tree_root;  /* pointer to root node of the tree */
	int fd;
	uint32_t start_chunk;
	uint32_t end_chunk;

	SLIST_ENTRY(peregrine_file) entry;
};

/**
 * @brief peregrine peer structure - main communication object
 *
 */
struct peregrine_peer
{
	struct peregrine_context *context;

	int sock_fd;
	char str_addr[PEER_STR_ADDR];
	struct sockaddr_storage addr;
	// Operation status
	uint8_t to_remove;                              // Peer makrked to remove (send handshake finish)
	uint8_t handshake_send;                         // Peer under initialization (wainting for second handshake)
	struct ppspp_protocol_options protocol_options; // Protocol configuration for peer
	struct peregrine_file *file;                    // Selected file
	// Main peer info

	// Handle REQUEST message
	uint8_t *seeder_data_bmp;
	uint32_t seeder_current_chunk;
	uint32_t seeder_request_start_chunk;
	uint32_t seeder_request_end_chunk;
	uint8_t seeder_pex_request;

	// Make a list of them
	LIST_HEAD(, peregrine_peer_swarm) swarms;
	LIST_ENTRY(peregrine_peer) entry;
};

struct peregrine_swarm
{
	struct peregrine_peer *peer;
	struct peregrine_context *context;
	struct peregrine_file *file;
	struct peregrine_bitmap *have_bitmap;
	struct peregrine_bitmap *request_bitmap;
	uint64_t nc;
	uint8_t swarm_id[20];
	uint32_t dst_channel_id;
	uint32_t src_channel_id;

	LIST_HEAD(, peregrine_peer_swarm) peers;
	LIST_ENTRY(peregrine_swarm) entry;
};

struct peregrine_peer_swarm
{
	struct peregrine_peer *peer;
	struct peregrine_swarm *swarm;
	uint32_t dst_channel_id;
	uint32_t src_channel_id;

	LIST_ENTRY(peregrine_peer_swarm) entry;
};

/* file being downloaded */
struct peregrine_download
{
	struct peregrine_context *context;
	char hash[256];
	int out_fd;
	LIST_HEAD(peregrine_download_peers, peregrine_peer) peers; // peers we download from
	/* other download state: downloaded chunks, known chunks, etc */
	LIST_ENTRY(peregrine_download) entry;
};

/* instance */
struct peregrine_context
{
	int sock_fd;
	uint32_t swarm_id;
	struct sockaddr_storage addr;
	LIST_HEAD(, peregrine_peer) peers;
	LIST_HEAD(, peregrine_swarm) swarms;
	SLIST_HEAD(, peregrine_file) files;
	LIST_HEAD(, peregrine_download) downloads;
	TAILQ_HEAD(, peregrine_block) io;
	/* other instance state */
};


#endif //PEREGRINE_INTERNAL_H
