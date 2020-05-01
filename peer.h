#ifndef _PEER_H_
#define _PEER_H_

#include <netinet/in.h>
#include <semaphore.h>

struct peer {

	enum { LEECHER, SEEDER } type;
	enum { SM_NONE = 0, SM_HANDSHAKE_INIT, SM_HANDSHAKE_HAVE, SM_WAIT_REQUEST, SM_REQUEST, SM_INTEGRITY, SM_DATA, SM_WAIT_ACK, SM_ACK, SM_WAIT_FINISH,  SM_HANDSHAKE_FINISH } sm;

	uint32_t src_chan_id;
	uint32_t dest_chan_id;
	struct node *tree;		/* pointer to beginning (index 0) array with tree nodes */
	struct node *tree_root;		/* pointer to root of the tree */
	struct chunk *chunk;		/* array of chunks */
	uint32_t nl;			/* number of leaves */
	uint32_t nc;			/* number of chunks */

	/* todo: remove it */
	char *handshake_req;
	int handshake_req_len;
	char *handshake_resp;
	int handshake_resp_len;
	char *request;
	int request_len;

	uint32_t chunk_size;

	/* for finishing thread */
	uint8_t finishing;
	uint8_t finished;

	/* timestamp of last received and send message */
	struct timespec ts_last_recv, ts_last_send;

	/* last recieved and send message */
	uint8_t d_last_recv, d_last_send;

	/* network things */
	struct sockaddr_in sa;
	char *recv_buf;
	char *send_buf;

	uint16_t recv_len;
	int sockfd;

	/* synchronization */
	sem_t *sem;
	char sem_name[64];

	uint32_t start_chunk;
	uint32_t end_chunk;
	uint64_t curr_chunk;		/* currently serviced chunk */
	uint64_t file_size;
	char fname[256];
	char fname_len;
};


struct two_peers {
	struct peer *we;		/* describes local SEEDER - we are seeder */
	struct peer *peer;		/* describes remote peer - LEECHER */
};


struct peer * new_peer (struct sockaddr_in *sa, int n, int sockfd);

#endif
