#ifndef _PEER_H_
#define _PEER_H_

#include <netinet/in.h>
#include <semaphore.h>
#include <time.h>

struct peer {
	enum { LEECHER, SEEDER } type;
	enum { SM_NONE = 0, SM_HANDSHAKE_INIT, SM_HANDSHAKE_HAVE, SM_WAIT_REQUEST, SM_REQUEST, SM_INTEGRITY, SM_DATA, SM_WAIT_ACK, SM_ACK, SM_WAIT_FINISH,  SM_HANDSHAKE_FINISH } sm;

	uint32_t src_chan_id;
	uint32_t dest_chan_id;
	struct peer *seeder;		/* pointer to seeder peer struct - used on seeder side in threads */
	struct node *tree;		/* pointer to beginning (index 0) array with tree nodes */
	struct node *tree_root;		/* pointer to root of the tree */
	struct chunk *chunk;		/* array of chunks */
	uint32_t nl;			/* number of leaves */
	uint32_t nc;			/* number of chunks */

	/* for thread */
	uint8_t finishing;
	pthread_t thread;

	/* timestamp of last received and sent message */
	struct timespec ts_last_recv, ts_last_send;

	/* last received and sent message */
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

	uint32_t chunk_size;
	uint32_t start_chunk;
	uint32_t end_chunk;
	uint64_t curr_chunk;		/* currently serviced chunk */
	uint64_t file_size;
	char fname[256];
	char fname_len;

	/* list of peers */
	struct peer *next;
};


void add_peer_to_list (struct peer *, struct peer *);
int remove_peer_from_list (struct peer *, struct peer *);
struct peer * ip_port_to_peer (struct peer *, struct sockaddr_in *);
struct peer * new_peer (struct sockaddr_in *, int, int);

#endif
