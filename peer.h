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


#ifndef _PEER_H_
#define _PEER_H_

#include <netinet/in.h>
#include <semaphore.h>
#include <time.h>
#include <stdint.h>

struct peer {
	enum {
		LEECHER,
		SEEDER
	} type;

	enum {
		SM_NONE = 0,
		SM_HANDSHAKE_INIT,
		SM_HANDSHAKE_HAVE,
		SM_WAIT_REQUEST,
		SM_REQUEST,
		SM_INTEGRITY,
		SM_DATA,
		SM_WAIT_ACK,
		SM_ACK,
		SM_WAIT_FINISH,
		SM_HANDSHAKE_FINISH
	} sm;

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

	uint32_t timeout;

	/* timestamp of last received and sent message */
	struct timespec ts_last_recv, ts_last_send;

	/* last received and sent message */
	uint8_t d_last_recv, d_last_send;

	/* network things */
	struct sockaddr_in sa;
	struct in_addr seeder_addr;
	char *recv_buf;
	char *send_buf;

	uint16_t recv_len;
	int sockfd;

	/* synchronization */
	sem_t *sem;
	char sem_name[64];
	uint8_t to_remove;
	pthread_mutex_t mutex;
	pthread_cond_t mtx_cond;
	enum { C_TODO = 1, C_DONE = 2 } cond;

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

extern struct peer peer_list_head;
extern uint8_t remove_dead_peers;

void add_peer_to_list (struct peer *, struct peer *);
int remove_peer_from_list (struct peer *, struct peer *);
struct peer * ip_port_to_peer (struct peer *, struct sockaddr_in *);
struct peer * new_peer (struct sockaddr_in *, int, int);
void cleanup_peer (struct peer *);
void cleanup_all_dead_peers (struct peer *);

#endif
