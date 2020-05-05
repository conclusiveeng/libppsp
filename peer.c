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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>

#include "peer.h"
#include "debug.h"

/* add peer to end of the list */
void add_peer_to_list (struct peer *list_head, struct peer *p)
{
	struct peer *l;

	/* find last element of the list */
	l = list_head;

	while (l->next != NULL)
		l = l->next;

	l->next = p;
	p->next = NULL;
}


int remove_peer_from_list (struct peer *list_head, struct peer *peer)
{
	int ret;
	struct peer *p, *prev, *next;

	p = list_head->next; /* get the first element of the list */

	if (p == NULL)
		return -1; /* list is empty */

	/* look for peer in the list */
	prev = list_head;
	while (p != NULL) {
		if (p == peer) {
			break;
		}
		prev = p;
		p = p->next;
	}

	if (p == peer) { /* peer has been found in the list */
		next = p->next;
		prev->next = next;
		ret = 0;
	} else {
		ret = -2; /* peer not found in the list */
	}

	return ret;
}


struct peer * ip_port_to_peer (struct peer *list_head, struct sockaddr_in *client)
{
	struct peer *p;

	p = list_head->next; /* get the first element of the list */
	while (p != NULL) {
		if (memcmp(&p->sa, client, sizeof(struct sockaddr_in)) == 0) {
			return p;
		}
		p = p->next;
	}

	return NULL;
}


/* create new remote peer (LEECHER) */
struct peer * new_peer (struct sockaddr_in *sa, int n, int sockfd)
{
	struct peer *p;

	p = malloc(sizeof(struct peer));
	if (p == NULL)
		return NULL;

	memset(p, 0, sizeof(struct peer));

	memcpy(&p->sa, sa, sizeof(struct sockaddr_in));

	p->recv_buf = malloc(n);			/* allocate receiving buffer */
	p->send_buf = malloc(n);			/* allocate sending buffer */

	p->sockfd = sockfd;
	p->type = LEECHER;
	p->seeder = NULL;
	p->finishing = 0;
	clock_gettime(CLOCK_MONOTONIC, &p->ts_last_recv);
	clock_gettime(CLOCK_MONOTONIC, &p->ts_last_send);

	return p;
}


void cleanup_peer (struct peer *p)
{
	pthread_join(p->thread, NULL);

	d_printf("cleaning up peer: %#lx\n", (uint64_t) p);
	(void) remove_peer_from_list(&peer_list_head, p);

	/* destroy the semaphore */
	sem_close(p->sem);
	sem_unlink(p->sem_name);

	/* free allocated memory */
	free(p->recv_buf);
	free(p->send_buf);
	free(p);
}

/* remove all the marked peers */
void cleanup_all_dead_peers (struct peer *list_head)
{
	struct peer *p, *pnext;

	_assert(list_head->next != NULL, "%s\n", "list_head->next should be != NULL");
	p = list_head->next;

	while (p != NULL) {
		pnext = p->next;
		if (p->to_remove == 1) { /* is this peer marked to remove ? */
			cleanup_peer(p);
		}
		p = pnext;
	}

	remove_dead_peers = 0;
}
