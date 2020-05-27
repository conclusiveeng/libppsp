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
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/queue.h>
#include <sys/stat.h>

#include "peer.h"
#include "debug.h"


struct slisthead file_list_head;


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
		if (memcmp(&p->leecher_addr, client, sizeof(struct sockaddr_in)) == 0) {
			return p;
		}
		p = p->next;
	}

	return NULL;
}


/* seeder side: create new remote peer (LEECHER) */
struct peer * new_peer (struct sockaddr_in *sa, int n, int sockfd)
{
	struct peer *p;

	p = malloc(sizeof(struct peer));
	if (p == NULL)
		return NULL;

	memset(p, 0, sizeof(struct peer));
	memcpy(&p->leecher_addr, sa, sizeof(struct sockaddr_in));

	d_printf("new peer[%u]: %#lx   IP: %s:%u\n", p->thread_num, (uint64_t) p, inet_ntoa(p->leecher_addr.sin_addr), ntohs(p->leecher_addr.sin_port));

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

/* leecher side: create new remote peer (SEEDER) */
struct peer * new_seeder (struct sockaddr_in *sa, int n)
{
	struct peer *p;

	p = malloc(sizeof(struct peer));
	if (p == NULL)
		return NULL;

	memset(p, 0, sizeof(struct peer));

	memcpy(&p->leecher_addr, sa, sizeof(struct sockaddr_in));

	p->recv_buf = malloc(n);			/* allocate receiving buffer */
	p->send_buf = malloc(n);			/* allocate sending buffer */

	p->type = SEEDER;
	p->seeder = NULL;
	p->finishing = 0;
	p->thread = 0;
	clock_gettime(CLOCK_MONOTONIC, &p->ts_last_recv);
	clock_gettime(CLOCK_MONOTONIC, &p->ts_last_send);

	return p;
}


void cleanup_peer (struct peer *p)
{
	d_printf("cleaning up peer[%u]: %#lx   IP: %s:%u\n", p->thread_num, (uint64_t) p, inet_ntoa(p->leecher_addr.sin_addr), ntohs(p->leecher_addr.sin_port));

	/* method1 only - wait for pthread, destroy mutex and condition variable */
	if (p->to_remove == 1) {
		pthread_join(p->thread, NULL);

		d_printf("cleaning up peer: %#lx\n", (uint64_t) p);
		(void) remove_peer_from_list(&peer_list_head, p);

		/* destroy the semaphore */
		pthread_mutex_destroy(&p->mutex);
		pthread_cond_destroy(&p->mtx_cond);
	}

	/* free allocated memory */
	if (p->recv_buf)
		free(p->recv_buf);
	if (p->send_buf)
		free(p->send_buf);
	p->recv_buf = p->send_buf = NULL;
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
		if (p->to_remove != 0) { /* is this peer (leecher) marked to remove? */
			cleanup_peer(p);
		}
		p = pnext;
	}

	remove_dead_peers = 0;
}


/*
 * basing on chunk array - create download schedule (array)
 */
void create_download_schedule (struct peer *p)
{
	uint64_t o, oldo, y;

	d_printf("creating schedule for %u chunks\n", p->nc);

	p->download_schedule_len = 0;
	o = 0;
	while (o < p->nc) {
		/* find first/closest not yet downloaded chunk */
		while ((p->chunk[o].downloaded == CH_YES) && (o < p->nc)) o++;
		if (o >= p->nc) break;

		oldo = o;
		y = 0;
		while ((y < p->hashes_per_mtu) && (o < p->nc)) {
			if (p->chunk[o].downloaded == CH_NO) o++;
			else break;
			y++;
		}
		d_printf("%lu-%lu   %lu\n", oldo, o - 1, o - oldo);

		p->download_schedule[p->download_schedule_len].begin = oldo;
		p->download_schedule[p->download_schedule_len].end = o - 1;
		p->download_schedule_len++;
	}
	printf("\n");
}


int all_chunks_downloaded (struct peer *p)
{
	int ret;
	uint64_t x;

	d_printf("%s", "checking whether all of chunks has been downloaded\n");

	ret = 1;
	x = 0;
	while ((x < p->nc)) {
		if (p->chunk[x].downloaded == CH_NO) {
			ret = 0;
			break;
		}
		x++;
	}
	return ret;
}


void list_dir (char *dname)
{
	DIR *dir;
	struct dirent *dirent;
	char newdir[1024];
	struct file_list_entry *f;
	struct stat stat;

	dir = opendir(dname);
	if (dir == NULL) return;

	while (1) {
		dirent = readdir(dir);
		if (dirent == NULL)
			break;

		if (dirent->d_type == DT_REG) {
			f = malloc(sizeof(struct file_list_entry));
			SLIST_INSERT_HEAD(&file_list_head, f, next);
			memset(f->path, 0, sizeof(f->path));
			sprintf(f->path, "%s/%s", dname, dirent->d_name);
			lstat(f->path, &stat);
			f->file_size = stat.st_size;
		}

		if ((dirent->d_type == DT_DIR) && (strcmp(dirent->d_name, ".") != 0) && (strcmp(dirent->d_name, "..") != 0)) {
			snprintf(newdir, sizeof(newdir) - 1, "%s/%s", dname, dirent->d_name);
			list_dir(newdir);
		}
	}
	closedir(dir);
}


void create_file_list (char *dname)
{
	SLIST_INIT(&file_list_head);
	list_dir(dname);
}

