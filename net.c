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
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>
#include <inttypes.h>
#include <semaphore.h>
#include <libgen.h>

#include "mt.h"
#include "net.h"
#include "ppspp_protocol.h"
#include "peer.h"
#include "sha1.h"
#include "debug.h"

#define SEM_NAME "/ppspp"

extern int h_errno;
struct peer peer_list_head = { .next = NULL };
uint8_t remove_dead_peers;

sem_t * semaph_init (struct peer *p)
{
	sem_t *sem;

	memset(p->sem_name, 0, sizeof(p->sem_name));
	snprintf(p->sem_name, sizeof(p->sem_name) - 1, "%s_%x_%lx", SEM_NAME, (uint32_t) getpid(), random());

	sem_unlink(p->sem_name);

	sem = sem_open(p->sem_name, O_CREAT, 0777, 0);		/* create semaphore initially locked */
	if (sem == SEM_FAILED) {
		printf("sem_open error: %s\n", strerror(errno));
		abort();
	}

	return sem;
}


int semaph_post (sem_t *sem)
{
	int s;

	s = sem_post(sem);
	if (s != 0) {
		printf("%s: error: %u  %s\n", __func__, errno, strerror(errno));
		abort();
	}

	return 0;
}


int semaph_wait (sem_t *sem)
{
	int s;

	s = sem_wait(sem);
	if (s != 0) {
		printf("%s: error: %u  %s\n", __func__, errno, strerror(errno));
		abort();
	}

	return 0;
}


int mutex_init (pthread_mutex_t *mutex)
{
	int s;

	s = pthread_mutex_init(mutex, NULL);
	if (s != 0) {
		printf("%s: error: %u  %s\n", __func__, errno, strerror(errno));
		abort();
	}

	return 0;
}


int mutex_lock (pthread_mutex_t *mutex)
{
	int s;

	s = pthread_mutex_lock(mutex);
	if (s != 0) {
		printf("%s: error: %u  %s\n", __func__, errno, strerror(errno));
		abort();
	}

	return 0;
}


int mutex_unlock (pthread_mutex_t *mutex)
{
	int s;

	s = pthread_mutex_unlock(mutex);
	if (s != 0) {
		printf("%s: error: %u  %s\n", __func__, errno, strerror(errno));
		abort();
	}

	return 0;
}


int cond_lock_init (struct peer *p)
{
	int s;

	s = pthread_mutex_init(&p->mutex, NULL);
	if (s != 0) {
		printf("%s: error: %u  %s\n", __func__, errno, strerror(errno));
		abort();
	}

	s = pthread_cond_init(&p->mtx_cond, NULL);
	if (s != 0) {
		printf("%s: error: %u  %s\n", __func__, errno, strerror(errno));
		abort();
	}

	return 0;
}


int cond_lock (struct peer *p)
{
	pthread_mutex_lock(&p->mutex);
	p->cond = C_TODO;
	do {
		if (p->cond == C_DONE)
			break;
		else
			pthread_cond_wait(&p->mtx_cond, &p->mutex);

	} while(1);

	pthread_mutex_unlock(&p->mutex);

	return 0;
}


int cond_unlock (struct peer *p)
{
	pthread_mutex_lock(&p->mutex);

	p->cond = C_DONE;
	pthread_cond_signal(&p->mtx_cond);

	pthread_mutex_unlock(&p->mutex);

	return 0;
}


/* thread - seeder worker */
void * seeder_worker (void *data)
{
	int n, clientlen, sockfd, data_payload_len, h_resp_len, opts_len, s, y;
	char *data_payload, *bn, buf[40 + 1];
	char opts[1024];			/* buffer for encoded options */
	char swarm_id[] = "swarm_id";
	char handshake_resp[256];
	struct peer *p, *we;
	struct proto_opt_str pos;
	struct timespec ts;

	clientlen = sizeof(struct sockaddr_in);
	p = (struct peer *) data;			/* data of remote host (leecher) connecting to us (seeder)*/
	we = p->seeder;					/* our data (seeder) */
	sockfd = p->sockfd;

	d_printf("%s", "worker started\n");

	memset(&pos, 0, sizeof(struct proto_opt_str));
	memset(&opts, 0, sizeof(opts));

	/* prepare structure as a set of parameters to make_handshake_options() proc */
	pos.version = 1;
	pos.minimum_version = 1;
	pos.swarm_id_len = strlen(swarm_id);
	pos.swarm_id = (uint8_t *)swarm_id;
	pos.content_prot_method = 1;			/* merkle hash tree */
	pos.merkle_hash_func = 0;			/* 0 = sha-1 */
	pos.live_signature_alg = 0;			/* should be taken from DNSSEC */
	pos.chunk_addr_method = 2;			/* 2 = 32 bit chunk ranges */
	*(unsigned int *)pos.live_disc_wind = 0x12345678;
	pos.supported_msgs_len = 2;			/* bitmap of supported messages consists of 2 bytes */
	*(unsigned int *)pos.supported_msgs = 0xffff;	/* bitmap of supported messages */
	pos.chunk_size = we->chunk_size;
	pos.file_size = we->file_size;

	bn = basename(we->fname);
	pos.file_name_len = strlen(bn);
	memset(pos.file_name, 0, sizeof(pos.file_name));
	memcpy(pos.file_name, bn, pos.file_name_len);
	memcpy(pos.sha_demanded, "aaaaaaaaaaaaaaaaaaaa", 20);	/* it doesn't matter here because leecher doesn't use this field as read field */

	/* mark the options we want to pass to make_handshake_options() (which ones are valid) */
	pos.opt_map = 0;
	pos.opt_map |= (1 << VERSION);
	pos.opt_map |= (1 << MINIMUM_VERSION);
	pos.opt_map |= (1 << SWARM_ID);
	pos.opt_map |= (1 << CONTENT_PROT_METHOD);
	pos.opt_map |= (1 << MERKLE_HASH_FUNC);
	pos.opt_map |= (1 << LIVE_SIGNATURE_ALG);
	pos.opt_map |= (1 << CHUNK_ADDR_METHOD);
	pos.opt_map |= (1 << LIVE_DISC_WIND);
	pos.opt_map |= (1 << SUPPORTED_MSGS);
	pos.opt_map |= (1 << CHUNK_SIZE);
	pos.opt_map |= (1 << FILE_SIZE);
	pos.opt_map |= (1 << FILE_NAME);
	pos.opt_map |= (1 << FILE_HASH);

	p->sm_seeder = SM_NONE;

	data_payload = malloc(we->chunk_size + 4 + 1 + 4 + 4 + 8);	/* chunksize + headers */

	while (p->finishing == 0) {
		/* check how long ago we received anything from LEECHER */
		clock_gettime(CLOCK_MONOTONIC, &ts);
		if (ts.tv_sec - p->ts_last_recv.tv_sec > p->seeder->timeout) {
			d_printf("finishing thread due to timeout in communication: %#lx\n", (uint64_t)p);
			p->finishing = 1;
			p->to_remove = 1;	/* mark this particular peer to remove by GC */
			remove_dead_peers = 1;	/* set global flag for removing dead peers by garbage collector */
			cond_unlock(p);
			continue;
		}

		if ((p->sm_seeder == SM_NONE) && (message_type(p->recv_buf) == HANDSHAKE) && (p->recv_len > 0))
			p->sm_seeder = SM_HANDSHAKE_INIT;

		if (p->sm_seeder == SM_HANDSHAKE_INIT) {
			clock_gettime(CLOCK_MONOTONIC, &p->ts_last_recv);
			p->d_last_recv = HANDSHAKE;

			dump_handshake_request(p->recv_buf, p->recv_len, p);

			/* we've just received hash of the file from LEECHER so update "pos" structure */

			pos.file_size = p->file_size;

			pos.file_name_len = p->fname_len;
			memset(pos.file_name, 0, sizeof(pos.file_name));
			memcpy(pos.file_name, p->fname, pos.file_name_len);

			opts_len = make_handshake_options(opts, &pos);

			_assert((unsigned long int) opts_len <= sizeof(opts), "%s but has value: %u\n", "opts_len should be <= 1024", opts_len);

			h_resp_len = make_handshake_have(handshake_resp, 0, 0xfeedbabe, opts, opts_len, p);

			_assert((unsigned long int) h_resp_len <= sizeof(handshake_resp), "%s but has value: %u\n", "h_resp_len should be <= 256", h_resp_len);

			p->sm_seeder = SM_SEND_HANDSHAKE_HAVE;
			cond_unlock(p);
			continue;
		}

		if (p->sm_seeder == SM_SEND_HANDSHAKE_HAVE) {
			_assert(p->recv_len != 0, "%s but has value: %u\n", "p->recv_len should be != 0", p->recv_len);

			/* send HANDSHAKE + HAVE */
			n = sendto(sockfd, handshake_resp, h_resp_len, 0, (struct sockaddr *) &p->leecher_addr, clientlen);
			if (n < 0) {
				printf("%s", "ERROR in sendto\n");
				abort();
			}

			/* if we (seeder) have no such SHA1 file then p->file_list_entry is NULL and as a result we cannot send anything 
			   to leecher but the HANDSHAKE_HAVE with special range of chunks 0xfffffffe-0xfffffffe,
			   make_handshake_have() prepared appropriate message for leecher and we've just sent him this special message,
			   next step is to end this thread
			*/
			if (p->file_list_entry == NULL) {
				s = 0;
				for (y = 0; y < 20; y++)
					s += sprintf(buf + s, "%02x", p->sha_demanded[y] & 0xff);
				buf[40] = '\0';
				d_printf("Error: there is no file with hash %s for %s:%u. Closing connection.\n", buf, inet_ntoa(p->leecher_addr.sin_addr), ntohs(p->leecher_addr.sin_port));
				p->finishing = 1;
				p->to_remove = 1;	/* mark this particular peer to remove by GC */
				remove_dead_peers = 1;	/* set global flag for removing dead peers by garbage collector */
				cond_unlock(p);
				continue;
			}

			clock_gettime(CLOCK_MONOTONIC, &p->ts_last_send);
			p->d_last_send = HAVE;

			memset(p->fname, 0, sizeof(p->fname));
			strcpy(p->fname, basename(p->file_list_entry->path));	/* do we really need this here? */
			p->chunk_size = we->chunk_size;
			p->recv_len = 0;
			p->sm_seeder = SM_WAIT_REQUEST;
			cond_unlock(p);
			continue;
		}

		if (p->sm_seeder == SM_WAIT_REQUEST) {
			if ((message_type(p->recv_buf) == REQUEST) && (p->recv_len > 0))
				p->sm_seeder = SM_REQUEST;

			cond_unlock(p);
			continue;
		}

		if (p->sm_seeder == SM_REQUEST) {
			_assert(p->recv_len != 0, "%s but has value: %u\n", "p->recv_len should be != 0", p->recv_len);

			clock_gettime(CLOCK_MONOTONIC, &p->ts_last_recv);
			p->d_last_recv = REQUEST;

			d_printf("%s", "REQ\n");

			dump_request(p->recv_buf, p->recv_len, p);

			if (p->pex_required == 1)		/* does the leecher want PEX? */
				p->sm_seeder = SM_SEND_PEX_RESP;
			else
				p->sm_seeder = SM_SEND_INTEGRITY;
			cond_unlock(p);
			continue;
		}

		if (p->sm_seeder == SM_SEND_PEX_RESP) {
			n = make_pex_resp(p->send_buf, p, we);

			_assert(n <= BUFSIZE, "%s but n has value: %u and BUFSIZE: %u\n", "n should be <= BUFSIZE", n, BUFSIZE);

			n = sendto(sockfd, p->send_buf, n, 0, (struct sockaddr *) &p->leecher_addr, clientlen);
			if (n < 0) {
				printf("%s", "ERROR in sendto\n");
				abort();
			}

			clock_gettime(CLOCK_MONOTONIC, &p->ts_last_send);
			p->d_last_send = INTEGRITY;
			p->recv_len = 0;
			p->curr_chunk = p->start_chunk;		/* set beginning number of chunk for DATA0 */
			p->pex_required = 0;

			/* check whether is not a special range of chunks (empty set of chunks )*/
			/* if yes - don't send INTEGRITY nor DATAx and return to SM_NONE state */
			/* used by leecher algorithm 5 for first ask for PEX_REQ */
			if ((p->start_chunk == 0xffffffff) && (p->end_chunk == 0xffffffff))
				p->sm_seeder = SM_NONE;
			else
				p->sm_seeder = SM_SEND_INTEGRITY;
			cond_unlock(p);
			continue;
		}

		if (p->sm_seeder == SM_SEND_INTEGRITY) {
			n = make_integrity(p->send_buf, p, we);

			_assert(n <= BUFSIZE, "%s but n has value: %u and BUFSIZE: %u\n", "n should be <= BUFSIZE", n, BUFSIZE);

			/* send INTEGRITY with data */
			n = sendto(sockfd, p->send_buf, n, 0, (struct sockaddr *) &p->leecher_addr, clientlen);
			if (n < 0) {
				printf("%s", "ERROR in sendto\n");
				abort();
			}

			clock_gettime(CLOCK_MONOTONIC, &p->ts_last_send);
			p->d_last_send = INTEGRITY;
			p->recv_len = 0;
			p->curr_chunk = p->start_chunk;		/* set beginning number of chunk for DATA0 */
			p->sm_seeder = SM_SEND_DATA;

			cond_unlock(p);
			continue;
		}

		if (p->sm_seeder == SM_SEND_DATA) {
			data_payload_len = make_data(data_payload, p);

			_assert((uint32_t) data_payload_len <= we->chunk_size + 4 + 1 + 4 + 4 + 8, "%s but data_payload_len has value: %d and we->chunk_size: %u\n", "data_payload_len should be <= we->chunk_size", data_payload_len, we->chunk_size);

			/* send DATA datagram with contents of the chunk */
			n = sendto(sockfd, data_payload, data_payload_len, 0, (struct sockaddr *) &p->leecher_addr, clientlen);
			if (n < 0) {
				printf("%s", "ERROR in sendto\n");
				abort();
			}

			clock_gettime(CLOCK_MONOTONIC, &p->ts_last_send);
			p->d_last_send = DATA;
			p->sm_seeder = SM_WAIT_ACK;

			cond_unlock(p);
			continue;
		}

		if (p->sm_seeder == SM_WAIT_ACK) {
			if ((message_type(p->recv_buf) == ACK) && (p->recv_len > 0))
				p->sm_seeder = SM_ACK;
			else {
#if 0
				if ((message_type(p->recv_buf) == REQUEST) && (p->recv_len > 0)) {
					p->sm_seeder = SM_WAIT_REQUEST;
				}
#endif
				cond_unlock(p);
				continue;
			}
		}

		if (p->sm_seeder == SM_ACK) {
			clock_gettime(CLOCK_MONOTONIC, &p->ts_last_recv);

			dump_ack(p->recv_buf, p->recv_len, p);

			p->curr_chunk++;
			p->recv_len = 0;

			if (p->curr_chunk <= p->end_chunk)		/* if this is not ACK for our last sent DATA then go to DATA state */
				p->sm_seeder = SM_SEND_DATA;
			else if (p->curr_chunk > p->end_chunk)
				p->sm_seeder = SM_WAIT_REQUEST;		/* that was ACK for last DATA in serie so wait for REQUEST */

			cond_unlock(p);
			continue;
		}
	}

	/* finishing thread */

	free(data_payload);

	pthread_exit(NULL);
}


/* UDP datagram server (SEEDER) */
int net_seeder(struct peer *seeder)
{
	int sockfd, optval, n, st;
	char buf[BUFSIZE];
	socklen_t clientlen;
	struct sockaddr_in serveraddr;
	struct sockaddr_in clientaddr;
	struct peer *p;
	pthread_t thread;

	printf("Ok, ready for sharing\n");

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0)
		d_printf("%s", "ERROR opening socket\n");

	optval = 1;
	setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval , sizeof(int));

	memset((char *) &serveraddr, 0, sizeof(serveraddr));
	serveraddr.sin_family = AF_INET;
	serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);
	serveraddr.sin_port = htons((unsigned short)seeder->port);

	if (bind(sockfd, (struct sockaddr *) &serveraddr, sizeof(serveraddr)) < 0)
		d_printf("%s", "ERROR on binding\n");

	clientlen = sizeof(clientaddr);
	remove_dead_peers = 0;

	while (1) {
		/* invoke garbage collector */
		if (remove_dead_peers == 1)
			cleanup_all_dead_peers(&peer_list_head);

		memset(buf, 0, BUFSIZE);
		n = recvfrom(sockfd, buf, BUFSIZE, 0, (struct sockaddr *) &clientaddr, &clientlen);
		if (n < 0)
			d_printf("%s", "ERROR in recvfrom\n");

		/* locate peer basing on IP address and UDP port */
		p = ip_port_to_peer(&peer_list_head, &clientaddr);
		if ((p == NULL) && (message_type(buf) != HANDSHAKE))
                        continue;

		if (message_type(buf) == HANDSHAKE) {
			d_printf("%s", "OK HANDSHAKE\n");
			if (handshake_type(buf) == HANDSHAKE_INIT) {

				p = new_peer(&clientaddr, BUFSIZE, sockfd);
				add_peer_to_list(&peer_list_head, p);

				_assert(n <= BUFSIZE, "%s but n has value: %u and BUFSIZE: %u\n", "n should be <= BUFSIZE", n, BUFSIZE);

				memcpy(p->recv_buf, buf, n);
				p->recv_len = n;
				p->seeder = seeder;
				/* create new conditional variable */
				cond_lock_init(p);

				/* create worker thread for this client (leecher) */
				st = pthread_create(&thread, NULL, &seeder_worker, p);
				if (st != 0) {
					printf("%s", "cannot create new thread\n");
					abort();
				}

				d_printf("new pthread created: %#lx\n", (uint64_t) thread);

				p->thread = thread;
				continue;
			} else if (handshake_type(buf) == HANDSHAKE_FINISH) {	/* does the seeder want to close connection ? */
				d_printf("%s", "FINISH\n");

				if (p == NULL) {
					d_printf("searched IP: %s:%u  n: %u\n",  inet_ntoa(clientaddr.sin_addr), ntohs(clientaddr.sin_port), n);
					p = peer_list_head.next;
					while (p != NULL) {
						d_printf("    IP: %s:%u\n", inet_ntoa(p->leecher_addr.sin_addr), ntohs(p->leecher_addr.sin_port));
						p = p->next;
					}
				}

				if (p != NULL) {
					p->finishing = 1;	/* set the flag for finishing the thread */
					cleanup_peer(p);
				}
				continue;
			}
		}

		if (message_type(buf) == REQUEST) {
			_assert(p != NULL, "%s but p has value: %lu\n", "p should be != NULL", (uint64_t)p);

			cond_lock(p);

			d_printf("%s", "OK REQUEST\n");

			_assert(n <= BUFSIZE, "%s but n has value: %u and BUFSIZE: %u\n", "n should be <= BUFSIZE", n, BUFSIZE);

			memcpy(p->recv_buf, buf, n);
			p->recv_len = n;
			continue;
		}

		if (message_type(buf) == ACK) {
			_assert(p != NULL, "%s but p has value: %lu\n", "p should be != NULL", (uint64_t)p);

			cond_lock(p);

			d_printf("%s", "OK ACK\n");
			_assert(n <= BUFSIZE, "%s but n has value: %u and BUFSIZE: %u\n", "n should be <= BUFSIZE", n, BUFSIZE);

			memcpy(p->recv_buf, buf, n);
			p->recv_len = n;
			continue;
		}
	}
}


/* UDP datagram client - LEECHER */
int net_leecher_algo1_nosm(struct peer *peer)
{
	char buffer[BUFSIZE];
	char fname [256 + 32];
	char swarm_id[] = "swarm_id";
	char opts[1024];			/* buffer for encoded options */
	char handshake_req[256], request[256];
	unsigned char digest[20];
	uint8_t *data_buffer;
	uint8_t sha_buf[40 + 1], sha_seeder_buf[40 + 1];
	uint8_t cmp;
	int sockfd, n, s, y, fd, nr, opts_len, h_req_len, request_len;
	uint32_t data_buffer_len, z;
	uint64_t ack_len, cc, x, num_series, hashes_per_mtu, rest, begin, end;
	struct sockaddr_in servaddr;
	socklen_t len;
	SHA1Context context;
	struct proto_opt_str pos;
	struct timeval tv;
	fd_set fs;

	memset(&pos, 0, sizeof(struct proto_opt_str));
	memset(&opts, 0, sizeof(opts));
	memset(&handshake_req, 0, sizeof(handshake_req));

	/* prepare structure as a set of parameters to make_handshake_options() proc */
	pos.version = 1;
	pos.minimum_version = 1;
	pos.swarm_id_len = strlen(swarm_id);
	pos.swarm_id = (uint8_t *)swarm_id;
	pos.content_prot_method = 1;			/* merkle hash tree */
	pos.merkle_hash_func = 0;			/* 0 = sha-1 */
	pos.live_signature_alg = 0;			/* number from dnssec */
	pos.chunk_addr_method = 2;			/* 2 = 32 bit chunk ranges */
	*(unsigned int *)pos.live_disc_wind = 0x12345678;
	pos.supported_msgs_len = 2;			/* 2 bytes of bitmap of serviced commands */
	*(unsigned int *)pos.supported_msgs = 0xffff;	/* bitmap - we are servicing all of the commands from RFC*/
	pos.chunk_size = peer->chunk_size;
	pos.file_size = peer->file_size;
	pos.file_name_len = peer->fname_len;
	memset(pos.file_name, 0, sizeof(pos.file_name));
	memcpy(pos.file_name, peer->fname, peer->fname_len);

	/* mark the options we want to pass to make_handshake_options() (which ones are valid) */
	pos.opt_map = 0;
	pos.opt_map |= (1 << VERSION);
	pos.opt_map |= (1 << MINIMUM_VERSION);
	pos.opt_map |= (1 << SWARM_ID);
	pos.opt_map |= (1 << CONTENT_PROT_METHOD);
	pos.opt_map |= (1 << MERKLE_HASH_FUNC);
	pos.opt_map |= (1 << LIVE_SIGNATURE_ALG);
	pos.opt_map |= (1 << CHUNK_ADDR_METHOD);
	pos.opt_map |= (1 << LIVE_DISC_WIND);
	pos.opt_map |= (1 << SUPPORTED_MSGS);
	pos.opt_map |= (1 << CHUNK_SIZE);

	pos.opt_map |= (1 << FILE_SIZE);
	pos.opt_map |= (1 << FILE_NAME);

	/* for leecher */
	opts_len = make_handshake_options(opts, &pos);
	dump_options(opts, peer);
	d_printf("%s", "\n\ninitial handshake:\n");
	/* make initial HANDSHAKE request - serialize dest chan id, src chan id and protocol options */
	h_req_len = make_handshake_request(handshake_req, 0, 0xfeedbabe, opts, opts_len);
	dump_handshake_request(handshake_req, h_req_len, peer);

	len = sizeof(servaddr);

	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("socket creation failed");
		exit(EXIT_FAILURE);
	}

	memset(&servaddr, 0, sizeof(servaddr));

	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(PORT);
	//servaddr.sin_addr.s_addr = peer->seeder_addr.s_addr;
	servaddr.sin_addr.s_addr = peer->seeder_addr.sin_addr.s_addr;

	/* wait for SEEDER */
	do {
		/* send initial HANDSHAKE to SEEDER */
		n = sendto(sockfd, handshake_req, h_req_len, 0, (const struct sockaddr *) &servaddr, sizeof(servaddr));
		if (n < 0) {
			printf("error sending handhsake: %d\n", n);
			abort();
		}
		d_printf("%s", "initial message 1/3 sent\n");

		FD_ZERO(&fs);
		FD_SET(sockfd, &fs);
		tv.tv_sec = 1;
		tv.tv_usec = 0;

		s = select(sockfd + 1, &fs, NULL, NULL, &tv);
		n = 0;
		if (FD_ISSET(sockfd, &fs)) {
			/* receive response from SEEDER: HANDSHAKE + HAVE */
			n = recvfrom(sockfd, (char *)buffer, BUFSIZE, 0, (struct sockaddr *) &servaddr, &len);
		}
	} while (n <= 0);

	buffer[n] = '\0';
	d_printf("server replied with %u bytes\n", n);
	dump_handshake_have(buffer, n, peer);

	/* calculate number of SHA hashes per 1500 bytes MTU */
	/* (MTU - sizeof(iphdr) - sizeof(udphdr) - ppspp_headers) / sha_size */
	hashes_per_mtu = (1500 - 20 - 8 - (4 + 1 + 4 + 4 + 8))/20;
	d_printf("hashes_per_mtu: %lu\n", hashes_per_mtu);

	/* calculate number of series */
	num_series = peer->nc / hashes_per_mtu;
	rest = peer->nc % hashes_per_mtu;
	d_printf("nc: %u   num_series: %lu   rest: %lu\n", peer->nc, num_series, rest);

	/* build the tree */
	peer->tree_root = build_tree(peer->nc, &peer->tree);

	data_buffer_len = peer->chunk_size + 4 + 1 + 4 + 4 + 8;
	data_buffer = malloc(data_buffer_len);

	snprintf(fname, sizeof(fname), "%s", peer->fname);
	unlink(fname);

	fd = open(fname, O_WRONLY | O_CREAT, 0744);
	if (fd < 0) {
		printf("error opening file '%s' for writing: %u %s\n", fname, errno, strerror(errno));
		abort();
	}

	z = peer->start_chunk;
	while (z < peer->end_chunk) {
		d_printf("z: %u  peer->end_chunk: %u\n", z, peer->end_chunk);
		begin = z;

		if (z + hashes_per_mtu >= peer->end_chunk)
			end = peer->end_chunk;
		else
			end = z + hashes_per_mtu -1 ;

		d_printf("begin: %lu   end: %lu\n", begin, end);

		/* create REQUEST  */
		request_len = make_request(request, 0xfeedbabe, begin, end, peer);

		_assert((unsigned long int) request_len <= sizeof(request), "%s but request_len has value: %u and sizeof(request): %lu\n", "request_len should be <= sizeof(request)", request_len, sizeof(request));

		do {
			/* send REQUEST */
			n = sendto(sockfd, request, request_len, 0, (const struct sockaddr *) &servaddr, sizeof(servaddr));
			if (n < 0) {
				printf("error sending request: %d\n", n);
				abort();
			}
			d_printf("%s", "request message 3/3 sent\n");

			FD_ZERO(&fs);
			FD_SET(sockfd, &fs);
			tv.tv_sec = 1;
			tv.tv_usec = 0;

			s = select(sockfd + 1, &fs, NULL, NULL, &tv);
			n = 0;
			if (FD_ISSET(sockfd, &fs)) {
				/* receive INTEGRITY from SEEDER */
				n = recvfrom(sockfd, (char *)buffer, BUFSIZE, 0, (struct sockaddr *) &servaddr, &len);

				if (n < 0) {
					printf("error: recvfrom: %d errno: %d %s\n", n, errno, strerror(errno));
					printf("	len: %d\n", len);
					abort();
				}
			}
		} while (n <= 0);
		d_printf("server sent INTEGRITY: %d\n", n);
		dump_integrity(buffer, n, peer);		/* copy SHA hashes to peer->chunk[] */

		/* copy all the received now SHA hashes to tree */
		d_printf("copying sha %lu-%lu\n", begin, end);
		for (x = begin; x < end; x++)
			memcpy(peer->tree[2 * x].sha, peer->chunk[x].sha, 20);

		/* receive the whole range of chunks from SEEDER */
		for (cc = begin; cc <= end; cc++) {
			peer->curr_chunk = cc;

			/* receive single DATA datagram */
			nr = recvfrom(sockfd, (char *)data_buffer, data_buffer_len, 0, (struct sockaddr *) &servaddr, &len);
			if (nr <= 0) {
				printf("error: recvfrom: %d errno: %d %s\n", n, errno, strerror(errno));
				abort();
			}

			/* save received chunk to disk */
			lseek(fd, cc * peer->chunk_size, SEEK_SET);
			write(fd, data_buffer + 1 + 4 + 4 + 8 + 4, nr - (1 + 4 + 4 + 8 + 4));

			/* calculate SHA hash */
			SHA1Reset(&context);
			SHA1Input(&context, data_buffer + 1 + 4 + 4 + 8 + 4 , nr - (1 + 4 + 4 + 8 + 4)); /* skip the headers */
			SHA1Result(&context, digest);

			/* convert to ASCII calculated locally SHA hash */
			s = 0;
			for (y = 0; y < 20; y++)
				s += sprintf((char *)(sha_buf + s), "%02x", digest[y] & 0xff);
			sha_buf[40] = '\0';

			/* convert to ASCII remote SHA hash from SEEDER */
			s = 0;
			for (y = 0; y < 20; y++)
				s += sprintf((char *)(sha_seeder_buf + s), "%02x", peer->chunk[peer->curr_chunk].sha[y] & 0xff);
			sha_seeder_buf[40] = '\0';

			/* compare both SHA hashes: calculated locally and remote from SEEDER */
			cmp = memcmp(peer->chunk[peer->curr_chunk].sha, digest , 20);

			if (cmp != 0) {
				printf("error - hashes are different[%lu]: seeder %s vs digest: %s\n", cc, sha_seeder_buf, sha_buf);
				abort();
			}

			/* create ACK message to confirm that chunk in last DATA datagram has been transferred correctly */
			ack_len = make_ack(buffer, peer);

			_assert(ack_len <= BUFSIZE, "%s but ack_len has value: %lu and BUFSIZE: %u\n", "ack_len should be <= BUFSIZE", ack_len, BUFSIZE);

			/* send ACK */
			n = sendto(sockfd, buffer, ack_len, 0, (const struct sockaddr *) &servaddr, sizeof(servaddr));
			if (n < 0) {
				printf("error sending request: %d\n", n);
				abort();
			}
			d_printf("ACK[%lu] sent\n" ,cc);
		}
		z += hashes_per_mtu;
	}

	/* send HANDSHAKE FINISH */
	n = make_handshake_finish(buffer, peer);
	n = sendto(sockfd, buffer, ack_len, 0, (const struct sockaddr *) &servaddr, sizeof(servaddr));
	if (n < 0) {
		printf("error sending request: %d\n", n);
		abort();
	}
	d_printf("%s", "HANDSHAKE_FINISH sent\n");

	free(data_buffer);
	close(sockfd);
	close(fd);
	return 0;

}


int net_leecher_algo2_sm(struct peer *local_peer)
{
	char buffer[BUFSIZE];
	char fname [256 + 32];
	char swarm_id[] = "swarm_id";
	char opts[1024];			/* buffer for encoded options */
	char handshake_req[256], request[256];
	unsigned char digest[20];
	uint8_t *data_buffer;
	uint8_t sha_buf[40 + 1], sha_seeder_buf[40 + 1];
	uint8_t cmp;
	int sockfd, n, fd, nr, opts_len, h_req_len, request_len;
	uint32_t data_buffer_len, z;
	uint64_t ack_len, cc, x, num_series, hashes_per_mtu, rest, begin, end;
	struct sockaddr_in servaddr;
	socklen_t len;
	SHA1Context context;
	struct proto_opt_str pos;
	struct timeval tv;
	fd_set fs;


	memset(&pos, 0, sizeof(struct proto_opt_str));
	memset(&opts, 0, sizeof(opts));
	memset(&handshake_req, 0, sizeof(handshake_req));

	/* prepare structure as a set of parameters to make_handshake_options() proc */
	pos.version = 1;
	pos.minimum_version = 1;
	pos.swarm_id_len = strlen(swarm_id);
	pos.swarm_id = (uint8_t *)swarm_id;
	pos.content_prot_method = 1;			/* merkle hash tree */
	pos.merkle_hash_func = 0;			/* 0 = sha-1 */
	pos.live_signature_alg = 0;			/* number from dnssec */
	pos.chunk_addr_method = 2;			/* 2 = 32 bit chunk ranges */
	*(unsigned int *)pos.live_disc_wind = 0x12345678;
	pos.supported_msgs_len = 2;			/* 2 bytes of bitmap of serviced commands */
	*(unsigned int *)pos.supported_msgs = 0xffff;	/* bitmap - we are servicing all of the commands from RFC*/
	pos.chunk_size = local_peer->chunk_size;
	pos.file_size = local_peer->file_size;
	pos.file_name_len = local_peer->fname_len;
	memset(pos.file_name, 0, sizeof(pos.file_name));
	memcpy(pos.file_name, local_peer->fname, local_peer->fname_len);

	/* mark the options we want to pass to make_handshake_options() (which ones are valid) */
	pos.opt_map = 0;
	pos.opt_map |= (1 << VERSION);
	pos.opt_map |= (1 << MINIMUM_VERSION);
	pos.opt_map |= (1 << SWARM_ID);
	pos.opt_map |= (1 << CONTENT_PROT_METHOD);
	pos.opt_map |= (1 << MERKLE_HASH_FUNC);
	pos.opt_map |= (1 << LIVE_SIGNATURE_ALG);
	pos.opt_map |= (1 << CHUNK_ADDR_METHOD);
	pos.opt_map |= (1 << LIVE_DISC_WIND);
	pos.opt_map |= (1 << SUPPORTED_MSGS);
	pos.opt_map |= (1 << CHUNK_SIZE);

	pos.opt_map |= (1 << FILE_SIZE);
	pos.opt_map |= (1 << FILE_NAME);

	/* for leecher */
	opts_len = make_handshake_options(opts, &pos);
	dump_options(opts, local_peer);
	d_printf("%s", "\n\ninitial handshake:\n");

	/* make initial HANDSHAKE request - serialize dest chan id, src chan id and protocol options */
	h_req_len = make_handshake_request(handshake_req, 0, 0xfeedbabe, opts, opts_len);
	dump_handshake_request(handshake_req, h_req_len, local_peer);

	len = sizeof(servaddr);

	local_peer->sm_leecher = SM_HANDSHAKE;

	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("socket creation failed");
		exit(EXIT_FAILURE);
	}

	local_peer->finishing = 0;

	/* beginning of the state machine */
	while (local_peer->finishing == 0) {

		if (local_peer->sm_leecher == SM_HANDSHAKE) {
			memset(&servaddr, 0, sizeof(servaddr));

			servaddr.sin_family = AF_INET;
			servaddr.sin_port = htons(PORT);
			servaddr.sin_addr.s_addr = local_peer->seeder_addr.sin_addr.s_addr;

			/* send initial HANDSHAKE and wait for SEEDER's answer */
			n = sendto(sockfd, handshake_req, h_req_len, 0, (const struct sockaddr *) &servaddr, sizeof(servaddr));
			if (n < 0) {
				printf("error sending handshake: %d\n", n);
				abort();
			}
			d_printf("%s", "initial message 1/3 sent\n");

			local_peer->sm_leecher = SM_WAIT_HAVE;
		}

		if (local_peer->sm_leecher == SM_WAIT_HAVE) {
			FD_ZERO(&fs);
			FD_SET(sockfd, &fs);
			tv.tv_sec = 1;
			tv.tv_usec = 0;

			(void) select(sockfd + 1, &fs, NULL, NULL, &tv);
			n = 0;
			if (FD_ISSET(sockfd, &fs)) {
				/* receive response from SEEDER: HANDSHAKE + HAVE */
				n = recvfrom(sockfd, (char *)buffer, BUFSIZE, 0, (struct sockaddr *) &servaddr, &len);
			}

			if (n <= 0) {
				local_peer->sm_leecher = SM_HANDSHAKE;
				continue;
			} else {
				local_peer->sm_leecher = SM_PREPARE_REQUEST;
			}

		}

		if (local_peer->sm_leecher == SM_PREPARE_REQUEST) {
			buffer[n] = '\0';
			d_printf("server replied with %u bytes\n", n);
			dump_handshake_have(buffer, n, local_peer);

			/* calculate number of SHA hashes per 1500 bytes MTU */
			/* (MTU - sizeof(iphdr) - sizeof(udphdr) - ppspp_headers) / sha_size */
			hashes_per_mtu = (1500 - 20 - 8 - (4 + 1 + 4 + 4 + 8))/20;
			d_printf("hashes_per_mtu: %lu\n", hashes_per_mtu);

			/* calculate number of series */
			num_series = local_peer->nc / hashes_per_mtu;
			rest = local_peer->nc % hashes_per_mtu;
			d_printf("nc: %u   num_series: %lu   rest: %lu\n", local_peer->nc, num_series, rest);

			/* build the tree */
			local_peer->tree_root = build_tree(local_peer->nc, &local_peer->tree);

			data_buffer_len = local_peer->chunk_size + 4 + 1 + 4 + 4 + 8;
			data_buffer = malloc(data_buffer_len);   /* memory leak - bpo w petli while a frre poza petla */

			snprintf(fname, sizeof(fname), "%s", local_peer->fname);
			unlink(fname);

			fd = open(fname, O_WRONLY | O_CREAT, 0744);
			if (fd < 0) {
				printf("error opening file '%s' for writing: %u %s\n", fname, errno, strerror(errno));
				abort();
			}

			z = local_peer->start_chunk;
			local_peer->sm_leecher = SM_WHILE_REQUEST;
		}

		if (local_peer->sm_leecher == SM_WHILE_REQUEST) {
			d_printf("z: %u  local_peer->end_chunk: %u\n", z, local_peer->end_chunk);
			begin = z;

			if (z + hashes_per_mtu >= local_peer->end_chunk)
				end = local_peer->end_chunk;
			else
				end = z + hashes_per_mtu -1 ;

			d_printf("begin: %lu   end: %lu\n", begin, end);

			/* create REQUEST  */
			request_len = make_request(request, 0xfeedbabe, begin, end, local_peer);

			_assert((unsigned long int) request_len <= sizeof(request), "%s but request_len has value: %u and sizeof(request): %lu\n", "request_len should be <= sizeof(request)", request_len, sizeof(request));
			local_peer->sm_leecher = SM_SEND_REQUEST;
		}


		if (local_peer->sm_leecher == SM_SEND_REQUEST) {
			/* send REQUEST */
			n = sendto(sockfd, request, request_len, 0, (const struct sockaddr *) &servaddr, sizeof(servaddr));
			if (n < 0) {
				printf("error sending request: %d\n", n);
				abort();
			}
			d_printf("%s", "request message 3/3 sent\n");
			local_peer->sm_leecher = SM_WAIT_PEX_RESP;
			printf("request sent: %u\n", n);
		}

		if (local_peer->sm_leecher == SM_WAIT_PEX_RESP) {
			FD_ZERO(&fs);
			FD_SET(sockfd, &fs);
			tv.tv_sec = 1;
			tv.tv_usec = 0;

			(void) select(sockfd + 1, &fs, NULL, NULL, &tv);
			n = 0;
			if (FD_ISSET(sockfd, &fs)) {
				/* receive PEX_RESP from SEEDER */
				n = recvfrom(sockfd, (char *)buffer, BUFSIZE, 0, (struct sockaddr *) &servaddr, &len);
			}

			if (n <= 0) {
				local_peer->sm_leecher = SM_SEND_REQUEST;
				continue;
			} else
				local_peer->sm_leecher = SM_PEX_RESP;
		}

		if (local_peer->sm_leecher == SM_PEX_RESP) {
			printf("PEX_RESP\n");
			dump_pex_resp(buffer, n, local_peer, sockfd);

			local_peer->sm_leecher = SM_WAIT_INTEGRITY;
		}

		if (local_peer->sm_leecher == SM_WAIT_INTEGRITY) {
			FD_ZERO(&fs);
			FD_SET(sockfd, &fs);
			tv.tv_sec = 1;
			tv.tv_usec = 0;

			(void) select(sockfd + 1, &fs, NULL, NULL, &tv);
			n = 0;
			if (FD_ISSET(sockfd, &fs)) {
				/* receive INTEGRITY from SEEDER */
				n = recvfrom(sockfd, (char *)buffer, BUFSIZE, 0, (struct sockaddr *) &servaddr, &len);
			}

			if (n <= 0) {
				local_peer->sm_leecher = SM_SEND_REQUEST;
				continue;
			} else {
				local_peer->sm_leecher = SM_INTEGRITY;
			}
		}

		if (local_peer->sm_leecher == SM_INTEGRITY) {
			d_printf("server sent INTEGRITY: %d\n", n);
			dump_integrity(buffer, n, local_peer);		/* copy SHA hashes to local_peer->chunk[] */

			/* copy all the received now SHA hashes to tree */
			d_printf("copying sha %lu-%lu\n", begin, end);
			for (x = begin; x < end; x++)
				memcpy(local_peer->tree[2 * x].sha, local_peer->chunk[x].sha, 20);

			cc = begin;
			local_peer->sm_leecher = SM_WAIT_DATA;
		}

		if (local_peer->sm_leecher == SM_WAIT_DATA) {

			/* receive the whole range of chunks from SEEDER */
				local_peer->curr_chunk = cc;

				/* receive single DATA datagram */
				nr = recvfrom(sockfd, (char *)data_buffer, data_buffer_len, 0, (struct sockaddr *) &servaddr, &len);
				if (nr <= 0) {
					printf("error: recvfrom: %d errno: %d %s\n", n, errno, strerror(errno));
					abort();
				}
			local_peer->sm_leecher = SM_DATA;
		}

		if (local_peer->sm_leecher == SM_DATA) {

				/* save received chunk to disk */
				lseek(fd, cc * local_peer->chunk_size, SEEK_SET);
				write(fd, data_buffer + 1 + 4 + 4 + 8 + 4, nr - (1 + 4 + 4 + 8 + 4));

				/* calculate SHA hash */
				SHA1Reset(&context);
				SHA1Input(&context, data_buffer + 1 + 4 + 4 + 8 + 4 , nr - (1 + 4 + 4 + 8 + 4)); /* skip the headers */
				SHA1Result(&context, digest);


				/* compare both SHA hashes: calculated locally and remote from SEEDER */
				cmp = memcmp(local_peer->chunk[local_peer->curr_chunk].sha, digest , 20);

				if (cmp != 0) {
#if 0
					/* convert to ASCII calculated locally SHA hash */
					s = 0;
					for (y = 0; y < 20; y++)
						s += sprintf((char *)(sha_buf + s), "%02x", digest[y] & 0xff);
					sha_buf[40] = '\0';

					/* convert to ASCII remote SHA hash from SEEDER */
					s = 0;
					for (y = 0; y < 20; y++)
						s += sprintf((char *)(sha_seeder_buf + s), "%02x", local_peer->chunk[local_peer->curr_chunk].sha[y] & 0xff);
					sha_seeder_buf[40] = '\0';
#endif
					printf("error - hashes are different[%lu]: seeder %s vs digest: %s\n", cc, sha_seeder_buf, sha_buf);
					abort();
				}
				else {
					local_peer->sm_leecher = SM_SEND_ACK;
				}
		}

		if (local_peer->sm_leecher == SM_SEND_ACK) {
				/* create ACK message to confirm that chunk in last DATA datagram has been transferred correctly */
				ack_len = make_ack(buffer, local_peer);

				_assert(ack_len <= BUFSIZE, "%s but ack_len has value: %lu and BUFSIZE: %u\n", "ack_len should be <= BUFSIZE", ack_len, BUFSIZE);

				/* send ACK */
				n = sendto(sockfd, buffer, ack_len, 0, (const struct sockaddr *) &servaddr, sizeof(servaddr));
				if (n < 0) {
					printf("error sending request: %d\n", n);
					abort();
				}
				d_printf("ACK[%lu] sent\n" ,cc);

			cc++;

			if (cc <= end) {
				local_peer->sm_leecher = SM_WAIT_DATA;
				continue;
			} else
				local_peer->sm_leecher = SM_INC_Z;
		}

		if (local_peer->sm_leecher == SM_INC_Z) {
			z += hashes_per_mtu;
			if (z < local_peer->end_chunk) {
				local_peer->sm_leecher = SM_WHILE_REQUEST;
				continue;
			} else {
				local_peer->sm_leecher = SM_SEND_HANDSHAKE_FINISH;
			}
		}

		if (local_peer->sm_leecher == SM_SEND_HANDSHAKE_FINISH) {
			/* send HANDSHAKE FINISH */
			n = make_handshake_finish(buffer, local_peer);
			n = sendto(sockfd, buffer, n, 0, (const struct sockaddr *) &servaddr, sizeof(servaddr));
			if (n < 0) {
				printf("error sending request: %d\n", n);
				abort();
			}

			local_peer->finishing = 1;
			continue;
		}
	}
	d_printf("%s", "HANDSHAKE_FINISH sent\n");

	free(data_buffer);
	close(sockfd);
	close(fd);
	return 0;

}


int net_leecher_algo3_sm_switching_seeders(struct peer *local_peer)
{
	char buffer[BUFSIZE];
	char fname [256 + 32];
	char swarm_id[] = "swarm_id";
	char opts[1024];			/* buffer for encoded options */
	char handshake_req[256], request[256];
	unsigned char digest[20];
	uint8_t *data_buffer;
	uint8_t sha_buf[40 + 1], sha_seeder_buf[40 + 1];
	uint8_t cmp;
	int sockfd, n, fd, nr, opts_len, h_req_len, request_len;
	uint32_t data_buffer_len, z;
	uint64_t ack_len, cc, x, num_series, hashes_per_mtu, rest, begin, end;
	struct sockaddr_in servaddr;
	socklen_t len;
	SHA1Context context;
	struct proto_opt_str pos;
	struct timeval tv;
	fd_set fs;

	memset(&pos, 0, sizeof(struct proto_opt_str));
	memset(&opts, 0, sizeof(opts));
	memset(&handshake_req, 0, sizeof(handshake_req));

	/* prepare structure as a set of parameters to make_handshake_options() proc */
	pos.version = 1;
	pos.minimum_version = 1;
	pos.swarm_id_len = strlen(swarm_id);
	pos.swarm_id = (uint8_t *)swarm_id;
	pos.content_prot_method = 1;			/* merkle hash tree */
	pos.merkle_hash_func = 0;			/* 0 = sha-1 */
	pos.live_signature_alg = 0;			/* number from dnssec */
	pos.chunk_addr_method = 2;			/* 2 = 32 bit chunk ranges */
	*(unsigned int *)pos.live_disc_wind = 0x12345678;
	pos.supported_msgs_len = 2;			/* 2 bytes of bitmap of serviced commands */
	*(unsigned int *)pos.supported_msgs = 0xffff;	/* bitmap - we are servicing all of the commands from RFC*/
	pos.chunk_size = local_peer->chunk_size;
	pos.file_size = local_peer->file_size;
	pos.file_name_len = local_peer->fname_len;
	memset(pos.file_name, 0, sizeof(pos.file_name));
	memcpy(pos.file_name, local_peer->fname, local_peer->fname_len);

	/* mark the options we want to pass to make_handshake_options() (which ones are valid) */
	pos.opt_map = 0;
	pos.opt_map |= (1 << VERSION);
	pos.opt_map |= (1 << MINIMUM_VERSION);
	pos.opt_map |= (1 << SWARM_ID);
	pos.opt_map |= (1 << CONTENT_PROT_METHOD);
	pos.opt_map |= (1 << MERKLE_HASH_FUNC);
	pos.opt_map |= (1 << LIVE_SIGNATURE_ALG);
	pos.opt_map |= (1 << CHUNK_ADDR_METHOD);
	pos.opt_map |= (1 << LIVE_DISC_WIND);
	pos.opt_map |= (1 << SUPPORTED_MSGS);
	pos.opt_map |= (1 << CHUNK_SIZE);

	pos.opt_map |= (1 << FILE_SIZE);
	pos.opt_map |= (1 << FILE_NAME);

	/* for leecher */
	opts_len = make_handshake_options(opts, &pos);
	dump_options(opts, local_peer);
	d_printf("%s", "\n\ninitial handshake:\n");


	/* make initial HANDSHAKE request - serialize dest chan id, src chan id and protocol options */
	h_req_len = make_handshake_request(handshake_req, 0, 0xfeedbabe, opts, opts_len);
	dump_handshake_request(handshake_req, h_req_len, local_peer);

	len = sizeof(servaddr);

	local_peer->sm_leecher = SM_HANDSHAKE;


	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("socket creation failed");
		exit(EXIT_FAILURE);
	}


	/* set primary seeder IP:port as a initial default values */
	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(PORT);
	servaddr.sin_addr.s_addr = local_peer->seeder_addr.sin_addr.s_addr;

	local_peer->finishing = 0;

	while (local_peer->finishing == 0) {

		if (local_peer->sm_leecher == SM_HANDSHAKE) {
#if 0
			memset(&servaddr, 0, sizeof(servaddr));
			servaddr.sin_family = AF_INET;
			servaddr.sin_port = htons(PORT);
			servaddr.sin_addr.s_addr = local_peer->current_seeder->seeder_addr.sin_addr.s_addr;
#endif
			/* send initial HANDSHAKE and wait for SEEDER's answer */
			n = sendto(sockfd, handshake_req, h_req_len, 0, (const struct sockaddr *) &servaddr, sizeof(servaddr));
			if (n < 0) {
				printf("error sending handshake: %d\n", n);
				abort();
			}
			d_printf("%s", "initial message 1/3 sent\n");

			local_peer->sm_leecher = SM_WAIT_HAVE;
		}

		if (local_peer->sm_leecher == SM_WAIT_HAVE) {
			FD_ZERO(&fs);
			FD_SET(sockfd, &fs);
			tv.tv_sec = 1;
			tv.tv_usec = 0;

			(void) select(sockfd + 1, &fs, NULL, NULL, &tv);
			n = 0;
			if (FD_ISSET(sockfd, &fs)) {
				/* receive response from SEEDER: HANDSHAKE + HAVE */
				n = recvfrom(sockfd, (char *)buffer, BUFSIZE, 0, (struct sockaddr *) &servaddr, &len);
			}

			if (n <= 0) {
				local_peer->sm_leecher = SM_HANDSHAKE;
				continue;
			} else {
				local_peer->sm_leecher = SM_PREPARE_REQUEST;
			}
		}

		if (local_peer->sm_leecher == SM_PREPARE_REQUEST) {
			buffer[n] = '\0';
			d_printf("server replied with %u bytes\n", n);
			dump_handshake_have(buffer, n, local_peer);

			/* calculate number of SHA hashes per 1500 bytes MTU */
			/* (MTU - sizeof(iphdr) - sizeof(udphdr) - ppspp_headers) / sha_size */
			hashes_per_mtu = (1500 - 20 - 8 - (4 + 1 + 4 + 4 + 8))/20;
			d_printf("hashes_per_mtu: %lu\n", hashes_per_mtu);

			/* calculate number of series */
			num_series = local_peer->nc / hashes_per_mtu;
			rest = local_peer->nc % hashes_per_mtu;
			d_printf("nc: %u   num_series: %lu   rest: %lu\n", local_peer->nc, num_series, rest);

			/* build the tree */
			local_peer->tree_root = build_tree(local_peer->nc, &local_peer->tree);

			data_buffer_len = local_peer->chunk_size + 4 + 1 + 4 + 4 + 8;
			data_buffer = malloc(data_buffer_len);   /* memory leak - bpo w petli while a frre poza petla */

			snprintf(fname, sizeof(fname), "%s", local_peer->fname);
			unlink(fname);

			fd = open(fname, O_WRONLY | O_CREAT, 0744);
			if (fd < 0) {
				printf("error opening file '%s' for writing: %u %s\n", fname, errno, strerror(errno));
				abort();
			}

			z = local_peer->start_chunk;
			local_peer->sm_leecher = SM_WHILE_REQUEST;
		}

		if (local_peer->sm_leecher == SM_WHILE_REQUEST) {

			d_printf("z: %u  local_peer->end_chunk: %u\n", z, local_peer->end_chunk);
			begin = z;

			if (z + hashes_per_mtu >= local_peer->end_chunk)
				end = local_peer->end_chunk;
			else
				end = z + hashes_per_mtu -1 ;

			d_printf("begin: %lu   end: %lu\n", begin, end);

			/* create REQUEST  */
			request_len = make_request(request, 0xfeedbabe, begin, end, local_peer);

			_assert((long unsigned int)request_len <= sizeof(request), "%s but request_len has value: %u and sizeof(request): %lu\n", "request_len should be <= sizeof(request)", request_len, sizeof(request));
			local_peer->sm_leecher = SM_SEND_REQUEST;
		}

		if (local_peer->sm_leecher == SM_SEND_REQUEST) {
			/* send REQUEST */
			n = sendto(sockfd, request, request_len, 0, (const struct sockaddr *) &servaddr, sizeof(servaddr));
			if (n < 0) {
				printf("error sending request: %d\n", n);
				abort();
			}
			d_printf("%s", "request message 3/3 sent\n");
			local_peer->sm_leecher = SM_WAIT_PEX_RESP;
			d_printf("request sent: %u\n", n);
		}

		if (local_peer->sm_leecher == SM_WAIT_PEX_RESP) {
			FD_ZERO(&fs);
			FD_SET(sockfd, &fs);
			tv.tv_sec = 1;
			tv.tv_usec = 0;

			(void) select(sockfd + 1, &fs, NULL, NULL, &tv);
			n = 0;
			if (FD_ISSET(sockfd, &fs)) {
				/* receive PEX_RESP from SEEDER */
				n = recvfrom(sockfd, (char *)buffer, BUFSIZE, 0, (struct sockaddr *) &servaddr, &len);
			}

			if (n <= 0) {
				local_peer->sm_leecher = SM_SEND_REQUEST;
				continue;
			} else
				local_peer->sm_leecher = SM_PEX_RESP;
		}

		if (local_peer->sm_leecher == SM_PEX_RESP) {
			d_printf("%s", "PEX_RESP\n");
			dump_pex_resp(buffer, n, local_peer, sockfd);

			local_peer->sm_leecher = SM_WAIT_INTEGRITY;
		}

		if (local_peer->sm_leecher == SM_WAIT_INTEGRITY) {
			FD_ZERO(&fs);
			FD_SET(sockfd, &fs);
			tv.tv_sec = 1;
			tv.tv_usec = 0;

			(void) select(sockfd + 1, &fs, NULL, NULL, &tv);
			n = 0;
			if (FD_ISSET(sockfd, &fs)) {
				/* receive INTEGRITY from SEEDER */
				n = recvfrom(sockfd, (char *)buffer, BUFSIZE, 0, (struct sockaddr *) &servaddr, &len);
			}

			if (n <= 0) {
				local_peer->sm_leecher = SM_SWITCH_SEEDER;
				continue;
			} else {
				local_peer->sm_leecher = SM_INTEGRITY;
			}
		}

		if (local_peer->sm_leecher == SM_INTEGRITY) {
			d_printf("server sent INTEGRITY: %d\n", n);
			dump_integrity(buffer, n, local_peer);		/* copy SHA hashes to local_peer->chunk[] */

			/* copy all the received now SHA hashes to tree */
			d_printf("copying sha %lu-%lu\n", begin, end);
			for (x = begin; x < end; x++)
				memcpy(local_peer->tree[2 * x].sha, local_peer->chunk[x].sha, 20);

			cc = begin;
			local_peer->sm_leecher = SM_WAIT_DATA;
		}

		if (local_peer->sm_leecher == SM_WAIT_DATA) {

			/* receive the whole range of chunks from SEEDER */
			local_peer->curr_chunk = cc;

			FD_ZERO(&fs);
			FD_SET(sockfd, &fs);
			tv.tv_sec = 1;
			tv.tv_usec = 0;

			(void) select(sockfd + 1, &fs, NULL, NULL, &tv);
			nr = 0;

			if (FD_ISSET(sockfd, &fs)) {
				/* receive single DATA datagram */
				nr = recvfrom(sockfd, (char *)data_buffer, data_buffer_len, 0, (struct sockaddr *) &servaddr, &len);
			}
			if (nr <= 0) {
				local_peer->sm_leecher = SM_SWITCH_SEEDER;
				continue;
			} else {
				local_peer->sm_leecher = SM_DATA;
			}
		}

		if (local_peer->sm_leecher == SM_DATA) {

				/* save received chunk to disk */
				lseek(fd, cc * local_peer->chunk_size, SEEK_SET);
				write(fd, data_buffer + 1 + 4 + 4 + 8 + 4, nr - (1 + 4 + 4 + 8 + 4));

				/* calculate SHA hash */
				SHA1Reset(&context);
				SHA1Input(&context, data_buffer + 1 + 4 + 4 + 8 + 4 , nr - (1 + 4 + 4 + 8 + 4)); /* skip the headers */
				SHA1Result(&context, digest);


				/* compare both SHA hashes: calculated locally and remote from SEEDER */
				cmp = memcmp(local_peer->chunk[local_peer->curr_chunk].sha, digest , 20);

				if (cmp != 0) {
#if 0
					/* convert to ASCII calculated locally SHA hash */
					s = 0;
					for (y = 0; y < 20; y++)
						s += sprintf((char *)(sha_buf + s), "%02x", digest[y] & 0xff);
					sha_buf[40] = '\0';

					/* convert to ASCII remote SHA hash from SEEDER */
					s = 0;
					for (y = 0; y < 20; y++)
						s += sprintf((char *)(sha_seeder_buf + s), "%02x", local_peer->chunk[local_peer->curr_chunk].sha[y] & 0xff);
					sha_seeder_buf[40] = '\0';
#endif
					printf("error - hashes are different[%lu]: seeder %s vs digest: %s\n", cc, sha_seeder_buf, sha_buf);
					abort();
				}
				else {
					local_peer->sm_leecher = SM_SEND_ACK;
				}
		}

		if (local_peer->sm_leecher == SM_SEND_ACK) {
				/* create ACK message to confirm that chunk in last DATA datagram has been transferred correctly */
				ack_len = make_ack(buffer, local_peer);

				_assert(ack_len <= BUFSIZE, "%s but ack_len has value: %lu and BUFSIZE: %u\n", "ack_len should be <= BUFSIZE", ack_len, BUFSIZE);

				/* send ACK */
				n = sendto(sockfd, buffer, ack_len, 0, (const struct sockaddr *) &servaddr, sizeof(servaddr));
				if (n < 0) {
					printf("error sending request: %d\n", n);
					abort();
				}
				d_printf("ACK[%lu] sent\n" ,cc);
			/* } for cc */

			cc++;  /* increment cc: for cc */


			if (cc <= end) {  /* ending condition of for loop */
				local_peer->sm_leecher = SM_WAIT_DATA;
				continue;
			} else
				local_peer->sm_leecher = SM_INC_Z;
		}

		if (local_peer->sm_leecher == SM_INC_Z) {
			z += hashes_per_mtu;
			if (z < local_peer->end_chunk) {
				local_peer->sm_leecher = SM_WHILE_REQUEST;
				continue;
			} else {
				/* end of while loop - exit from while and going to HANDSHAKE_FINISH */
				local_peer->sm_leecher = SM_SEND_HANDSHAKE_FINISH;
			}
		}


		if (local_peer->sm_leecher == SM_SEND_HANDSHAKE_FINISH) {
			/* send HANDSHAKE FINISH */
			n = make_handshake_finish(buffer, local_peer);
			n = sendto(sockfd, buffer, n, 0, (const struct sockaddr *) &servaddr, sizeof(servaddr));
			if (n < 0) {
				printf("error sending request: %d\n", n);
				abort();
			}

			local_peer->finishing = 1;
			continue;
		}


		if (local_peer->sm_leecher == SM_SWITCH_SEEDER) {
			d_printf("%s", "switching seeder state machine\n");
			/* finish transmission with current seeder */

			n = make_handshake_finish(buffer, local_peer);
			n = sendto(sockfd, buffer, ack_len, 0, (const struct sockaddr *) &servaddr, sizeof(servaddr));
			if (n < 0) {
				printf("error sending request: %d\n", n);
				abort();
			}


			/* create new connection to new selected seeder */
			/* choose new seeder */

			if (local_peer->current_seeder->next != NULL)	/* select next peer */
				local_peer->current_seeder = local_peer->current_seeder->next;
			else
				local_peer->current_seeder = peer_list_head.next; /* select begin of the qeueue */

			printf("selected: %s\n", inet_ntoa(local_peer->current_seeder->leecher_addr.sin_addr));

			/* change IP address and port for all the new connections */
			memset(&servaddr, 0, sizeof(servaddr));
			servaddr.sin_family = AF_INET;
			servaddr.sin_port = htons(PORT);
			servaddr.sin_addr.s_addr = local_peer->current_seeder->leecher_addr.sin_addr.s_addr;

			free(data_buffer);
			data_buffer = NULL;

			local_peer->sm_leecher = SM_HANDSHAKE;
			continue;

		}

	/* } while */

	}
	d_printf("%s", "HANDSHAKE_FINISH sent\n");

	free(data_buffer);
	close(sockfd);
	close(fd);
	return 0;

}


int net_leecher_algo4_sm_switching_seeders_continue_transmission(struct peer *local_peer)
{
	char buffer[BUFSIZE];
	char fname [256 + 32];
	char swarm_id[] = "swarm_id";
	char opts[1024];			/* buffer for encoded options */
	char handshake_req[256], request[256];
	unsigned char digest[20];
	uint8_t *data_buffer;
	uint8_t sha_buf[40 + 1], sha_seeder_buf[40 + 1];
	uint8_t cmp;
	int sockfd, n, s, y, fd, nr, opts_len, h_req_len, request_len;
	uint32_t data_buffer_len, z, prev_chunk_size;
	uint64_t ack_len, cc, x, rest, begin, end;
	struct sockaddr_in servaddr;
	socklen_t len;
	SHA1Context context;
	struct proto_opt_str pos;
	struct timeval tv;
	fd_set fs;


	memset(&pos, 0, sizeof(struct proto_opt_str));
	memset(&opts, 0, sizeof(opts));
	memset(&handshake_req, 0, sizeof(handshake_req));

	/* prepare structure as a set of parameters to make_handshake_options() proc */
	pos.version = 1;
	pos.minimum_version = 1;
	pos.swarm_id_len = strlen(swarm_id);
	pos.swarm_id = (uint8_t *)swarm_id;
	pos.content_prot_method = 1;			/* merkle hash tree */
	pos.merkle_hash_func = 0;			/* 0 = sha-1 */
	pos.live_signature_alg = 0;			/* number from dnssec */
	pos.chunk_addr_method = 2;			/* 2 = 32 bit chunk ranges */
	*(unsigned int *)pos.live_disc_wind = 0x12345678;
	pos.supported_msgs_len = 2;			/* 2 bytes of bitmap of serviced commands */
	*(unsigned int *)pos.supported_msgs = 0xffff;	/* bitmap - we are servicing all of the commands from RFC*/
	pos.chunk_size = local_peer->chunk_size;
	pos.file_size = local_peer->file_size;
	pos.file_name_len = local_peer->fname_len;
	memset(pos.file_name, 0, sizeof(pos.file_name));
	memcpy(pos.file_name, local_peer->fname, local_peer->fname_len);

	/* mark the options we want to pass to make_handshake_options() (which ones are valid) */
	pos.opt_map = 0;
	pos.opt_map |= (1 << VERSION);
	pos.opt_map |= (1 << MINIMUM_VERSION);
	pos.opt_map |= (1 << SWARM_ID);
	pos.opt_map |= (1 << CONTENT_PROT_METHOD);
	pos.opt_map |= (1 << MERKLE_HASH_FUNC);
	pos.opt_map |= (1 << LIVE_SIGNATURE_ALG);
	pos.opt_map |= (1 << CHUNK_ADDR_METHOD);
	pos.opt_map |= (1 << LIVE_DISC_WIND);
	pos.opt_map |= (1 << SUPPORTED_MSGS);
	pos.opt_map |= (1 << CHUNK_SIZE);

	pos.opt_map |= (1 << FILE_SIZE);
	pos.opt_map |= (1 << FILE_NAME);

	/* for leecher */
	opts_len = make_handshake_options(opts, &pos);
	dump_options(opts, local_peer);
	d_printf("%s", "\n\ninitial handshake:\n");


	/* make initial HANDSHAKE request - serialize dest chan id, src chan id and protocol options */
	h_req_len = make_handshake_request(handshake_req, 0, 0xfeedbabe, opts, opts_len);
	dump_handshake_request(handshake_req, h_req_len, local_peer);

	len = sizeof(servaddr);

	local_peer->sm_leecher = SM_HANDSHAKE;


	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("socket creation failed");
		exit(EXIT_FAILURE);
	}

	local_peer->download_schedule_len = 0;
	local_peer->download_schedule = NULL;
	data_buffer = NULL;

	/* set primary seeder IP:port as a initial default values */
	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(PORT);
	servaddr.sin_addr.s_addr = local_peer->seeder_addr.sin_addr.s_addr;


	local_peer->finishing = 0;
	local_peer->download_schedule_idx = 0;
	local_peer->after_seeder_switch = 0;
	local_peer->pex_required = 1;			/* mark flag that we want list of other seeders form primary seeder */
	prev_chunk_size = 0;

	/* leecher's state machine */
	while (local_peer->finishing == 0) {

		if (local_peer->sm_leecher == SM_HANDSHAKE) {
			/* send initial HANDSHAKE and wait for SEEDER's answer */
			n = sendto(sockfd, handshake_req, h_req_len, 0, (const struct sockaddr *) &servaddr, sizeof(servaddr));
			if (n < 0) {
				printf("error sending handshake: %d\n", n);
				abort();
			}
			d_printf("%s", "initial message 1/3 sent\n");

			local_peer->sm_leecher = SM_WAIT_HAVE;
		}

		if (local_peer->sm_leecher == SM_WAIT_HAVE) {
			FD_ZERO(&fs);
			FD_SET(sockfd, &fs);
			tv.tv_sec = 1;
			tv.tv_usec = 0;

			(void) select(sockfd + 1, &fs, NULL, NULL, &tv);
			n = 0;
			if (FD_ISSET(sockfd, &fs)) {
				/* receive response from SEEDER: HANDSHAKE + HAVE */
				n = recvfrom(sockfd, (char *)buffer, BUFSIZE, 0, (struct sockaddr *) &servaddr, &len);
			}

			if (n <= 0) {
				local_peer->sm_leecher = SM_HANDSHAKE;
				continue;
			} else {
				local_peer->sm_leecher = SM_PREPARE_REQUEST;
			}
		}

		if (local_peer->sm_leecher == SM_PREPARE_REQUEST) {
			buffer[n] = '\0';
			d_printf("server replied with %u bytes\n", n);

			/* calculate number of SHA hashes per 1500 bytes MTU */
			/* (MTU - sizeof(iphdr) - sizeof(udphdr) - ppspp_headers) / sha_size */
			local_peer->hashes_per_mtu = (1500 - 20 - 8 - (4 + 1 + 4 + 4 + 8))/20;
			d_printf("hashes_per_mtu: %lu\n", local_peer->hashes_per_mtu);

			/* calculate number of series */
			local_peer->num_series = local_peer->nc / local_peer->hashes_per_mtu;
			rest = local_peer->nc % local_peer->hashes_per_mtu;
			d_printf("nc: %u   num_series: %lu   rest: %lu\n", local_peer->nc, local_peer->num_series, rest);

			dump_handshake_have(buffer, n, local_peer);

			if ((local_peer->after_seeder_switch == 1) && (prev_chunk_size != local_peer->chunk_size)) {
				printf("previous and current seeder have different chunk size: %u vs %u\n", prev_chunk_size, local_peer->chunk_size);
				abort();
			}

			/* build the tree */
			local_peer->tree_root = build_tree(local_peer->nc, &local_peer->tree);

			_assert(data_buffer == NULL, "%s but has value: %lx (potential mem-leak?)\n", "data_buffer should be == NULL", (uint64_t)data_buffer);

			data_buffer_len = local_peer->chunk_size + 4 + 1 + 4 + 4 + 8;
			data_buffer = malloc(data_buffer_len);   /* memory leak - bo w petli while a free poza petla */

			/* create and open new file only when we are downloading from primary seeder without switching to another one */
			if (local_peer->after_seeder_switch == 0) {
				snprintf(fname, sizeof(fname), "%s", local_peer->fname);
				unlink(fname);

				fd = open(fname, O_WRONLY | O_CREAT, 0744);
				if (fd < 0) {
					printf("error opening file '%s' for writing: %u %s\n", fname, errno, strerror(errno));
					abort();
				}
			}
			z = local_peer->start_chunk;
			local_peer->sm_leecher = SM_WHILE_REQUEST;
		}


		/* external "while" loop, iterator "z" */
		if (local_peer->sm_leecher == SM_WHILE_REQUEST) {
			d_printf("z: %u  local_peer->end_chunk: %u\n", z, local_peer->end_chunk);

			/* take begin/end from schedule array */
			begin = local_peer->download_schedule[local_peer->download_schedule_idx].begin;
			end = local_peer->download_schedule[local_peer->download_schedule_idx].end;

			d_printf("begin: %lu   end: %lu\n", begin, end);

			/* create REQUEST  */
			request_len = make_request(request, 0xfeedbabe, begin, end, local_peer);

			_assert((long unsigned int) request_len <= sizeof(request), "%s but request_len has value: %u and sizeof(request): %lu\n", "request_len should be <= sizeof(request)", request_len, sizeof(request));
			local_peer->sm_leecher = SM_SEND_REQUEST;
		}

		if (local_peer->sm_leecher == SM_SEND_REQUEST) {
			/* send REQUEST */
			n = sendto(sockfd, request, request_len, 0, (const struct sockaddr *) &servaddr, sizeof(servaddr));
			if (n < 0) {
				printf("error sending request: %d\n", n);
				abort();
			}
			d_printf("%s", "request message 3/3 sent\n");
			local_peer->sm_leecher = SM_WAIT_PEX_RESP;
			d_printf("request sent: %u\n", n);
		}

		/* wait for PEX_RESV4 or INTEGRITY */
		if (local_peer->sm_leecher == SM_WAIT_PEX_RESP) {
			FD_ZERO(&fs);
			FD_SET(sockfd, &fs);
			tv.tv_sec = 1;
			tv.tv_usec = 0;

			(void) select(sockfd + 1, &fs, NULL, NULL, &tv);
			n = 0;
			if (FD_ISSET(sockfd, &fs)) {
				/* receive PEX_RESP or INTEGRITY from SEEDER */
				n = recvfrom(sockfd, (char *)buffer, BUFSIZE, 0, (struct sockaddr *) &servaddr, &len);
			}
#if 0
			if (n <= 0) {
				local_peer->sm_leecher = SM_SWITCH_SEEDER;
				continue;
			} else
				local_peer->sm_leecher = SM_PEX_RESP;
#endif

			if (n <= 0) {
				local_peer->sm_leecher = SM_SWITCH_SEEDER;
				continue;
			} else {
				if (message_type(buffer) == INTEGRITY)
					local_peer->sm_leecher = SM_INTEGRITY;
				else
					local_peer->sm_leecher = SM_PEX_RESP;
			}
		}

		if (local_peer->sm_leecher == SM_PEX_RESP) {
			d_printf("%s", "PEX_RESP\n");
			dump_pex_resp(buffer, n, local_peer, sockfd);
			local_peer->pex_required = 0;		/* unset flag  */

			local_peer->sm_leecher = SM_WAIT_INTEGRITY;
		}

		if (local_peer->sm_leecher == SM_WAIT_INTEGRITY) {
			FD_ZERO(&fs);
			FD_SET(sockfd, &fs);
			tv.tv_sec = 1;
			tv.tv_usec = 0;

			(void) select(sockfd + 1, &fs, NULL, NULL, &tv);
			n = 0;
			if (FD_ISSET(sockfd, &fs)) {
				/* receive INTEGRITY from SEEDER */
				n = recvfrom(sockfd, (char *)buffer, BUFSIZE, 0, (struct sockaddr *) &servaddr, &len);
			}

			if (n <= 0) {
				local_peer->sm_leecher = SM_SWITCH_SEEDER;
				continue;
			} else {
				local_peer->sm_leecher = SM_INTEGRITY;
			}
		}

		if (local_peer->sm_leecher == SM_INTEGRITY) {
			d_printf("server sent INTEGRITY: %d\n", n);
			dump_integrity(buffer, n, local_peer);		/* copy SHA hashes to local_peer->chunk[] */

			/* copy all the received now SHA hashes to tree */
			d_printf("copying sha %lu-%lu\n", begin, end);
			for (x = begin; x < end; x++)
				memcpy(local_peer->tree[2 * x].sha, local_peer->chunk[x].sha, 20);

			cc = begin;	/* internal "for" loop, iterator - cc */
			local_peer->sm_leecher = SM_WAIT_DATA;
		}

		/* internal "for" loop - wait for next DATA packet from seeder */
		if (local_peer->sm_leecher == SM_WAIT_DATA) {

			/* for (cc = begin; cc <= end; cc++) */
			/* receive the whole range of chunks from SEEDER */
			local_peer->curr_chunk = cc;


			FD_ZERO(&fs);
			FD_SET(sockfd, &fs);
			tv.tv_sec = 1;
			tv.tv_usec = 0;

			(void) select(sockfd + 1, &fs, NULL, NULL, &tv);
			nr = 0;

			if (FD_ISSET(sockfd, &fs)) {
				/* receive single DATA datagram */
				nr = recvfrom(sockfd, (char *)data_buffer, data_buffer_len, 0, (struct sockaddr *) &servaddr, &len);
			}
			if (nr <= 0) {
				local_peer->sm_leecher = SM_SWITCH_SEEDER;
				continue;
			} else {
				local_peer->sm_leecher = SM_DATA;
			}
		}

		if (local_peer->sm_leecher == SM_DATA) {
			/* save received chunk to disk */
			lseek(fd, cc * local_peer->chunk_size, SEEK_SET);
			write(fd, data_buffer + 1 + 4 + 4 + 8 + 4, nr - (1 + 4 + 4 + 8 + 4));

			/* calculate SHA hash */
			SHA1Reset(&context);
			SHA1Input(&context, data_buffer + 1 + 4 + 4 + 8 + 4 , nr - (1 + 4 + 4 + 8 + 4)); /* skip the headers */
			SHA1Result(&context, digest);


			/* compare both SHA hashes: calculated locally and remote from SEEDER */
			cmp = memcmp(local_peer->chunk[local_peer->curr_chunk].sha, digest , 20);

			if (cmp != 0) {
				/* convert to ASCII calculated locally SHA hash */
				s = 0;
				for (y = 0; y < 20; y++)
					s += sprintf((char *)(sha_buf + s), "%02x", digest[y] & 0xff);
				sha_buf[40] = '\0';

				/* convert to ASCII remote SHA hash from SEEDER */
				s = 0;
				for (y = 0; y < 20; y++)
					s += sprintf((char *)(sha_seeder_buf + s), "%02x", local_peer->chunk[local_peer->curr_chunk].sha[y] & 0xff);
				sha_seeder_buf[40] = '\0';

				printf("error - hashes are different[%lu]: seeder %s vs digest: %s\n", cc, sha_seeder_buf, sha_buf);
				abort();
			} else {
				local_peer->chunk[local_peer->curr_chunk].downloaded = CH_YES;
				local_peer->sm_leecher = SM_SEND_ACK;
			}
		}

		if (local_peer->sm_leecher == SM_SEND_ACK) {
				/* create ACK message to confirm that chunk in last DATA datagram has been transferred correctly */
				ack_len = make_ack(buffer, local_peer);

				_assert(ack_len <= BUFSIZE, "%s but ack_len has value: %lu and BUFSIZE: %u\n", "ack_len should be <= BUFSIZE", ack_len, BUFSIZE);

				/* send ACK */
				n = sendto(sockfd, buffer, ack_len, 0, (const struct sockaddr *) &servaddr, sizeof(servaddr));
				if (n < 0) {
					printf("error sending request: %d\n", n);
					abort();
				}
				d_printf("ACK[%lu] sent\n" ,cc);
			cc++;  /* "cc" is iterator from "for" loop */

			if (cc <= end) {  /* end condition of "for" loop */
				local_peer->sm_leecher = SM_WAIT_DATA;
				continue;
			} else
				local_peer->sm_leecher = SM_INC_Z;
		}

		/* end of external "while" loop, iterator "z" */
		if (local_peer->sm_leecher == SM_INC_Z) {
			z += local_peer->hashes_per_mtu;
			local_peer->download_schedule_idx++;

			if (local_peer->download_schedule_idx < local_peer->download_schedule_len) {
				local_peer->sm_leecher = SM_WHILE_REQUEST;
				continue;
			} else {
				/* end of "while" loop */
				local_peer->sm_leecher = SM_SEND_HANDSHAKE_FINISH;
			}

		}


		if (local_peer->sm_leecher == SM_SEND_HANDSHAKE_FINISH) {
			/* send HANDSHAKE FINISH */
			n = make_handshake_finish(buffer, local_peer);
			n = sendto(sockfd, buffer, n, 0, (const struct sockaddr *) &servaddr, sizeof(servaddr));
			if (n < 0) {
				printf("error sending request: %d\n", n);
				abort();
			}

			local_peer->finishing = 1;
			continue;
		}


		if (local_peer->sm_leecher == SM_SWITCH_SEEDER) {
			d_printf("%s", "switching seeder state machine\n");
			/* finish transmission with current seeder */

			n = make_handshake_finish(buffer, local_peer);
			n = sendto(sockfd, buffer, ack_len, 0, (const struct sockaddr *) &servaddr, sizeof(servaddr));
			if (n < 0) {
				printf("error sending request: %d\n", n);
				abort();
			}

			prev_chunk_size = local_peer->chunk_size;	/* remember chunk size from previouse seeder */
			local_peer->current_seeder->to_remove = 2; /* mark current_seeder to remove by garbage collector */
			local_peer->after_seeder_switch = 1;	/* mark that we are switching from one seeder to another */


			/* re-create download_schedule array */
			printf("re-creating download_schedule array\n");
			create_download_schedule(local_peer);
			local_peer->download_schedule_idx = 0;
			printf("continuing from series of chunk: %lu-%lu\n", local_peer->download_schedule[0].begin, local_peer->download_schedule[0].end);

			/* create new connection to new selected seeder */
			/* choose new seeder */

			if (local_peer->current_seeder->next != NULL)	/* select next peer */
				local_peer->current_seeder = local_peer->current_seeder->next;
			else
				local_peer->current_seeder = peer_list_head.next; /* select begin of the qeueue */

			printf("selected: %s\n", inet_ntoa(local_peer->current_seeder->leecher_addr.sin_addr));

			/* change IP address and port for all the new connections */
			memset(&servaddr, 0, sizeof(servaddr));
			servaddr.sin_family = AF_INET;
			servaddr.sin_port = htons(PORT);
			servaddr.sin_addr.s_addr = local_peer->current_seeder->leecher_addr.sin_addr.s_addr;

			free(data_buffer);
			data_buffer = NULL;

			local_peer->sm_leecher = SM_HANDSHAKE;
			continue;
		}

	}
	d_printf("%s", "HANDSHAKE_FINISH sent\n");

	free(data_buffer);
	close(sockfd);
	close(fd);
	cleanup_all_dead_peers(&peer_list_head);
	return 0;

}


/*
 * multithread leecher algorithm:
 * 1. connect us (leecher) to the primary seeder
 * 2. get the list of other seeders from primary seeder
 * 3. disconnect from primary seeder
 * 4. create global schedule of downloading chunks - list of chunk series
 * 5. create one thread for every seeder we know (from primary seeder)
 *
 */
void * leecher_algo5_worker(void *data)
{
	char buffer[BUFSIZE], buf[40 + 1];
	char swarm_id[] = "swarm_id";
	char opts[1024];			/* buffer for encoded options */
	char handshake_req[256], request[256];
	unsigned char digest[20];
	uint8_t *data_buffer;
	uint8_t sha_buf[40 + 1], sha_seeder_buf[40 + 1];
	uint8_t cmp;
	int sockfd, n, s, y, fd, nr, opts_len, h_req_len, request_len;
	uint32_t data_buffer_len, prev_chunk_size;
	uint64_t ack_len, cc, x, begin, end;
	struct sockaddr_in servaddr;
	struct peer *p, *local_peer;
	socklen_t len;
	SHA1Context context;
	struct proto_opt_str pos;
	struct timeval tv;
	fd_set fs;

	memset(&pos, 0, sizeof(struct proto_opt_str));
	memset(&opts, 0, sizeof(opts));
	memset(&handshake_req, 0, sizeof(handshake_req));

	p = (struct peer *)data;			/* struct describing remote peer - seeder */
	local_peer = p->local_leecher;			/* we - local peer - leecher */

	/* prepare structure as a set of parameters to make_handshake_options() proc */
	pos.version = 1;
	pos.minimum_version = 1;
	pos.swarm_id_len = strlen(swarm_id);
	pos.swarm_id = (uint8_t *)swarm_id;
	pos.content_prot_method = 1;			/* merkle hash tree */
	pos.merkle_hash_func = 0;			/* 0 = sha-1 */
	pos.live_signature_alg = 0;			/* number from dnssec */
	pos.chunk_addr_method = 2;			/* 2 = 32 bit chunk ranges */
	*(unsigned int *)pos.live_disc_wind = 0x12345678;
	pos.supported_msgs_len = 2;			/* 2 bytes of bitmap of serviced commands */
	*(unsigned int *)pos.supported_msgs = 0xffff;	/* bitmap - we are servicing all of the commands from RFC*/
	pos.chunk_size = local_peer->chunk_size;
	pos.file_size = local_peer->file_size;
	pos.file_name_len = local_peer->fname_len;
	memset(pos.file_name, 0, sizeof(pos.file_name));
	memcpy(pos.file_name, local_peer->fname, local_peer->fname_len);
	memcpy(pos.sha_demanded, local_peer->sha_demanded, 20);	/* leecher demands file with hash given in "-s" command line parameter */

	/* mark the options we want to pass to make_handshake_options() (which ones are valid) */
	pos.opt_map = 0;
	pos.opt_map |= (1 << VERSION);
	pos.opt_map |= (1 << MINIMUM_VERSION);
	pos.opt_map |= (1 << SWARM_ID);
	pos.opt_map |= (1 << CONTENT_PROT_METHOD);
	pos.opt_map |= (1 << MERKLE_HASH_FUNC);
	pos.opt_map |= (1 << LIVE_SIGNATURE_ALG);
	pos.opt_map |= (1 << CHUNK_ADDR_METHOD);
	pos.opt_map |= (1 << LIVE_DISC_WIND);
	pos.opt_map |= (1 << SUPPORTED_MSGS);
	pos.opt_map |= (1 << CHUNK_SIZE);

	pos.opt_map |= (1 << FILE_SIZE);
	pos.opt_map |= (1 << FILE_NAME);
	pos.opt_map |= (1 << FILE_HASH);

	/* for leecher */
	opts_len = make_handshake_options(opts, &pos);
	dump_options(opts, p);
	d_printf("%s", "\n\ninitial handshake:\n");

	/* make initial HANDSHAKE request - serialize dest chan id, src chan id and protocol options */
	h_req_len = make_handshake_request(handshake_req, 0, 0xfeedbabe, opts, opts_len);
	dump_handshake_request(handshake_req, h_req_len, p);

	len = sizeof(servaddr);

	p->sm_leecher = SM_HANDSHAKE;

	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("socket creation failed");
		exit(EXIT_FAILURE);
	}

	data_buffer = NULL;
	data_buffer_len = local_peer->chunk_size + 4 + 1 + 4 + 4 + 8;
	data_buffer = malloc(data_buffer_len);

	/* set primary seeder IP:port as a initial default values */
	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	//servaddr.sin_port = htons(PORT);
	servaddr.sin_port = p->leecher_addr.sin_port;
	servaddr.sin_addr.s_addr = p->leecher_addr.sin_addr.s_addr;
	d_printf("pthread %#lx   IP: %s\n", p->thread, inet_ntoa(servaddr.sin_addr));

	fd = local_peer->fd;

	p->finishing = 0;
	p->after_seeder_switch = 0;		/* flag: 0 = we are still connected to first seeder, 1 = we are switched to another seeder at least once */
	p->pex_required = 0;			/* unmark flag that we want list of other seeders form primary seeder */
	p->fetch_schedule = 1;			/* allow to fetch series of chunks from download_schedule[] */
	prev_chunk_size = 0;

	/* leecher's state machine */
	while (p->finishing == 0) {

		if (p->sm_leecher == SM_HANDSHAKE) {
			/* send initial HANDSHAKE and wait for SEEDER's answer */
			n = sendto(sockfd, handshake_req, h_req_len, 0, (const struct sockaddr *) &servaddr, sizeof(servaddr));
			if (n < 0) {
				printf("error sending handshake: %d\n", n);
				abort();
			}
			d_printf("%s", "initial message 1/3 sent\n");

			p->sm_leecher = SM_WAIT_HAVE;
		}

		if (p->sm_leecher == SM_WAIT_HAVE) {
			FD_ZERO(&fs);
			FD_SET(sockfd, &fs);
			tv.tv_sec = p->timeout;
			tv.tv_usec = 0;

			(void) select(sockfd + 1, &fs, NULL, NULL, &tv);
			n = 0;
			if (FD_ISSET(sockfd, &fs)) {
				/* receive response from SEEDER: HANDSHAKE + HAVE */
				n = recvfrom(sockfd, (char *)buffer, BUFSIZE, 0, (struct sockaddr *) &servaddr, &len);
			}

			if (n <= 0) {
				if (p->after_seeder_switch == 0)
					p->sm_leecher = SM_HANDSHAKE;
				else
					p->sm_leecher = SM_SWITCH_SEEDER;
				continue;
			} else {
				p->sm_leecher = SM_PREPARE_REQUEST;
			}
		}

		if (p->sm_leecher == SM_PREPARE_REQUEST) {
			buffer[n] = '\0';
			d_printf("server replied with %u bytes\n", n);

			dump_handshake_have(buffer, n, p);

			if ((p->start_chunk == 0xfffffffe) && (p->end_chunk == 0xfffffffe)) {
				s = 0;
				for (y = 0; y < 20; y++)
					s += sprintf(buf + s, "%02x", local_peer->sha_demanded[y] & 0xff);
				buf[40] = '\0';
				printf("Seeder %s:%u has no file for hash: %s\n", inet_ntoa(servaddr.sin_addr), ntohs(servaddr.sin_port), buf);
				//p->sm_leecher = SM_SEND_HANDSHAKE_FINISH;
				p->to_remove = 1; /* mark peer to remove by garbage collector */
				
				goto exit;
				continue;
			}

			if ((p->after_seeder_switch == 1) && (prev_chunk_size != local_peer->chunk_size)) {
				printf("previous and current seeder have different chunk size: %u vs %u\n", prev_chunk_size, local_peer->chunk_size);
				abort();
			}

			p->sm_leecher = SM_WHILE_REQUEST;
		}


		/* external "while" loop, iterator "z" */
		if (p->sm_leecher == SM_WHILE_REQUEST) {
			d_printf("local_peer->end_chunk: %u\n", local_peer->end_chunk);

			if (p->fetch_schedule == 1) {
				/* lock "download_schedule" array and "download_schedule_idx" index */
				mutex_lock(&local_peer->download_schedule_mutex);
				/* take begin/end from schedule array */
				begin = local_peer->download_schedule[local_peer->download_schedule_idx].begin;
				end = local_peer->download_schedule[local_peer->download_schedule_idx].end;

				local_peer->download_schedule_idx++;
				mutex_unlock(&local_peer->download_schedule_mutex);
			}

			d_printf("begin: %lu   end: %lu\n", begin, end);

			/* create REQUEST  */
			request_len = make_request(request, 0xfeedbabe, begin, end, p);

			_assert((long unsigned int) request_len <= sizeof(request), "%s but request_len has value: %u and sizeof(request): %lu\n", "request_len should be <= sizeof(request)", request_len, sizeof(request));
			p->sm_leecher = SM_SEND_REQUEST;
		}

		if (p->sm_leecher == SM_SEND_REQUEST) {
			/* send REQUEST */
			n = sendto(sockfd, request, request_len, 0, (const struct sockaddr *) &servaddr, sizeof(servaddr));
			if (n < 0) {
				printf("error sending request: %d\n", n);
				abort();
			}
			d_printf("%s", "request message 3/3 sent\n");
			p->sm_leecher = SM_WAIT_PEX_RESP;
			d_printf("request sent: %u\n", n);
		}

		/* wait for PEX_RESV4 or INTEGRITY */
		if (p->sm_leecher == SM_WAIT_PEX_RESP) {
			FD_ZERO(&fs);
			FD_SET(sockfd, &fs);
			tv.tv_sec = p->timeout;
			tv.tv_usec = 0;

			(void) select(sockfd + 1, &fs, NULL, NULL, &tv);
			n = 0;
			if (FD_ISSET(sockfd, &fs)) {
				/* receive PEX_RESP or INTEGRITY from SEEDER */
				n = recvfrom(sockfd, (char *)buffer, BUFSIZE, 0, (struct sockaddr *) &servaddr, &len);
			}

			if (n <= 0) {
				p->sm_leecher = SM_SWITCH_SEEDER;
				continue;
			} else {
				if (message_type(buffer) == INTEGRITY)
					p->sm_leecher = SM_INTEGRITY;
				else
					p->sm_leecher = SM_PEX_RESP;
			}
		}

		if (p->sm_leecher == SM_PEX_RESP) {
			d_printf("%s", "PEX_RESP\n");
			p->pex_required = 0;		/* unset flag */ /* is it necessery here yet? */

			p->sm_leecher = SM_WAIT_INTEGRITY;
		}

		if (p->sm_leecher == SM_WAIT_INTEGRITY) {
			FD_ZERO(&fs);
			FD_SET(sockfd, &fs);
			tv.tv_sec = p->timeout;
			tv.tv_usec = 0;

			(void) select(sockfd + 1, &fs, NULL, NULL, &tv);
			n = 0;
			if (FD_ISSET(sockfd, &fs)) {
				/* receive INTEGRITY from SEEDER */
				n = recvfrom(sockfd, (char *)buffer, BUFSIZE, 0, (struct sockaddr *) &servaddr, &len);
			}

			if (n <= 0) {
				p->sm_leecher = SM_SWITCH_SEEDER;
				continue;
			} else {
				p->sm_leecher = SM_INTEGRITY;
			}
		}

		if (p->sm_leecher == SM_INTEGRITY) {
			d_printf("server sent INTEGRITY: %d\n", n);
			dump_integrity(buffer, n, local_peer);		/* copy SHA hashes to local_peer->chunk[] */

			/* copy all the received now SHA hashes to tree */
			d_printf("copying sha %lu-%lu\n", begin, end);
			for (x = begin; x < end; x++)
				memcpy(local_peer->tree[2 * x].sha, local_peer->chunk[x].sha, 20);

			cc = begin;	/* internal "for" loop, iterator - cc */
			p->sm_leecher = SM_WAIT_DATA;
		}

		/* internal "for" loop - wait for next DATA packet from seeder */
		if (p->sm_leecher == SM_WAIT_DATA) {

			/* for (cc = begin; cc <= end; cc++) */
			/* receive the whole range of chunks from SEEDER */
			p->curr_chunk = cc;


			FD_ZERO(&fs);
			FD_SET(sockfd, &fs);
			tv.tv_sec = p->timeout;
			tv.tv_usec = 0;

			(void) select(sockfd + 1, &fs, NULL, NULL, &tv);
			nr = 0;

			if (FD_ISSET(sockfd, &fs)) {
				/* receive single DATA datagram */
				nr = recvfrom(sockfd, (char *)data_buffer, data_buffer_len, 0, (struct sockaddr *) &servaddr, &len);
			}
			if (nr <= 0) {
				p->sm_leecher = SM_SWITCH_SEEDER;
				continue;
			} else {
				p->sm_leecher = SM_DATA;
			}
		}

		if (p->sm_leecher == SM_DATA) {
			/* save received chunk to disk */

			mutex_lock(&local_peer->fd_mutex);

			lseek(fd, cc * local_peer->chunk_size, SEEK_SET);
			write(fd, data_buffer + 1 + 4 + 4 + 8 + 4, nr - (1 + 4 + 4 + 8 + 4));

			mutex_unlock(&local_peer->fd_mutex);

			/* calculate SHA hash */
			SHA1Reset(&context);
			SHA1Input(&context, data_buffer + 1 + 4 + 4 + 8 + 4 , nr - (1 + 4 + 4 + 8 + 4)); /* skip the headers */
			SHA1Result(&context, digest);

			/* compare both SHA hashes: calculated locally and remote from SEEDER */
			cmp = memcmp(local_peer->chunk[p->curr_chunk].sha, digest , 20);

			if (cmp != 0) {
				/* convert to ASCII calculated locally SHA hash */
				s = 0;
				for (y = 0; y < 20; y++)
					s += sprintf((char *)(sha_buf + s), "%02x", digest[y] & 0xff);
				sha_buf[40] = '\0';

				/* convert to ASCII remote SHA hash from SEEDER */
				s = 0;
				for (y = 0; y < 20; y++)
					s += sprintf((char *)(sha_seeder_buf + s), "%02x", local_peer->chunk[p->curr_chunk].sha[y] & 0xff);
				sha_seeder_buf[40] = '\0';

				printf("error - hashes are different[%lu]: seeder %s vs digest: %s\n", cc, sha_seeder_buf, sha_buf);
				printf("pthread %#lx   IP: %s\n", p->thread, inet_ntoa(servaddr.sin_addr));
				abort();
			} else {
				local_peer->chunk[p->curr_chunk].downloaded = CH_YES;
				p->sm_leecher = SM_SEND_ACK;
			}
		}

		if (p->sm_leecher == SM_SEND_ACK) {
			/* create ACK message to confirm that chunk in last DATA datagram has been transferred correctly */
			ack_len = make_ack(buffer, p);

			_assert(ack_len <= BUFSIZE, "%s but ack_len has value: %lu and BUFSIZE: %u\n", "ack_len should be <= BUFSIZE", ack_len, BUFSIZE);

			/* send ACK */
			n = sendto(sockfd, buffer, ack_len, 0, (const struct sockaddr *) &servaddr, sizeof(servaddr));
			if (n < 0) {
				printf("error sending request: %d\n", n);
				abort();
			}
			d_printf("ACK[%lu] sent\n" ,cc);
			cc++;  /* "cc" is iterator from "for" loop */

			if (cc <= end) {  /* end condition of "for cc" loop */
				p->sm_leecher = SM_WAIT_DATA;
				continue;
			} else
				p->sm_leecher = SM_INC_Z;
		}

		/* end of external "while" loop, iterator "z" */
		if (p->sm_leecher == SM_INC_Z) {
			p->fetch_schedule = 1;			/* all the current schedule is completed so allow to get next one */

			if (local_peer->download_schedule_idx < local_peer->download_schedule_len) {
				p->sm_leecher = SM_WHILE_REQUEST;
				continue;
			} else {
				/* end of "while" loop */
				p->sm_leecher = SM_SEND_HANDSHAKE_FINISH;
			}
		}

		if (p->sm_leecher == SM_SEND_HANDSHAKE_FINISH) {
			/* send HANDSHAKE FINISH */
			n = make_handshake_finish(buffer, p);
			n = sendto(sockfd, buffer, n, 0, (const struct sockaddr *) &servaddr, sizeof(servaddr));
			if (n < 0) {
				printf("error sending request: %d\n", n);
				abort();
			}
			p->to_remove = 1; /* mark peer to remove by garbage collector */

			p->finishing = 1;
			continue;
		}


		if (p->sm_leecher == SM_SWITCH_SEEDER) {
			d_printf("%s", "switching seeder state machine\n");
			/* finish transmission with current seeder */

			n = make_handshake_finish(buffer, p);
			n = sendto(sockfd, buffer, ack_len, 0, (const struct sockaddr *) &servaddr, sizeof(servaddr));
			if (n < 0) {
				printf("error sending request: %d\n", n);
				abort();
			}

			prev_chunk_size = local_peer->chunk_size;	/* remember chunk size from previous seeder */
			p->after_seeder_switch = 1;	/* mark that we are switching from one seeder to another */
			p->fetch_schedule = 0;

			d_printf("chunks not downloaded yet: begin: %lu  end: %lu  cc: %lu\n", begin, end, cc);

			/* choose new seeder */
			if (p->current_seeder->next != NULL)	/* select next peer */
				p->current_seeder = p->current_seeder->next;
			else
				p->current_seeder = peer_list_head.next; /* select begin of the qeueue */

			d_printf("selected new seeder: %s\n", inet_ntoa(p->current_seeder->leecher_addr.sin_addr));

			/* change IP address and port for all the new connections */
			memset(&servaddr, 0, sizeof(servaddr));
			servaddr.sin_family = AF_INET;
			//servaddr.sin_port = htons(PORT);
			servaddr.sin_port = p->current_seeder->leecher_addr.sin_port;
			servaddr.sin_addr.s_addr = p->current_seeder->leecher_addr.sin_addr.s_addr;

			p->sm_leecher = SM_HANDSHAKE;
			continue;
		}

	}
	d_printf("%s", "HANDSHAKE_FINISH from thread sent\n");

exit:
	free(data_buffer);
	close(sockfd);
	pthread_exit(NULL);
}


int net_leecher_algo5_parallel_downloading(struct peer *local_peer)
{
	char buffer[BUFSIZE], buf[40 + 1];
	char swarm_id[] = "swarm_id";
	char fname [256 + 32];
	char opts[1024];			/* buffer for encoded options */
	char handshake_req[256], request[256];
	int sockfd, n, opts_len, h_req_len, request_len, fd, xx, s, y;
	uint32_t z, yy;
	uint64_t begin, end;
	struct sockaddr_in servaddr;
	socklen_t len;
	struct proto_opt_str pos;
	struct peer *p;
	struct timeval tv;
	pthread_t thread;
	fd_set fs;


	memset(&pos, 0, sizeof(struct proto_opt_str));
	memset(&opts, 0, sizeof(opts));
	memset(&handshake_req, 0, sizeof(handshake_req));

	/* prepare structure as a set of parameters to make_handshake_options() proc */
	pos.version = 1;
	pos.minimum_version = 1;
	pos.swarm_id_len = strlen(swarm_id);
	pos.swarm_id = (uint8_t *)swarm_id;
	pos.content_prot_method = 1;			/* merkle hash tree */
	pos.merkle_hash_func = 0;			/* 0 = sha-1 */
	pos.live_signature_alg = 0;			/* number from dnssec */
	pos.chunk_addr_method = 2;			/* 2 = 32 bit chunk ranges */
	*(unsigned int *)pos.live_disc_wind = 0x12345678;
	pos.supported_msgs_len = 2;			/* 2 bytes of bitmap of serviced commands */
	*(unsigned int *)pos.supported_msgs = 0xffff;	/* bitmap - we are servicing all of the commands from RFC*/
	pos.chunk_size = local_peer->chunk_size;
	pos.file_size = local_peer->file_size;
	pos.file_name_len = local_peer->fname_len;
	memset(pos.file_name, 0, sizeof(pos.file_name));	/* do we need this here? */
	memcpy(pos.file_name, local_peer->fname, local_peer->fname_len);
	memcpy(pos.sha_demanded, local_peer->sha_demanded, 20);	/* leecher demands file with hash given in "-s" command line parameter */


	/* mark the options we want to pass to make_handshake_options() (which ones are valid) */
	pos.opt_map = 0;
	pos.opt_map |= (1 << VERSION);
	pos.opt_map |= (1 << MINIMUM_VERSION);
	pos.opt_map |= (1 << SWARM_ID);
	pos.opt_map |= (1 << CONTENT_PROT_METHOD);
	pos.opt_map |= (1 << MERKLE_HASH_FUNC);
	pos.opt_map |= (1 << LIVE_SIGNATURE_ALG);
	pos.opt_map |= (1 << CHUNK_ADDR_METHOD);
	pos.opt_map |= (1 << LIVE_DISC_WIND);
	pos.opt_map |= (1 << SUPPORTED_MSGS);
	pos.opt_map |= (1 << CHUNK_SIZE);
	pos.opt_map |= (1 << FILE_SIZE);
	pos.opt_map |= (1 << FILE_NAME);
	pos.opt_map |= (1 << FILE_HASH);

	/* for leecher */
	opts_len = make_handshake_options(opts, &pos);
	d_printf("%s", "\n\ninitial handshake:\n");

	/* make initial HANDSHAKE request - serialize dest chan id, src chan id and protocol options */
	h_req_len = make_handshake_request(handshake_req, 0, 0xfeedbabe, opts, opts_len);
	dump_handshake_request(handshake_req, h_req_len, local_peer);

	len = sizeof(servaddr);

	local_peer->sm_leecher = SM_HANDSHAKE;

	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("socket creation failed");
		exit(EXIT_FAILURE);
	}

	local_peer->download_schedule_len = 0;
	local_peer->download_schedule = NULL;
	local_peer->download_schedule_idx = 0;

	/* set primary seeder IP:port as a initial default values */
	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	//servaddr.sin_port = htons(PORT);
	servaddr.sin_port = local_peer->seeder_addr.sin_port;
	servaddr.sin_addr.s_addr = local_peer->seeder_addr.sin_addr.s_addr;

	local_peer->finishing = 0;
	local_peer->download_schedule_idx = 0;
	local_peer->pex_required = 1;			/* mark flag that we want list of other seeders form primary seeder */
	mutex_init(&local_peer->download_schedule_mutex);

	/* leecher's state machine */
	while (local_peer->finishing == 0) {

		if (local_peer->sm_leecher == SM_HANDSHAKE) {
			/* send initial HANDSHAKE and wait for SEEDER's answer */
			n = sendto(sockfd, handshake_req, h_req_len, 0, (const struct sockaddr *) &servaddr, sizeof(servaddr));
			if (n < 0) {
				printf("error sending handshake: %d\n", n);
				abort();
			}
			d_printf("%s", "initial message 1/3 sent\n");

			local_peer->sm_leecher = SM_WAIT_HAVE;
		}

		if (local_peer->sm_leecher == SM_WAIT_HAVE) {
			FD_ZERO(&fs);
			FD_SET(sockfd, &fs);
			tv.tv_sec = local_peer->timeout;
			tv.tv_usec = 0;

			(void) select(sockfd + 1, &fs, NULL, NULL, &tv);
			n = 0;
			if (FD_ISSET(sockfd, &fs)) {
				/* receive response from SEEDER: HANDSHAKE + HAVE */
				n = recvfrom(sockfd, (char *)buffer, BUFSIZE, 0, (struct sockaddr *) &servaddr, &len);
			}

			if (n <= 0) { printf("error: timeout of %u seconds occured\n", local_peer->timeout);
				local_peer->sm_leecher = SM_HANDSHAKE;
				continue;
			} else {
				local_peer->sm_leecher = SM_PREPARE_REQUEST;
			}
		}

		if (local_peer->sm_leecher == SM_PREPARE_REQUEST) {
			buffer[n] = '\0';
			d_printf("server replied with %u bytes\n", n);

			/* calculate number of SHA hashes per 1500 bytes MTU */
			/* (MTU - sizeof(iphdr) - sizeof(udphdr) - ppspp_headers) / sha_size */
			local_peer->hashes_per_mtu = (1500 - 20 - 8 - (4 + 1 + 4 + 4 + 8))/20;
			d_printf("hashes_per_mtu: %lu\n", local_peer->hashes_per_mtu);

			dump_handshake_have(buffer, n, local_peer);

			if ((local_peer->start_chunk == 0xfffffffe) && (local_peer->end_chunk == 0xfffffffe)) {
				s = 0;
				for (y = 0; y < 20; y++)
					s += sprintf(buf + s, "%02x", local_peer->sha_demanded[y] & 0xff);
				buf[40] = '\0';
				printf("Primary seeder %s:%u has no file for hash: %s\n", inet_ntoa(servaddr.sin_addr), ntohs(servaddr.sin_port), buf);
				goto exit;
			}
			
			/* build the tree */
			local_peer->tree_root = build_tree(local_peer->nc, &local_peer->tree);

			/* create and open new file only when we are downloading from primary seeder without switching to another one */
			snprintf(fname, sizeof(fname), "%s", local_peer->fname);
			unlink(fname);
			fd = open(fname, O_WRONLY | O_CREAT, 0744);
			if (fd < 0) {
				printf("error opening file '%s' for writing: %u %s\n", fname, errno, strerror(errno));
				abort();
			}
			local_peer->fd = fd;


			z = local_peer->start_chunk;
			local_peer->sm_leecher = SM_WHILE_REQUEST;
		}

		/* external "while" loop, iterator "z" */
		if (local_peer->sm_leecher == SM_WHILE_REQUEST) {
			d_printf("z: %u  local_peer->end_chunk: %u\n", z, local_peer->end_chunk);

			begin = 0xffffffffffffffff;
			end = 0xffffffffffffffff;

			d_printf("begin: %lu   end: %lu\n", begin, end);

			/* create REQUEST  */
			request_len = make_request(request, 0xfeedbabe, begin, end, local_peer);

			_assert((long unsigned int) request_len <= sizeof(request), "%s but request_len has value: %u and sizeof(request): %lu\n", "request_len should be <= sizeof(request)", request_len, sizeof(request));
			local_peer->sm_leecher = SM_SEND_REQUEST;
		}

		if (local_peer->sm_leecher == SM_SEND_REQUEST) {
			/* send REQUEST */
			n = sendto(sockfd, request, request_len, 0, (const struct sockaddr *) &servaddr, sizeof(servaddr));
			if (n < 0) {
				printf("error sending request: %d\n", n);
				abort();
			}
			d_printf("%s", "request message 3/3 sent\n");
			local_peer->sm_leecher = SM_WAIT_PEX_RESP;
			d_printf("request sent: %u\n", n);
		}

		/* wait for PEX_RESV4 or INTEGRITY */
		if (local_peer->sm_leecher == SM_WAIT_PEX_RESP) {
			FD_ZERO(&fs);
			FD_SET(sockfd, &fs);
			tv.tv_sec = local_peer->timeout;
			tv.tv_usec = 0;

			(void) select(sockfd + 1, &fs, NULL, NULL, &tv);
			n = 0;
			if (FD_ISSET(sockfd, &fs)) {
				/* receive PEX_RESP or INTEGRITY from SEEDER */
				n = recvfrom(sockfd, (char *)buffer, BUFSIZE, 0, (struct sockaddr *) &servaddr, &len);
			}

			if (n <= 0) {
				local_peer->sm_leecher = SM_SWITCH_SEEDER;
				continue;
			} else {
				if (message_type(buffer) == INTEGRITY)
					local_peer->sm_leecher = SM_INTEGRITY;
				else
					local_peer->sm_leecher = SM_PEX_RESP;
			}
		}

		if (local_peer->sm_leecher == SM_PEX_RESP) {
			d_printf("%s", "PEX_RESP\n");
			dump_pex_resp(buffer, n, local_peer, sockfd);
			local_peer->pex_required = 0;		/* unset flag  */

			local_peer->sm_leecher = SM_SEND_HANDSHAKE_FINISH;
		}

		if (local_peer->sm_leecher == SM_SEND_HANDSHAKE_FINISH) {
			/* send HANDSHAKE FINISH */
			n = make_handshake_finish(buffer, local_peer);
			d_printf("%s", "we're sending HANDSHAKE_FINISH\n");
			n = sendto(sockfd, buffer, n, 0, (const struct sockaddr *) &servaddr, sizeof(servaddr));
			if (n < 0) {
				printf("error sending request: %d: %s\n", n, strerror(errno));
				abort();
			}

			local_peer->finishing = 1;
			continue;
		}
	}
	d_printf("%s", "HANDSHAKE_FINISH from main process sent\n");

	/* preliminary connection with primary seeder has just end */

	close(sockfd);

	mutex_init(&local_peer->fd_mutex);

	xx = 0;
	/* create as many threads as many seeder peers are in the peer_list_head */
	p = peer_list_head.next;
	while (p != NULL) {
		p->hashes_per_mtu = local_peer->hashes_per_mtu;
		p->nc = local_peer->nc;
		p->nl = local_peer->nl;
		p->timeout = local_peer->timeout;
		p->thread_num = xx + 1;
		p->current_seeder = p;	/* set current_seeder to myself */
		p->local_leecher = local_peer;
		(void) pthread_create(&thread, NULL, leecher_algo5_worker, p);
		p->thread = thread;

		p->to_remove = 1;	/* mark flag that every thread created in this loop should be destroyed when his work is done */
		p = p->next;
		xx++;
	}

	d_printf("created %u leecher threads\n", xx);

	/* wait for end of all of the threads and free the allocated memory for them */
	cleanup_all_dead_peers(&peer_list_head);

	d_printf("%s", "chunks that are not downloaded yet:\n");
	yy = 0;
	while (yy < local_peer->nc) {
		if (local_peer->chunk[yy].downloaded != CH_YES)
			d_printf("chunk[%u]\n", yy);
		yy++;
	}

exit:
	pthread_mutex_destroy(&local_peer->fd_mutex);

	if (local_peer->download_schedule != NULL)
		free(local_peer->download_schedule);

	close(fd);
	return 0;
}


int net_leecher(struct peer *peer)
{
#if 0
	net_leecher_algo1_nosm(peer);
	net_leecher_algo2_sm(peer);
	net_leecher_algo3_sm_switching_seeders(peer);
	net_leecher_algo4_sm_switching_seeders_continue_transmission(peer);
#endif
	if (peer->algo == 4)
		net_leecher_algo4_sm_switching_seeders_continue_transmission(peer);
	else
		net_leecher_algo5_parallel_downloading(peer);

	return 0;
}
