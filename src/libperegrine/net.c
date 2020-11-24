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

#include "net.h"
#include "config.h"
#include "debug.h"
#include "mt.h"
#include "peer.h"
#include "ppspp_protocol.h"
#include "sha1.h"
#include "wqueue.h"
#include <arpa/inet.h>
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define SEM_NAME "/ppspp"

extern int h_errno;

uint8_t remove_dead_peers;

INTERNAL_LINKAGE
sem_t *
semaphore_init(struct peer *p)
{
  sem_t *sem;

  memset(p->sem_name, 0, sizeof(p->sem_name));
  snprintf(p->sem_name, sizeof(p->sem_name) - 1, "%s_%x_%lx", SEM_NAME, (uint32_t)getpid(), random());

  sem_unlink(p->sem_name);

  sem = sem_open(p->sem_name, O_CREAT, 0777, 0); /* create semaphore initially locked */
  if (sem == SEM_FAILED) {
    d_printf("sem_open error: %s\n", strerror(errno));
    abort();
  }

  return sem;
}

INTERNAL_LINKAGE
int
semaphore_post(sem_t *sem)
{
  int s;

  s = sem_post(sem);
  if (s != 0) {
    d_printf("%s: error: %d  %s\n", __func__, errno, strerror(errno));
    abort();
  }

  return 0;
}

INTERNAL_LINKAGE
int
semaphore_wait(sem_t *sem)
{
  int s;

  s = sem_wait(sem);
  if (s != 0) {
    d_printf("%s: error: %d  %s\n", __func__, errno, strerror(errno));
    abort();
  }

  return 0;
}

INTERNAL_LINKAGE
int
mutex_init(pthread_mutex_t *mutex)
{
  int s;

  s = pthread_mutex_init(mutex, NULL);
  if (s != 0) {
    d_printf("%s: error: %d  %s\n", __func__, errno, strerror(errno));
    abort();
  }

  return 0;
}

INTERNAL_LINKAGE
int
mutex_lock(pthread_mutex_t *mutex)
{
  int s;

  s = pthread_mutex_lock(mutex);
  if (s != 0) {
    d_printf("%s: error: %d  %s\n", __func__, errno, strerror(errno));
    abort();
  }

  return 0;
}

INTERNAL_LINKAGE
int
mutex_unlock(pthread_mutex_t *mutex)
{
  int s;

  s = pthread_mutex_unlock(mutex);
  if (s != 0) {
    d_printf("%s: error: %d  %s\n", __func__, errno, strerror(errno));
    abort();
  }

  return 0;
}

INTERNAL_LINKAGE
int
seeder_cond_unlock(struct peer *p)
{
  pthread_mutex_lock(&p->seeder_mutex);
  pthread_cond_signal(&p->seeder_mtx_cond);
  pthread_mutex_unlock(&p->seeder_mutex);

  return 0;
}

INTERNAL_LINKAGE
int
leecher_cond_lock_init(struct peer *p)
{
  int s;

  s = pthread_mutex_init(&p->leecher_mutex, NULL);
  if (s != 0) {
    d_printf("%s: error: %d  %s\n", __func__, errno, strerror(errno));
    abort();
  }

  s = pthread_cond_init(&p->leecher_mtx_cond, NULL);
  if (s != 0) {
    d_printf("%s: error: %d  %s\n", __func__, errno, strerror(errno));
    abort();
  }

  p->leecher_cond = L_SLEEP;
  return 0;
}

INTERNAL_LINKAGE
int
leecher_cond_sleep(struct peer *p)
{
  pthread_mutex_lock(&p->leecher_mutex);
  do {
    if (p->leecher_cond == L_WAKE) {
      break;
    }
    {
      pthread_cond_wait(&p->leecher_mtx_cond, &p->leecher_mutex);
    }

  } while (1);
  pthread_mutex_unlock(&p->leecher_mutex);

  return 0;
}

INTERNAL_LINKAGE
int
leecher_cond_set_and_sleep(struct peer *p)
{
  pthread_mutex_lock(&p->leecher_mutex);
  p->leecher_cond = L_SLEEP;
  do {
    if (p->leecher_cond == L_WAKE) {
      break;
    }
    {
      pthread_cond_wait(&p->leecher_mtx_cond, &p->leecher_mutex);
    }

  } while (1);
  pthread_mutex_unlock(&p->leecher_mutex);

  return 0;
}

INTERNAL_LINKAGE
int
leecher_cond_wake(struct peer *p)
{
  pthread_mutex_lock(&p->leecher_mutex);
  p->leecher_cond = L_WAKE;
  pthread_cond_signal(&p->leecher_mtx_cond);
  pthread_mutex_unlock(&p->leecher_mutex);

  return 0;
}

INTERNAL_LINKAGE
int
leecher_cond_set(struct peer *p, enum leech_condition val)
{
  pthread_mutex_lock(&p->leecher_mutex);
  p->leecher_cond = val;
  pthread_cond_signal(&p->leecher_mtx_cond);
  pthread_mutex_unlock(&p->leecher_mutex);

  return 0;
}

INTERNAL_LINKAGE
void *
on_handshake(struct peer *p, void *recv_buf, uint16_t recv_len)
{
  int n;
  int clientlen;
  int sockfd;
  int h_resp_len;
  int opts_len;
  int y;
  char *bn;
  char buf[40 + 1];
  uint8_t opts[1024]; /* buffer for encoded options */
  char swarm_id[] = "swarm_id";
  char handshake_resp[256];
  struct peer *we;
  struct proto_config pos;

  clientlen = sizeof(struct sockaddr_in);
  we = p->seeder; /* our data (seeder) */
  sockfd = p->sockfd;

  memset(&pos, 0, sizeof(struct proto_config));
  memset(&opts, 0, sizeof(opts));

  /* prepare structure as a set of parameters to make_handshake_options() proc
   */
  pos.version = 1;
  pos.minimum_version = 1;
  pos.swarm_id_len = strlen(swarm_id);
  pos.swarm_id = (uint8_t *)swarm_id;
  pos.content_prot_method = 1; /* merkle hash tree */
  pos.merkle_hash_func = 0;    /* 0 = sha-1 */
  pos.live_signature_alg = 5;  /* should be taken from DNSSEC */
  pos.chunk_addr_method = 2;   /* 2 = 32 bit chunk ranges */
  *(unsigned int *)pos.live_disc_wind = 0x12345678;
  pos.supported_msgs_len = 2;                   /* bitmap of supported messages consists of 2 bytes */
  *(unsigned int *)pos.supported_msgs = 0xffff; /* bitmap of supported messages */
  pos.chunk_size = we->chunk_size;
  pos.file_size = we->file_size;

  bn = basename(we->fname);
  pos.file_name_len = strlen(bn);
  memset(pos.file_name, 0, sizeof(pos.file_name));
  memcpy(pos.file_name, bn, pos.file_name_len);
  memcpy(pos.sha_demanded, "aaaaaaaaaaaaaaaaaaaa", 20); /* it doesn't matter here because leecher doesn't use this
                                                           field as read field */

  /* mark the options we want to pass to make_handshake_options() (which ones
   * are valid) */
  pos.opt_map = 0;
  pos.opt_map |= (1 << VERSION);
  pos.opt_map |= (1 << MINIMUM_VERSION);
  pos.opt_map |= (1 << CONTENT_PROT_METHOD);
  pos.opt_map |= (1 << MERKLE_HASH_FUNC);
  pos.opt_map |= (1 << CHUNK_ADDR_METHOD);

  swift_dump_handshake_request(recv_buf, recv_len, p);
  opts_len = make_proto_config_to_opts(opts, &pos);

  _assert((unsigned long int)opts_len <= sizeof(opts), "%s but has value: %d\n", "opts_len should be <= 1024",
          opts_len);

  h_resp_len = make_handshake_have(handshake_resp, p->dest_chan_id, 0xfeedbabe, opts, opts_len, p);

  _assert((unsigned long int)h_resp_len <= sizeof(handshake_resp), "%s but has value: %d\n",
          "h_resp_len should be <= 256", h_resp_len);
  _assert(recv_len != 0, "%s but has value: %d\n", "recv_len should be != 0", recv_len);

  /* send HANDSHAKE + HAVE */
  n = sendto(sockfd, handshake_resp, h_resp_len, 0, (struct sockaddr *)&p->leecher_addr, clientlen);
  if (n < 0) {
    d_printf("%s", "ERROR in sendto\n");
    abort();
  }

  if (p->file_list_entry == NULL) {
    int s = 0;
    for (y = 0; y < 20; y++) {
      s += sprintf(buf + s, "%02x", p->sha_demanded[y] & 0xff);
    }
    buf[40] = '\0';
    d_printf("Error: there is no file with hash %s for %s:%d. Closing connection.\n", buf,
             inet_ntoa(p->leecher_addr.sin_addr), ntohs(p->leecher_addr.sin_port));
    p->finishing = 1;
    p->to_remove = 1;      /* mark this particular peer to remove by GC */
    remove_dead_peers = 1; /* set global flag for removing dead peers by garbage collector */
    seeder_cond_unlock(p);
  }

  clock_gettime(CLOCK_MONOTONIC, &p->ts_last_send);

  memset(p->fname, 0, sizeof(p->fname));
  strcpy(p->fname, basename(p->file_list_entry->path)); /* do we really need this here? */
  p->chunk_size = we->chunk_size;
  p->sm_seeder = SM_WAIT_REQUEST;
  seeder_cond_unlock(p);

  return 0;
}

INTERNAL_LINKAGE
void *
on_request(struct peer *p, void *recv_buf, uint16_t recv_len)
{
  int clientlen;
  int data_payload_len;
  int n;
  char mq_buf[BUFSIZE + 1];
  ssize_t st;

  clientlen = sizeof(struct sockaddr_in);

  dump_request(recv_buf, recv_len, p);

  p->curr_chunk = p->start_chunk; /* set beginning number of chunk for DATA0 */

  do {
    /* shouldn't be here a loop? */
    if (p->data_bmp[p->curr_chunk / 8] & (1 << (p->curr_chunk % 8))) {
      d_printf("DATA %lu already sent - skipping\n", p->curr_chunk);
      p->curr_chunk++;
    }

    n = make_integrity_reverse(p->send_buf, p, p->seeder);

    _assert(n <= BUFSIZE, "%s but n has value: %d and BUFSIZE: %d\n", "n should be <= BUFSIZE", n, BUFSIZE);

    /* check if there is enough space in MTU to send all the INTEGRITY messages
     * and DATA in one packet */
    if (n + 4 + 1 + 4 + 4 + 8 + 20 + 8 + p->seeder->chunk_size
        <= BUFSIZE) { /* 4:chan_id, 1: DATA message id=1, 4:start, 4:end,
                         8:timestamp, 20: ip, 8: udp */

      /* yes there is enough space so we can send INTEGRITY and DATA together in
       * one frame */
      data_payload_len = make_data_no_chanid(p->send_buf + n, p);

      _assert((uint32_t)data_payload_len <= p->seeder->chunk_size + 4 + 1 + 4 + 4 + 8,
              "%s but data_payload_len has value: %d and we->chunk_size: %u\n",
              "data_payload_len should be <= we->chunk_size", data_payload_len, p->seeder->chunk_size);

      _assert(n + data_payload_len <= BUFSIZE, "we're trying to send too long UDP datagram: %d, should be <= %d\n",
              n + data_payload_len, BUFSIZE);

      /* send DATA datagram with contents of the chunk */
      n = sendto(p->sockfd, p->send_buf, n + data_payload_len, 0, (struct sockaddr *)&p->leecher_addr, clientlen);
      if (n < 0) {
	d_printf("%s", "ERROR in sendto\n");
	abort();
      }

      p->data_bmp[p->curr_chunk / 8] |= 1 << (p->curr_chunk % 8);
    } else {
      /* no - there is not enough space in MTU so we need to send INTEGRITY and
       * DATA in separate frames */

      /* first - send frame with INTEGRITY messages */
      n = sendto(p->sockfd, p->send_buf, n, 0, (struct sockaddr *)&p->leecher_addr, clientlen);
      if (n < 0) {
	d_printf("%s", "ERROR in sendto\n");
	abort();
      }

      /* next send DATA message with chunk's data */
      data_payload_len = make_data(p->send_buf, p);

      _assert((uint32_t)data_payload_len <= p->seeder->chunk_size + 4 + 1 + 4 + 4 + 8,
              "%s but data_payload_len has value: %d and we->chunk_size: %u\n",
              "data_payload_len should be <= we->chunk_size", data_payload_len, p->seeder->chunk_size);

      _assert(data_payload_len <= BUFSIZE, "we're trying to send too long UDP datagram: %d, should be <= %d\n",
              data_payload_len, BUFSIZE);

      /* send DATA datagram with contents of the chunk */
      n = sendto(p->sockfd, p->send_buf, data_payload_len, 0, (struct sockaddr *)&p->leecher_addr, clientlen);
      if (n < 0) {
	d_printf("%s", "ERROR in sendto\n");
	abort();
      }
      p->data_bmp[p->curr_chunk / 8] |= 1 << (p->curr_chunk % 8);
    }

    /* libswift sends HAVE first - so get it from our high priority queue */
    do {
      pthread_mutex_lock(&p->hi_mutex);
      st = wq_receive(&p->hi_wqueue, mq_buf, BUFSIZE);
      pthread_mutex_unlock(&p->hi_mutex);
      if (st <= 0) {
	usleep(1000);
      }
    } while (st <= 0);

    /* next libswift sends *sometimes* ACK - check if there is any in our
     * high-prio queue, if yes - get it from queue */
    do {
      pthread_mutex_lock(&p->hi_mutex);
      st = wq_peek(&p->hi_wqueue, mq_buf, BUFSIZE);
      pthread_mutex_unlock(&p->hi_mutex);
      if (st <= 0) {
	usleep(1000);
      }
    } while (st <= 0);

    if (mq_buf[0] == ACK) {
      do {
	pthread_mutex_lock(&p->hi_mutex);
	st = wq_receive(&p->hi_wqueue, mq_buf, BUFSIZE);
	pthread_mutex_unlock(&p->hi_mutex);
	if (st <= 0) {
	  usleep(1000);
	}
      } while (st <= 0);
    }

    p->curr_chunk++;
  } while (p->curr_chunk <= p->end_chunk);

  return 0;
}

/* thread - seeder worker */
INTERNAL_LINKAGE
void *
seeder_worker_mq(void *data)
{
  uint8_t opts[1024]; /* buffer for encoded options */
  struct peer *p;
  struct proto_config pos;
  char mq_buf[BUFSIZE + 1];
  ssize_t st;

  p = (struct peer *)data; /* data of remote host (leecher) connecting to us (seeder)*/

  d_printf("%s", "worker started\n");

  memset(&pos, 0, sizeof(struct proto_config));
  memset(&opts, 0, sizeof(opts));

  while (p->finishing == 0) {
    do {
      pthread_mutex_lock(&p->low_mutex);
      st = wq_receive(&p->low_wqueue, mq_buf, BUFSIZE);
      pthread_mutex_unlock(&p->low_mutex);
      if (st <= 0) {
	usleep(1000);
      }
    } while ((st <= 0) && (p->finishing == 0));
    if (p->finishing) {
      continue;
    }

    if (st <= 0) {
      abort();
    }

    switch (mq_buf[0]) {
    case HANDSHAKE:
      on_handshake(p, mq_buf, st);
      break;
    case REQUEST:
      on_request(p, mq_buf, st);
      break;
    case PEX_REQ:
      break;
    case HAVE:
      abort(); /* there shouldn't be HAVE message in low-prio queue */
    case ACK:
      abort(); /* there shouldn't be ACK message in low-prio queue */
    default:
      d_printf("another msg: %d\n", mq_buf[0]);
    }
  }

  pthread_exit(NULL);
  abort();
}

/* UDP datagram server (SEEDER) */
INTERNAL_LINKAGE
int
net_seeder_mq(struct peer *seeder)
{
  int sockfd;
  int optval;
  int n;
  int st;
  int off;
  int size;
  int skip_hdr;
  char buf[BUFSIZE];
  socklen_t clientlen;
  struct sockaddr_in serveraddr;
  struct sockaddr_in clientaddr;
  struct peer *p;
  pthread_t thread;
  unsigned int prio;

  sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (sockfd < 0) {
    d_printf("%s", "ERROR opening socket\n");
  }

  optval = 1;
  setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval, sizeof(int));

  memset((char *)&serveraddr, 0, sizeof(serveraddr));
  serveraddr.sin_family = AF_INET;
  serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);
  serveraddr.sin_port = htons((unsigned short)seeder->port);

  if (bind(sockfd, (struct sockaddr *)&serveraddr, sizeof(serveraddr)) < 0) {
    d_printf("%s", "ERROR on binding\n");
  }

  clientlen = sizeof(clientaddr);
  remove_dead_peers = 0;

  SLIST_INIT(&seeder->peers_list_head);
  pthread_mutex_init(&seeder->peers_list_head_mutex, NULL);

  while (1) {
    /* invoke garbage collector */
    if (remove_dead_peers == 1) {
      pthread_mutex_lock(&seeder->peers_list_head_mutex);
      cleanup_all_dead_peers(&seeder->peers_list_head);
      pthread_mutex_unlock(&seeder->peers_list_head_mutex);
    }

    memset(buf, 0, BUFSIZE);
    n = recvfrom(sockfd, buf, BUFSIZE, 0, (struct sockaddr *)&clientaddr, &clientlen);
    if (n < 0) {
      d_printf("%s", "ERROR in recvfrom\n");
    }

    /* locate peer basing on IP address and UDP port */
    pthread_mutex_lock(&seeder->peers_list_head_mutex);
    p = ip_port_to_peer(seeder, &seeder->peers_list_head, &clientaddr);
    pthread_mutex_unlock(&seeder->peers_list_head_mutex);

    if ((message_type(buf) == HANDSHAKE) && (n > 4)) { /* n > 4 to skip keepalive messages */
      d_printf("%s", "OK HANDSHAKE\n");
      if (handshake_type(buf) == HANDSHAKE_INIT) {
	p = new_peer(&clientaddr, BUFSIZE, sockfd);
	pthread_mutex_lock(&seeder->peers_list_head_mutex);
	add_peer_to_list(&seeder->peers_list_head, p);
	pthread_mutex_unlock(&seeder->peers_list_head_mutex);

	_assert(n <= BUFSIZE, "%s but n has value: %d and BUFSIZE: %d\n", "n should be <= BUFSIZE", n, BUFSIZE);

	p->seeder = seeder;
	wq_init(&p->hi_wqueue);
	wq_init(&p->low_wqueue);
	pthread_mutex_init(&p->hi_mutex, NULL);
	pthread_mutex_init(&p->low_mutex, NULL);

	/* create worker thread for this client (leecher) */
	st = pthread_create(&thread, NULL, &seeder_worker_mq, p);
	if (st != 0) {
	  d_printf("cannot create new thread: %s\n", strerror(errno));
	  abort();
	}

	d_printf("new pthread created: %#lx\n", (uint64_t)thread);

	p->thread = thread;
      } else if (handshake_type(buf) == HANDSHAKE_FINISH) {
	/* does the seeder want to close connection? */
	d_printf("%s", "FINISH\n");

	if (p == NULL) {
	  d_printf("searched IP: %s:%d  n: %d\n", inet_ntoa(clientaddr.sin_addr), ntohs(clientaddr.sin_port), n);
	  pthread_mutex_lock(&seeder->peers_list_head_mutex);
	  SLIST_FOREACH(p, &seeder->peers_list_head, snext)
	  {
	    d_printf("    IP: %s:%d\n", inet_ntoa(p->leecher_addr.sin_addr), ntohs(p->leecher_addr.sin_port));
	  }
	  pthread_mutex_unlock(&seeder->peers_list_head_mutex);
	}

	if (p != NULL) {
	  /* swift_semaph_post(p->sem);	*/ /* wake up seeder worker and allow
	                                      him finish his work */
	  p->finishing = 1;                /* set the flag for finishing the thread */
	  p->to_remove = 1;
	  pthread_mutex_lock(&seeder->peers_list_head_mutex);
	  cleanup_peer(p);
	  pthread_mutex_unlock(&seeder->peers_list_head_mutex);

	  free(p->integrity_bmp);
	  free(p->data_bmp);
	}
	continue; // uncomment this for demonized operation
	          // break;
      }
    }

    skip_hdr = 1; /* first message in udp payload always has dest_chan_id at
                     offset [0] so skip it in interpretation  */
    off = 0;
    size = 0;
    if (n > 4) { /* keep-alive? keep-alive has only dest_chan_id - and it takes
                    4 bytes */
      while (off < n) {
	/* parse payload to separate messages */
	switch (buf[off + skip_hdr * 4]) {
	case HANDSHAKE:
	  size = count_handshake(buf + off, n, skip_hdr);
	  prio = 0;
	  break;
	case REQUEST:
	  size = skip_hdr * 4 + 1 + 4 + 4;
	  prio = 0;
	  break;
	case PEX_REQ:
	  size = skip_hdr * 4 + 1;
	  prio = 0;
	  break;
	case HAVE:
	  size = skip_hdr * 4 + 1 + 4 + 4;
	  prio = 1;
	  break;
	case ACK:
	  size = skip_hdr * 4 + 1 + 4 + 4 + 8;
	  prio = 1;
	  break;
	default:
	  d_printf("another message: %d\n", buf[off + skip_hdr * 4]);
	}

	/* send the message to proper queue */
	if (prio == 0) {
	  pthread_mutex_lock(&p->low_mutex);
	  wq_send(&p->low_wqueue, buf + skip_hdr * 4 + off, size);
	  pthread_mutex_unlock(&p->low_mutex);
	} else {
	  pthread_mutex_lock(&p->hi_mutex);
	  wq_send(&p->hi_wqueue, buf + skip_hdr * 4 + off, size);
	  pthread_mutex_unlock(&p->hi_mutex);
	}

	off += size;
	skip_hdr = 0;
      }
    } else {
      d_printf("%s", "KEEP-ALIVE?\n");
    }
  }
}

INTERNAL_LINKAGE
void
node_cache_init(struct peer *local_peer)
{
  SLIST_INIT(&local_peer->cache);
}

INTERNAL_LINKAGE
void
print_sha1(const char *s1, int num)
{
  int s;
  int y;
  char bufs[256];

  s = 0;
  for (y = 0; y < num; y++) {
    s += sprintf((char *)(bufs + s), "%02x", s1[y] & 0xff);
  }
  bufs[s] = '\0';
  printf("%s", bufs);
}

INTERNAL_LINKAGE
int
verify_chunk(struct peer *local_peer, struct node *cn)
{
  char buf[40 + 1];
  char bufs[80 + 1];
  char zero[20];
  uint8_t sha_buf[40 + 1];
  uint8_t cmp;
  uint8_t f;
  int y;
  int s;
  uint32_t hci;
  uint32_t subroot_idx;
  unsigned char digest_sib[20];
  unsigned char c_digest_sib[20];
  struct node *si;
  struct node *p;
  struct node *left;
  struct node *right;
  struct node *curr;
  struct node *subroot;
  struct node_cache_entry *nc;
  struct node_cache_entry *ci;
  SHA1Context context;

  memset(zero, 0, sizeof(zero));

  d_printf("\nverification of node: %d\n", cn->number);

  _assert(local_peer->num_have_cache > 0, "%s\n", "local_peer->num_have_cache should be > 0");

  /* find subrange and basing on it subroot - in other words find entry in HAVE
   * cache */
  hci = 0;
  f = 0;
  while (hci < local_peer->num_have_cache) {
    if ((local_peer->have_cache[hci].start_chunk <= cn->number / 2)
        && (local_peer->have_cache[hci].end_chunk >= cn->number / 2)) {
      f = 1;
      break;
    }
    hci++;
  }

  _assert(f == 1, "current node %d hasn't been found in any range in HAVE cache\n", cn->number);

  /* subroot will be needed further in this procedure */
  subroot_idx = local_peer->have_cache[hci].start_chunk + local_peer->have_cache[hci].end_chunk;
  subroot = &local_peer->tree[subroot_idx];
  d_printf("subroot found: %d in have cache entry, range: %u..%u\n", subroot->number,
           local_peer->have_cache[hci].start_chunk, local_peer->have_cache[hci].end_chunk);

  /* find sibling for just received DATA message's node - needed to calculate
   * sum of SHA-1 hashes */
  si = find_sibling(cn);

  _assert(si != NULL, "%s\n", "s should be != NULL - sibling must exist");
  d_printf("sibling for: %d is: %d\n", cn->number, si->number);

  /* check if found sibling "si" is in ACTIVE state - it means if he has SHA-1
   * hash */
  _assert(si->state == ACTIVE,
          "si %d should be in ACTIVE state (and should have SHA1 hash), but "
          "has: %d\n",
          si->number, si->state);

  /* SHA-1 hash of the siblings always has to be linked like this: left_hash +
   * right_hash */
  if (cn == cn->parent->left) {
    left = cn;
    right = si;
  } else {
    left = si;
    right = cn;
  }

  if ((memcmp(left->sha, zero, sizeof(zero)) == 0) && (memcmp(right->sha, zero, sizeof(zero)) == 0)) {
    abort(); /* todo */
  }

  /* concatenate both SHA-1 hashes: just calculated from DATA payload and from
   * sibling */
  memset(buf, 0, sizeof(buf));
  memcpy(buf, left->sha, 20);       /* ??? just calculated SHA-1 hash of just received DATA payload */
  memcpy(buf + 20, right->sha, 20); /* SHA-1 of sibling */

  /* print sum of concatenated hashes */
  if (debug) {
    printf("siblings: ");
    print_sha1(buf, 40);
    printf("\n");
  }

  /* calculate SHA hash of sum of both siblings */
  SHA1Reset(&context);
  SHA1Input(&context, (uint8_t *)buf, 40);
  SHA1Result(&context, digest_sib);

  /* SHA-1 hash has been calculated for parent */

  /* print SHA-1 of concatenated sibling's hashes
   * this value will be assigned to parent SHA-1 hash
   * if the parent is not in ACTIVE state
   */
  if (debug) {
    printf("siblings digest: ");
    print_sha1((char *)sha_buf, 20);
    printf("\n");
  }

  _assert(cn->parent != NULL, "parent for node %d doesn't exist\n", cn->number);
  /* _assert(cn->parent->state == ACTIVE, "parent %d of node %d should be in
   * ACTIVE state, but is: %d\n", cn->parent->number, cn->number,
   * cn->parent->state); */

  node_cache_init(local_peer);

  /* example tree with 4 nodes: 0,2,4,6 - indexes 0,1,2,3
   * received hashes from libswift seeder for node 0 are: 3,5,2
   * so we need to calculate SHA-1 hash for parent node 1
   * as a sum of hashes of this parent (1) childrens: 0 and 2
   */
  curr = cn; /* working copy of cn */

  if (curr == curr->parent->left) {
    left = curr;
    right = si;
  } else {
    left = si;
    right = curr;
  }

  /* check if parent has SHA-1 hash - if it is in ACTIVE state */
  if (cn->parent->state != ACTIVE) { /* enter here when paren has not SHA-1 yet */
    p = curr->parent;                /* go to up - to the subroot of the subtree */
    si = find_sibling(curr);
    do {
      if ((memcmp(left->sha, zero, sizeof(zero)) == 0) && (memcmp(right->sha, zero, sizeof(zero)) == 0)) {
	abort(); /* todo */
      }

      /* concatenate both SHA-1 hashes: just calculated from DATA payload and
       * from sibling */
      memset(buf, 0, sizeof(buf));
      memcpy(buf, left->sha, 20);       /* ??? just calculated SHA-1 hash of just
                                           received DATA payload */
      memcpy(buf + 20, right->sha, 20); /* SHA-1 of sibling */

      /* print sum of concatenated hashes */
      if (debug) {
	printf("siblings[%d][%d]: ", left->number, right->number);
	print_sha1(buf, 40);
	printf("\n");
      }

      /* calculate SHA hash of sum of both siblings */
      SHA1Reset(&context);
      SHA1Input(&context, (uint8_t *)buf, 40);
      SHA1Result(&context, digest_sib);

      if (debug) {
	printf("sibling SHA-1: ");
	print_sha1((char *)digest_sib, 20);
	printf("\n");
      }

      nc = malloc(sizeof(struct node_cache_entry)); /* create node cache entry */
      nc->node.number = p->number;                  /* remember node number */
      memcpy(nc->node.sha, digest_sib, 20);         /* copy SHA-1 to cache node */
      SLIST_INSERT_HEAD(&local_peer->cache, nc, next);
      d_printf("new cache node: %d\n", nc->node.number);

      curr = curr->parent;
      p = curr->parent;
      si = find_sibling(curr);

      if (curr == curr->parent->left) {
	left = &nc->node;
	right = si;
      } else {
	left = si;
	right = &nc->node;
      }
    } while ((curr->parent != subroot) && (curr->parent->parent != NULL));

    si = find_sibling(curr); /* find sibling for node "curr" */

    d_printf("while loop ended with curr: %d  p: %d  nc: %d  si: %d\n", curr->number, p->number, nc->node.number,
             si->number);

    /* _assert(p_si != NULL, "sibling %d of parent %d must be ACTIVE\n",
     * p_si->number, p->number); */

    if ((memcmp(nc->node.sha, zero, sizeof(zero)) == 0) && (memcmp(si->sha, zero, sizeof(zero)) == 0)) {
      abort(); /* todo */
    }

    if (curr->parent->left == curr) { /* left side of the tree */
      memcpy(buf, nc->node.sha, 20);
      memcpy(buf + 20, si->sha, 20);
    } else { /* for verification of node 8 of 8-th nodes tree: 0,2,4,6,8,12,14 -
                right side of the tree */
      memcpy(buf, si->sha, 20);
      memcpy(buf + 20, nc->node.sha, 20);
    }
    SHA1Reset(&context);
    SHA1Input(&context, (uint8_t *)buf, 40);
    SHA1Result(&context, c_digest_sib); /* calculated hash of node 3 */

    /* is this the case when shared file (plik6k10) INTEGRITY doesn't return
     * SHA-1 hash of the whole tree (node 7) and we are forced to take it from
     * peer->sha_demanded?
     */
    if (p == local_peer->tree_root) {
      cmp = memcmp(local_peer->sha_demanded, c_digest_sib, 20);
    } else {
      /* compare just calculated above SHA-1 hash and from parent one */
      cmp = memcmp(p->sha, c_digest_sib, 20);
    }
    if (cmp != 0) {
      printf("error - hashes are different: ");
      printf("parent (from INTEGRITY) %d: ", p->number);
      print_sha1(p->sha, 20);
      printf(" vs calculated locally: ");
      print_sha1((char *)c_digest_sib, 20);
      printf("\n");

      printf("left[%d]: ", nc->node.number);
      print_sha1(nc->node.sha, 20);
      printf(" right[%d]: ", si->number);
      print_sha1(si->sha, 20);
      printf("\n");
      abort();
    }
  } else { /* enter here when parent has his own SHA-1 hash */
    if (cn == cn->parent->left) {
      left = cn;
      right = si;
    } else {
      left = si;
      right = cn;
    }

    if ((memcmp(left->sha, zero, sizeof(zero)) == 0) && (memcmp(right->sha, zero, sizeof(zero)) == 0)) {
      abort(); /* todo */
    }

    memcpy(buf, left->sha, 20);       /* SHA-1 of current node "cn" (node 4) */
    memcpy(buf + 20, right->sha, 20); /* SHA-1 of sibling (node 6) */

    SHA1Reset(&context);
    SHA1Input(&context, (uint8_t *)buf, 40);
    SHA1Result(&context, c_digest_sib); /* calculated hash fo node 3 */

    cmp = memcmp(cn->parent->sha, c_digest_sib, 20);

    if (cmp != 0) {
      printf("error - hashes are different: ");
      printf("parent (from INTEGRITY) %d: ", cn->parent->number);
      print_sha1(cn->parent->sha, 20);
      printf(" vs calculated locally: ");
      print_sha1((char *)c_digest_sib, 20);
      printf("\n");
    }
  }

  /* if both SHA-1 hashes are equal, dump node cache to tree */
  /* in other words - copy all the SHA-1 hashes from cache to the tree because
   * we will need those SHA-1 later */
  /* after copying of given hash - remove given cache entry from the list */
  if (cmp == 0) {
    SLIST_FOREACH(ci, &local_peer->cache, next)
    {
      d_printf("copying SHA-1 of node %d from cache to tree\n", ci->node.number);
      memcpy(local_peer->tree[ci->node.number].sha, ci->node.sha, 20);
      local_peer->tree[ci->node.number].state = ACTIVE;
      SLIST_REMOVE(&local_peer->cache, ci, node_cache_entry, next);
      free(ci);
    }
  }

  return cmp;
}

/* leecher worker in step-by-step version */
INTERNAL_LINKAGE
void *
leecher_worker_sbs(void *data)
{
  char buffer[BUFSIZE];
  uint8_t opts[1024]; /* buffer for encoded options */
  char handshake_req[256];
  char request[256];
  unsigned char digest[20];
  uint8_t *data_buffer;
  uint8_t cmp;
  int sockfd;
  int n;
  int nr;
  int opts_len;
  int h_req_len;
  int request_len;
  int r;
  uint32_t sc;
  uint32_t ec;
  uint32_t data_buffer_len;
  uint32_t prev_chunk_size;
  uint32_t first_chunk;
  uint64_t ack_len;
  uint64_t cc;
  uint64_t begin;
  uint64_t end;
  uint64_t offset;
  struct sockaddr_in servaddr;
  struct peer *p;
  struct peer *local_peer;
  struct node *cn;
  socklen_t len;
  SHA1Context context;
  struct proto_config pos;
  struct timeval tv;
  fd_set fs;

  memset(&pos, 0, sizeof(struct proto_config));
  memset(&opts, 0, sizeof(opts));
  memset(&handshake_req, 0, sizeof(handshake_req));

  p = (struct peer *)data;       /* struct describing remote peer - seeder */
  local_peer = p->local_leecher; /* we - local peer - leecher */

  /* prepare structure as a set of parameters to make_handshake_options() proc
   */
  pos.version = 1;
  pos.minimum_version = 1;
  pos.swarm_id = local_peer->sha_demanded;
  pos.swarm_id_len = 20;
  pos.content_prot_method = 1; /* merkle hash tree */
  pos.merkle_hash_func = 0;    /* 0 = sha-1 */
  pos.live_signature_alg = 5;  /* number from dnssec */
  pos.chunk_addr_method = 2;   /* 2 = 32 bit chunk ranges */
  *(unsigned int *)pos.live_disc_wind = 0x12345678;
  pos.supported_msgs_len = 2;                   /* 2 bytes of bitmap of serviced commands */
  *(unsigned int *)pos.supported_msgs = 0xffff; /* bitmap - we are servicing all of the commands from RFC */

#if LIB_SWIFT_PPSPP_EXT
  /* libswift doesn't service our option extensions */
  pos.chunk_size = local_peer->chunk_size;
  pos.file_size = local_peer->file_size;
  pos.file_name_len = local_peer->fname_len;
  memset(pos.file_name, 0, sizeof(pos.file_name));
  memcpy(pos.file_name, local_peer->fname, local_peer->fname_len);
#endif
  memcpy(pos.sha_demanded, local_peer->sha_demanded, 20); /* leecher demands file with hash given in "-s" command line
                                                             parameter */

  /* mark the options we want to pass to make_handshake_options() (which ones
   * are valid) */
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
#if LIB_SWIFT_PPSPP_EXT
  pos.opt_map |= (1 << CHUNK_SIZE);
  pos.opt_map |= (1 << FILE_SIZE);
  pos.opt_map |= (1 << FILE_NAME);
  pos.opt_map |= (1 << FILE_HASH);
#endif

  /* for leecher */
  opts_len = make_proto_config_to_opts(opts, &pos);
  dump_options(opts, p);
  clock_gettime(CLOCK_REALTIME, &local_peer->ts_start_time);
  d_printf("%s", "\n\ninitial handshake:\n");

  /* make initial HANDSHAKE request - serialize dest chan id, src chan id and
   * protocol options */
  h_req_len = make_handshake_request(handshake_req, 0, 0xfeedbabe, opts, opts_len);
  dump_handshake_request(handshake_req, h_req_len, p);

  len = sizeof(servaddr);

  p->sm_leecher = SW_SEND_HANDSHAKE_INIT;

  if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    perror("socket creation failed");
    exit(EXIT_FAILURE);
  }

  _assert(local_peer->chunk_size > 0, "%s\n", "local_peer->chunk_size should be > 0");

  data_buffer_len = local_peer->chunk_size + 4 + 1 + 4 + 4 + 8;
  data_buffer = malloc(data_buffer_len);

  /* set primary seeder IP:port as a initial default values */
  memset(&servaddr, 0, sizeof(servaddr));
  servaddr.sin_family = AF_INET;
  servaddr.sin_port = p->leecher_addr.sin_port;
  servaddr.sin_addr.s_addr = p->leecher_addr.sin_addr.s_addr;
  d_printf("pthread %#lx   IP: %s\n", (uint64_t)p->thread, inet_ntoa(servaddr.sin_addr));

  p->finishing = 0;
  p->after_seeder_switch = 0; /* flag: 0 = we are still connected to first seeder, 1 = we are
                                 switched to another seeder at least once */
  p->pex_required = 0;        /* unmark flag that we want list of other seeders form
                                 primary seeder */
  p->fetch_schedule = 1;      /* allow to fetch series of chunks from download_schedule[] */
  prev_chunk_size = 0;

  /* leecher's state machine */
  while (p->finishing == 0) {

    if (p->sm_leecher == SW_SEND_HANDSHAKE_INIT) {
      /* send initial HANDSHAKE and wait for SEEDER's answer */
      n = sendto(sockfd, handshake_req, h_req_len, 0, (const struct sockaddr *)&servaddr, sizeof(servaddr));
      if (n < 0) {
	d_printf("error sending handshake: %d\n", n);
	abort();
      }
      d_printf("%s", "initial message 1/3 sent\n");

      p->sm_leecher = SW_WAIT_HANDSHAKE_RESP;
    }

    if (p->sm_leecher == SW_WAIT_HANDSHAKE_RESP) {
      FD_ZERO(&fs);
      FD_SET(sockfd, &fs);
      tv.tv_sec = p->timeout;
      tv.tv_usec = 0;

      (void)select(sockfd + 1, &fs, NULL, NULL, &tv);
      n = 0;
      if (FD_ISSET(sockfd, &fs)) {
	/* receive response from SEEDER: HANDSHAKE + HAVE */
	n = recvfrom(sockfd, (char *)buffer, BUFSIZE, 0, (struct sockaddr *)&servaddr, &len);
      }

      if (n <= 0) {
	if (all_chunks_downloaded(local_peer) == 1) {
	  p->sm_leecher = SM_SEND_HANDSHAKE_FINISH;
	  continue;
	}

	if (p->after_seeder_switch == 0) {
	  p->sm_leecher = SW_SEND_HANDSHAKE_INIT;
	} else {
	  p->sm_leecher = SM_SWITCH_SEEDER;
	}
	continue;
      }
      p->sm_leecher = SM_PREPARE_REQUEST;
    }

    if (p->sm_leecher == SM_PREPARE_REQUEST) {
      buffer[n] = '\0';

      d_printf("server replied with %d bytes\n", n);
      dump_handshake_have(buffer, n, p);

      if ((p->after_seeder_switch == 1) && (prev_chunk_size != local_peer->chunk_size)) {
	d_printf("previous and current seeder have different chunk size: %u vs %u\n", prev_chunk_size,
	         local_peer->chunk_size);
	abort();
      }
      p->sm_leecher = SM_SYNC_REQUEST;
    }

    if (p->sm_leecher == SM_SYNC_REQUEST) {
      /* we are connected to some seeder - so go to sleep and wait for awakening
       * by some other task */
      leecher_cond_sleep(p);

      _assert((p->cmd == CMD_FETCH) || (p->cmd == CMD_FINISH),
              "Command for leecher state machine should be FETCH or FINISH but "
              "is: %d\n",
              p->cmd);

      /* here someone has awakened us - so check the command we need to do */
      /* other task has set proper command in p->local_leecher->cmd */
      if (p->cmd == CMD_FETCH) {
	p->sm_leecher = SM_WHILE_REQUEST;
      } else if (p->cmd == CMD_FINISH) {
	p->sm_leecher = SM_SEND_HANDSHAKE_FINISH;
      }
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
      request_len = make_request(request, p->dest_chan_id, begin, end, p);

      _assert((long unsigned int)request_len <= sizeof(request),
              "%s but request_len has value: %d and sizeof(request): %zu\n",
              "request_len should be <= sizeof(request)", request_len, sizeof(request));
      p->sm_leecher = SM_SEND_REQUEST;
    }

    if (p->sm_leecher == SM_SEND_REQUEST) {
      /* send REQUEST */
      n = sendto(sockfd, request, request_len, 0, (const struct sockaddr *)&servaddr, sizeof(servaddr));
      if (n < 0) {
	d_printf("error sending request: %d\n", n);
	abort();
      }
      d_printf("%s", "request message 3/3 sent\n");
      p->sm_leecher = SM_WAIT_INTEGRITY; /* jump over PEX_REQ because swift
                                            doesn't send any PEX_RESP answers */
      d_printf("request sent: %d\n", n);
      cc = begin; /* internal "for" loop, iterator - cc */
    }

    /* wait for PEX_RESV4 or INTEGRITY */
    if (p->sm_leecher == SM_WAIT_PEX_RESP) {
      FD_ZERO(&fs);
      FD_SET(sockfd, &fs);
      tv.tv_sec = p->timeout;
      tv.tv_usec = 0;

      (void)select(sockfd + 1, &fs, NULL, NULL, &tv);
      n = 0;
      if (FD_ISSET(sockfd, &fs)) {
	/* receive PEX_RESP or INTEGRITY from SEEDER */
	n = recvfrom(sockfd, (char *)buffer, BUFSIZE, 0, (struct sockaddr *)&servaddr, &len);
      }

      printf("PEX_RESP n: %d\n", n);

      if (n <= 0) {
	p->sm_leecher = SM_SWITCH_SEEDER;
	continue;
      }
      if (message_type(buffer) == INTEGRITY) {
	p->sm_leecher = SM_INTEGRITY;
      } else {
	p->sm_leecher = SM_PEX_RESP;
      }
    }

    if (p->sm_leecher == SM_PEX_RESP) {
      d_printf("%s", "PEX_RESP\n");
      p->pex_required = 0; /* unset flag */ /* is it necessery here yet? */

      p->sm_leecher = SM_WAIT_INTEGRITY;
    }

    /* here we can receive both: INTEGRITY or DATA message */
    if (p->sm_leecher == SM_WAIT_INTEGRITY) {
      FD_ZERO(&fs);
      FD_SET(sockfd, &fs);
      tv.tv_sec = p->timeout;
      tv.tv_usec = 0;

      p->curr_chunk = cc;

      (void)select(sockfd + 1, &fs, NULL, NULL, &tv);
      n = 0;
      memset(buffer, 0, BUFSIZE);
      if (FD_ISSET(sockfd, &fs)) {
	/* check the length of the packet in UDP/IP kernel stack queue */
	n = recvfrom(sockfd, (char *)buffer, 65535, MSG_PEEK, (struct sockaddr *)&servaddr, &len);
	_assert(n <= BUFSIZE, "error: too long udp datagram: %d - problem with seeder?\n", n);

	/* receive INTEGRITY or DATA from SEEDER */
	n = recvfrom(sockfd, (char *)buffer, BUFSIZE, 0, (struct sockaddr *)&servaddr, &len);
      }

      if (n <= 0) {
	p->sm_leecher = SM_SWITCH_SEEDER;
	continue;
      }
      if (n == 4) { /* is this swift KEEP-ALIVE */
	d_printf("%s", "seeder sent KEEP-ALIVE\n");
      } else {
	/* prepare data_buffer[] and nr variables for SM_DATA state */
	if (message_type(buffer) == DATA) { /* is this DATA message? */
	  nr = n;
	  memcpy(data_buffer, buffer, n);
	  p->sm_leecher = SM_DATA;
	} else {
	  p->sm_leecher = SM_INTEGRITY;
	}
      }
    }

    if (p->sm_leecher == SM_INTEGRITY) {
      d_printf("server sent INTEGRITY: %d\n", n);
      r = dump_integrity(buffer, n, local_peer); /* copy SHA hashes to local_peer->chunk[] */
      if (r != n) {
	d_printf("there are some bytes %d remaining for further parse\n", n - r);
      }

      /* correct number of transferred bytes in case of seeder switching */
      /* local_peer->tx_bytes -= (cc - begin) * local_peer->chunk_size; */ /* in
                                                                              swift
                                                                              version
                                                                              it
                                                                              brokes
                                                                              counting
                                                                              tx_bytes
                                                                            */

      /* cc = begin;	*/ /* internal "for" loop, iterator - cc */

      /* check if parsed bytes "r" by swift_dump_integrity() are different than
       * the whole UDP payload "n" */
      /* it means that after several INTEGRITY messages there can be also DATA
       * message */
      if (r != n) {
	/* next message after INTEGRITY can be also one DATA message */
	/* copy DATA part of this UDP payload directly to data_buffer[] for
	 * SM_DATA state */
	if (buffer[r] == DATA) {
	  memcpy(data_buffer + 4, &buffer[r], n - r); /* + 4: skip destination channel*/
	  nr = n - r + 4;                             /* + 4: skip destination channel*/
	  p->sm_leecher = SM_DATA;                    /* skip SM_WAIT_DATA state and jump directly
	                                                 to SM_DATA */
	} else {
	  _assert(buffer[r] == DATA, "should be DATA message but is: %d\n", buffer[r]);
	}
      } else {
	p->sm_leecher = SM_WAIT_DATA;
      }
    }

    /* internal "for" loop - wait for next DATA packet from seeder */
    if (p->sm_leecher == SM_WAIT_DATA) {

      /* for (cc = begin; cc <= end; cc++) */
      /* receive the whole range of chunks from SEEDER */

      FD_ZERO(&fs);
      FD_SET(sockfd, &fs);
      tv.tv_sec = p->timeout;
      tv.tv_usec = 0;

      (void)select(sockfd + 1, &fs, NULL, NULL, &tv);
      nr = 0;

      if (FD_ISSET(sockfd, &fs)) {
	/* receive single DATA datagram */
	nr = recvfrom(sockfd, (char *)data_buffer, data_buffer_len, 0, (struct sockaddr *)&servaddr, &len);
      }
      if (nr <= 0) {
	p->sm_leecher = SM_SWITCH_SEEDER;
	continue;
      }
      p->sm_leecher = SM_DATA;
    }

    if (p->sm_leecher == SM_DATA) {
      /* save received chunk to file descriptor or memory */

      /* is this transferring data via file descriptor? */
      if (local_peer->transfer_method == M_FD) {
	d_printf("writing chunk to file: nr: %d  offset: %lu\n", nr, cc * local_peer->chunk_size);
	mutex_lock(&local_peer->fd_mutex);
	lseek(local_peer->fd, cc * local_peer->chunk_size, SEEK_SET);
	write(local_peer->fd, data_buffer + 1 + 4 + 4 + 8 + 4, nr - (1 + 4 + 4 + 8 + 4));
	mutex_unlock(&local_peer->fd_mutex);
	// Account transmitted bytes also for FD transfers
	local_peer->tx_bytes += nr - (1 + 4 + 4 + 8 + 4);
      } else if (local_peer->transfer_method == M_BUF) {
	first_chunk = local_peer->download_schedule[0].begin;
	offset = cc * local_peer->chunk_size - first_chunk * local_peer->chunk_size;
	d_printf("buf offset: %lu\n", offset);
	memcpy(local_peer->transfer_buf + offset, data_buffer + 1 + 4 + 4 + 8 + 4, nr - (1 + 4 + 4 + 8 + 4));
	local_peer->tx_bytes += nr - (1 + 4 + 4 + 8 + 4);
      }

      _assert(nr <= BUFSIZE, "nr should be <= %d but has: %d\n", BUFSIZE, nr);
      _assert(nr >= 1 + 4 + 4 + 8 + 4, "nr should be >= %d but is: %d\n", 1 + 4 + 4 + 8 + 4, nr);
      /* calculate SHA hash of just received DATA */
      SHA1Reset(&context);
      SHA1Input(&context, data_buffer + 1 + 4 + 4 + 8 + 4, nr - (1 + 4 + 4 + 8 + 4)); /* skip the headers */
      SHA1Result(&context, digest);

      /* verify if start and end chunk are equal in DATA message - they should
       * be */
      sc = be32toh(*(uint32_t *)(data_buffer + 4 + 1));
      ec = be32toh(*(uint32_t *)(data_buffer + 4 + 1 + 4));
      _assert(sc == ec, "sc and ec should be equal but sc: %u and ec: %u\n", sc, ec);

      /* find node of tree which this DATA payload contains */
      cn = &local_peer->tree[sc * 2];

      /* copy just calculated SHA-1 for just received DATA into proper node */
      memcpy(cn->sha, digest, 20);

      cmp = verify_chunk(local_peer, cn);

      if (cmp != 0) {
	printf("error - hashes are different for node %lu\n", cc * 2);
	d_printf("pthread %#lx   IP: %s\n", (uint64_t)p->thread, inet_ntoa(servaddr.sin_addr));
	abort();
      } else {
	/* set state to ACTIVE to mark this node as having proper SHA-1 hash */
	cn->state = ACTIVE;

	local_peer->chunk[p->curr_chunk].downloaded = CH_YES;
	p->sm_leecher = SW_SEND_HAVE_ACK;
      }
    }

    if (p->sm_leecher == SW_SEND_HAVE_ACK) {
      /* create ACK message to confirm that chunk in last DATA datagram has been
       * transferred correctly */
      ack_len = make_have_ack(buffer, p);

      _assert(ack_len <= BUFSIZE, "%s but ack_len has value: %lu and BUFSIZE: %d\n", "ack_len should be <= BUFSIZE",
              ack_len, BUFSIZE);

      /* send ACK */
      n = sendto(sockfd, buffer, ack_len, 0, (const struct sockaddr *)&servaddr, sizeof(servaddr));
      if (n < 0) {
	d_printf("error sending request: %d\n", n);
	abort();
      }
      d_printf("ACK[%lu] sent\n", cc);
      cc++;            /* "cc" is iterator from "for" loop */
      if (cc <= end) { /* end condition of "for cc" loop */
	p->sm_leecher = SM_WAIT_INTEGRITY;
	continue;
      }
      p->sm_leecher = SM_INC_Z;
    }

    /* end of external "while" loop, iterator "z" */
    if (p->sm_leecher == SM_INC_Z) {
      p->fetch_schedule = 1; /* all the current schedule is completed so allow
                                to get next one */

      if (local_peer->download_schedule_idx < local_peer->download_schedule_len) {
	p->sm_leecher = SM_WHILE_REQUEST;
	continue;
      } /* end of external "while" loop */
      /* seems like we have just downloaded all the chunks */
      p->sm_leecher = SM_WAIT_FOR_NEXT_CMD;
    }

    /* given serie of chunks have been fetched - now wait for new command */
    if (p->sm_leecher == SM_WAIT_FOR_NEXT_CMD) {
      d_printf("%s", "wakening main leecher process\n");
      semaphore_post(p->local_leecher->sem);
      d_printf("%s", "main leecher process awakened\n");

      p->cmd = 0;

      d_printf("%s", "waiting for next command from main leecher process\n");
      leecher_cond_set_and_sleep(p);
      d_printf("%s", "next command arrived from main leecher process\n");
      if (p->cmd == CMD_FETCH) {
	p->sm_leecher = SM_SYNC_REQUEST;
      } else if (p->cmd == CMD_FINISH) {
	p->sm_leecher = SM_SEND_HANDSHAKE_FINISH;
      }
    }

    if (p->sm_leecher == SM_SEND_HANDSHAKE_FINISH) {
      /* send HANDSHAKE FINISH */
      n = make_handshake_finish(buffer, p);
      n = sendto(sockfd, buffer, n, 0, (const struct sockaddr *)&servaddr, sizeof(servaddr));
      if (n < 0) {
	d_printf("error sending request: %d\n", n);
	abort();
      }
      p->to_remove = 1; /* mark peer to be removed by garbage collector */

      p->finishing = 1;
      clock_gettime(CLOCK_REALTIME, &local_peer->ts_end_time);
      semaphore_post(p->local_leecher->sem); /* wake the main process */
      continue;
    }

    if (p->sm_leecher == SM_SWITCH_SEEDER) {
      d_printf("%s", "switching seeder state machine\n");
      /* finish transmission with current seeder */

      n = make_handshake_finish(buffer, p);
      n = sendto(sockfd, buffer, ack_len, 0, (const struct sockaddr *)&servaddr, sizeof(servaddr));
      if (n < 0) {
	d_printf("error sending request: %d\n", n);
	abort();
      }

      prev_chunk_size = local_peer->chunk_size; /* remember chunk size from previous seeder */
      p->after_seeder_switch = 1;               /* mark that we are switching from one seeder to another */
      p->fetch_schedule = 0;

      d_printf("chunks not downloaded yet: begin: %lu  end: %lu  cc: %lu\n", begin, end, cc);

      /* choose new seeder */
      if (SLIST_NEXT(p->current_seeder, snext) != NULL) {
	p->current_seeder = SLIST_NEXT(p, snext); /* select next peer */
      } else {
	p->current_seeder = SLIST_FIRST(&local_peer->peers_list_head); /* select begin of the qeueue */
      }

      d_printf("selected new seeder: %s:%d\n", inet_ntoa(p->current_seeder->leecher_addr.sin_addr),
               ntohs(p->current_seeder->leecher_addr.sin_port));

      /* change IP address and port for all the new connections */
      memset(&servaddr, 0, sizeof(servaddr));
      servaddr.sin_family = AF_INET;
      servaddr.sin_port = p->current_seeder->leecher_addr.sin_port;
      servaddr.sin_addr.s_addr = p->current_seeder->leecher_addr.sin_addr.s_addr;

      p->sm_leecher = SM_HANDSHAKE;
      continue;
    }
  }
  d_printf("%s", "HANDSHAKE_FINISH from thread sent\n");

  free(data_buffer);
  close(sockfd);
  pthread_exit(NULL);
}

INTERNAL_LINKAGE
int
net_preliminary_connection_sbs(struct peer *leecher)
{
  char buffer[BUFSIZE];
  uint8_t opts[1024]; /* buffer for encoded options */
  char handshake_req[256];
  int sockfd;
  int n;
  int opts_len;
  int h_req_len;
  struct sockaddr_in servaddr;
  socklen_t len;
  struct proto_config cfg;
  struct timeval tv;
  fd_set fs;

  memset(&cfg, 0, sizeof(struct proto_config));
  memset(&opts, 0, sizeof(opts));
  memset(&handshake_req, 0, sizeof(handshake_req));

  /* prepare structure as a set of parameters to make_handshake_options() proc
   */
  cfg.version = 1;
  cfg.minimum_version = 1;
  cfg.swarm_id = leecher->sha_demanded;
  cfg.swarm_id_len = 20;
  cfg.content_prot_method = 1; /* merkle hash tree */
  cfg.merkle_hash_func = 0;    /* 0 = sha-1 */
  cfg.live_signature_alg = 5;  /* number from dnssec - taken from file swift/livesig.h:48 */
  cfg.chunk_addr_method = 2;   /* 2 = 32 bit chunk ranges */
  *(unsigned int *)cfg.live_disc_wind = 0x12345678;
  cfg.supported_msgs_len = 2;                   /* 2 bytes of bitmap of serviced commands */
  *(unsigned int *)cfg.supported_msgs = 0xffff; /* bitmap - we are servicing all of the commands from RFC*/
  cfg.chunk_size = leecher->chunk_size;
  cfg.file_size = leecher->file_size;
  cfg.file_name_len = leecher->fname_len;
  memset(cfg.file_name, 0, sizeof(cfg.file_name)); /* do we need this here? */
  memcpy(cfg.file_name, leecher->fname, leecher->fname_len);
  memcpy(cfg.sha_demanded, leecher->sha_demanded, 20); /* leecher demands file with hash given in "-s" command line
                                                             parameter */

  /* mark the options we want to pass to make_handshake_options() (which ones
   * are valid) */
  cfg.opt_map = 0;
  cfg.opt_map |= (1 << VERSION);
  cfg.opt_map |= (1 << MINIMUM_VERSION);
  cfg.opt_map |= (1 << SWARM_ID);
  cfg.opt_map |= (1 << CONTENT_PROT_METHOD);
  cfg.opt_map |= (1 << MERKLE_HASH_FUNC);
  cfg.opt_map |= (1 << LIVE_SIGNATURE_ALG);
  cfg.opt_map |= (1 << CHUNK_ADDR_METHOD);
  cfg.opt_map |= (1 << LIVE_DISC_WIND);
  cfg.opt_map |= (1 << SUPPORTED_MSGS);
#if LIB_SWIFT_PPSPP_EXT
  pos.opt_map |= (1 << CHUNK_SIZE);
  pos.opt_map |= (1 << FILE_SIZE);
  pos.opt_map |= (1 << FILE_NAME);
  pos.opt_map |= (1 << FILE_HASH);
#endif

  /* for leecher */
  opts_len = make_proto_config_to_opts(opts, &cfg);
  d_printf("%s", "\n\ninitial handshake:\n");

  /* make initial HANDSHAKE request - serialize dest chan id, src chan id and
   * protocol options */
  h_req_len = make_handshake_request(handshake_req, 0, 0xfeedbabe, opts, opts_len);
  dump_handshake_request(handshake_req, h_req_len, leecher);

  len = sizeof(servaddr);

  leecher->sm_leecher = SM_HANDSHAKE;

  if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    perror("socket creation failed\n");
    exit(EXIT_FAILURE);
  }

  leecher->download_schedule_len = 0;
  leecher->download_schedule = NULL;
  leecher->download_schedule_idx = 0;

  /* set primary seeder IP:port as a initial default values */
  memset(&servaddr, 0, sizeof(servaddr));
  servaddr.sin_family = AF_INET;
  servaddr.sin_port = leecher->seeder_addr.sin_port;
  servaddr.sin_addr.s_addr = leecher->seeder_addr.sin_addr.s_addr;

  leecher->seeder_has_file = 0;
  leecher->finishing = 0;
  leecher->download_schedule_idx = 0;
  leecher->pex_required = 1; /* mark flag that we want list of other seeders form primary seeder */
  mutex_init(&leecher->download_schedule_mutex);

  /* leecher's state machine */
  while (leecher->finishing == 0) {

    if (leecher->sm_leecher == SM_HANDSHAKE) {
      /* send initial HANDSHAKE and wait for SEEDER's answer */
      n = sendto(sockfd, handshake_req, h_req_len, 0, (const struct sockaddr *)&servaddr, sizeof(servaddr));
      if (n < 0) {
	d_printf("error sending handshake: %d\n", n);
	abort();
      }
      d_printf("%s", "initial message 1/3 sent\n");

      leecher->sm_leecher = SM_WAIT_HAVE;
    }

    if (leecher->sm_leecher == SM_WAIT_HAVE) {
      FD_ZERO(&fs);
      FD_SET(sockfd, &fs);
      tv.tv_sec = leecher->timeout;
      tv.tv_usec = 0;

      (void)select(sockfd + 1, &fs, NULL, NULL, &tv);
      n = 0;
      if (FD_ISSET(sockfd, &fs)) {
	/* receive response from SEEDER: HANDSHAKE + HAVE */
	n = recvfrom(sockfd, (char *)buffer, BUFSIZE, 0, (struct sockaddr *)&servaddr, &len);
      }

      if (n <= 0) {
	d_printf("error: timeout of %u seconds occured\n", leecher->timeout);
	leecher->sm_leecher = SM_HANDSHAKE;
	continue;
      }
      leecher->sm_leecher = SM_PREPARE_REQUEST;
    }

    if (leecher->sm_leecher == SM_PREPARE_REQUEST) {
      buffer[n] = '\0';
      d_printf("server replied with %d bytes\n", n);

      /* calculate number of SHA hashes per 1500 bytes MTU */
      /* (MTU - sizeof(iphdr) - sizeof(udphdr) - ppspp_headers) / sha_size */
      leecher->hashes_per_mtu = (1500 - 20 - 8 - (4 + 1 + 4 + 4 + 8)) / 20;
      d_printf("hashes_per_mtu: %lu\n", leecher->hashes_per_mtu);

      dump_handshake_have(buffer, n, leecher);

      leecher->seeder_has_file = 1; /* seeder has file for our hash stored in sha_demanded[] */
      /* build the tree */
      leecher->tree_root = build_tree(leecher->nc, &leecher->tree);

      /* here we need to refill the tree with ACTIVE states - there where won't
       * be any chunks because file size is not power of 2 */
      /* so they will be those nodes in tree which have now chance to be in
       * ACTIVE state */
      for (int x = leecher->nc; x < leecher->nl; x++) {
	leecher->tree[x * 2].state = ACTIVE;
	d_printf("refill[%d] ACTIVE\n", x * 2);
      }
      /* dump_tree(local_peer->tree, local_peer->nl); */

      /* for libswift compatibility we're not sending REQUEST but we're
       * finishing connection */
      leecher->sm_leecher = SM_SEND_HANDSHAKE_FINISH;
    }

    if (leecher->sm_leecher == SM_SEND_HANDSHAKE_FINISH) {
      /* send HANDSHAKE FINISH */
      n = make_handshake_finish(buffer, leecher);
      d_printf("%s", "we're sending HANDSHAKE_FINISH\n");
      n = sendto(sockfd, buffer, n, 0, (const struct sockaddr *)&servaddr, sizeof(servaddr));
      if (n < 0) {
	d_printf("error sending request: %d: %s\n", n, strerror(errno));
	abort();
      }

      leecher->finishing = 1;
      continue;
    }
  }
  d_printf("%s", "HANDSHAKE_FINISH from main process sent\n");

  d_printf("seeder has demanded file: %d  size: %lu\n", leecher->seeder_has_file, leecher->file_size);

  close(sockfd);
  return 0;
}

INTERNAL_LINKAGE
void
net_leecher_create(struct peer *leecher)
{
  struct peer *c;
  struct sockaddr_in sa;

  SLIST_INIT(&leecher->peers_list_head);
  pthread_mutex_init(&leecher->peers_list_head_mutex, NULL);

  /* moved here from dump_pex_resp() */
  /* add primary seeder as a first entry to the peer_list_head list */
  memcpy(&sa.sin_addr.s_addr, &leecher->seeder_addr.sin_addr.s_addr, sizeof(sa.sin_addr.s_addr));
  sa.sin_port = leecher->seeder_addr.sin_port;
  c = new_seeder(&sa, BUFSIZE);

  pthread_mutex_lock(&leecher->peers_list_head_mutex);
  add_peer_to_list(&leecher->peers_list_head, c);
  pthread_mutex_unlock(&leecher->peers_list_head_mutex);

  /* initially set current_seeder on primary seeder */
  leecher->current_seeder = c;

  d_printf("[__] %s:%d\n", inet_ntoa(sa.sin_addr), ntohs(sa.sin_port));
}

INTERNAL_LINKAGE
int
net_leecher_sbs(struct peer *leecher)
{
  int xx;
  struct peer *p;
  pthread_t thread;

  /* swift_preliminary_connection_sbs(local_peer); */
  leecher->sem = semaphore_init(leecher);
  mutex_init(&leecher->fd_mutex);

  xx = 0;
  /* create as many threads as many seeder peers are in the peer_list_head */
  pthread_mutex_lock(&leecher->peers_list_head_mutex);
  p = SLIST_FIRST(&leecher->peers_list_head);

  /* temporarily we're using only one thread for step-by-step state machine */
  p->hashes_per_mtu = leecher->hashes_per_mtu;
  p->sbs_mode = leecher->sbs_mode;
  p->nc = leecher->nc;
  p->nl = leecher->nl;
  p->timeout = leecher->timeout;
  p->thread_num = xx + 1;
  p->current_seeder = p; /* set current_seeder to myself */
  p->local_leecher = leecher;
  leecher_cond_lock_init(p);

  (void)pthread_create(&thread, NULL, leecher_worker_sbs, p);
  p->thread = thread;

  p->to_remove = 1; /* mark flag that every thread created in this loop should
                       be destroyed when his work is done */
  xx++;
  pthread_mutex_unlock(&leecher->peers_list_head_mutex);

  d_printf("created %d leecher threads\n", xx);

  return 0;
}

INTERNAL_LINKAGE
void
net_leecher_fetch_chunk(struct peer *leecher)
{
  struct peer *p;

  pthread_mutex_lock(&leecher->peers_list_head_mutex);
  p = SLIST_FIRST(&leecher->peers_list_head);
  pthread_mutex_unlock(&leecher->peers_list_head_mutex);

  d_printf("%s", "sending FETCH command\n");
  p->cmd = leecher->cmd;

  /* wake up the step-by-step state machine - she is waiting in
   * SM_PREPARE_REQUEST state */
  leecher_cond_wake(p);

  d_printf("%s", "command FETCH sent\n");
  semaphore_wait(leecher->sem);
}

INTERNAL_LINKAGE
void
net_leecher_close(struct peer *leecher)
{
  uint32_t yy;
  struct peer *p;

  pthread_mutex_lock(&leecher->peers_list_head_mutex);
  p = SLIST_FIRST(&leecher->peers_list_head);
  pthread_mutex_unlock(&leecher->peers_list_head_mutex);

  d_printf("%s", "sending FINISH command\n");
  p->cmd = leecher->cmd;
  /* wake up the step-by-step state machine */
  leecher_cond_wake(p);

  d_printf("%s", "command FINISH sent\n");
  semaphore_wait(leecher->sem);

  /* wait for end of all of the threads and free the allocated memory for them
   */
  pthread_mutex_lock(&leecher->peers_list_head_mutex);
  cleanup_all_dead_peers(&leecher->peers_list_head);
  pthread_mutex_unlock(&leecher->peers_list_head_mutex);

  d_printf("%s", "chunks that are not downloaded yet:\n");
  yy = 0;
  while (yy < leecher->nc) {
    if (leecher->chunk[yy].downloaded != CH_YES) {
      d_printf("chunk[%u]\n", yy);
    }
    yy++;
  }

  pthread_mutex_destroy(&leecher->fd_mutex);
  pthread_mutex_destroy(&p->leecher_mutex);
  pthread_cond_destroy(&p->leecher_mtx_cond);

  if (leecher->download_schedule != NULL) {
    free(leecher->download_schedule);
  }

  close(leecher->fd);
}
