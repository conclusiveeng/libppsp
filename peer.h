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

#include <dirent.h>
#include <mqueue.h>
#include <netinet/in.h>
#include <semaphore.h>
#include <stdint.h>
#include <string.h>
#include <sys/queue.h>
#include <time.h>

#include "mt.h"
//#include "wqueue.h"

#define INTERNAL_LINKAGE __attribute__((__visibility__("hidden")))

struct schedule_entry {
  uint64_t begin, end;
};

/* list of files shared by seeder */
SLIST_HEAD(slisthead, file_list_entry);
struct file_list_entry {
  char path[1024]; /* full path to file: directory name + file name */
  char sha[20];    /* do we need this? */
  uint64_t file_size;
  uint32_t nl;             /* number of leaves */
  uint32_t nc;             /* number of chunks */
  struct chunk *tab_chunk; /* array of chunks for this file */
  struct node *tree;       /* tree of the file */
  struct node *tree_root;  /* pointer to root node of the tree */
  uint32_t start_chunk;
  uint32_t end_chunk;

  SLIST_ENTRY(file_list_entry) next;
};

/* list of other (alternative) seeders maintained by primary seeder */
SLIST_HEAD(slist_seeders, other_seeders_entry);
struct other_seeders_entry {
  struct sockaddr_in sa;
  SLIST_ENTRY(other_seeders_entry) next;
};

SLIST_HEAD(slist_peers, peer);

extern uint8_t remove_dead_peers;

/* node cache for verifying SHA-1 in swift compatibility mode */
SLIST_HEAD(slist_node_cache, node_cache_entry);
struct node_cache_entry {
  struct node node;
  SLIST_ENTRY(node_cache_entry) next;
  //	struct slist_node_cache next;
};

#if 0
SLIST_HEAD(wqueue_head, wqueue_entry);
struct wqueue_entry {
	char *msg;
	uint16_t msg_len;
	SLIST_ENTRY(wqueue_entry) next;
};
#else
STAILQ_HEAD(wqueue_head, wqueue_entry);
struct wqueue_entry {
  char *msg;
  uint16_t msg_len;
  STAILQ_ENTRY(wqueue_entry) next;
};
#endif

struct have_cache {
  uint32_t start_chunk;
  uint32_t end_chunk;
};

enum peer_type { LEECHER, SEEDER };

enum state_machine_seed {
  SM_NONE = 0,
  SM_HANDSHAKE_INIT,
  SM_SEND_HANDSHAKE_HAVE,
  SM_WAIT_REQUEST,
  SM_REQUEST,
  SM_SEND_PEX_RESP,
  SM_SEND_INTEGRITY,
  SM_SEND_DATA,
  SM_WAIT_ACK,
  SM_ACK,
  SM_WAIT_FINISH,

  // SWIFT compatibility mode state machine states
  SW_SEND_INTEGRITY_DATA,
  SW_WAIT_HAVE_ACK,
  SW_HAVE_ACK
};

enum state_machine_leech {
  SM_HANDSHAKE = 1,
  SM_WAIT_HAVE,
  SM_PREPARE_REQUEST,
  SM_SEND_REQUEST,
  SM_WAIT_PEX_RESP,
  SM_PEX_RESP,
  SM_WAIT_INTEGRITY,
  SM_INTEGRITY,
  SM_WAIT_DATA,
  SM_DATA,
  SM_SEND_ACK,
  SM_INC_Z,
  SM_WHILE_REQUEST,
  SM_SEND_HANDSHAKE_FINISH,
  SM_SWITCH_SEEDER,
  SM_WAIT_FOR_NEXT_CMD,
  SM_SYNC_REQUEST,

  // SWIFT compatibility mode state machine states
  SW_SEND_HANDSHAKE_INIT,
  SW_WAIT_HANDSHAKE_RESP,
  SW_SEND_HAVE_ACK,
};

enum seed_condition { S_TODO = 1, S_DONE = 2 };
enum leech_condition { L_SLEEP = 1, L_WAKE };
enum leech_condition2 { L_TODO = 1, L_DONE };
enum leech_cmd { CMD_CONNECT = 1, CMD_FETCH = 2, CMD_FINISH = 3 };
enum trans_method { M_FD = 1, M_BUF };

struct peer {
  enum peer_type type;
  enum state_machine_seed sm_seeder;
  enum state_machine_leech sm_leecher;

  uint32_t src_chan_id;
  uint32_t dest_chan_id;
  struct peer *seeder; /* pointer to seeder peer struct - used on seeder side in
                          threads */
  struct peer *local_leecher; /* pointer to local leecher peer struct - used on
                                 leecher side in threads */
  struct node *tree; /* pointer to beginning (index 0) array with tree nodes */
  struct node *tree_root;  /* pointer to root of the tree */
  struct chunk *chunk;     /* array of chunks */
  uint32_t nl;             /* number of leaves */
  uint32_t nc;             /* number of chunks */
  uint64_t num_series;     /* number of series */
  uint64_t hashes_per_mtu; /* number of hashes that fit MTU size, for example if
                              == 5 then series are 0..4, 5..9, 10..14 */
  uint8_t sha_demanded[20];
  uint8_t seeder_has_file; /* flag on leecher side: 1 = seeder has file for
                              which we have demanded in ->sha_demanded[], 0 =
                              seeder has not file */
  uint8_t fetch_schedule;  /* 0 = peer is not allowed to get next schedule from
                              download_schedule array */
  uint8_t after_seeder_switch; /* 0 = still downloading from primary seeder, 1 =
                                  switched to another seeder after connection
                                  lost */
  struct schedule_entry
      *download_schedule; /* leecher side: array of elements of pair: begin,end
                             of chunks, max number of index: peer->nl-1 */
  uint64_t download_schedule_len; /* number of indexes of allocated array
                                     "download_schedule", 0 = all chunks
                                     downloaded */
  volatile uint64_t
      download_schedule_idx; /* index (iterator) for download_schedule array */
  pthread_mutex_t download_schedule_mutex; /* mutex for "download_schedule"
                                              array protection */

  /* for thread */
  uint8_t finishing;
  pthread_t thread;
  uint8_t thread_num; /* only for debugging - thread number */

  uint32_t timeout;

  /* timestamp of last received and sent message */
  struct timespec ts_last_recv, ts_last_send;

  /* last received and sent message */
  uint8_t d_last_recv, d_last_send;

  /* network things */
  uint16_t port; /* seeder: udp port number to bind to */
  struct sockaddr_in
      leecher_addr; /* leecher address: IP/PORT from seeder point of view */
  struct sockaddr_in seeder_addr; /* primary seeder IP/PORT address from leecher
                                     point of view */
  char *recv_buf;
  char *send_buf;

  uint16_t recv_len;
  int sockfd, fd;
  pthread_mutex_t fd_mutex;

  /* synchronization */
  sem_t *sem;
  char sem_name[64];
  uint8_t to_remove;
  pthread_mutex_t seeder_mutex;
  pthread_cond_t seeder_mtx_cond;
  enum seed_condition seeder_cond;
  mqd_t mq;

  pthread_mutex_t leecher_mutex;
  pthread_cond_t leecher_mtx_cond;
  enum leech_condition leecher_cond;

  pthread_mutex_t leecher_mutex2;
  pthread_cond_t leecher_mtx_cond2;
  enum leech_condition2 leecher_cond2;

  /* controlling leecher step-by-step state machine */
  enum leech_cmd cmd;

  uint8_t sbs_mode; /* 0 = continuous state machine and old API, 1 =
                       step-by-step state machine and new API */
  uint32_t chunk_size;
  uint32_t start_chunk;
  uint32_t end_chunk;
  uint64_t curr_chunk; /* currently serviced chunk */
  uint64_t file_size;
  char fname[256];
  char fname_len;
  uint8_t pex_required; /* leecher side: 1=we want list of seeders from primary
                           seeder */
  uint8_t *transfer_buf;
  uint32_t tx_bytes; /* number of bytes transferred in transfer_buf in current
                        request */
  enum trans_method transfer_method;

  uint8_t *integrity_bmp;  /* bitmap used by seeder for given leecher (libswift
                              compat mode) - to mark which tree node has already
                              been sent, 1-integrity node sent */
  uint8_t *data_bmp; /* */ // zwolnic pamiec podczas finish

  struct peer *current_seeder; /* leecher side: points to one element of the
                                  list seeders in ->snext */

  pthread_mutex_t
      peers_list_head_mutex; /* mutex for protecting peers_list_head */
  struct slist_peers
      peers_list_head; /* seeder: list of connected leechers, leecher: ? */
  struct slist_seeders
      other_seeders_list_head; /* seeder: list of other (alternative) seeders
                                  maintained by primary seeder */
  struct slisthead
      file_list_head; /* seeder: head of list of files shared by seeder */
  struct file_list_entry
      *file_list_entry; /* seeder side: pointer to file choosen by leecher using
                           SHA1 hash */

  struct slist_node_cache cache;
  struct wqueue_head hi_wqueue;
  struct wqueue_head low_wqueue;
  pthread_mutex_t hi_mutex;
  pthread_mutex_t low_mutex;

  /* HAVE cache */
  struct have_cache *have_cache;
  /* used by both - seeder and leecher */ // zwolnic te pamiec w momencie
                                          // finish
  uint16_t num_have_cache;                /* number of entries in HAVE cache */

  SLIST_ENTRY(peer)
  snext; /* list of peers - leechers from seeder point of view or seeders from
            leecher pov */
};

void add_peer_to_list(struct slist_peers *, struct peer *);
void print_peer_list(struct slist_peers *);
int remove_peer_from_list(struct slist_peers *, struct peer *);
struct peer *ip_port_to_peer(struct peer *, struct slist_peers *,
                             struct sockaddr_in *);
struct peer *new_peer(struct sockaddr_in *, int, int);
struct peer *new_seeder(struct sockaddr_in *, int);
void cleanup_peer(struct peer *);
void cleanup_all_dead_peers(struct slist_peers *);
void create_download_schedule(struct peer *);
int32_t create_download_schedule_sbs(struct peer *, uint32_t, uint32_t);
int32_t swift_create_download_schedule_sbs(struct peer *, uint32_t, uint32_t);
int all_chunks_downloaded(struct peer *);
void create_file_list(struct peer *, char *);
void process_file(struct file_list_entry *, struct peer *);

#endif /* _PEER_H_ */
