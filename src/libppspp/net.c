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
#include <arpa/inet.h>
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

#if MQ_SYNC
#define MQ_NAME "/mq"
#endif

extern int h_errno;
uint8_t remove_dead_peers;

INTERNAL_LINKAGE
int
semaph_wait(sem_t *sem)
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
leecher_cond_wake(struct peer *p)
{
  pthread_mutex_lock(&p->leecher_mutex);
  p->leecher_cond = L_WAKE;
  pthread_cond_signal(&p->leecher_mtx_cond);
  pthread_mutex_unlock(&p->leecher_mutex);

  return 0;
}

INTERNAL_LINKAGE
void
net_leecher_fetch_chunk(struct peer *local_peer)
{
  struct peer *p;

  pthread_mutex_lock(&local_peer->peers_list_head_mutex);
  p = SLIST_FIRST(&local_peer->peers_list_head);
  pthread_mutex_unlock(&local_peer->peers_list_head_mutex);

  d_printf("%s", "sending FETCH command\n");
  p->cmd = local_peer->cmd;

  /* wake up the step-by-step state machine - she is waiting in
   * SM_PREPARE_REQUEST state */
  leecher_cond_wake(p);

  d_printf("%s", "command FETCH sent\n");
  semaph_wait(local_peer->sem);
}

INTERNAL_LINKAGE
void
net_leecher_close(struct peer *local_peer)
{
  uint32_t yy;
  struct peer *p;

  pthread_mutex_lock(&local_peer->peers_list_head_mutex);
  p = SLIST_FIRST(&local_peer->peers_list_head);
  pthread_mutex_unlock(&local_peer->peers_list_head_mutex);

  d_printf("%s", "sending FINISH command\n");
  p->cmd = local_peer->cmd;
  /* wake up the step-by-step state machine */
  leecher_cond_wake(p);

  d_printf("%s", "command FINISH sent\n");
  semaph_wait(local_peer->sem);

  /* wait for end of all of the threads and free the allocated memory for them
   */
  pthread_mutex_lock(&local_peer->peers_list_head_mutex);
  cleanup_all_dead_peers(&local_peer->peers_list_head);
  pthread_mutex_unlock(&local_peer->peers_list_head_mutex);

  d_printf("%s", "chunks that are not downloaded yet:\n");
  yy = 0;
  while (yy < local_peer->nc) {
    if (local_peer->chunk[yy].downloaded != CH_YES)
      d_printf("chunk[%u]\n", yy);
    yy++;
  }

  pthread_mutex_destroy(&local_peer->fd_mutex);
  pthread_mutex_destroy(&p->leecher_mutex);
  pthread_mutex_destroy(&p->leecher_mutex2);
  pthread_cond_destroy(&p->leecher_mtx_cond);
  pthread_cond_destroy(&p->leecher_mtx_cond2);

  if (local_peer->download_schedule != NULL)
    free(local_peer->download_schedule);

  close(local_peer->fd);
}
