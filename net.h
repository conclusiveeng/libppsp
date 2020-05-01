#ifndef _NET_H_
#define _NET_H_

#include "mt.h"
#include "peer.h"


struct threads {
	pthread_t tid;
	struct sockaddr_in sa;
	struct peer *peer;
};

struct threads threads[16];
uint16_t num_threads;
int net_seeder(struct peer *);
int net_leecher(struct peer *);

#endif
