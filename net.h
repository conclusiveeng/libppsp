#ifndef _NET_H_
#define _NET_H_

#include "mt.h"
#include "peer.h"

int net_seeder(struct peer *, struct req *);
int net_leecher(struct peer *, struct req *);

#endif
