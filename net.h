#ifndef _NET_H_
#define _NET_H_

#include "mt.h"
#include "peer.h"

//int net_seeder(char *, int, struct node *);
int net_seeder(struct peer *);
//int net_leecher(char *, int, char *, int);
int net_leecher(struct peer *);

#endif
