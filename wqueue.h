#ifndef _WQUEUE_H_
#define _WQUEUE_H_

#include <sys/queue.h>
#include <stdint.h>

#include "peer.h"


void wq_init(struct wqueue_head *);
void wq_append(struct wqueue_head *, struct wqueue_entry *);
int wq_send(struct wqueue_head *, char *, uint16_t);
int wq_receive(struct wqueue_head *, char *, uint16_t);
int wq_peek(struct wqueue_head *, char *, uint16_t);
int wq_no_elements (struct wqueue_head *);

#endif
