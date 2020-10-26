#ifndef _WQUEUE_H_
#define _WQUEUE_H_

#include <stdint.h>
#include <sys/queue.h>

#include "peer.h"

void wq_init(struct wqueue_head * /*wh*/);
void wq_append(struct wqueue_head * /*wh*/, struct wqueue_entry * /*e*/);
int wq_send(struct wqueue_head * /*wh*/, char * /*buf*/, uint16_t /*buf_len*/);
int wq_receive(struct wqueue_head * /*wh*/, char * /*buf*/, uint16_t /*buf_len*/);
int wq_peek(struct wqueue_head * /*wh*/, char * /*buf*/, uint16_t /*buf_len*/);
int wq_no_elements(struct wqueue_head * /*wh*/);

#endif
