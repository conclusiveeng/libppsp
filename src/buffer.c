//
// Created by jakub on 12.12.2020.
//

#include <stdlib.h>
#include "internal.h"

#define MAX_FRAME_SIZE	1400

struct pg_buffer *
pg_buffer_create(struct pg_peer *peer)
{
	struct pg_buffer *buffer;

	buffer = calloc(1, sizeof(*buffer));
	buffer->peer = peer;
	buffer->allocated = MAX_FRAME_SIZE;
	buffer->used = 0;
	buffer->storage = malloc(buffer->allocated);

	return (buffer);
}



int
pg_buffer_send(struct pg_buffer *buffer)
{

}

void
pg_buffer_free(struct pg_buffer *buffer)
{

}
