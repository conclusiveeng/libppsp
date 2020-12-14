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


#include <stdlib.h>
#include "internal.h"

#define MAX_FRAME_SIZE	1400

struct pg_buffer *
pg_buffer_create(struct pg_peer *peer, uint32_t channel_id)
{
	struct pg_buffer *buffer;

	buffer = calloc(1, sizeof(*buffer));
	buffer->peer = peer;
	buffer->allocated = MAX_FRAME_SIZE;
	buffer->storage = malloc(buffer->allocated);
	buffer->channel_id = channel_id;
	((uint32_t *)buffer->storage)[0] = htobe32(channel_id);
	buffer->used = sizeof(channel_id);

	return (buffer);
}

void
pg_buffer_free(struct pg_buffer *buffer)
{

	free(buffer->storage);
	free(buffer);
}

void *
pg_buffer_advance(struct pg_buffer *buffer, size_t len)
{
	void *ret;

	if (buffer->allocated - buffer->used - len <= 0)
		pg_buffer_enqueue(buffer);

	ret = buffer->storage + buffer->used;
	buffer->used += len;

	return (ret);
}

size_t
pg_buffer_enqueue(struct pg_buffer *buffer)
{
	struct pg_buffer *buffer_copy;
	size_t used = buffer->used;

	buffer_copy = malloc(sizeof(*buffer_copy));
	*buffer_copy = *buffer;

	buffer->storage = malloc(MAX_FRAME_SIZE);
	pg_buffer_reset(buffer);

	pg_socket_enqueue_tx(buffer->peer->context, buffer_copy);
	return (used);
}

void
pg_buffer_reset(struct pg_buffer *buffer)
{

	((uint32_t *)buffer->storage)[0] = htobe32(buffer->channel_id);
	buffer->used = sizeof(buffer->channel_id);
}

void *
pg_buffer_ptr(struct pg_buffer *buffer)
{

	return (buffer->storage + buffer->used);
}

size_t
pg_buffer_size_left(struct pg_buffer *buffer)
{

	return (buffer->allocated - buffer->used);
}
