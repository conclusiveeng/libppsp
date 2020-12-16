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
#include <string.h>
#include "internal.h"

struct pg_bitmap *
pg_bitmap_create(uint64_t size)
{
	struct pg_bitmap *bmp;
	uint64_t data_size;

	data_size = size % 8 ? (size / 8) + 1 : size / 8;

	bmp = calloc(1, sizeof(*bmp));
	bmp->size = size;
	bmp->data = calloc(1, data_size);

	return (bmp);
}

void
pg_bitmap_resize(struct pg_bitmap *bmp, uint64_t new_size)
{
	uint64_t new_data_size = new_size % 8 ? (new_size / 8) + 1 : new_size / 8;

	bmp->size = new_size;
	bmp->data = realloc(bmp->data, new_data_size);
}

void
pg_bitmap_free(struct pg_bitmap *bmp)
{

	free(bmp->data);
	free(bmp);
}

void
pg_bitmap_set(struct pg_bitmap *bmp, uint64_t position)
{

	bmp->data[position / 8] |= (1 << (position % 8));
}

void
pg_bitmap_set_range(struct pg_bitmap *bmp, uint64_t start, uint64_t end, bool value)
{
	uint64_t i;

	for (i = start; i <= end; i++) {
		if (value)
			pg_bitmap_set(bmp, i);
		else
			pg_bitmap_clear(bmp, i);
	}
}

void
pg_bitmap_clear(struct pg_bitmap *bmp, uint64_t position)
{

	bmp->data[position / 8] &= ~(1 << (position %8));
}

void
pg_bitmap_fill(struct pg_bitmap *bmp, bool value)
{
	(void)value;

	uint64_t data_size = bmp->size % 8 ? (bmp->size / 8) + 1 : bmp->size / 8;
	memset(bmp->data, 0xff, data_size);
}

bool
pg_bitmap_get(struct pg_bitmap *bmp, uint64_t position)
{

	return (bmp->data[position / 8] & (1 << (position % 8)));
}

void
pg_bitmap_scan(struct pg_bitmap *bmp, enum pg_bitmap_scan_mode mode,
    pg_bitmap_scan_func_t fn, void *arg)
{
	uint64_t start = 0;
	bool old_val;
	bool new_val = pg_bitmap_get(bmp, start);

	for (uint64_t i = 0; i < bmp->size; i++) {
		old_val = new_val;
		new_val = pg_bitmap_get(bmp, i);
		if (new_val == old_val)
			continue;

		switch (mode) {
		case BITMAP_SCAN_0:
			if (old_val) {
				start = i;
				continue;
			}
			break;
		case BITMAP_SCAN_1:
			if (!old_val) {
				start = i;
				continue;
			}
			break;
		case BITMAP_SCAN_BOTH:
		default:
			break;
		}

		if (!fn(start, i - 1, old_val, arg))
			return;

		if (mode == BITMAP_SCAN_BOTH)
			start = i;
	}

	switch (mode) {
	case BITMAP_SCAN_0:
		if (!old_val)
			fn(start, bmp->size - 1, old_val, arg);
		break;
	case BITMAP_SCAN_1:
		if (old_val)
			fn(start, bmp->size - 1, old_val, arg);
		break;
	case BITMAP_SCAN_BOTH:
	default:
		fn(start, bmp->size - 1, old_val, arg);
		break;
	}
}