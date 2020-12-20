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
#include <inttypes.h>
#include "internal.h"
#include "log.h"

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
pg_bitmap_grow(struct pg_bitmap *bmp, uint64_t new_size)
{
	uint64_t new_data_size = new_size % 8 ? (new_size / 8) + 1 : new_size / 8;
	uint64_t old_data_size = bmp->size % 8 ? (bmp->size / 8) + 1 : bmp->size / 8;

	/* Bitmap cannot shrink */
	if (new_size < bmp->size)
		return;

	bmp->size = new_size;
	bmp->data = realloc(bmp->data, new_data_size);
	memset(bmp->data + old_data_size, 0, new_data_size - old_data_size);
}

void
pg_bitmap_free(struct pg_bitmap *bmp)
{

	free(bmp->data);
	free(bmp);
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
	uint64_t data_size = bmp->size % 8 ? (bmp->size / 8) + 1 : bmp->size / 8;
	memset(bmp->data, value ? 0xff : 0x00, data_size);
}

bool
pg_bitmap_is_filled(struct pg_bitmap *bmp, bool value)
{
	uint64_t data_size = bmp->size % 8 ? (bmp->size / 8) + 1 : bmp->size / 8;

	if (data_size > 2) {
		if ((value && (bmp->data[0] != 0xff)) || (!value && (bmp->data[0] != 0x00)))
			return (false);

		if (memcmp(bmp->data, bmp->data + 1, data_size - 2) != 0)
			return (false);
	}

	for (uint64_t i = ((data_size - 1) * 8); i < bmp->size; i++) {
		if (pg_bitmap_get(bmp, i) != value)
			return (false);
	}
	return (true);
}



bool
pg_bitmap_scan(struct pg_bitmap *bmp, enum pg_bitmap_scan_mode mode,
    pg_bitmap_scan_func_t fn, void *arg)
{

	return(pg_bitmap_scan_range_limit(bmp, 0, bmp->size - 1, 0, mode, fn, arg));
}

bool
pg_bitmap_find_first_fn(uint64_t start, uint64_t end, bool __unused value, void *arg)
{
	struct pg_bitmap_scan_result *res = arg;

	res->start = start;
	res->count = end - start + 1;

	return (false);
}

void
pg_bitmap_find_first(struct pg_bitmap *bmp, size_t limit,
    enum pg_bitmap_scan_mode mode, uint64_t *start, uint64_t *count)
{
	struct pg_bitmap_scan_result res;

	res.count = 0;
	res.start = 0;

	pg_bitmap_scan_range_limit(bmp, 0, bmp->size - 1, limit, mode,
	    pg_bitmap_find_first_fn, &res);

	*start = res.start;
	*count = res.count;
}

bool
pg_bitmap_scan_range_limit(struct pg_bitmap *bmp, size_t start, size_t end,
    size_t limit, enum pg_bitmap_scan_mode mode, pg_bitmap_scan_func_t fn,
    void *arg)
{
	size_t range_start = start;
	size_t range_size = 0;
	bool old_val;
	bool new_val = pg_bitmap_get(bmp, range_start);
	bool cb_called = false;

	for (uint64_t i = range_start; i <= end; i++) {
		if (i % 64 == 0 && i + 64 < end) {
			uint64_t cmp_val;

			if (new_val)
				cmp_val = 0xffffffffffffffff;
			else
				cmp_val = 0x0000000000000000;

			if (((uint64_t *)bmp->data)[i / 64] == cmp_val) {
				i += 63;
				range_size += 64;
				continue;
			}
		}

		old_val = new_val;
		new_val = pg_bitmap_get(bmp, i);

		if (limit != 0) {
			bool call = false;
			if (range_size >= limit) {
				switch (mode) {
				case BITMAP_SCAN_0:
					if (!old_val) {
						range_size = 0;
						call = true;
					}
					break;
				case BITMAP_SCAN_1:
					if (old_val) {
						range_size = 0;
						call = true;
					}
					break;
				case BITMAP_SCAN_BOTH:
				default:
					range_size = 0;
					call = true;
					break;
				}
			}

			if (call) {
				cb_called = true;
				if (!fn(range_start, range_start + limit - 1, old_val, arg))
					return (cb_called);

				i = range_size + limit - 1;
				continue;
			}
		}

		if (new_val == old_val) {
			range_size++;
			continue;
		}

		switch (mode) {
		case BITMAP_SCAN_0:
			if (old_val) {
				range_start = i;
				range_size = 1;
				continue;
			}
			break;
		case BITMAP_SCAN_1:
			if (!old_val) {
				range_start = i;
				range_size = 1;
				continue;
			}
			break;
		case BITMAP_SCAN_BOTH:
		default:
			break;
		}

		cb_called = true;
		if (!fn(range_start, i - 1, old_val, arg))
			return (cb_called);

		if (mode == BITMAP_SCAN_BOTH) {
			range_start = i;
			range_size = 1;
		}
	}

	if (range_start == end && old_val == new_val)
		return (cb_called);

	switch (mode) {
	case BITMAP_SCAN_0:
		if (new_val)
			return (cb_called);
		break;
	case BITMAP_SCAN_1:
		if (!new_val)
			return (cb_called);
		break;
	case BITMAP_SCAN_BOTH:
	default:
		break;
	}

	fn(range_start, end, new_val, arg);
	return (true);
}

static bool
pg_bitmap_dump_scan_fn(uint64_t start, uint64_t end, bool value, void *arg)
{
	DEBUG("%p: %" PRIu64 "-%" PRIu64, arg, start, end);
	return (true);
}

void
pg_bitmap_dump(struct pg_bitmap *bmp)
{
	pg_bitmap_scan(bmp, BITMAP_SCAN_1, pg_bitmap_dump_scan_fn, bmp);
}
