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

#ifndef PEREGRINE_BITMAP_H
#define PEREGRINE_BITMAP_H

#include <inttypes.h>
#include <stdbool.h>

typedef bool (*pg_bitmap_scan_func_t)(uint64_t start, uint64_t end, bool value,
    void *arg);

enum pg_bitmap_scan_mode
{
	BITMAP_SCAN_0,
	BITMAP_SCAN_1,
	BITMAP_SCAN_BOTH
};

struct pg_bitmap
{
	uint64_t size;
	uint8_t *data;
};

void pg_bitmap_create(uint64_t size, struct pg_bitmap **bmpp);
void pg_bitmap_free(struct pg_bitmap *bmp);
void pg_bitmap_set(struct pg_bitmap *bmp, uint64_t position);
void pg_bitmap_clear(struct pg_bitmap *bmp, uint64_t position);
bool pg_bitmap_get(struct pg_bitmap *bmp, uint64_t position);
void pg_bitmap_scan(struct pg_bitmap *bmp, enum pg_bitmap_scan_mode mode,
    pg_bitmap_scan_func_t fn, void *arg);
#endif //PEREGRINE_BITMAP_H