//
// Created by jakub on 10.12.2020.
//

#ifndef PEREGRINE_BITMAP_H
#define PEREGRINE_BITMAP_H

typedef void (*pg_bitmap_scan_func_t)(uint64_t start, uint64_t end, bool value,
    void *arg);

enum peregrine_bitmap_scan_mode
{
	BITMAP_SCAN_0
	BITMAP_SCAN_1
	BITMAP_SCAN_BOTH
};

struct peregrine_bitmap
{
	uint64_t size;
	uint8_t *data;
};

void pg_bitmap_create(uint64_t size, struct peregrine_bitmap **bmpp);
void pg_bitmap_free(struct peregrine_bitmap *bmp);
void pg_bitmap_set(struct peregrine_bitmap *bmp, uint64_t position);
bool pg_bitmap_get(struct peregrine_bitmap *bmp, uint64_t position);
void pg_bitmap_scan(struct peregrine_bitmap *bmp, enum peregrine_bitmap_scan_mode,
    pg_bitmap_scan_func_t fn, void *arg);

#endif //PEREGRINE_BITMAP_H
