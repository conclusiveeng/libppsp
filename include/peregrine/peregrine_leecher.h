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

#ifndef _PEREGRINE_LEECHER_H_
#define _PEREGRINE_LEECHER_H_

#include <netinet/in.h>
#include <stdint.h>

typedef int64_t peregrine_handle_t;
typedef struct {
  uint32_t timeout;               /**< Timeout for network communication */
  uint8_t sha_demanded[20];       /**< SHA1 of demanded file */
  struct sockaddr_in seeder_addr; /**< Primary seeder IP/PORT address from
                                     leecher point of view */
} peregrine_leecher_params_t;
typedef struct {
  char file_name[256];  /**< File name for demanded SHA1 hash */
  uint64_t file_size;   /**< Size of the file */
  uint32_t chunk_size;  /**< Size of the chunk */
  uint32_t start_chunk; /**< Number of first chunk in file */
  uint32_t end_chunk;   /**< Number of last chunk in file */
} peregrine_metadata_t;

peregrine_handle_t peregrine_leecher_create(peregrine_leecher_params_t *params);
int peregrine_leecher_get_metadata(peregrine_handle_t handle, peregrine_metadata_t *meta);
uint32_t peregrine_prepare_chunk_range(peregrine_handle_t handle, uint32_t start_chunk, uint32_t end_chunk);
void peregrine_leecher_fetch_chunk_to_fd(peregrine_handle_t handle, int fd);
int32_t peregrine_leecher_fetch_chunk_to_buf(peregrine_handle_t handle, uint8_t *transfer_buf);
void peregrine_leecher_close(peregrine_handle_t handle);
void peregrine_leecher_run(peregrine_handle_t handle);
void peregrine_leecher_print_stats(peregrine_handle_t handle);
#endif
