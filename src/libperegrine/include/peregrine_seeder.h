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

#ifndef _PEREGRINE_SEEDER_H_
#define _PEREGRINE_SEEDER_H_

#include <netinet/in.h>
#include <stdint.h>

typedef int64_t peregrine_handle_t;
typedef struct {
  uint32_t chunk_size; /**< Size of the chunk for seeded files */
  uint32_t timeout;    /**< Timeout for network communication */
  uint16_t port;       /**< UDP port number to bind to */
} peregrine_seeder_params_t;

peregrine_handle_t peregrine_seeder_create(peregrine_seeder_params_t *params);
int peregrine_seeder_add_seeder(peregrine_handle_t handle, struct sockaddr_in *sa);
int peregrine_seeder_remove_seeder(peregrine_handle_t handle, struct sockaddr_in *sa);
void peregrine_seeder_add_file_or_directory(peregrine_handle_t handle, char *name);
int peregrine_seeder_remove_file_or_directory(peregrine_handle_t handle, char *name);
void peregrine_seeder_run(peregrine_handle_t handle);
void peregrine_seeder_close(peregrine_handle_t handle);

#endif
