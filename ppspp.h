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

#ifndef _PPSPP_H_
#define _PPSPP_H_

typedef struct {
	uint32_t chunk_size;
	uint32_t timeout;
	uint16_t port;					/* seeder: udp port number to bind to */
} ppspp_seeder_params_t;

typedef struct {
	uint32_t timeout;
	uint8_t sha_demanded[20];
	struct sockaddr_in seeder_addr;			/* primary seeder IP/PORT address from leecher point of view */
} ppspp_leecher_params_t;

/* metadata of the file published for user of library */
typedef struct {
	char file_name[256];
	uint64_t file_size;
	uint32_t chunk_size;
	uint32_t start_chunk;
	uint32_t end_chunk;
} ppspp_metadata_t;

void process_file(struct file_list_entry *, int);
void ppspp_seeder_create(ppspp_seeder_params_t *);
int ppspp_seeder_add_seeder(struct sockaddr_in *);
int ppspp_seeder_remove_seeder(struct sockaddr_in *);
void ppspp_seeder_list_seeders(void);
void ppspp_seeder_add_file_or_directory(char *);
int ppspp_seeder_remove_file_or_directory(char *);
void ppspp_seeder_run(void);
void ppspp_seeder_close(void);
void ppspp_leecher_create(ppspp_leecher_params_t *);
int ppspp_leecher_get_metadata(ppspp_metadata_t *);
uint32_t ppspp_prepare_chunk_range(uint32_t, uint32_t);
void ppspp_leecher_fetch_chunk_to_fd(int);
int32_t ppspp_leecher_fetch_chunk_to_buf(uint8_t *);
void ppspp_leecher_close(void);
void ppspp_leecher_run(void);
#endif /* _PPSPP_H_ */
