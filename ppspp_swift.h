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

#ifndef _PPSPP_SWIFT_H_
#define _PPSPP_SWIFT_H_

/**
 * @file ppspp.h
 */

#if 0

typedef struct {
	uint32_t chunk_size;		/**< Size of the chunk for seeded files */
	uint32_t timeout;		/**< Timeout for network communication */
	uint16_t port;			/**< UDP port number to bind to */
} ppspp_seeder_params_t;

typedef struct {
	uint32_t timeout;		/**< Timeout for network communication */
	uint8_t sha_demanded[20];	/**< SHA1 of demanded file */
	struct sockaddr_in seeder_addr;	/**< Primary seeder IP/PORT address from leecher point of view */
} ppspp_leecher_params_t;

/* metadata of the file published for user of library */
typedef struct {
	char file_name[256];		/**< File name for demanded SHA1 hash */
	uint64_t file_size;		/**< Size of the file */
	uint32_t chunk_size;		/**< Size of the chunk */
	uint32_t start_chunk;		/**< Number of first chunk in file */
	uint32_t end_chunk;		/**< Number of last chunk in file */
} ppspp_metadata_t;

typedef int64_t ppspp_handle_t;	/**< seeder or leecher handle */

#endif

ppspp_handle_t swift_seeder_create(ppspp_seeder_params_t *);
int swift_seeder_add_seeder(ppspp_handle_t, struct sockaddr_in *);
int swift_seeder_remove_seeder(ppspp_handle_t, struct sockaddr_in *);
void swift_seeder_add_file_or_directory(ppspp_handle_t, char *);
int swift_seeder_remove_file_or_directory(ppspp_handle_t, char *);
void swift_seeder_run(ppspp_handle_t);
void swift_seeder_close(ppspp_handle_t);
ppspp_handle_t swift_leecher_create(ppspp_leecher_params_t *);
int swift_leecher_get_metadata(ppspp_handle_t, ppspp_metadata_t *);
uint32_t swift_prepare_chunk_range(ppspp_handle_t, uint32_t, uint32_t);
void swift_leecher_fetch_chunk_to_fd(ppspp_handle_t, int);
int32_t swift_leecher_fetch_chunk_to_buf(ppspp_handle_t, uint8_t *);
void swift_leecher_close(ppspp_handle_t);
void swift_leecher_run(ppspp_handle_t);

#endif /* _PPSPP_SWIFT_H_ */
