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

#ifndef _PROTO_HELPER_H_
#define _PROTO_HELPER_H_

#include "peregrine_socket.h"
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>

/**
 * @brief Prepare HAVE message (seeder) that informs about what chunks we have
 *
 * @param peer peer handle
 * @param response_buffer output buffer to store the message
 * @return size_t amount of data stored in the buffer
 */
size_t prepare_have_msg(struct pg_peer *peer, char *response_buffer);

size_t pack_handshake(void *dptr, uint32_t src_channel_id, uint8_t *options, size_t optlen);
size_t pack_have(void *dptr, uint32_t start_chunk, uint32_t end_chunk);
size_t pack_data(void *dptr, uint32_t start_chunk, uint32_t end_chunk, uint64_t timestamp);
size_t pack_ack(void *dptr, uint32_t start_chunk, uint32_t end_chunk, uint64_t sample);
size_t pack_integrity(void *dptr, uint32_t end_chunk, uint8_t *hash);
size_t pack_signed_integrity(void *dptr, uint32_t start_chunk, uint32_t end_chunk, int64_t timestamp,
                             uint8_t *signature, size_t siglen);
size_t pack_request(void *dptr, uint32_t start_chunk, uint32_t end_chunk);
size_t pack_cancel(void *dptr, uint32_t start_chunk, uint32_t end_chunk);
size_t pack_dest_chan(void *dptr, uint32_t dst_channel_id);
size_t pack_pex_resv4(void *dptr, in_addr_t ip_address, uint16_t port);
size_t pack_pex_req(void *dptr);

#endif /* _PPSPP_PROTOCOL_H_ */
