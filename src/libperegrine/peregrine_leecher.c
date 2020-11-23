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

#include "peregrine_leecher.h"
#include "net.h"
#include "peer.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>

/**
 * @brief Create instance of leecher
 *
 * @param[in] params Initial parameters for leecher
 *
 * @return Handle of just created leecher
 */
peregrine_handle_t
peregrine_leecher_create(peregrine_leecher_params_t *params)
{
  peregrine_handle_t handle;
  struct peer *local_leecher;

  local_leecher = malloc(sizeof(struct peer));
  if (local_leecher != NULL) {
    memset(local_leecher, 0, sizeof(struct peer));

    local_leecher->sbs_mode = 1;
    local_leecher->timeout = params->timeout;
    local_leecher->type = LEECHER;
    local_leecher->current_seeder = NULL;
    local_leecher->tree = NULL;
    local_leecher->tree_root = NULL;
    memcpy(&local_leecher->seeder_addr, &params->seeder_addr, sizeof(struct sockaddr_in));
    memcpy(&local_leecher->sha_demanded, params->sha_demanded, 20);

    net_leecher_create(local_leecher);
  }
  handle = (int64_t)local_leecher;

  return handle;
}

/**
 * @brief Run leecher pointed by handle parameter
 *
 * @param[in] handle Handle of leecher
 */
void
peregrine_leecher_run(peregrine_handle_t handle)
{
  struct peer *local_leecher;

  local_leecher = (struct peer *)handle;
  net_leecher_sbs(local_leecher);
}

/**
 * @brief Get metadata for hash demanded by user
 * Hash of demanded file is given by user in "params" parameter passed to
 * "ppspp_leecher_create" procedure
 *
 * @param[in] handle Handle of leecher
 * @param[out] meta Pointer to structure where meta data will be returned
 *
 * @return Return status of fetching metadata
 * On success return 0
 * On error returns value below 0
 */
int
peregrine_leecher_get_metadata(peregrine_handle_t handle, peregrine_metadata_t *meta)
{
  int ret;
  struct peer *local_leecher;

  local_leecher = (struct peer *)handle;

  /* ask seeder if he has got a file for our sha stored in
   * local_leecher->sha_demanded[] */

  net_preliminary_connection_sbs(local_leecher);

  if (local_leecher->seeder_has_file == 1) {
    ret = 0;
    if (meta != NULL) {
      /* prepare returning data for user */
      strcpy(meta->file_name, local_leecher->fname);
      meta->file_size = local_leecher->file_size;
      meta->chunk_size = local_leecher->chunk_size;
      meta->start_chunk = local_leecher->start_chunk;
      meta->end_chunk = local_leecher->end_chunk;
    }
  } else {
    ret = -ENOENT; /* file does not exist for demanded SHA on seeder */
  }

  /* response is in local_leecher */
  return ret;
}

/**
 * @brief Prepare range of chunks for fetching in next fetch invocation
 *
 * @param[in] handle Handle of seeder
 * @param[in] start_chunk Number of first chunk to fetch
 * @param[in] end_chunk Number of last chunk to fetch
 *
 * @return Return size of buffer needed for fetching given chunk range
 * User should allocate that number of bytes for buffer and pass it to
 * peregrine_leecher_fetch_chunk_to_buf() procedure if he/she choosen
 * transferring buffer method instead of transferring vie file descriptor
 */
uint32_t
peregrine_prepare_chunk_range(peregrine_handle_t handle, uint32_t start_chunk, uint32_t end_chunk)
{
  uint32_t buf_size;
  struct peer *local_leecher;

  local_leecher = (struct peer *)handle;

  /* if download_schedule previously allocated - free it now */
  if (local_leecher->download_schedule != NULL) {
    free(local_leecher->download_schedule);
    local_leecher->download_schedule = NULL;
  }

  local_leecher->download_schedule = malloc(local_leecher->nl * sizeof(struct schedule_entry));
  memset(local_leecher->download_schedule, 0, local_leecher->nl * sizeof(struct schedule_entry));
  buf_size = create_download_schedule_sbs(local_leecher, start_chunk, end_chunk);
  local_leecher->download_schedule_idx = 0;

  return buf_size;
}

/**
 * @brief Fetch range of chunks to file descriptor
 *
 * @param[in] handle Handle of leecher
 * @param[in] fd File descriptor of opened by user file
 */
void
peregrine_leecher_fetch_chunk_to_fd(peregrine_handle_t handle, int fd)
{
  struct peer *local_leecher;

  local_leecher = (struct peer *)handle;

  local_leecher->cmd = CMD_FETCH;
  local_leecher->fd = fd;
  local_leecher->transfer_method = M_FD;

  net_leecher_fetch_chunk(local_leecher);
}

/**
 * @brief Fetch range of chunks to user buffer
 *
 * @param[in] handle Handle of leecher
 * @param[out] transfer_buf Pointer to user buffer for selected chunk range
 *
 * @return Return number of returned valid bytes in passed by user buffer
 */
int32_t
peregrine_leecher_fetch_chunk_to_buf(peregrine_handle_t handle, uint8_t *transfer_buf)
{
  struct peer *local_leecher;

  local_leecher = (struct peer *)handle;

  local_leecher->cmd = CMD_FETCH;
  local_leecher->transfer_buf = transfer_buf;
  local_leecher->transfer_method = M_BUF;
  local_leecher->tx_bytes = 0;

  net_leecher_fetch_chunk(local_leecher);

  return local_leecher->tx_bytes;
}

/**
 * @brief Close of opened leecher handle
 *
 * @param[in] handle Handle of leecher
 */
void
peregrine_leecher_close(peregrine_handle_t handle)
{
  struct peer *local_leecher;

  local_leecher = (struct peer *)handle;
  local_leecher->cmd = CMD_FINISH;
  net_leecher_close(local_leecher);
}
