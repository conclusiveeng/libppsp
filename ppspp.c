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

#include <stdio.h>
#include <sys/queue.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include "mt.h"
#include "net.h"
#include "ppspp_protocol.h"
#include "peer.h"
#include "sha1.h"
#include "debug.h"
#include "ppspp.h"


/**
 * @file ppspp.c
 */

struct slist_seeders other_seeders_list_head;
int debug;


/**
 * @brief Create instance of seeder
 *
 * @param[in] params Initial parameters for seeder
 *
 * @return Handle of just created seeder
 */
ppspp_handle_t
ppspp_seeder_create(ppspp_seeder_params_t *params) {
	ppspp_handle_t handle;
	struct peer *local_seeder;

	local_seeder = malloc(sizeof(struct peer));
	memset(local_seeder, 0, sizeof(struct peer));

	local_seeder->chunk_size = params->chunk_size;
	local_seeder->timeout = params->timeout;
	local_seeder->port = params->port;
	local_seeder->type = SEEDER;

	SLIST_INIT(&file_list_head);
	SLIST_INIT(&other_seeders_list_head);

	handle = (uint64_t) local_seeder;
	return handle;
}


/**
 * @brief Add new seeder to list of alternative seeders
 *
 * @param[in] handle Handle of seeder
 * @param[in] sa Structure with IP address and UDP port number of added seeder
 *
 * @return Return status of adding new seeder
 */
int
ppspp_seeder_add_seeder(ppspp_handle_t handle, struct sockaddr_in *sa)
{
	struct other_seeders_entry *ss;
	int ret;

	ret = 0;

	ss = malloc(sizeof(struct other_seeders_entry));
	memcpy(&ss->sa, sa, sizeof(struct sockaddr_in));

	SLIST_INSERT_HEAD(&other_seeders_list_head, ss, next);

	return ret;
}


/**
 * @brief Remove seeder from list of alternative seeders
 *
 * @param[in] handle Handle of seeder
 * @param[in] sa Structure with IP address and UDP port number of added seeder
 *
 * @return Return status of removing seeder
 */
int
ppspp_seeder_remove_seeder(ppspp_handle_t handle, struct sockaddr_in *sa)
{
	int ret;
	struct other_seeders_entry *e;

	ret = 0;
	SLIST_FOREACH(e, &other_seeders_list_head, next) {
		d_printf("%s:%u\n", inet_ntoa(e->sa.sin_addr), ntohs(e->sa.sin_port));
		if (memcmp(&sa->sin_addr, &e->sa.sin_addr, sizeof(e->sa.sin_addr)) == 0) {
			d_printf("entry to remove found - removing: %s:%u\n", inet_ntoa(e->sa.sin_addr), ntohs(e->sa.sin_port));
			SLIST_REMOVE(&other_seeders_list_head, e, other_seeders_entry, next);
		}
	}

	return ret;
}


/**
 * @brief Add file or directory to set of seeded files
 *
 * @param[in] handle Handle of seeder
 * @param[in] name Path to the file or directory
 */
void
ppspp_seeder_add_file_or_directory(ppspp_handle_t handle, char *name)
{
	char sha[40 + 1];
	int st, s, y;
	struct stat stat;
	struct file_list_entry *f;
	struct peer *local_seeder;

	local_seeder = (struct peer *)handle;

	st = lstat(name, &stat);
	if (st != 0) {
		d_printf("Error: %s\n", strerror(errno));
	}

	/* is "name" directory name or filename? */
	if (stat.st_mode & S_IFDIR) {			/* directory */
		d_printf("adding files from directory: %s\n", name);
		create_file_list(name);
	} else if (stat.st_mode & S_IFREG) {		/* filename */
		d_printf("adding file: %s\n", name);
		f = malloc(sizeof(struct file_list_entry));
		memset(f->path, 0, sizeof(f->path));
		strcpy(f->path, name);
		lstat(f->path, &stat);
		f->file_size = stat.st_size;
		SLIST_INSERT_HEAD(&file_list_head, f, next);
	}

	SLIST_FOREACH(f, &file_list_head, next) {
		/* does the tree already exist for given file? */
		if (f->tree_root == NULL) {		/* no - so create tree for it */
			printf("processing: %s  ", f->path);
			fflush(stdout);
			process_file(f, local_seeder->chunk_size);

			memset(sha, 0, sizeof(sha));
			s = 0;
			for (y = 0; y < 20; y++)
				s += sprintf(sha + s, "%02x", f->tree_root->sha[y] & 0xff);
			printf("sha1: %s\n", sha);
		}
	}
}


/*
 * @brief Remove given file entry from seeded file list
 *
 * @param[in] f File entry to remove
 */
INTERNAL_LINKAGE void
remove_and_free(struct file_list_entry *f)
{
	free(f->tab_chunk);
	free(f->tree);
	f->tab_chunk = NULL;
	f->tree = f->tree_root = NULL;

	SLIST_REMOVE(&file_list_head, f, file_list_entry, next);
	free(f);
}


/**
 * @brief Remove file or directory from seeded file list
 *
 * @param[in] handle Handle of seeder
 * @param[in] name Path to the file or directory
 *
 * @return Return status of removing file or directory
 */
int
ppspp_seeder_remove_file_or_directory(ppspp_handle_t handle, char *name)
{
	char *c, *buf;
	int ret;
	struct file_list_entry *f;
	struct stat stat;

	ret = 0;
	lstat(name, &stat);
	if (stat.st_mode & S_IFREG) {	/* does the user want to remove file? */
		SLIST_FOREACH(f, &file_list_head, next) {
			if (strcmp(f->path, name) == 0) {
				d_printf("file to remove found: %s\n", name);
				remove_and_free(f);
			}
		}
	} else if (stat.st_mode & S_IFDIR) {	/* does the user want to remove files from specific directory? */
		buf = malloc(strlen(name) + 2);
		memset(buf, 0, strlen(name) + 2);
		strcpy(buf, name);

		/* "name" is directory name and must be ended with slash here - check it */
		if (buf[strlen(buf) - 1] != '/') {
			buf[strlen(buf)] = '/';
			d_printf("adding / to dir name: %s => %s\n", name, buf);
		}

		SLIST_FOREACH(f, &file_list_head, next) {
			c = strstr(f->path, buf);	/* compare current file entry with directory name to remove */
			if (c == f->path) {		/* if both matches */
				d_printf("removing file: %s\n", f->path);
				remove_and_free(f);
			}
		}
		free(buf);
	}

	return ret;
}


/**
 * @brief Run seeder pointed by handle parameter
 *
 * @param[in] handle Handle of seeder
 */
void
ppspp_seeder_run(ppspp_handle_t handle)
{
	struct peer *local_seeder;

	local_seeder = (struct peer *)handle;
	net_seeder(local_seeder);
}


/**
 * @brief Close of opened seeder handle
 *
 * @param[in] handle Handle of seeder
 */
void
ppspp_seeder_close(ppspp_handle_t handle)
{
	struct peer *local_seeder;

	local_seeder = (struct peer *)handle;

	free(local_seeder);
}


/**
 * @brief Create instance of leecher
 *
 * @param[in] params Initial parameters for leecher
 *
 * @return Handle of just created leecher
 */
ppspp_handle_t
ppspp_leecher_create(ppspp_leecher_params_t *params)
{
	ppspp_handle_t handle;
	struct peer *local_leecher;

	local_leecher = malloc(sizeof(struct peer));
	memset(local_leecher, 0, sizeof(struct peer));

	local_leecher->sbs_mode = 1;
	local_leecher->timeout = params->timeout;
	local_leecher->type = LEECHER;
	local_leecher->current_seeder = NULL;
	memcpy(&local_leecher->seeder_addr, &params->seeder_addr, sizeof(struct sockaddr_in));
	memcpy(&local_leecher->sha_demanded, params->sha_demanded, 20);

	net_leecher_create();

	handle = (uint64_t) local_leecher;

	return handle;
}


/**
 * @brief Run leecher pointed by handle parameter
 *
 * @param[in] handle Handle of leecher
 */
void
ppspp_leecher_run(ppspp_handle_t handle)
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
ppspp_leecher_get_metadata(ppspp_handle_t handle, ppspp_metadata_t *meta)
{
	int ret;
	struct peer *local_leecher;

	local_leecher = (struct peer *)handle;

	/* ask seeder if he has got a file for our sha stored in local_leecher->sha_demanded[] */
	preliminary_connection_sbs(local_leecher);

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
	} else
		ret = -1;	/* file does not exist for demanded SHA on seeder */

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
 * ppspp_leecher_fetch_chunk_to_buf() procedure if he/she choosen
 * transferring buffer method instead of transferring vie file descriptor
 */
uint32_t
ppspp_prepare_chunk_range(ppspp_handle_t handle, uint32_t start_chunk, uint32_t end_chunk)
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
ppspp_leecher_fetch_chunk_to_fd(ppspp_handle_t handle, int fd)
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
ppspp_leecher_fetch_chunk_to_buf(ppspp_handle_t handle, uint8_t *transfer_buf)
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
ppspp_leecher_close(ppspp_handle_t handle)
{
	struct peer *local_leecher;

	local_leecher = (struct peer *)handle;
	local_leecher->cmd = CMD_FINISH;
	net_leecher_close(local_leecher);
}
