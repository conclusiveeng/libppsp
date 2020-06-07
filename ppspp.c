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

struct slist_seeders other_seeders_list_head;

int debug;
struct peer local_seeder, local_leecher;


void
ppspp_seeder_create(ppspp_seeder_params_t *params)
{
	memset(&local_seeder, 0, sizeof(struct peer));

	local_seeder.chunk_size = params->chunk_size;
	local_seeder.timeout = params->timeout;
	local_seeder.port = params->port;
	local_seeder.type = SEEDER;

	SLIST_INIT(&file_list_head);
	SLIST_INIT(&other_seeders_list_head);
}


int
ppspp_seeder_add_seeder(struct sockaddr_in *sa)
{
	struct other_seeders_entry *ss;
	int ret;

	ret = 0;

	ss = malloc(sizeof(struct other_seeders_entry));

	memcpy(&ss->sa, sa, sizeof(struct sockaddr_in));

	SLIST_INSERT_HEAD(&other_seeders_list_head, ss, next);

	return ret;
}


int
ppspp_seeder_remove_seeder(struct sockaddr_in *sa)
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


void
ppspp_seeder_add_file_or_directory(char *name)
{
	char sha[40 + 1];
	int st, s, y;
	struct stat stat;
	struct file_list_entry *f;

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
			process_file(f, local_seeder.chunk_size);

			memset(sha, 0, sizeof(sha));
			s = 0;
			for (y = 0; y < 20; y++)
				s += sprintf(sha + s, "%02x", f->tree_root->sha[y] & 0xff);
			printf("sha1: %s\n", sha);
		}
	}
}


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


int
ppspp_seeder_remove_file_or_directory(char *name)
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


void
ppspp_seeder_run(void)
{
	net_seeder(&local_seeder);
}


void
ppspp_seeder_close(void)
{
}


void
ppspp_leecher_create(ppspp_leecher_params_t *params)
{
	memset(&local_leecher, 0, sizeof(struct peer));

	local_leecher.sbs_mode = 1;
	local_leecher.timeout = params->timeout;
	local_leecher.type = LEECHER;
	local_leecher.current_seeder = NULL;
	memcpy(&local_leecher.seeder_addr, &params->seeder_addr, sizeof(struct sockaddr_in));
	memcpy(&local_leecher.sha_demanded, params->sha_demanded, 20);

	net_leecher_create();
}


void
ppspp_leecher_run(void)
{
	net_leecher_sbs(&local_leecher);
}


int
ppspp_leecher_get_metadata(ppspp_metadata_t *meta)
{
	int ret;

	/* ask seeder if he has got a file for our sha stored in local_leecher->sha_demanded[] */
	preliminary_connection_sbs(&local_leecher);

	if (local_leecher.seeder_has_file == 1) {
		ret = 0;
		if (meta != NULL) {
			/* prepare returning data for user */
			strcpy(meta->file_name, local_leecher.fname);
			meta->file_size = local_leecher.file_size;
			meta->chunk_size = local_leecher.chunk_size;
			meta->start_chunk = local_leecher.start_chunk;
			meta->end_chunk = local_leecher.end_chunk;
		}
	} else
		ret = -1;	/* file does not exist for demanded SHA on seeder */

	/* response is in local_leecher */
	return ret;
}


uint32_t
ppspp_prepare_chunk_range(uint32_t start_chunk, uint32_t end_chunk)
{
	uint32_t buf_size;

	/* if download_schedule previously allocated - free it now */
	if (local_leecher.download_schedule != NULL) {
		free(local_leecher.download_schedule);
		local_leecher.download_schedule = NULL;
	}

	local_leecher.download_schedule = malloc(local_leecher.nl * sizeof(struct schedule_entry));
	memset(local_leecher.download_schedule, 0, local_leecher.nl * sizeof(struct schedule_entry));
	buf_size = create_download_schedule_sbs(&local_leecher, start_chunk, end_chunk);
	local_leecher.download_schedule_idx = 0;

	return buf_size;
}


void
ppspp_leecher_fetch_chunk_to_fd(int fd)
{
	local_leecher.cmd = CMD_FETCH;
	local_leecher.fd = fd;
	local_leecher.transfer_method = M_FD;

	net_leecher_fetch_chunk(&local_leecher);
}


int32_t
ppspp_leecher_fetch_chunk_to_buf(uint8_t *transfer_buf)
{
	local_leecher.cmd = CMD_FETCH;
	local_leecher.transfer_buf = transfer_buf;
	local_leecher.transfer_method = M_BUF;
	local_leecher.tx_bytes = 0;

	net_leecher_fetch_chunk(&local_leecher);

	return local_leecher.tx_bytes;
}


void
ppspp_leecher_close(void)
{
	local_leecher.cmd = CMD_FINISH;
	net_leecher_close(&local_leecher);
}
