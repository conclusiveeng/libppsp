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

#include "peregrine/file.h"
#include "peregrine/log.h"
#include "peregrine/mt.h"
#include "peregrine/peer_handler.h"
#include "peregrine/socket.h"
#include "peregrine/sha1.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "internal.h"

int
peregrine_file_process_file(struct pg_file *file)
{
	char *buf;
	unsigned char digest[20 + 1];
	int fd;
	uint64_t x;
	uint64_t number_chunks;
	uint64_t nl;
	uint64_t c;
	uint64_t rd;
	struct stat stat;
	SHA1Context context;
	struct node *ret;
	struct node *root8;
	uint32_t chunk_size;

	chunk_size = CHUNK_SIZE;
	fd = open(file->path, O_RDONLY);
	if (fd < 0) {
		ERROR("error opening file: %s", file->path);
		return -1;
	}
	fstat(fd, &stat);

	buf = malloc(chunk_size);

	number_chunks = stat.st_size / chunk_size;
	if ((stat.st_size - stat.st_size / chunk_size * chunk_size) > 0) {
		number_chunks++;
	}
	file->nc = number_chunks;
	//   PEREGRINE_DEBUG("number of chunks [%u]: %lu", chunk_size, number_chunks);

	/* compute number of leaves - it is not the same as number of chunks */
	nl = 1 << (mt_order2(number_chunks));
	//   PEREGRINE_DEBUG("number of leaves %lu", nl);
	file->nl = nl;

	file->start_chunk = 0;
	file->end_chunk = number_chunks - 1;

	/* allocate array of chunks which will be linked to leaves later */
	file->tab_chunk = malloc(nl * sizeof(struct chunk));
	memset(file->tab_chunk, 0, nl * sizeof(struct chunk));

	/* initialize array of chunks */
	for (x = 0; x < nl; x++) {
		file->tab_chunk[x].state = CH_EMPTY;
	}

	root8 = mt_build_tree(number_chunks, &ret);
	file->tree_root = root8;
	file->tree = ret;

	/* compute SHA hash for every chunk for given file */
	rd = 0;
	c = 0;
	while (rd < (uint64_t)stat.st_size) {
		int r = read(fd, buf, chunk_size);

		SHA1Reset(&context);
		SHA1Input(&context, (uint8_t *)buf, r);
		SHA1Result(&context, digest);

		file->tab_chunk[c].state = CH_ACTIVE;
		file->tab_chunk[c].offset = c * chunk_size;
		file->tab_chunk[c].len = r;
		memcpy(file->tab_chunk[c].sha, digest, 20);
		memcpy(ret[2 * c].sha, digest, 20);
		ret[2 * c].state = ACTIVE;
		rd += r;
		c++;
	}
	close(fd);

	/* link array of chunks to leaves */
	for (x = 0; x < nl; x++) {
		ret[x * 2].chunk = &file->tab_chunk[x];
		file->tab_chunk[x].node = &ret[x * 2];
	}

	// Only fot debug
	// mt_show_tree_root_based(&ret[root8->number]);

	// Only fot debug
	// mt_dump_chunk_tab(file->tab_chunk, nl);

	/* update all the SHAs in the tree */
	mt_update_sha(ret, nl);

	// Only fot debug
	// mt_dump_tree(ret, nl);

	free(buf);

	return 0;
}

void
pg_file_generate_sha1(struct pg_context *context)
{
	int s;
	int y;
	struct pg_file *f;

	SLIST_FOREACH(f, &context->files, entry)
	{
		/* does the tree already exist for given file? */
		if (f->tree_root == NULL) { /* no - so create tree for it */
			peregrine_file_process_file(f);

			char sha[40 + 1];
			memset(sha, 0, sizeof(sha));
			s = 0;
			for (y = 0; y < 20; y++) {
				s += sprintf(sha + s, "%02x", f->tree_root->sha[y] & 0xff);
			}
			memcpy(f->sha, sha, 41);
		}
	}
}

struct pg_file *
pg_file_add_file(struct pg_context *context, const char *name)
{
	struct stat stat;
	int st;

	st = lstat(name, &stat);
	if (st != 0) {
		ERROR("Error: %s", strerror(errno));
	}
	if (stat.st_mode & S_IFREG) { /* filename */
		struct pg_file *f = malloc(sizeof(struct pg_file));
		memset(f->path, 0, sizeof(f->path));
		strcpy(f->path, name);
		lstat(f->path, &stat);
		f->file_size = stat.st_size;
		SLIST_INSERT_HEAD(&context->files, f, entry);
		return (f);
	}

	return (NULL);
}

void
pg_file_add_directory(struct pg_context *context, const char *dname)
{
	DIR *dir;
	char newdir[BUFSIZ];
	char path[BUFSIZ];

	dir = opendir(dname);
	if (dir == NULL) {
		return;
	}

	while (1) {
		struct dirent *dirent = readdir(dir);
		if (dirent == NULL)
			break;

		if (dirent->d_type == DT_REG) {
			sprintf(path, "%s/%s", dname, dirent->d_name);
			pg_file_add_file(context, path);
		}

		if ((dirent->d_type == DT_DIR) && (strcmp(dirent->d_name, ".") != 0)
		    && (strcmp(dirent->d_name, "..") != 0)) {
			snprintf(newdir, sizeof(newdir) - 1, "%s/%s", dname, dirent->d_name);
			pg_file_add_directory(context, newdir);
		}
	}
	closedir(dir);
}

void
pg_file_list_sha1(struct pg_context *context)
{
	struct pg_file *f;
	SLIST_FOREACH(f, &context->files, entry) { INFO("File: %s, NC:%d, SHA1: %s", f->path, f->nc, f->sha); }
}
