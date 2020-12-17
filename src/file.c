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
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <peregrine/peregrine.h>
#include "sha1.h"
#include "internal.h"
#include "log.h"

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
	uint32_t chunk_size;

	chunk_size = file->chunk_size;
	fd = open(file->path, O_RDONLY);
	if (fd < 0) {
		ERROR("error opening file %s: %s", file->path, strerror(errno));
		return (-1);
	}
	fstat(fd, &stat);

	buf = malloc(chunk_size);

	number_chunks = stat.st_size / chunk_size;
	if ((stat.st_size - stat.st_size / chunk_size * chunk_size) > 0) {
		number_chunks++;
	}
	file->nc = number_chunks;
	//   PEREGRINE_DEBUG("number of chunks [%u]: %lu", chunk_size, number_chunks);

	ret = pg_tree_create(number_chunks);
	/* compute number of leaves - it is not the same as number of chunks */
	nl = pg_tree_get_leaves_count(ret);
	//   PEREGRINE_DEBUG("number of leaves %lu", nl);
	file->nl = nl;

	/* allocate array of chunks which will be linked to leaves later */
	file->tab_chunk = malloc(nl * sizeof(struct chunk));
	memset(file->tab_chunk, 0, nl * sizeof(struct chunk));

	/* initialize array of chunks */
	for (x = 0; x < nl; x++)
		file->tab_chunk[x].state = CH_EMPTY;

	file->tree_root = pg_tree_get_root(ret);
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

	/* update all the SHAs in the tree */
	pg_tree_update_sha(ret);

	free(buf);

	return 0;
}

void
pg_file_generate_sha1(struct pg_context *context)
{
	struct pg_file *f;

	SLIST_FOREACH(f, &context->files, entry)
	{
		/* does the tree already exist for given file? */
		if (f->tree_root == NULL && f->file_size > 0) { /* no - so create tree for it */
			peregrine_file_process_file(f);
			memcpy(f->sha, f->tree_root->sha, sizeof(f->sha));
			strcpy(f->hash, pg_hexdump(f->sha, sizeof(f->sha)));
		}

		pg_swarm_create(context, f);
	}
}

struct pg_file *
pg_file_add_file(struct pg_context *context, const uint8_t *sha1, const char *path)
{
	struct pg_file *file;
	struct stat stat;
	int oflag = 0;
	int fd;

	if (sha1 != NULL) {
		/* Leecher mode */
		oflag = O_WRONLY | O_CREAT | O_TRUNC;
	} else {
		/* Seeder mode */
		oflag = O_RDONLY;
	}

	if (sha1 != NULL && path == NULL) {
		/* Create path from SHA1 */
		path = strdup(pg_hexdump(sha1, 20));
	}

	fd = open(path, oflag, 0660);
	if (fd < 0) {
		WARN("cannot open or create %s: %s", path, strerror(errno));
		return (NULL);
	}

	if (fstat(fd, &stat) != 0) {
		WARN("cannot fstat on fd %d: %s", fd, strerror(errno));
		return (NULL);
	}

	file = calloc(1, sizeof(*file));
	file->fd = fd;
	file->path = strdup(path);
	file->file_size = stat.st_size;
	file->chunk_size = 1024;
	file->nc = 1; /* We assume the file has at least one chunk */
	SLIST_INSERT_HEAD(&context->files, file, entry);

	if (sha1 != NULL)
		memcpy(file->sha, sha1, sizeof(file->sha));

	return (file);
}

int
pg_file_add_directory(struct pg_context *context, const char *dname,
    pg_file_dir_add_func_t fn)
{
	DIR *dir;
	char newdir[BUFSIZ];
	char path[BUFSIZ];
	struct pg_file *new_file;

	dir = opendir(dname);
	if (dir == NULL)
		return (-1);

	for (;;) {
		struct dirent *dirent = readdir(dir);
		if (dirent == NULL)
			break;

		if (dirent->d_type == DT_REG) {
			sprintf(path, "%s/%s", dname, dirent->d_name);
			new_file = pg_file_add_file(context, NULL, path);
			if (fn != NULL)
				fn(new_file, dname);
		}

		if ((dirent->d_type == DT_DIR) && (strcmp(dirent->d_name, ".") != 0)
		    && (strcmp(dirent->d_name, "..") != 0)) {
			snprintf(newdir, sizeof(newdir) - 1, "%s/%s", dname, dirent->d_name);
			pg_file_add_directory(context, newdir, NULL);
		}
	}

	closedir(dir);
	return (0);
}

int
pg_file_read_chunks(struct pg_file *file, uint64_t chunk, uint64_t count, void *buf)
{
	ssize_t total = file->chunk_size * count;

	return (pread(file->fd, buf, total, file->chunk_size * chunk));
}

int
pg_file_write_chunks(struct pg_file *file, uint64_t chunk, uint64_t count, void *buf)
{
	ssize_t ret;
	ssize_t total = file->chunk_size * count;

	ret = pwrite(file->fd, buf, total, file->chunk_size * chunk);
	if (ret != total)
		return (-1);

	return (0);
}

void
pg_file_list_sha1(struct pg_context *context)
{
	struct pg_file *f;

	SLIST_FOREACH(f, &context->files, entry) {
		INFO("file: %s, NC:%d, SHA1: %s", f->path, f->nc, f->hash);
	}
}

const char *
pg_file_get_path(struct pg_file *file)
{

	return (file->path);
}

const uint8_t *
pg_file_get_sha(struct pg_file *file)
{

	return (file->sha);
}

struct pg_file *
pg_file_by_sha(struct pg_context *ctx, const uint8_t *sha)
{
	struct pg_file *file;

	SLIST_FOREACH(file, &ctx->files, entry) {
		if (memcmp(file->sha, sha, sizeof(file->sha)) == 0)
			return (file);
	}

	return (NULL);
}

