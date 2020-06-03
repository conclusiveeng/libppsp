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


INTERNAL_LINKAGE void process_file(struct file_list_entry *file_entry, int chunk_size)
{
	char *buf;
	unsigned char digest[20 + 1];
	int fd, r;
	uint64_t x, nc, nl, c, rd;
	struct stat stat;
	SHA1Context context;
	struct node *ret, *root8;

	fd = open(file_entry->path, O_RDONLY);
	if (fd < 0) {
		printf("error opening file: %s\n", file_entry->path);
		exit(1);
	}
	fstat(fd, &stat);

	buf = malloc(chunk_size);

	nc = stat.st_size / chunk_size;
	if ((stat.st_size - stat.st_size / chunk_size * chunk_size) > 0)
		nc++;
	file_entry->nc = nc;
	d_printf("number of chunks [%u]: %lu\n", chunk_size, nc);

	/* compute number of leaves - it is not the same as number of chunks */
	nl = 1 << (order2(nc));
	file_entry->nl = nl;

	file_entry->start_chunk = 0;
	file_entry->end_chunk = nc - 1;

	/* allocate array of chunks which will be linked to leaves later*/
	file_entry->tab_chunk = malloc(nl * sizeof(struct chunk));
	memset(file_entry->tab_chunk, 0, nl * sizeof(struct chunk));

	/* initialize array of chunks */
	for (x = 0; x < nl; x++)
		file_entry->tab_chunk[x].state = CH_EMPTY;

	root8 = build_tree(nc, &ret);
	file_entry->tree_root = root8;
	file_entry->tree = ret;

	/* compute SHA hash for every chunk for given file */
	rd = 0;
	c = 0;
	while (rd < (uint64_t) stat.st_size) {
		r = read(fd, buf, chunk_size);

		SHA1Reset(&context);
		SHA1Input(&context, (uint8_t *)buf, r);
		SHA1Result(&context, digest);

		file_entry->tab_chunk[c].state = CH_ACTIVE;
		file_entry->tab_chunk[c].offset = c * chunk_size;
		file_entry->tab_chunk[c].len = r;
		memcpy(file_entry->tab_chunk[c].sha, digest, 20);
		memcpy(ret[2 * c].sha, digest, 20);
		ret[2 * c].state = ACTIVE;
		rd += r;
		c++;
	}
	close(fd);

	/* link array of chunks to leaves */
	for (x = 0; x < nl; x++) {
		ret[x * 2].chunk = &file_entry->tab_chunk[x];
		file_entry->tab_chunk[x].node = &ret[x * 2];
	}

	/* print the tree for given file */
	show_tree_root_based(&ret[root8->number]);

	/* print array tab_chunk */
	dump_chunk_tab(file_entry->tab_chunk, nl);

	/* update all the SHAs in the tree */
	update_sha(ret, nl);


	dump_tree(ret, nl);

	free(buf);
}


void ppspp_seeder_create (seeder_params_t *params)
{
	memset(&local_seeder, 0, sizeof(struct peer));

	local_seeder.chunk_size = params->chunk_size;
	local_seeder.timeout = params->timeout;
	local_seeder.port = params->port;
	local_seeder.type = SEEDER;
	
	SLIST_INIT(&file_list_head);
	// init other_seeders list
	SLIST_INIT(&other_seeders_list_head);
}


int ppspp_seeder_add_seeder(struct sockaddr_in *sa)
{
	struct other_seeders_entry *ss;
	int ret;

	// add mutex protection here

	ret = 0;

	ss = malloc(sizeof(struct other_seeders_entry));

	memcpy(&ss->sa, sa, sizeof(struct sockaddr_in));

	SLIST_INSERT_HEAD(&other_seeders_list_head, ss, next);

	return ret;
}


int ppspp_seeder_remove_seeder(struct sockaddr_in *sa)
{
	int ret;
	struct other_seeders_entry *e;

	ret = 0;
	// add mutex protection here
	SLIST_FOREACH(e, &other_seeders_list_head, next) {
		d_printf("%s:%u\n", inet_ntoa(e->sa.sin_addr), ntohs(e->sa.sin_port));
		if (memcmp(&sa->sin_addr, &e->sa.sin_addr, sizeof(e->sa.sin_addr)) == 0) {
			d_printf("entry to remove found - removing: %s:%u\n", inet_ntoa(e->sa.sin_addr), ntohs(e->sa.sin_port));
			SLIST_REMOVE(&other_seeders_list_head, e, other_seeders_entry, next);
		}
	}

	return ret;
}


void ppspp_seeder_list_seeders(void)
{
	struct other_seeders_entry *e;

	SLIST_FOREACH(e, &other_seeders_list_head, next) {
		printf("%s:%u\n", inet_ntoa(e->sa.sin_addr), ntohs(e->sa.sin_port));
	}
}


void ppspp_seeder_add_file_or_directory(char *name)
{
	char sha[40 + 1];
	int st, s, y;
	struct stat stat;
	struct file_list_entry *f;

	// add mutex protection here

	st = lstat(name, &stat);
	if (st != 0) {
		printf("Error: %s\n", strerror(errno));
	}

	/* is "name" directory name or filename? */
	if (stat.st_mode & S_IFDIR) {			/* directory */
		d_printf("adding files from directory: %s\n", name);
		create_file_list(name);
	} else if (stat.st_mode & S_IFREG) {		/* filename */
		d_printf("adding file: %s\n", name);
		f = malloc(sizeof(struct file_list_entry));
		SLIST_INSERT_HEAD(&file_list_head, f, next);
		memset(f->path, 0, sizeof(f->path));
		strcpy(f->path, name);
		lstat(f->path, &stat);
		f->file_size = stat.st_size;
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



INTERNAL_LINKAGE void remove_and_free(struct file_list_entry *f)
{
	free(f->tab_chunk);
	free(f->tree);
	f->tab_chunk = NULL;
	f->tree = f->tree_root = NULL;

	SLIST_REMOVE(&file_list_head, f, file_list_entry, next);
	free(f);
}


int ppspp_seeder_remove_file_or_directory(char *name)
{
	char *c, *buf;
	int ret;
	struct file_list_entry *f;
	struct stat stat;

	// add mutex protection here
	// add reference counter here
	
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


void ppspp_seeder_run(void)
{
	proto_test(&local_seeder);
}


void ppspp_seeder_close(void)
{
}


void ppspp_leecher_create(leecher_params_t *params)
{
	memset(&local_leecher, 0, sizeof(struct peer));

	local_leecher.sbs_mode = 1;
	local_leecher.timeout = params->timeout;
	local_leecher.type = LEECHER;
	local_leecher.current_seeder = NULL;
	memcpy(&local_leecher.seeder_addr, &params->seeder_addr, sizeof(struct sockaddr_in));
	//printf("create leecher: %s:%u\n", inet_ntoa(local_leecher.seeder_addr.sin_addr), ntohs(local_leecher.seeder_addr.sin_port));
	memcpy(&local_leecher.sha_demanded, params->sha_demanded, 20);

	
}


void ppspp_leecher_run(void)
{
	net_leecher_sbs(&local_leecher);
}


// this proc is optional because ppspp_leecher_create() also sets sha_demanded
void ppspp_leecher_set_sha(leecher_params_t *params)
{
	memcpy(&local_leecher.sha_demanded, params->sha_demanded, 20);
}


int ppspp_leecher_get_metadata(metadata_t *meta)
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


// ta proc zostala zastapiona przez ppspp_leecher_fetch_chunk_to_fd()
/*
void ppspp_set_fd_transfer_method(int fd)
{
	local_leecher.fd = fd;
	local_leecher.transfer_method = M_FD;
}
*/

// ta proc zostala zastapiona przez ppspp_leecher_fetch_chunk_to_buf()
/*
void ppspp_set_buf_transfer_method(void)
{
	// tu pobrac od usera adrs bufora do komunkacji, jego wielkosc, i ilosc chunkow, albo raczej index w tab schedule_download
//	local_leecher.fd = fd;
	local_leecher.transfer_method = M_BUF;
}
*/


uint32_t ppspp_prepare_chunk_range(uint32_t start_chunk, uint32_t end_chunk)
{
	uint32_t buf_size;
	// tu utworzyc download_schedule dla podanego przez usera zakresu chunkow

	/* if download_schedule previously allocated - free it now */
	if (local_leecher.download_schedule != NULL) {
		free(local_leecher.download_schedule);
		local_leecher.download_schedule = NULL;
	}

	local_leecher.download_schedule = malloc(local_leecher.nl * sizeof(struct schedule_entry));
	memset(local_leecher.download_schedule, 0, local_leecher.nl * sizeof(struct schedule_entry));
	create_download_schedule_sbs(&local_leecher, start_chunk, end_chunk);

	buf_size = (end_chunk - start_chunk + 1) * local_leecher.chunk_size;

	// tu zwrocic wielkosc bufora w bajtach ktora musi sobie user zaallokowac
	return buf_size;
}



void ppspp_leecher_fetch_chunk_to_fd(int fd)
{
	local_leecher.cmd = CMD_FETCH;
	local_leecher.fd = fd;
	local_leecher.transfer_method = M_FD;
	
	// tu trzebaby poczekac az maszyna stanow zglosi sie w stanie connected
	// wyslij komende do wszysktich peer-ow poprzez strukture local_peer
	net_leecher_fetch_chunk(&local_leecher);
}



void ppspp_leecher_fetch_chunk_to_buf(uint8_t *transfer_buf)
{
	local_leecher.cmd = CMD_FETCH;
	local_leecher.transfer_buf = transfer_buf;
	local_leecher.transfer_method = M_BUF;
	
	// tu trzebaby poczekac az maszyna stanow zglosi sie w stanie connected
	// wyslij komende do wszysktich peer-ow poprzez strukture local_peer
	net_leecher_fetch_chunk(&local_leecher);
}






void ppspp_leecher_close(void)
{
	local_leecher.cmd = CMD_FINISH;
	net_leecher_close(&local_leecher);
}

