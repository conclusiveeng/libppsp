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
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <libgen.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "mt.h"
#include "sha1.h"
#include "ppspp_protocol.h"
#include "net.h"
#include "peer.h"
#include "debug.h"

extern char *optarg;
extern int optind, opterr, optopt;
int debug;
struct node *tree, *root8, *root16, *root32;
struct chunk *tab_chunk;
struct peer local_peer;


void init_seeder(struct file_list_entry *file_entry, int chunk_size)
{
	char *buf;
	unsigned char digest[20 + 1];
	int fd, r;
	uint64_t x, nc, nl, c, rd;
	struct stat stat;
	SHA1Context context;
	struct node *ret;

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


void ascii_sha_to_bin (char *sha_ascii, uint8_t *bin)
{
	int y;
	uint8_t b;
	char buf[2 + 1];

	memset(buf, 0, sizeof(buf));
	d_printf("scanning SHA1: %s\n", sha_ascii);
	for (y = 0; y < 40; y += 2) {
		memcpy(buf, sha_ascii + y, 2);
		b = strtoul(buf, NULL, 16);
		bin[y / 2] = b & 0xff;
	}
}


int main (int argc, char *argv[])
{
	char *fname1, *fname, *fname2, usage, *peer_list, *colon, *comma, *last_char, *ch, *dir, *sa;
	char sha[40 + 1], *sha_demanded;
	char buf_ip_addr[24], buf_ip_port[64];
	int opt, chunk_size, type, sia, algo, s, y, port;
	uint32_t timeout;
	struct stat stat;
	struct file_list_entry *f, *fi;


	chunk_size = 1024;
	fname = fname1 = NULL;
	debug = 0;
	usage = 0;
	peer_list = NULL;
	algo = -1;
	dir = NULL;
	type = LEECHER;
	timeout = 3 * 60;	/* 3 minutes timeout as default */
	sha_demanded = NULL;
	port = 6778;
	sa = NULL;
	while ((opt = getopt(argc, argv, "a:c:d:f:g:hl:p:s:t:v")) != -1) {
		switch (opt) {
			case 'a':				/* remote address of seeder */
				//(void) inet_aton(optarg, &ia);
				sa = optarg;
				break;
			case 'c':				/* chunk size [bytes] */
				chunk_size = atoi(optarg);
				break;
			case 'd':				/* directory with files */
				dir = optarg;
				break;
			case 'f':				/* filename */
				fname1 = optarg;
				break;
			case 'g':				/* algorithm */
				algo = atoi(optarg);
				break;
			case 'h':				/* help/usage */
				usage = 1;
				break;
			case 'l':				/* peer IP list separated by ':' */
				peer_list = optarg;
				break;
			case 'p':				/* UDP port number of seeder */
				port = atoi(optarg);
				break;
			case 's':				/* demanded SHA of the file */
				sha_demanded = optarg;
				break;
			case 't':				/* timeout [seconds] */
				timeout = atoi(optarg);
				break;
			case 'v':				/* debug */
				debug = 1;
				break;
			default:
				usage = 1;
		}
	}

	if (usage || (argc == 1)) {
		printf("Peer-to-Peer Streaming Peer Protocol proof of concept\n");
		printf("usage:\n");
		printf("%s: -acdfghlpstv\n", argv[0]);
		printf("-a ip_address:	numeric IP address of the remote SEEDER, enables LEECHER mode\n");
		printf("		example: -a 192.168.1.1\n");
		printf("-c:		chunk size in bytes valid only on the SEEDER side, default: 1024 bytes\n");
		printf("		example: -c 1024\n");
		printf("-d directory:	name of directory with files for sharing, enables SEEDER mode\n");
		printf("		example: -d /tmp/directory\n");
		printf("-f filename:	filename of the file for sharing, enables SEEDER mode\n");
		printf("		example: -f ./filename\n");
		printf("-g algorithm:	algorithm number: 4 or 5, valid only on LEECHER side\n");
		printf("-h:		this help\n");
		printf("-l:		list of pairs of IP address and udp port of other seeders, separated by comma ','\n");
		printf("		valid only for SEEDER\n");
		printf("		example: -l 192.168.1.1:6778,192.168.1.2:6778,192.168.1.4:6778\n");
		printf("-p port:	UDP listening port number, valid only on SEEDER side, default 6778\n");
		printf("		example: -p 7777\n");
		printf("-s sha1:	SHA1 of the file for downloading, valid only on LEECHER side\n");
		printf("		example: -s 82da6c1c7ac0de27c3fedf1dd52560323e7b1758\n");
		printf("-t:		timeout of network communication in seconds, default: 180 seconds\n");
		printf("		example: -t 10\n");
		printf("-v:		enables debugging messages\n");
		printf("\nInvocation examples:\n");
		printf("SEEDER mode:\n");
		printf("%s -f filename -c 1024\n", argv[0]);
		printf("%s -f filename -c 1024 -t 5 -l 192.168.1.1:6778\n", argv[0]);
		printf("%s -d /tmp/test -c 1024 -t 5 -l 192.168.1.1:6778,192.168.1.2:6778 -p 6778\n\n", argv[0]);
		printf("LEECHER mode:\n");
		printf("%s -a 192.168.1.1 -g 5 -s 82da6c1c7ac0de27c3fedf1dd52560323e7b1758 -t 10\n\n", argv[0]);
		exit(0);
	}

	if (fname1 != NULL) {
		type = SEEDER;
		fname2 = strdup(fname1);
		fname = fname2;
	}

	if (dir != NULL) {
		type = SEEDER;
	}

	if (type == LEECHER) {
		if (sa == NULL) {
			printf("Error: in LEECHER mode '-a' parameter is obligatory\n");
			exit(1);
		}

		if ((algo == -1) || ((algo != 4) && (algo != 5))) {
			printf("Error: algorithm must have value of 4 or 5\n");
			exit(1);
		}

		if (sha_demanded == NULL) {
			printf("Error: in LEECHER mode '-s' parameter is obligatory\n");
			exit(1);
		}
	}

	if (sa != NULL) {
		colon = strchr(sa, ':');
		if (colon != NULL) {
			memset(buf_ip_port, 0, sizeof(buf_ip_port));
			memcpy(buf_ip_port, sa, colon - sa);
			inet_aton(buf_ip_port, &local_peer.seeder_addr.sin_addr);
			local_peer.seeder_addr.sin_port = ntohs(atoi(colon + 1));
		} else {
			printf("Error: no colon found at: %s\n", sa);
			exit(1);
		}
	}

	if (peer_list != NULL) {
		d_printf("peer_list: %s   len: %lu\n", peer_list, strlen(peer_list));

		local_peer.nr_in_addr = 0;
		ch = peer_list;

		while (ch < peer_list + strlen(peer_list)) {
			comma = strchr(ch, ',');
			if (comma != NULL) { /* if comma found */
				last_char = comma - 1;
			} else if (ch < peer_list + strlen(peer_list)) { /* last IP without ending comma */
				last_char = peer_list + strlen(peer_list);
			}

			/* copy IP:PORT pair to temporary buffer */
			memset(buf_ip_port, 0, sizeof(buf_ip_port));
			memcpy(buf_ip_port, ch, last_char - ch + 1);

			/* extract IP address */
			colon = strchr(buf_ip_port, ':');
			if (colon != NULL) { /* colon found */
				memset(buf_ip_addr, 0, sizeof(buf_ip_addr));
				memcpy(buf_ip_addr, buf_ip_port, colon - buf_ip_port);
			} else {
				printf("Error: no colon found at: %s\n", buf_ip_port);
				exit(1);
			}

			//sia = inet_aton(buf_ip_addr, &local_peer.other_seeders[local_peer.nr_in_addr]);
			sia = inet_aton(buf_ip_addr, &local_peer.other_seeders[local_peer.nr_in_addr].sin_addr);
			local_peer.other_seeders[local_peer.nr_in_addr].sin_port = ntohs(atoi(colon + 1));
			printf("IP: %s   sia: %d\n", buf_ip_addr, sia);

			if (sia == 1) { /* if conversion succeeded */
				local_peer.nr_in_addr++;
			}
			ch = last_char + 2;
		}
	}


	if (type == SEEDER) {
		/* SEEDER mode */
		printf("Processing data, please wait... \n");

		/* does the user pass the directory name? */
		if (dir != NULL) {
			create_file_list(dir);
		} else {	/* no, user gave file name */
			f = malloc(sizeof(struct file_list_entry));
			SLIST_INSERT_HEAD(&file_list_head, f, next);
			memset(f->path, 0, sizeof(f->path));
			strcpy(f->path, fname);
			lstat(f->path, &stat);
			f->file_size = stat.st_size;
		}

		/* for each file in file_list_head create tree and tab_chunk[] */
		SLIST_FOREACH(fi, &file_list_head, next) {
			printf("processing: %s  ", fi->path);
			fflush(stdout);
			init_seeder(fi, chunk_size);

			memset(sha, 0, sizeof(sha));
			s = 0;
			for (y = 0; y < 20; y++)
				s += sprintf(sha + s, "%02x", fi->tree_root->sha[y] & 0xff);
			printf("sha1: %s\n", sha);
		}

		local_peer.tree = NULL;
		local_peer.nl = 0;
		local_peer.nc = 0;
		local_peer.type = SEEDER;
		local_peer.start_chunk = 0;
		local_peer.end_chunk = 0;
		local_peer.chunk_size = chunk_size;
		local_peer.file_size = stat.st_size;
		local_peer.timeout = timeout;
		local_peer.port = port;
		proto_test(&local_peer);

		free(fname2);

	} else { /* LEECHER mode */
		local_peer.tree = NULL;
		local_peer.nl = 0;
		local_peer.nc = 0;
		local_peer.type = LEECHER;
		memset(local_peer.fname, 0, sizeof(local_peer.fname));
		local_peer.fname_len = 0;
		local_peer.file_size = 0;
		local_peer.timeout = timeout;
		local_peer.current_seeder = NULL;
		local_peer.algo = algo;
		ascii_sha_to_bin(sha_demanded, local_peer.sha_demanded);

		proto_test(&local_peer);
	}

	return 0;
}
