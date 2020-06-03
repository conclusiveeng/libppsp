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
#include <errno.h>

#include "mt.h"
#include "sha1.h"
#include "ppspp_protocol.h"
#include "net.h"
#include "peer.h"
#include "debug.h"
#include "ppspp.h"


struct peer local_peer;


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
	char *fname1, *fdname, *fname2, usage, *peer_list, *colon, *comma, *last_char, *ch, *sa;
	char *sha_demanded;
	char buf_ip_addr[24], buf_ip_port[64];
	uint8_t *transfer_buf;
	int opt, chunk_size, type, sia, port, old, file_exist, fd;
	uint32_t timeout, buf_size;
	struct sockaddr_in sa_in;
	seeder_params_t seeder_params;
	leecher_params_t leecher_params;
	metadata_t meta;

	chunk_size = 1024;
	fdname = fname1 = NULL;
	debug = 0;
	usage = 0;
	peer_list = NULL;
	type = LEECHER;
	timeout = 3 * 60;	/* 3 minutes timeout as default */
	sha_demanded = NULL;
	port = 6778;
	sa = NULL;
	old = 0;
	while ((opt = getopt(argc, argv, "a:c:f:hl:op:s:t:v")) != -1) {
		switch (opt) {
			case 'a':				/* remote address of seeder */
				sa = optarg;
				break;
			case 'c':				/* chunk size [bytes] */
				chunk_size = atoi(optarg);
				break;
			case 'f':				/* filename */
				fdname = optarg;
				break;
			case 'h':				/* help/usage */
				usage = 1;
				break;
			case 'l':				/* peer IP list separated by ':' */
				peer_list = optarg;
				break;
			case 'o':				/* old method for calling leecher */
				old = 1;
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
		printf("%s: -acfhlopstv\n", argv[0]);
		printf("-a ip_address:port:	numeric IP address and udp port of the remote SEEDER, enables LEECHER mode\n");
		printf("			example: -a 192.168.1.1:6778\n");
		printf("-c:			chunk size in bytes valid only on the SEEDER side, default: 1024 bytes\n");
		printf("			example: -c 1024\n");
		printf("-f dir or filename:	filename of the file or directory name for sharing, enables SEEDER mode\n");
		printf("			example: -f ./filename\n");
		printf("			example: -f /path/to/directory\n");
		printf("-h:			this help\n");
		printf("-l:			list of pairs of IP address and udp port of other seeders, separated by comma ','\n");
		printf("			valid only for SEEDER\n");
		printf("			example: -l 192.168.1.1:6778,192.168.1.2:6778,192.168.1.4:6778\n");
		printf("-o:			old method for calling leecher\n");
		printf("-p port:		UDP listening port number, valid only on SEEDER side, default 6778\n");
		printf("			example: -p 7777\n");
		printf("-s sha1:		SHA1 of the file for downloading, valid only on LEECHER side\n");
		printf("			example: -s 82da6c1c7ac0de27c3fedf1dd52560323e7b1758\n");
		printf("-t:			timeout of network communication in seconds, default: 180 seconds\n");
		printf("			example: -t 10\n");
		printf("-v:			enables debugging messages\n");
		printf("\nInvocation examples:\n");
		printf("SEEDER mode:\n");
		printf("%s -f filename -c 1024\n", argv[0]);
		printf("%s -f filename -c 1024 -t 5 -l 192.168.1.1:6778\n", argv[0]);
		printf("%s -f /tmp/test -c 1024 -t 5 -l 192.168.1.1:6778,192.168.1.2:6778 -p 6778\n\n", argv[0]);
		printf("LEECHER mode:\n");
		printf("%s -a 192.168.1.1:6778 -s 82da6c1c7ac0de27c3fedf1dd52560323e7b1758 -t 10\n\n", argv[0]);
		exit(0);
	}

	if (fname1 != NULL) {
		type = SEEDER;
		fname2 = strdup(fname1);
		fdname = fname2;
	}

	if (fdname != NULL) {
		type = SEEDER;
	}

	if (type == LEECHER) {
		if (sa == NULL) {
			printf("Error: in LEECHER mode '-a' parameter is obligatory\n");
			exit(1);
		}

		if (sha_demanded == NULL) {
			printf("Error: in LEECHER mode '-s' parameter is obligatory\n");
			exit(1);
		}
	}

	/* for leecher only */
	if (sa != NULL) {
		colon = strchr(sa, ':');
		if (colon != NULL) {
			memset(buf_ip_port, 0, sizeof(buf_ip_port));
			memcpy(buf_ip_port, sa, colon - sa);
			if (old) {
				inet_aton(buf_ip_port, &local_peer.seeder_addr.sin_addr);
				local_peer.seeder_addr.sin_port = ntohs(atoi(colon + 1));
			} else {
				inet_aton(buf_ip_port, &leecher_params.seeder_addr.sin_addr);
				leecher_params.seeder_addr.sin_port = ntohs(atoi(colon + 1));
			}
		} else {
			printf("Error: no colon found at: %s\n", sa);
			exit(1);
		}
	}


	if (type == SEEDER) {
		/* SEEDER mode */
		printf("Processing data, please wait... \n");

		seeder_params.chunk_size = chunk_size;
		seeder_params.timeout = timeout;
		seeder_params.port = port;

		ppspp_seeder_create(&seeder_params);

		if (peer_list != NULL) {

			d_printf("peer_list: %s   len: %lu\n", peer_list, strlen(peer_list));

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

				sia = inet_aton(buf_ip_addr, &sa_in.sin_addr);
				sa_in.sin_port = htons(atoi(colon + 1));

				//printf("IP: %s:%u   sia: %d\n", buf_ip_addr, ntohs(sa_in.sin_port), sia);

				if (sia == 1) { /* if conversion succeeded */
					ppspp_seeder_add_seeder(&sa_in);
				}
				ch = last_char + 2;
			}

			//ppspp_seeder_list_seeders();
			//ppspp_seeder_remove_seeder(&sa_in);		// usun ostatni z petli dla testu
			//ppspp_seeder_list_seeders();
		}

		if (fdname != NULL) {
			ppspp_seeder_add_file_or_directory(fdname);
		}

		ppspp_seeder_add_file_or_directory("/tmp/test22");
		ppspp_seeder_remove_file_or_directory("/tmp/test2//plik256k");
		ppspp_seeder_remove_file_or_directory("/tmp/test2/plik256k");
		ppspp_seeder_remove_file_or_directory("/tmp/test2");
		

		ppspp_seeder_run();

		free(fname2);

	} else { /* LEECHER mode */
		if (old) {
			/* leecher continuous version (old one) */
			printf("old method\n");
			local_peer.sbs_mode = 0;
			local_peer.tree = NULL;
			local_peer.nl = 0;
			local_peer.nc = 0;
			local_peer.type = LEECHER;
			memset(local_peer.fname, 0, sizeof(local_peer.fname));
			local_peer.fname_len = 0;
			local_peer.file_size = 0;
			local_peer.timeout = timeout;
			local_peer.current_seeder = NULL;
			ascii_sha_to_bin(sha_demanded, local_peer.sha_demanded);
			//proto_test(&local_peer);
			net_leecher_continuous(&local_peer);
		} else {
			/* prepare data for step-by-step leecher version */
			leecher_params.timeout = timeout;
			ascii_sha_to_bin(sha_demanded, leecher_params.sha_demanded);
			ppspp_leecher_create(&leecher_params);

			/* get metadata for demanded sha file */
			file_exist = ppspp_leecher_get_metadata(&meta);
			if (file_exist == 0) {
				printf("seeder has demanded file: %s  size: %lu  chunks: %lu-%lu\n", meta.file_name, meta.file_size, meta.start_chunk, meta.end_chunk);

				unlink(meta.file_name);
				fd = open(meta.file_name, O_WRONLY | O_CREAT, 0744);
				if (fd < 0) {
					printf("error opening file '%s' for writing: %u %s\n", meta.file_name, errno, strerror(errno));
					abort();
				}
#if 1
				/* file descriptor transfer method */
				//ppspp_set_fd_transfer_method(fd); // proc zastapiona przez ppspp_leecher_fetch_chunk_to_fd

				/* run 1 (non-blocking) leecher thread with state machine */
				//net_leecher_sbs(&local_peer);
				ppspp_leecher_run();

				/* let the library prepare itself for transfer */
				//ppspp_prepare_chunk_range(0, 1);
				ppspp_prepare_chunk_range(meta.start_chunk, meta.end_chunk);

				printf("fd: %u\n\n", fd);

				ppspp_leecher_fetch_chunk_to_fd(fd);
				printf("main: przed close\n");

				ppspp_leecher_close();
#else
				/* transfering buffer transfer method */

				/* run 1 (non-blocking) leecher thread with state machine */
				//net_leecher_sbs(&local_peer);
				ppspp_leecher_run();

				/* let the library prepare itself for transfer */
				buf_size = ppspp_prepare_chunk_range(0, 99);
				printf("wielkosc bufora do zaallokowania: %u\n", buf_size);
		
				transfer_buf = malloc(buf_size);
				
				ppspp_leecher_fetch_chunk_to_buf(transfer_buf);

				buf_size = ppspp_prepare_chunk_range(100, 199);
				ppspp_leecher_fetch_chunk_to_buf(transfer_buf);


				printf("main: przed close\n");

				ppspp_leecher_close();
				free(transfer_buf);

#endif	
			}
			
		}

	}

	return 0;
}
