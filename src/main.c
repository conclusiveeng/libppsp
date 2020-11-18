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

#include "config.h" // FIXME: should not be used by main.c after change file should be removed from public include
#include "peregrine_leecher.h"
#include "peregrine_seeder.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int debug;

enum { SEEDER_TYPE = 1, LEECHER_TYPE = 2 };

void
ascii_sha_to_bin(char *sha_ascii, uint8_t *bin)
{
  int y;
  uint8_t b;
  char buf[2 + 1];

  memset(buf, 0, sizeof(buf));
  for (y = 0; y < 40; y += 2) {
    memcpy(buf, sha_ascii + y, 2);
    b = strtoul(buf, NULL, 16);
    bin[y / 2] = b & 0xff;
  }
}

int
main(int argc, char *argv[])
{
  char *fname1;
  char *fdname;
  char *fname2;
  char usage;
  char *peer_list;
  char *colon;
  char *sa;
  char *sha_demanded;
  char buf_ip_port[64];
  int opt;
  int chunk_size;
  int type;
  int port;
  int file_exist;
  int fd;
  uint32_t timeout;
  peregrine_seeder_params_t seeder_params;
  peregrine_leecher_params_t leecher_params;
  peregrine_metadata_t meta;
  peregrine_handle_t seeder_handle;
  peregrine_handle_t leecher_handle;
#if MULTIPLE_SEEDERS
  char *comma, *last_char, *ch;
  char buf_ip_addr[24];
  int sia;
  struct sockaddr_in sa_in;
#endif

  chunk_size = 1024;
  fdname = fname1 = NULL;
  debug = 0;
  usage = 0;
  peer_list = NULL;
  type = LEECHER_TYPE;
  timeout = 3 * 60; /* 3 minutes timeout as default */
  sha_demanded = NULL;
  port = 6778;
  sa = NULL;
  while ((opt = getopt(argc, argv, "a:c:f:hp:s:t:v")) != -1) {
    switch (opt) {
    case 'a': /* remote address of seeder */
      sa = optarg;
      break;
    case 'c': /* chunk size [bytes] */
      chunk_size = atoi(optarg);
      break;
    case 'f': /* filename */
      fdname = optarg;
      break;
    case 'h': /* help/usage */
      usage = 1;
      break;
#if MULTIPLE_SEEDERS
    case 'l': /* peer IP list separated by ':' */
      peer_list = optarg;
      break;
#endif
    case 'p': /* UDP port number of seeder */
      port = atoi(optarg);
      break;
    case 's': /* demanded SHA of the file */
      sha_demanded = optarg;
      break;
    case 't': /* timeout [seconds] */
      timeout = atoi(optarg);
      break;
    case 'v': /* debug */
      debug = 1;
      break;
    default:
      usage = 1;
    }
  }

  if (usage || (argc == 1)) {
    printf("Peregrine - Peer-to-Peer Streaming Peer Protocol - DEMO CLIENT\n");
    printf("usage:\n");
    printf("%s: -acfhpstv\n", argv[0]);
    printf("-a ip_address:port:	numeric IP address and udp port of the remote "
           "SEEDER, enables LEECHER mode\n");
    printf("			example: -a 192.168.1.1:6778\n");
    printf("-c:			chunk size in bytes valid only on the SEEDER "
           "side, default: 1024 bytes\n");
    printf("			example: -c 1024\n");
    printf("-f dir or filename:	filename of the file or directory name for "
           "sharing, enables SEEDER mode\n");
    printf("			example: -f ./filename\n");
    printf("			example: -f /path/to/directory\n");
    printf("-h:			this help\n");
#if MULTIPLE_SEEDERS
    printf("-l:			list of pairs of IP address and udp port of "
           "other seeders, separated by comma ','\n");
    printf("			valid only for SEEDER\n");
    printf("			example: -l "
           "192.168.1.1:6778,192.168.1.2:6778,192.168.1.4:6778\n");
#endif
    printf("-p port:		UDP listening port number, valid only on "
           "SEEDER side, default 6778\n");
    printf("			example: -p 7777\n");
    printf("-s sha1:		SHA1 of the file for downloading, valid only "
           "on LEECHER side\n");
    printf("			example: -s "
           "82da6c1c7ac0de27c3fedf1dd52560323e7b1758\n");
    printf("-t:			timeout of network communication in seconds, "
           "default: 180 seconds\n");
    printf("			example: -t 10\n");
    printf("-v:			enables debugging messages\n");
    printf("\nInvocation examples:\n");
    printf("SEEDER mode:\n");
    printf("%s -f filename -c 1024\n", argv[0]);
    printf("%s -f /tmp/directory -c 1024 -t 5\n", argv[0]);
    printf("LEECHER mode:\n");
    printf("%s -a 192.168.1.1:6778 -s 82da6c1c7ac0de27c3fedf1dd52560323e7b1758 "
           "-t 10\n\n",
           argv[0]);
    exit(0);
  }

  if (fname1 != NULL) {
    type = SEEDER_TYPE;
    fname2 = strdup(fname1);
    fdname = fname2;
  }

  if (fdname != NULL) {
    type = SEEDER_TYPE;
  }

  if (type == LEECHER_TYPE) {
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
      inet_aton(buf_ip_port, &leecher_params.seeder_addr.sin_addr);
      leecher_params.seeder_addr.sin_port = ntohs(atoi(colon + 1));
    } else {
      printf("Error: no colon found at: %s\n", sa);
      exit(1);
    }
  }
  if (type == SEEDER_TYPE) {
    /* SEEDER mode */
    printf("Processing data, please wait... \n");

    seeder_params.chunk_size = chunk_size;
    seeder_params.timeout = timeout;
    seeder_params.port = port;

    seeder_handle = peregrine_seeder_create(&seeder_params);

#if MULTIPLE_SEEDERS
    if (peer_list != NULL) {
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

	if (sia == 1) { /* if conversion succeeded */
	  peregrine_seeder_add_seeder(seeder_handle, &sa_in);
	}
	ch = last_char + 2;
      }
    }
#endif

    if (fdname != NULL) {
      peregrine_seeder_add_file_or_directory(seeder_handle, fdname);
    }

    printf("Ok, ready for sharing\n");

    peregrine_seeder_run(seeder_handle);

    peregrine_seeder_close(seeder_handle);

    free(fname2);

  } else { /* LEECHER mode */
    /* prepare data for step-by-step leecher version */
    leecher_params.timeout = timeout;
    ascii_sha_to_bin(sha_demanded, leecher_params.sha_demanded);
    leecher_handle = peregrine_leecher_create(&leecher_params);

    /* get metadata for demanded sha file */
    file_exist = peregrine_leecher_get_metadata(leecher_handle, &meta);
    if (file_exist == 0) {
      sprintf(meta.file_name, "%s", sha_demanded);
      unlink(meta.file_name);
      fd = open(meta.file_name, O_WRONLY | O_CREAT, 0644);
      if (fd < 0) {
	printf("error opening file '%s' for writing: %u %s\n", meta.file_name, errno, strerror(errno));
	abort();
      }
#if FILE_DESCRIPTOR_TRANSFER
      /* run 1 (non-blocking) leecher thread with state machine */
      peregrine_leecher_run(leecher_handle);

      /* let the library prepare itself for transfer */
      peregrine_prepare_chunk_range(leecher_handle, meta.start_chunk, meta.end_chunk);

      peregrine_leecher_fetch_chunk_to_fd(leecher_handle, fd);

      peregrine_leecher_close(leecher_handle);
#endif
#if BUFFER_TRANSFER
      /* transfering with buffer transfer method */

      /* run 1 (non-blocking) leecher thread with state machine */
      peregrine_leecher_run(leecher_handle);

      x = meta.start_chunk;
      /* let the library prepare itself for transfer */
      buf_size = peregrine_prepare_chunk_range(leecher_handle, x, x + 1000 - 1);
      transfer_buf = malloc(buf_size);

      while ((x <= meta.end_chunk) && (buf_size > 0)) {
	size = peregrine_leecher_fetch_chunk_to_buf(leecher_handle, transfer_buf);
	write(fd, transfer_buf, size);
	x += 1000;
	buf_size = peregrine_prepare_chunk_range(leecher_handle, x, x + 1000 - 1);
      }
      close(fd);
      peregrine_leecher_close(leecher_handle);
      free(transfer_buf);
#endif
    }
  }

  return 0;
}
