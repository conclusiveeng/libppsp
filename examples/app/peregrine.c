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
#include <err.h>
#include <errno.h>
#include <getopt.h>
#include <poll.h>
#include <string.h>
#include <sysexits.h>
#include <inttypes.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <sys/param.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <peregrine/peregrine.h>

#define SHA1STR_MAX	41

struct peregrine_file
{
	const char *path;
	const uint8_t *sha1;
	TAILQ_ENTRY(peregrine_file) entry;
};

struct peregrine_directory
{
	const char *path;
	TAILQ_ENTRY(peregrine_directory) entry;
};

struct peregrine_peer
{
	struct sockaddr_storage sa;
	TAILQ_ENTRY(peregrine_peer) entry;
};

static TAILQ_HEAD(, peregrine_file) files;
static TAILQ_HEAD(, peregrine_directory) directories;
static TAILQ_HEAD(, peregrine_peer) peers;
static struct pg_context *context;

static void
usage(const char *argv0)
{
	fprintf(stderr, "Usage: %s -l port [options]\n", argv0);
	fprintf(stderr, "Options:\n");
}

static int
add_file(const char *filespec)
{
	struct peregrine_file *file;
	char path[PATH_MAX];
	char shastr[SHA1STR_MAX];

	if (sscanf(filespec, "%[^:]:%[^:]", path, shastr) < 2) {
		fprintf(stderr, "Cannot parse file spec: %s\n", filespec);
		return (-1);
	}

	file = calloc(1, sizeof(*file));
	file->path = strdup(path);
	file->sha1 = pg_parse_sha1(shastr);
	TAILQ_INSERT_TAIL(&files, file, entry);

	return (0);
}

static int
add_directory(const char *dirspec)
{
	struct peregrine_directory *dir;

	dir = calloc(1, sizeof(*dir));
	dir->path = strdup(dirspec);
	TAILQ_INSERT_TAIL(&directories, dir, entry);

	return (0);
}

static int
add_peer(const char *peerspec)
{
	struct peregrine_peer *peer;
	struct sockaddr_in *sin;
	char addr[32];
	uint16_t port;

	peer = calloc(1, sizeof(*peer));
	sin = (struct sockaddr_in *)&peer->sa;

	if (sscanf(peerspec, "%[^:]:%hd", addr, &port) < 2) {
		fprintf(stderr, "Cannot parse peer spec: %s", peerspec);
		return (-1);
	}

	sin->sin_family = AF_INET;
	sin->sin_port = htons(port);
	inet_aton(addr, &sin->sin_addr);

	TAILQ_INSERT_TAIL(&peers, peer, entry);
	return (0);
}

int
main(int argc, char *const argv[])
{
	struct sockaddr_in sin;
	struct pollfd pfd;
	struct peregrine_file *file;
	struct peregrine_directory *dir;
	struct peregrine_peer *peer;
	int local_port = 0;
	int ch;
	int ret;

	struct pg_context_options options;

	TAILQ_INIT(&files);
	TAILQ_INIT(&directories);
	TAILQ_INIT(&peers);

	while ((ch = getopt(argc, argv, "hl:p:f:d:h")) != -1) {
		switch (ch) {
		case 'h':
			usage(argv[0]);
			exit(EX_USAGE);

		case 'l':
			local_port = strtol(optarg, NULL, 10);
			break;

		case 'p':
			add_peer(optarg);
			break;

		case 'f':
			add_file(optarg);
			break;

		case 'd':
			add_directory(optarg);
			break;
		}
	}

	if (local_port == 0) {
		fprintf(stderr, "Local port not specified\n");
		exit(EX_USAGE);
	}

	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = INADDR_ANY;
	sin.sin_port = htons(local_port);
	options.listen_addr = (struct sockaddr *)&sin;
	options.listen_addr_len = sizeof(struct sockaddr_in);

	if (pg_context_create(&options, &context) != 0) {
		fprintf(stderr, "cannot create context: %s\n", strerror(errno));
		exit(EX_OSERR);
	}

	TAILQ_FOREACH(peer, &peers, entry) {
		if (pg_add_peer(context, (struct sockaddr *)&peer->sa, NULL) != 0) {
			fprintf(stderr, "cannot add peer: %s\n", strerror(errno));
			exit(EX_OSERR);
		}
	}

	TAILQ_FOREACH(file, &files, entry) {
		if (pg_file_add_file(context, file->sha1, file->path) != 0) {

		}
	}

	TAILQ_FOREACH(dir, &directories, entry) {
		if (pg_file_add_directory(context, dir->path, NULL) != 0) {

		}
	}

	pg_file_generate_sha1(context);
	pg_file_list_sha1(context);

	pfd.fd = pg_context_get_fd(context);
	pfd.events = POLLIN;
	pfd.revents = 0;

	for (;;) {
		ret = poll(&pfd, 1, 0);
		if (ret < 0) {
			if (errno == EINTR)
				continue;

			err(1, "epoll_wait");
		}

		if (pfd.revents & POLLIN) {
			if (pg_context_step(context) != 0)
				break;
		}
	}

	return (0);
}
