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

/**
 * @file peregrine.c
 * @author Conclusive Engineerg
 * @brief Example application using libperegrine
 * @version 0.4
 * @date 2020-12-15
 * 
 * @copyright Copyright (c) 2020 Conclusive Engineering Sp. z o.o.
 * 
 */

#include <arpa/inet.h>
#include <err.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <peregrine/peregrine.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/poll.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sysexits.h>

/**
 * @brief Maximum length of SHA1 in HEX string
 *
 */
#define SHA1STR_MAX	41

/**
 * @brief File specification parsed from the command line.
 *
 */
struct peregrine_file
{
	const char *path;			/**< Path to the file */
	const uint8_t *sha1;			/**< SHA1 of the file */
	TAILQ_ENTRY(peregrine_file) entry;	/**< Tail queue */
};

/**
 * @brief Directory specification parsed from the command line.
 */
struct peregrine_directory
{
	const char *path;			/**< Path to directory */
	TAILQ_ENTRY(peregrine_directory) entry; /**< Tail queue */
};

/**
 * @brief Peer specification parsed from the command line.
 */
struct peregrine_peer
{
	struct sockaddr_storage sa;		/**< Peer address */
	TAILQ_ENTRY(peregrine_peer) entry;	/**< Tail queue */
};

static TAILQ_HEAD(, peregrine_file) files;
static TAILQ_HEAD(, peregrine_directory) directories;
static TAILQ_HEAD(, peregrine_peer) peers;
static struct pg_context *context;
static bool finished = false;
static bool print_events = false;

static void
usage(const char *argv0)
{
	fprintf(stderr, "Usage: %s -lhpfds \n", argv0);
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "-h	show this help message \n");
	fprintf(stderr, "-l	local port 	(eg. -l <port>) \n");
	fprintf(stderr, "-p	peer address	(eg. -p <ip addr>:<port> OR -p <hostname>:<port>) \n");
	fprintf(stderr, "-f	file, sha1 	(eg. -f <filename> or -f <filename>:<sha1> ) \n");
	fprintf(stderr, "-d	directory 	(eg. -d <path/to/directory> ) \n");
	fprintf(stderr, "-s	enable showing summary (if disabled only callbacks will be used ) \n");
}

static void
event_printf(const char *fmt, ...)
{
	va_list ap;

	if (print_events) {
		va_start(ap, fmt);
		vprintf(fmt, ap);
		va_end(ap);
	}
}

static void
check_signals(void)
{

}

static int
add_file(const char *filespec)
{
	struct peregrine_file *file;
	char path[PATH_MAX] = "";
	char shastr[SHA1STR_MAX] = "";

	if (sscanf(filespec, "%[^:]:%[^:]", path, shastr) < 1) {
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
add_peer_check_addr(struct sockaddr_in *addr) {
        struct peregrine_peer *existing_peer;
        struct sockaddr_in *other_addr;
        struct sockaddr_in zero_addr;

        inet_aton("0.0.0.0", &zero_addr.sin_addr);
        if (memcmp((void *)&zero_addr.sin_addr, (void *)&addr->sin_addr, sizeof (zero_addr.sin_addr)) == 0)
		return -1;

        TAILQ_FOREACH(existing_peer, &peers, entry) {
		other_addr = (struct sockaddr_in *)&existing_peer->sa;
		if (memcmp((void *)&other_addr->sin_addr, (void *)&addr->sin_addr, sizeof (other_addr->sin_addr)) == 0)
			return -1;
	}

	return 0;
}

static int
add_peer(const char *peerspec)
{
	struct peregrine_peer *peer;
	struct sockaddr_in *sin;
        struct addrinfo hints;
	struct addrinfo *result;
        struct addrinfo* res;
	char addr[NAME_MAX];
	uint16_t port;
	int ret;

	if (sscanf(peerspec, "%[^:]:%hd", addr, &port) < 2) {
		fprintf(stderr, "Cannot parse peer spec: %s", peerspec);
		return (-1);
	}

        memset(&hints, 0, sizeof(struct addrinfo));
        hints.ai_family = AF_INET;
        hints.ai_protocol = SOCK_DGRAM;
	ret = getaddrinfo(addr, NULL, &hints, &result);
        if (ret != 0) {
                fprintf(stderr, "getaddrinfo error: %s \n", gai_strerror(ret));
                exit(EX_OSERR);
        }

        for (res = result; res != NULL; res = res->ai_next) {
                if ( res->ai_family == AF_INET ) {
                        if (add_peer_check_addr((struct sockaddr_in *)res->ai_addr) == 0) {
                                peer = calloc(1, sizeof(*peer));
                                sin = (struct sockaddr_in *)&peer->sa;
                                sin->sin_family = AF_INET;
                                sin->sin_port = htons(port);
                                sin->sin_addr = ((struct sockaddr_in *)res->ai_addr)->sin_addr;
			        TAILQ_INSERT_TAIL(&peers, peer, entry);
                        }
		}
	}

        freeaddrinfo(result);
        return (0);
}

static void
print_event(struct pg_event *ev, void *arg __attribute__((unused)))
{
	switch (ev->type) {
	case EVENT_PEER_ADDED:
		event_printf("Peer %s added\n", pg_peer_to_str(ev->peer));
		break;

	case EVENT_PEER_REMOVED:
		event_printf("Peer %s removed\n", pg_peer_to_str(ev->peer));
		break;

	case EVENT_PEER_JOINED_SWARM:
		event_printf("Peer %s joined swarm %s\n", pg_peer_to_str(ev->peer),
	 	    pg_swarm_to_str(ev->swarm));
		break;

	case EVENT_PEER_LEFT_SWARM:
		event_printf("Peer %s joined swarm %s\n", pg_peer_to_str(ev->peer),
		    pg_swarm_to_str(ev->swarm));
		break;
	case EVENT_SWARM_ADDED:
                event_printf("Swarm %s was created\n", pg_swarm_to_str(ev->swarm));
                break;

        case EVENT_SWARM_REMOVED:
                event_printf("Swarm was removed\n");
                break;

	case EVENT_SWARM_FINISHED:
		event_printf("Finished downloading %s\n", pg_swarm_to_str(ev->swarm));
		break;

	case EVENT_SWARM_FINISHED_ALL:
		event_printf("Finished all downloads\n");
		finished = true;
		exit(0);
		break;

	case EVENT_UNKNOWN:
		break;
	}
}

static bool
print_peer(struct pg_peer *peer, void *arg)
{
	(void)arg;

	printf("  %s (%" PRIu64 " down, %" PRIu64 " up)\n", pg_peer_to_str(peer),
	    pg_peer_get_received_chunks(peer), pg_peer_get_sent_chunks(peer));
	return (true);
}

static bool
print_swarm(struct pg_swarm *swarm, void *arg)
{
	uint64_t sent = pg_swarm_get_sent_chunks(swarm);
	uint64_t received = pg_swarm_get_received_chunks(swarm);
	uint64_t total = pg_swarm_get_total_chunks(swarm);
	double down_percent = (double)received / (double)total * 100;
	double up_percent = (double)sent / (double)total * 100;

	(void)arg;

	printf("  [%s]\n", pg_swarm_to_str(swarm));
	printf("    Seeded: %" PRIu64 " (%3.2f%%)\n", sent, up_percent);
	printf("    Downloaded: %" PRIu64 " of %" PRIu64 " (%3.2f%%)\n",
	    received, total, down_percent);

	return (true);
}

static void
print_summary(struct pg_context *ctx)
{
	printf("Peers:\n");
	pg_peer_iterate(ctx, print_peer, NULL);

	printf("Swarms:\n");
	pg_swarm_iterate(ctx, print_swarm, NULL);
}

int
main(int argc, char *const argv[])
{
	struct sockaddr_in sin;
	struct pollfd pfd;
	struct peregrine_file *file;
	struct peregrine_directory *dir;
	struct peregrine_peer *peer;
	struct pg_context_options options;
	int local_port = 0;
	int chunk_size = 1024;
	bool summary = 0;
	int ch;
	int ret;

	TAILQ_INIT(&files);
	TAILQ_INIT(&directories);
	TAILQ_INIT(&peers);

	if (argc == 1) {
		usage(argv[0]);
		exit(EX_USAGE);
	}

	while ((ch = getopt(argc, argv, "hl:p:f:d:c:hs")) != -1) {
		switch (ch) {
		case 'h':
			usage(argv[0]);
			exit(EX_USAGE);

		case 'c':
			chunk_size = strtol(optarg, NULL, 10);
			break;

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

		case 'r':
			remain = strtol(optarg, NULL, 10);
			break;

		case 's':
			summary = true;
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
	options.event_fn = print_event;
	options.fn_arg = NULL;
	options.chunk_size = chunk_size;

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
		if (pg_file_add_file(context, file->sha1, file->path) == NULL) {
			fprintf(stderr, "cannot add file %s: %s\n", file->path,strerror(errno));
			exit(EX_OSERR);
		}
	}

	TAILQ_FOREACH(dir, &directories, entry) {
		if (pg_file_add_directory(context, dir->path, NULL) != 0) {
			fprintf(stderr, "cannot add directory %s: %s\n", dir->path, strerror(errno));
			exit(EX_OSERR);
		}
	}

	pg_file_generate_sha1(context);
	pg_file_list_sha1(context);

	pfd.fd = pg_context_get_fd(context);
	pfd.events = POLLIN;
	pfd.revents = 0;

	for (;;) {
		ret = poll(&pfd, 1, summary ? 500 : -1);
		if (ret < 0) {
			if (errno == EINTR) {
				check_signals();
				continue;
			}

			err(1, "epoll_wait");
		}

		if (pfd.revents & POLLIN) {
			if (pg_context_step(context) != 0)
				break;
		}

		if (summary) {
			printf("\033[2J\033[H");
			print_summary(context);
		}
	}

	return (0);
}
