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
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "peregrine/socket.h"
#include "peregrine/file.h"
#include "peregrine/utils.h"

static struct pg_context *context;
static int epollfd;

void
peregrine_add_fd(struct pg_context *ctx, void *arg, int fd, int events)
{
	struct epoll_event ev = { 0 };

	if (events & POLLIN)
		ev.events |= EPOLLIN;

	if (events & POLLOUT)
		ev.events |= EPOLLOUT;

	if (epoll_ctl(epollfd, EPOLL_CTL_ADD, fd, &ev) != 0)
		err(1, "epoll_ctl(EPOLL_CTL_ADD)");
}

void
peregrine_mod_fd(struct pg_context *ctx, void *arg, int fd, int events)
{
	struct epoll_event ev = { 0 };

	if (events & POLLIN)
		ev.events |= EPOLLIN;

	if (events & POLLOUT)
		ev.events |= EPOLLOUT;

	if (epoll_ctl(epollfd, EPOLL_CTL_MOD, fd, &ev) != 0)
		err(1, "epoll_ctl(EPOLL_CTL_MOD)");
}

void
peregrine_del_fd(struct pg_context *ctx, void *arg, int fd)
{
	struct epoll_event ev = { 0 };

	if (epoll_ctl(epollfd, EPOLL_CTL_DEL, fd, &ev) != 0)
		err(1, "epoll_ctl(EPOLL_CTL_DEL)");
}

static int
add_file(const char *sha1str)
{
	uint8_t *sha1;

	sha1 = pg_parse_sha1(sha1str);

	if (pg_file_add_file(context, sha1, NULL) == NULL)
		err(1, "pg_file_add_file");

	return (0);
}

static int
add_peer(const char *peerspec)
{
	struct sockaddr_in sin;
	char addr[32];
	uint16_t port;

	if (sscanf(peerspec, "%[^:]:%hd", addr, &port) < 2) {
		errno = EINVAL;
		return (-1);
	}

	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);
	inet_aton(addr, &sin.sin_addr);

	if (pg_add_peer(context, (struct sockaddr *)&sin) != 0) {
		fprintf(stderr, "Cannot add peer: %s\n", strerror(errno));
		return (-1);
	}

	printf("Added peer %s:%d\n", addr, port);
	return (0);
}

void
peregrine_print_new_file(struct pg_file *file, const char *dname)
{
	printf("Added new file: %s, parent dir: %s",
	    pg_file_get_path(file), dname);
}

int
main(int argc, char *const argv[])
{
	struct sockaddr_in sin;
	struct epoll_event events[16];
	const char *directory = NULL;
	const char *sha1 = NULL;
	const char *peer = NULL;
	int local_port = 0;
	int ch;
	int ret;
	int i;

	struct pg_context_options options = {
	    .add_fd = peregrine_add_fd,
	    .mod_fd = peregrine_mod_fd,
	    .del_fd = peregrine_del_fd,
	    .arg = NULL,
	};

	while ((ch = getopt(argc, argv, "l:p:s:d:h")) != -1) {
		switch (ch) {
		case 'p':
			peer = optarg;
			break;

		case 'l':
			local_port = strtol(optarg, NULL, 10);
			break;

		case 's':
			sha1 = optarg;
			break;

		case 'd':
			directory = optarg;
			break;
		}
	}

	if (local_port == 0) {
		fprintf(stderr, "port not specified\n");
		exit(EX_USAGE);
	}

	if (directory == NULL) {
		fprintf(stderr, "directory not specified\n");
		exit(EX_USAGE);
	}

	epollfd = epoll_create(1);
	if (epollfd < 0) {
		err(1, "epoll_create");
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

	if (sha1 != NULL)
		add_file(sha1);

	if (peer != NULL)
		add_peer(peer);

	if (pg_file_add_directory(context, directory, peregrine_print_new_file) != 0) {
		fprintf(stderr, "cannot add directory to context: %s\n", strerror(errno));
		exit(EX_OSERR);
	}

	pg_file_generate_sha1(context);
	pg_file_list_sha1(context);

	for (;;) {
		ret = epoll_wait(epollfd, events, sizeof(events) / sizeof(events[0]), -1);
		if (ret < 0) {
			if (errno == EINTR)
				continue;

			err(1, "epoll_wait");
		}

		for (i = 0; i < ret; i++) {
			if (events[i].events & EPOLLIN)
				pg_handle_fd_read(context, events[i].data.fd);

			if (events[i].events & EPOLLOUT)
				pg_handle_fd_write(context, events[i].data.fd);
		}
	}

	return (0);
}
