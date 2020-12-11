#include "peregrine/log.h"
#include "peregrine/socket.h"
#include <errno.h>
#include <getopt.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

int debug;

int
main(int argc, char const *argv[])
{
	struct peregrine_context *context;
	struct sockaddr_in sin;
	struct pollfd pfd;
	const char *directory = NULL;
	int local_port = 0;
	int ch;
	int ret;

	while ((ch = getopt(argc, argv, "p:d:h")) != -1) {
		switch (ch) {
		case 'p':
			local_port = strtol(optarg, NULL, 10);
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

	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = INADDR_ANY;
	sin.sin_port = htons(local_port);

	if (pg_context_create((struct sockaddr *)&sin, sizeof(struct sockaddr_in), &context) != 0) {
		fprintf(stderr, "cannot create context: %s\n", strerror(errno));
		exit(EX_OSERR);
	}

	if (pg_context_add_directory(context, directory) != 0) {
		fprintf(stderr, "cannot add directory to context: %s\n", strerror(errno));
		exit(EX_OSERR);
	}

	pfd.fd = pg_context_get_fd(context);
	pfd.events = POLLIN | /* POLLOUT | */ POLLERR;
	pfd.revents = 0;

	for (;;) {
		ret = poll(&pfd, 1, -1);
		if (ret < 0)
			break;

		if (pfd.revents & POLLIN)
			pg_handle_fd_read(context);

#if 0
		if (pfd.revents & POLLOUT)
			pg_handle_fd_write(context);
#endif

		if (pfd.revents & POLLERR)
			break;
	}

	return (0);
}
