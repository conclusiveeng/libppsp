#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>
#include <poll.h>
#include <string.h>
#include <sysexits.h>
#include "peregrine/socket.h"
#include "peregrine/file.h"

static int tx = 0;

void
peregrine_start_tx(struct pg_context *ctx, void *arg)
{
	tx = 1;
}

void
peregrine_stop_tx(struct pg_context *ctx, void *arg)
{
	tx = 0;
}

int
main(int argc, char *const argv[])
{
	struct pg_context *context;
	struct sockaddr_in sin;
	struct pollfd pfd;
	const char *directory = NULL;
	int local_port = 0;
	int ch;
	int ret;

	struct pg_context_callbacks callbacks = {
	    .pg_start_sending = peregrine_start_tx,
	    .pg_stop_sending = peregrine_stop_tx
	};

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

	pg_context_set_callbacks(context, &callbacks, NULL);

	if (pg_file_add_directory(context, directory) != 0) {
		fprintf(stderr, "cannot add directory to context: %s\n", strerror(errno));
		exit(EX_OSERR);
	}

	pg_file_generate_sha1(context);
	pg_file_list_sha1(context);

	pfd.fd = pg_context_get_fd(context);
	pfd.events = POLLIN  | POLLERR;
	pfd.revents = 0;

	for (;;) {
		if (tx)
			pfd.events |= POLLOUT;

		ret = poll(&pfd, 1, -1);
		if (ret < 0)
			break;

		if (pfd.revents & POLLIN)
			pg_handle_fd_read(context);

		if (pfd.revents & POLLOUT)
			pg_handle_fd_write(context);

		if (pfd.revents & POLLERR)
			break;
	}

	return (0);
}
