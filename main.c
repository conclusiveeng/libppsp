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


int main (int argc, char *argv[])
{
	char *fname1, *fname, *fname2, *buf, usage;
	unsigned char digest[20 + 1];
	int fd, r, opt, chunk_size, type;
	uint32_t timeout;
	uint64_t x, nc, nl, c, rd;
	struct stat stat;
	SHA1Context context;
	struct node *ret;
	struct in_addr ia;

	chunk_size = 1024;
	fname = NULL;
	debug = 0;
	usage = 0;
	ia.s_addr = -1;
	type = LEECHER;
	timeout = 3 * 60;	/* 3 minutes timeout as default */
	while ((opt = getopt(argc, argv, "a:df:hs:t:")) != -1) {
		switch (opt) {
			case 'a':				/* remote address of seeder */
				(void) inet_aton(optarg, &ia);
				break;
			case 'd':				/* debug */
				debug = 1;
				break;
			case 'f':				/* filename */
				fname1 = optarg;
				break;
			case 'h':				/* help/usage */
				usage = 1;
				break;
			case 's':				/* chunk size [bytes] */
				chunk_size = atoi(optarg);
				break;
			case 't':				/* timeout [seconds] */
				timeout = atoi(optarg);
				break;
			default:
				usage = 1;
		}
	}

	if (usage || (argc == 1)) {
		printf("Peer-to-Peer Streaming Peer Protocol proof of concept\n");
		printf("usage:\n");
		printf("%s: -adfhst\n", argv[0]);
		printf("-a ip_address:	numeric IP address of the remote SEEDER, enables LEECHER mode\n");
		printf("		example: -a 192.168.1.1\n");
		printf("-d:		enables debugging messages\n");
		printf("-f filename:	filename of the file for sharing, enables SEEDER mode\n");
		printf("		example: -f ./filename\n");
		printf("-h:		this help\n");
		printf("-s:		chunk size in bytes valid only on the SEEDER side, default: 1024 bytes\n");
		printf("		example: -s 1024\n");
		printf("-t:		timeout of network communication in seconds, valid only on SEEDER side, default: 180 seconds\n");
		printf("		example: -t 10\n");
		printf("\nInvocation examples:\n");
		printf("SEEDER mode:\n");
		printf("%s -f filename -s 1024\n\n", argv[0]);
		printf("LEECHER mode:\n");
		printf("%s -a 192.168.1.1\n\n", argv[0]);
		exit(0);
	}

	if (fname1 != NULL) {
		type = SEEDER;
		fname2 = strdup(fname1);
		fname = basename(fname2);		/* skip any "./" and other directory parts */
	}

	if (type == LEECHER) {
		if (ia.s_addr == -1) {
			printf("Error: in LEECHER mode '-a' parameter is obligatory\n");
			exit(1);
		}
	}


	if (type == SEEDER) {
		/* SEEDER mode */
		printf("Processing data, please wait... \n");

		fd = open(fname, O_RDONLY);
		if (fd < 0) {
			d_printf("error opening file1: %s\n", fname);
			exit(1);
		}
		fstat(fd, &stat);

		buf = malloc(chunk_size);

		nc = stat.st_size / chunk_size;
		if ((stat.st_size - stat.st_size / chunk_size * chunk_size) > 0)
			nc++;
		d_printf("number of chunks [%u]: %lu\n", chunk_size, nc);

		/* compute number of leaves - it is not the same as number of chunks */
		nl = 1 << (order2(nc));

		/* allocate array of chunks which will be linked to leaves later*/
		tab_chunk = malloc(nl * sizeof(struct chunk));
		memset(tab_chunk, 0, nl * sizeof(struct chunk));

		/* initialize array of chunks */
		for (x = 0; x < nl; x++)
			tab_chunk[x].state = CH_EMPTY;

		root8 = build_tree(nc, &ret);

		/* compute SHA hash for every chunk for given file */
		rd = 0;
		c = 0;
		while (rd < (uint64_t) stat.st_size) {
			r = read(fd, buf, chunk_size);

			SHA1Reset(&context);
			SHA1Input(&context, (uint8_t *)buf, r);
			SHA1Result(&context, digest);

			tab_chunk[c].state = CH_ACTIVE;
			tab_chunk[c].offset = c * chunk_size;
			tab_chunk[c].len = r;
			memcpy(tab_chunk[c].sha, digest, 20);
			memcpy(ret[2 * c].sha, digest, 20);
			ret[2 * c].state = ACTIVE;
			rd += r;
			c++;
		}
		close(fd);

		/* link array of chunks to leaves */
		for (x = 0; x < nl; x++) {
			ret[x * 2].chunk = &tab_chunk[x];
			tab_chunk[x].node = &ret[x * 2];
		}

		/* print the tree for given file */
		show_tree_root_based(&ret[root8->number]);

		dump_chunk_tab(tab_chunk, nl);

		update_sha(ret, nl);
		dump_tree(ret, nl);

		local_peer.tree = ret;
		local_peer.nl = nl;
		local_peer.nc = nc;
		local_peer.type = SEEDER;
		local_peer.start_chunk = 0;
		local_peer.end_chunk = nc - 1;
		local_peer.chunk_size = chunk_size;
		memcpy(local_peer.fname, fname, strlen(fname));
		local_peer.fname_len = strlen(fname);
		local_peer.file_size = stat.st_size;
		local_peer.timeout = timeout;

		proto_test(&local_peer);
	} else { /* LEECHER mode */
		local_peer.tree = NULL;
		local_peer.nl = 0;
		local_peer.nc = 0;
		local_peer.type = LEECHER;
		memset(local_peer.fname, 0, sizeof(local_peer.fname));
		local_peer.fname_len = 0;
		local_peer.file_size = 0;
		memcpy(&local_peer.seeder_addr, &ia, sizeof(struct in_addr));
		local_peer.timeout = 0;

		proto_test(&local_peer);
	}

	free(fname2);
	if (type == SEEDER) free(buf);
	free(tab_chunk);

	return 0;
}
