#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include "peregrine/utils.h"

int
pg_sockaddr_cmp(const struct sockaddr *s1, const struct sockaddr *s2)
{
	const struct sockaddr_in *sin1;
	const struct sockaddr_in *sin2;

	if (s1->sa_family != s2->sa_family) {
		return (-1);
	}

	switch (s1->sa_family) {
	case AF_INET:
		sin1 = (const struct sockaddr_in *)s1;
		sin2 = (const struct sockaddr_in *)s2;

		if (sin1->sin_addr.s_addr != sin2->sin_addr.s_addr) {
			return (-1);
		}

		if (sin1->sin_port != sin2->sin_port) {
			return (-1);
		}

		return (0);
	}

	return (-1);
}

void
pg_sockaddr_copy(struct sockaddr_storage *dest, const struct sockaddr *src)
{
	switch (src->sa_family) {
	case AF_INET:
		memcpy(dest, src, sizeof(struct sockaddr_in));
		return;
	}
}

const char *
pg_context_sha_by_file(struct pg_file *file)
{

	return (file->sha);
}

struct pg_file *
pg_context_file_by_sha(struct pg_context *ctx, const char *sha)
{
	struct pg_file *file;
	SLIST_FOREACH(file, &ctx->files, entry) {
		if (strcmp(file->sha, sha) == 0)
			return (file);
	}

	return (NULL);
}
