#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <inttypes.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <peregrine/peregrine.h>
#include "internal.h"

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
pg_sockaddr_to_str(struct sockaddr *sa)
{
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	static char storage[64];

	switch (sa->sa_family) {
	case AF_INET:
		sin = (struct sockaddr_in *)sa;
		sprintf(storage, "%s:%d", inet_ntoa(sin->sin_addr), ntohs(sin->sin_port));
		return (storage);
	}

	errno = EINVAL;
	return (NULL);
}

struct pg_file *
pg_context_file_by_sha(struct pg_context *ctx, const char *sha)
{
	struct pg_file *file;

	SLIST_FOREACH(file, &ctx->files, entry) {
		if (memcmp(file->sha, sha, sizeof(file->sha)) == 0)
			return (file);
	}

	return (NULL);
}

const char *
pg_hexdump(const uint8_t *buf, size_t len)
{
	static char storage[1024];
	int bytes = 0;
	size_t i;

	for (i = 0; i < len; i++)
		bytes += sprintf(&storage[bytes], "%02x", buf[i]);

	return (storage);
}

const char *
pg_swarm_to_str(struct pg_swarm *swarm)
{
	return pg_hexdump(swarm->swarm_id, swarm->swarm_id_len);
}

const char *
pg_peer_to_str(struct pg_peer *peer)
{
	return pg_sockaddr_to_str((struct sockaddr *)&peer->addr);
}

uint32_t
pg_new_channel_id(void)
{
	return (rand());
}

uint8_t *
pg_parse_sha1(const char *str)
{
	int i;
	int pos = 0;
	uint8_t *result;

	if (str == NULL || strlen(str) == 0)
		return (NULL);

	result = malloc(20);
	for (i = 0; i < 20; i++) {
		if (sscanf(str + pos, "%02" SCNx8, &result[i]) < 1) {
			errno = EINVAL;
			free(result);
			return (NULL);
		}

		pos += 2;
	}

	return (result);
}

void *
xmalloc(size_t length)
{
	void *ret;

	ret = malloc(length);
	assert(ret != NULL);

	return (ret);
}

void *
xcalloc(size_t nelems, size_t length)
{
	void *ret;

	ret = calloc(nelems, length);
	assert(ret != NULL);

	return (ret);
}

void *
xrealloc(void *ptr, size_t length)
{
	void *ret;

	ret = realloc(ptr, length);
	assert(ret != NULL);

	return (ret);
}
