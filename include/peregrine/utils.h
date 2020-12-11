//
// Created by jakub on 10.12.2020.
//

#ifndef PEREGRINE_UTILS_H
#define PEREGRINE_UTILS_H

#include <sys/socket.h>
#include "file.h"

int pg_sockaddr_cmp(const struct sockaddr *s1, const struct sockaddr *s2);
void pg_sockaddr_copy(struct sockaddr_storage *dest, const struct sockaddr *src);
const char *pg_context_sha_by_file(struct pg_file *file);
struct pg_file *pg_context_file_by_sha(struct pg_context *ctx, const char *sha);

#endif // PEREGRINE_UTILS_H
