//
// Created by jakub on 10.12.2020.
//

#ifndef PEREGRINE_UTILS_H
#define PEREGRINE_UTILS_H

#include <sys/socket.h>

int pg_sockaddr_cmp(const struct sockaddr *s1, const struct sockaddr *s2);
void pg_sockaddr_copy(struct sockaddr_storage *dest, const struct sockaddr *src);

#endif // PEREGRINE_UTILS_H
