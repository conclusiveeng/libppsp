/*
 * Copyright (c) 2020 Conclusive Engineering Sp. z o.o.
 * Copyright 2016 Jakub Klama <jceel@FreeBSD.org>
 * All rights reserved
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted providing that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef LIBPEREGRINE_LOG_H
#define LIBPEREGRINE_LOG_H

#include <stddef.h>
#include <stdint.h>

enum peregrine_log_level { PEREGRINE_DEBUG, PEREGRINE_INFO, PEREGRINE_WARNING, PEREGRINE_ERROR };

void pg_logf(enum peregrine_log_level level, const char *func, const char *fmt, ...);

#define LIBPEREGRINE_DEBUG_ENABLED

#if defined(LIBPEREGRINE_DEBUG_ENABLED)
#define LOG(level, fmt, ...) pg_logf(level, __func__, fmt, ##__VA_ARGS__)
#define DEBUG(fmt, ...)      pg_logf(PEREGRINE_DEBUG, __func__, fmt, ##__VA_ARGS__)
#define INFO(fmt, ...)       pg_logf(PEREGRINE_INFO, __func__, fmt, ##__VA_ARGS__)
#define WARN(fmt, ...)       pg_logf(PEREGRINE_WARNING, __func__, fmt, ##__VA_ARGS__)
#define ERROR(fmt, ...)      pg_logf(PEREGRINE_ERROR, __func__, fmt, ##__VA_ARGS__)
#else
#define LOG(level, fmt, ...)
#define DEBUG(fmt, ...)
#define INFO(fmt, ...)
#define WARN(fmt, ...)
#define ERROR(fmt, ...)
#endif

void dbgutil_str2hex(char *in, size_t in_size, char *out, size_t out_size);

#endif /* LIBPEREGRINE_LOG_H */
