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

enum libperegrine_log_level { LIBPEREGRINE_DEBUG, LIBPEREGRINE_INFO, LIBPEREGRINE_WARNING, LIBPEREGRINE_ERROR };

void libperegrine_logf(enum libperegrine_log_level level, const char *func, const char *fmt, ...);

#if defined(LIBPEREGRINE_DEBUG_ENABLED)
#define PEREGRINE_LOG(level, fmt, ...) libperegrine_logf(level, __func__, fmt, ##__VA_ARGS__)
#define PEREGRINE_DEBUG(fmt, ...)      libperegrine_logf(LIBPEREGRINE_DEBUG, __func__, fmt, ##__VA_ARGS__)
#define PEREGRINE_INFO(fmt, ...)       libperegrine_logf(LIBPEREGRINE_INFO, __func__, fmt, ##__VA_ARGS__)
#define PEREGRINE_WARN(fmt, ...)       libperegrine_logf(LIBPEREGRINE_WARNING, __func__, fmt, ##__VA_ARGS__)
#define PEREGRINE_ERROR(fmt, ...)      libperegrine_logf(LIBPEREGRINE_ERROR, __func__, fmt, ##__VA_ARGS__)
#else
#define PEREGRINE_LOG(level, fmt, ...)
#define PEREGRINE_DEBUG(fmt, ...)
#define PEREGRINE_INFO(fmt, ...)
#define PEREGRINE_WARN(fmt, ...)
#define PEREGRINE_ERROR(fmt, ...)
#endif

void dbgutil_str2hex(char *in, size_t in_size, char *out, size_t out_size);

#endif /* LIBPEREGRINE_LOG_H */
