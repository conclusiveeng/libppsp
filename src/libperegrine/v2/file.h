/*
 * Copyright (c) 2020 Conclusive Engineering Sp. z o.o.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _PEER_H_
#define _PEER_H_
#include "peregrine_socket.h"

/**
 * @brief Genrate sha1 for all files added to peregrine context
 *
 * @param context peregrine_context
 */
void peregrine_file_generate_sha1(struct peregrine_context *context);

/**
 * @brief Adds single file to peregrine context
 *
 * @param context peregrine_contex
 * @param name path/name to file to be added
 */
void peregrine_file_add_file(struct peregrine_context *context, char *name);

/**
 * @brief Adds recursively all files from provided directory to peregrine contex
 *
 * @param context peregrine_contex
 * @param dname path to directory where the files are (should be without tailing '/')
 */
void peregrine_file_add_directory(struct peregrine_context *context, char *dname);

/**
 * @brief Prints to INFO log all files with calculated SHA1
 *
 * @param context  peregrine_context
 */
void peregrine_file_list_sha1(struct peregrine_context *context);

/**
 * @brief Finds file handle of selected file by it's SHA1
 *
 * @param context peregrine_context
 * @param sha1 sha1 of the file to look for
 * @return struct peregrine_file* handle to first file with corresponging SHA1 or NULL
 */
struct peregrine_file *peregrine_file_find(struct peregrine_context *context, uint8_t sha1[20]);

#endif /* _PEER_H_ */
