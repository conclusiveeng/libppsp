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

#include "peregrine_seeder.h"
#include "debug.h"
#include "net.h"
#include "peer.h"
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

/**
 * @brief Create instance of seeder
 *
 * @param[in] params Initial parameters for seeder
 *
 * @return Handle of just created seeder
 */
peregrine_handle_t
peregrine_seeder_create(peregrine_seeder_params_t *params)
{
  peregrine_handle_t handle;
  struct peer *local_seeder;

  local_seeder = malloc(sizeof(struct peer));
  if (local_seeder != NULL) {
    memset(local_seeder, 0, sizeof(struct peer));

    local_seeder->chunk_size = params->chunk_size;
    local_seeder->timeout = params->timeout;
    local_seeder->port = params->port;
    local_seeder->type = SEEDER;

    SLIST_INIT(&local_seeder->file_list_head);
    SLIST_INIT(&local_seeder->other_seeders_list_head);
  }
  handle = (int64_t)local_seeder;
  return handle;
}

/**
 * @brief Add new seeder to list of alternative seeders
 *
 * @param[in] handle Handle of seeder
 * @param[in] sa Structure with IP address and UDP port number of added seeder
 *
 * @return Return status of adding new seeder
 */
int
peregrine_seeder_add_seeder(peregrine_handle_t handle, struct sockaddr_in *sa)
{
  int ret;
  struct other_seeders_entry *ss;
  struct peer *local_seeder;

  local_seeder = (struct peer *)handle;

  ret = 0;

  ss = malloc(sizeof(struct other_seeders_entry));
  if (ss != NULL) {
    memcpy(&ss->sa, sa, sizeof(struct sockaddr_in));
    SLIST_INSERT_HEAD(&local_seeder->other_seeders_list_head, ss, next);
  } else {
    ret = -ENOMEM;
  }

  return ret;
}

/**
 * @brief Remove seeder from list of alternative seeders
 *
 * @param[in] handle Handle of seeder
 * @param[in] sa Structure with IP address and UDP port number of added seeder
 *
 * @return Return status of removing seeder
 */
int
peregrine_seeder_remove_seeder(peregrine_handle_t handle, struct sockaddr_in *sa)
{
  int ret;
  struct other_seeders_entry *e;
  struct peer *local_seeder;

  local_seeder = (struct peer *)handle;

  ret = 0;
  SLIST_FOREACH(e, &local_seeder->other_seeders_list_head, next)
  {
    d_printf("%s:%u\n", inet_ntoa(e->sa.sin_addr), ntohs(e->sa.sin_port));
    if (memcmp(&sa->sin_addr, &e->sa.sin_addr, sizeof(e->sa.sin_addr)) == 0) {
      d_printf("entry to remove found - removing: %s:%u\n", inet_ntoa(e->sa.sin_addr), ntohs(e->sa.sin_port));
      SLIST_REMOVE(&local_seeder->other_seeders_list_head, e, other_seeders_entry, next);
    }
  }

  return ret;
}

/**
 * @brief Add file or directory to set of seeded files
 *
 * @param[in] handle Handle of seeder
 * @param[in] name Path to the file or directory
 */
void
peregrine_seeder_add_file_or_directory(peregrine_handle_t handle, char *name)
{
  char sha[40 + 1];
  int st;
  int s;
  int y;
  struct stat stat;
  struct file_list_entry *f;
  struct peer *local_seeder;

  local_seeder = (struct peer *)handle;

  st = lstat(name, &stat);
  if (st != 0) {
    d_printf("Error: %s\n", strerror(errno));
  }

  /* is "name" directory name or filename? */
  if (stat.st_mode & S_IFDIR) { /* directory */
    d_printf("adding files from directory: %s\n", name);
    create_file_list(local_seeder, name);
  } else if (stat.st_mode & S_IFREG) { /* filename */
    d_printf("adding file: %s\n", name);
    f = malloc(sizeof(struct file_list_entry));
    memset(f->path, 0, sizeof(f->path));
    strcpy(f->path, name);
    lstat(f->path, &stat);
    f->file_size = stat.st_size;
    SLIST_INSERT_HEAD(&local_seeder->file_list_head, f, next);
  }

  SLIST_FOREACH(f, &local_seeder->file_list_head, next)
  {
    /* does the tree already exist for given file? */
    if (f->tree_root == NULL) { /* no - so create tree for it */
      printf("processing: %s \n", f->path);
      fflush(stdout);
      process_file(f, local_seeder);

      memset(sha, 0, sizeof(sha));
      s = 0;
      for (y = 0; y < 20; y++) {
	s += sprintf(sha + s, "%02x", f->tree_root->sha[y] & 0xff);
      }
      printf("sha1: %s\n", sha);
    }
  }
}

/*
 * @brief Remove given file entry from seeded file list
 *
 * @param[in] f File entry to remove
 */
INTERNAL_LINKAGE
void
peregrine_remove_and_free(peregrine_handle_t handle, struct file_list_entry *f)
{
  struct peer *local_seeder;

  local_seeder = (struct peer *)handle;
  free(f->tab_chunk);
  free(f->tree);
  f->tab_chunk = NULL;
  f->tree = f->tree_root = NULL;

  SLIST_REMOVE(&local_seeder->file_list_head, f, file_list_entry, next);
  free(f);
}

/**
 * @brief Remove file or directory from seeded file list
 *
 * @param[in] handle Handle of seeder
 * @param[in] name Path to the file or directory
 *
 * @return Return status of removing file or directory
 */
int
peregrine_seeder_remove_file_or_directory(peregrine_handle_t handle, char *name)
{
  char *c;
  char *buf;
  int ret;
  struct file_list_entry *f;
  struct stat stat;
  struct peer *local_seeder;

  local_seeder = (struct peer *)handle;

  ret = 0;
  lstat(name, &stat);
  if (stat.st_mode & S_IFREG) { /* does the user want to remove file? */
    SLIST_FOREACH(f, &local_seeder->file_list_head, next)
    {
      if (strcmp(f->path, name) == 0) {
	d_printf("file to remove found: %s\n", name);
	peregrine_remove_and_free(handle, f);
      }
    }
  } else if (stat.st_mode & S_IFDIR) { /* does the user want to remove files
                                          from specific directory? */
    buf = malloc(strlen(name) + 2);
    memset(buf, 0, strlen(name) + 2);
    strcpy(buf, name);

    /* "name" is directory name and must be ended with slash here - check it */
    if (buf[strlen(buf) - 1] != '/') {
      buf[strlen(buf)] = '/';
      d_printf("adding / to dir name: %s => %s\n", name, buf);
    }

    SLIST_FOREACH(f, &local_seeder->file_list_head, next)
    {
      c = strstr(f->path, buf); /* compare current file entry with directory name to remove */
      if (c == f->path) {       /* if both matches */
	d_printf("removing file: %s\n", f->path);
	peregrine_remove_and_free(handle, f);
      }
    }
    free(buf);
  }

  return ret;
}

/**
 * @brief Run seeder pointed by handle parameter
 *
 * @param[in] handle Handle of seeder
 */
void
peregrine_seeder_run(peregrine_handle_t handle)
{
  struct peer *local_seeder;

  local_seeder = (struct peer *)handle;
  net_seeder_mq(local_seeder);
}

/**
 * @brief Close of opened seeder handle
 *
 * @param[in] handle Handle of seeder
 */
void
peregrine_seeder_close(peregrine_handle_t handle)
{
  struct peer *local_seeder;

  local_seeder = (struct peer *)handle;

  free(local_seeder);
}
