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

#ifndef LIBPEREGRINE_EVENTLOOP_H
#define LIBPEREGRINE_EVENTLOOP_H

#include <stdbool.h>
#include <unistd.h>
#include <signal.h>

/**
 * @file eventloop.h
 *
 * Event loop API.
 */

/**
 * Enumeration of possible triggers of a file descriptor watcher.
 */
enum pg_eventloop_fd_filter
{
	EVENTLOOP_FD_READABLE,	/**< Trigger when file descriptor is readable */
	EVENTLOOP_FD_WRITEABLE	/**< Trigger when file descriptor is writable */
};

/**
 * Event loop handle struct.
 */
struct pg_eventloop;

/**
 * A generic event loop callback type. Used by fd, timer and callback
 * events.
 */
typedef bool (*pg_eventloop_callback_t)(void *arg);

/**
 * Event loop callback type passing signal information. Used by signal
 * events.
 */
typedef bool (*pg_eventloop_signal_callback_t)(siginfo_t *siginfo, void *arg);

/**
 * Create a new event loop.
 *
 * @return Pointer to newly created @ref eventloop structure
 */
struct pg_eventloop *pg_eventloop_create(void);

/**
 * Destroy the event loop.
 *
 * This function frees all the memory associated with the event loop @p loop.
 *
 * @param loop Pointer to the existing @ref eventloop instance
 */
void pg_eventloop_destroy(struct pg_eventloop *loop);

/**
 * Return the event loop file descriptor.
 *
 * Use this function when integrating with a higher-order event loop.
 *
 * @param loop Pointer to the existing @ref eventloop instance
 * @return File descriptor number representing the event loop
 */
int pg_eventloop_get_fd(struct pg_eventloop *loop);

/**
 * Execute a callback when file descriptor becomes readable/writable.
 *
 * @param loop Pointer to existing @ref eventloop instance
 * @param fd File descriptor to be watched
 * @param fn Callback to be called when requested event occurs on the @p fd
 * @param filter Type of event triggering the callback: @p fd readable or writable
 * @param arg Pointer argument to be passed to the callback @p fn
 * @return Event identifier - can be used to remove event from @ref eventloop
 */
void *pg_eventloop_add_fd(struct pg_eventloop *loop, int fd, pg_eventloop_callback_t fn,
    enum pg_eventloop_fd_filter filter, void *arg);

/**
 * Execute a callback after a timeout.
 *
 * @param loop Pointer to existing @ref eventloop instance
 * @param timeout_ms Timer timeout
 * @param fn Callback to be called when requested event occurs
 * @param arg Pointer argument to be passed to the callback @p fn
 * @return Event identifier - can be used to remove event from @ref eventloop
 */
void *pg_eventloop_add_timer(struct pg_eventloop *loop, int timeout_ms,
    pg_eventloop_callback_t fn, void *arg);

/**
 * Execute a callback when event loop is idle.
 *
 * @param loop Pointer to existing @ref eventloop instance
 * @param fn Callback to be called when requested event occurs
 * @param arg Pointer argument to be passed to the callback @p fn
 * @return Event identifier - can be used to remove event from @ref eventloop
 */
void *pg_eventloop_add_callback(struct pg_eventloop *loop, pg_eventloop_callback_t fn,
    void *arg);

/**
 * Execute a callback when signal arrives.
 *
 * @param loop Pointer to existing @ref eventloop instance
 * @param signo Signal identifier triggering the event
 * @param fn Callback to be called when requested event occurs
 * @param arg Pointer argument to be passed to the callback @p fn
 * @return Event identifier - can be used to remove event from @ref eventloop
 */
void *pg_eventloop_add_signal(struct pg_eventloop *loop, int signo,
    pg_eventloop_signal_callback_t fn, void *arg);

/**
 * Remove a specified event from the @ref eventloop.
 *
 * @param event Event identifier to be removed - acquired from eventloop_add_*
 */
void pg_eventloop_remove_event(void *event);

/**
 * Execute one iteration of the event loop.
 *
 * @param loop Pointer to the @ref eventloop structure
 */
int pg_eventloop_step(struct pg_eventloop *loop);

/**
 * Force @ref pg_eventloop_run() to return from within the event callback
 *
 * @param loop  Pointer to existing @ref eventloop instance
 */
void pg_eventloop_quit(struct pg_eventloop *loop);

/**
 * Run the event loop forever.
 *
 * @param loop Pointer to the @ref eventloop structure
 */
int pg_eventloop_run(struct pg_eventloop *loop);

#endif /* LIBPEREGRINE_EVENTLOOP_H */
