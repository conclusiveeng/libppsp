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

#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/timerfd.h>
#include <sys/signalfd.h>
#include <sys/queue.h>
#include "../internal.h"
#include "../eventloop.h"
#include "../log.h"

#define EVENTLOOP_MAXEVENTS		16

enum pg_eventloop_event_type
{
	EVENT_FD,
	EVENT_TIMER,
	EVENT_CALLBACK,
	EVENT_SIGNAL,
	EVENT_PROCESS
};

struct pg_eventloop_event
{
	struct pg_eventloop *loop;
	enum pg_eventloop_event_type type;
	int fd;
	pg_eventloop_callback_t fn;
	pg_eventloop_signal_callback_t signal_fn;
	void *fn_arg;
	TAILQ_ENTRY(pg_eventloop_event) link;
};

struct pg_eventloop
{
	int epfd;
	bool quit;
	TAILQ_HEAD(, pg_eventloop_event) events;
};

static void pg_eventloop_handle_event(struct pg_eventloop_event *ev);

struct pg_eventloop *
pg_eventloop_create(void)
{
	struct pg_eventloop *loop;

	loop = xcalloc(1, sizeof(*loop));
	TAILQ_INIT(&loop->events);

	loop->epfd = epoll_create1(EPOLL_CLOEXEC);
	if (loop->epfd == -1) {
		free(loop);
		return (NULL);
	}

	return (loop);
}

int
pg_eventloop_get_fd(struct pg_eventloop *loop)
{
	return (loop->epfd);
}

void
pg_eventloop_destroy(struct pg_eventloop *loop)
{

}

void *
pg_eventloop_add_fd(struct pg_eventloop *loop, int fd, pg_eventloop_callback_t fn,
    enum pg_eventloop_fd_filter filter, void *arg)
{
	struct pg_eventloop_event *ev;
	struct epoll_event epev;

	DEBUG("add fd %d, callback %p(%p)", fd, fn, arg);

	ev = xcalloc(1, sizeof(*ev));
	ev->type = EVENT_FD;
	ev->loop = loop;
	ev->fd = fd;
	ev->fn = fn;
	ev->fn_arg = arg;

	switch (filter) {
	case EVENTLOOP_FD_READABLE:
		epev.events = EPOLLIN | EPOLLERR;
		break;

	case EVENTLOOP_FD_WRITEABLE:
		epev.events = EPOLLOUT | EPOLLERR;
		break;

	default:
		PANIC("Invalid filter value: %d", filter);
	}

	epev.data.ptr = ev;

	if (epoll_ctl(loop->epfd, EPOLL_CTL_ADD, ev->fd, &epev) != 0) {
		free(ev);
		return (NULL);
	}

	return (ev);
}

void *
pg_eventloop_add_timer(struct pg_eventloop *loop, int timeout_ms,
    pg_eventloop_callback_t fn, void *arg)
{
	struct pg_eventloop_event *ev;
	struct epoll_event epev;
	struct itimerspec ts;
	int fd;

	DEBUG("add timer every %d ms, callback %p(%p)", timeout_ms, fn, arg);

	fd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC);
	if (fd < 0)
		return (NULL);

	ts.it_interval.tv_sec = timeout_ms / 1000;
	ts.it_interval.tv_nsec = (timeout_ms % 1000) * 1000000;
	ts.it_value.tv_sec = ts.it_interval.tv_sec;
	ts.it_value.tv_nsec = ts.it_interval.tv_nsec;

	ev = xcalloc(1, sizeof(*ev));
	ev->type = EVENT_TIMER;
	ev->loop = loop;
	ev->fd = fd;
	ev->fn = fn;
	ev->fn_arg = arg;

	epev.events = EPOLLIN | EPOLLERR;
	epev.data.ptr = ev;

	if (timerfd_settime(fd, 0, &ts, NULL) != 0) {
		close(fd);
		free(ev);
		return (NULL);
	}

	if (epoll_ctl(loop->epfd, EPOLL_CTL_ADD, ev->fd, &epev) != 0) {
		close(fd);
		free(ev);
		return (NULL);
	}

	return (ev);
}

void *
pg_eventloop_add_callback(struct pg_eventloop *loop, pg_eventloop_callback_t fn, void *arg)
{
	struct pg_eventloop_event *ev;
	struct epoll_event epev;
	int fd;

	DEBUG("add callback %p(%p)", fn, arg);

	fd = eventfd(0, EFD_CLOEXEC);
	if (fd < 0)
		return (NULL);

	ev = xcalloc(1, sizeof(*ev));
	ev->type = EVENT_CALLBACK;
	ev->loop = loop;
	ev->fd = fd;
	ev->fn = fn;
	ev->fn_arg = arg;

	epev.events = EPOLLIN | EPOLLERR;
	epev.data.ptr = ev;

	if (epoll_ctl(loop->epfd, EPOLL_CTL_ADD, ev->fd, &epev) != 0) {
		close(fd);
		free(ev);
		return (NULL);
	}

	eventfd_write(fd, 1);
	return (ev);
}

void *
pg_eventloop_add_signal(struct pg_eventloop *loop, int signo,
    pg_eventloop_signal_callback_t fn, void *arg)
{
	struct pg_eventloop_event *ev;
	struct epoll_event epev;
	sigset_t mask;
	int fd;

	DEBUG("add signal %d, callback %p(%p)", signo, fn, arg);

	sigemptyset(&mask);
	sigaddset(&mask, signo);
	sigprocmask(SIG_BLOCK, &mask, NULL);

	fd = signalfd(-1, &mask, SFD_CLOEXEC);
	if (fd < 0)
		return (NULL);

	ev = xcalloc(1, sizeof(*ev));
	ev->type = EVENT_SIGNAL;
	ev->loop = loop;
	ev->fd = fd;
	ev->signal_fn = fn;
	ev->fn_arg = arg;

	epev.events = EPOLLIN | EPOLLERR;
	epev.data.ptr = ev;

	if (epoll_ctl(loop->epfd, EPOLL_CTL_ADD, ev->fd, &epev) != 0) {
		close(fd);
		free(ev);
		return (NULL);
	}

	return (ev);
}

void
pg_eventloop_remove_event(void *event)
{
	struct pg_eventloop_event *ev = event;

	DEBUG("remove event %p, fd %d", event, ev->fd);

	if (epoll_ctl(ev->loop->epfd, EPOLL_CTL_DEL, ev->fd, NULL) < 0) {
		if (errno != EBADF)
			PANIC("epoll_ctl error: %s", strerror(errno));
	}
}

int
pg_eventloop_step(struct pg_eventloop *loop)
{
	struct epoll_event evs[EVENTLOOP_MAXEVENTS];
	sigset_t sigset;
	int ret;
	int i;

	sigemptyset(&sigset);
	sigaddset(&sigset, SIGCHLD);
	sigaddset(&sigset, SIGTERM);
	sigaddset(&sigset, SIGINT);
	sigaddset(&sigset, SIGIO);
	sigaddset(&sigset, SIGPIPE);

	ret = epoll_pwait(loop->epfd, evs, EVENTLOOP_MAXEVENTS, -1, &sigset);
	if (ret < 0)
		return (-1);

	DEBUG("epoll_wait returned %d", ret);

	for (i = 0; i < ret; i++)
		pg_eventloop_handle_event(evs[i].data.ptr);

	return (0);
}

int
pg_eventloop_run(struct pg_eventloop *loop)
{
	int ret;

	while (!loop->quit) {
		ret = pg_eventloop_step(loop);
		if (ret < 0) {
			if (errno == EINTR)
				continue;

			return (-1);
		};
	}

	return (0);
}

void
eventloop_quit(struct pg_eventloop *loop)
{

	loop->quit = true;
}

static void
pg_eventloop_handle_event(struct pg_eventloop_event *ev)
{
	struct signalfd_siginfo sfd_siginfo;
	struct itimerspec ts;
	siginfo_t siginfo;
	eventfd_t val;
	uint64_t timeval;

	DEBUG("processing event %p", ev);

	switch (ev->type) {
	case EVENT_FD:
		DEBUG("EVENT_FD: fd=%d", ev->fd);
		if (!ev->fn(ev->fn_arg))
			pg_eventloop_remove_event(ev);
		break;

	case EVENT_TIMER:
		DEBUG("EVENT_TIMER: fd=%d", ev->fd);

		if (read(ev->fd, &timeval, sizeof(uint64_t)) != sizeof(uint64_t))
			WARN("read: error: %s", strerror(errno));

		if (timerfd_gettime(ev->fd, &ts) != 0) {
			WARN("timerfd_gettime: error: %s", strerror(errno));
			break;
		}

		if (!ev->fn(ev->fn_arg)) {
			pg_eventloop_remove_event(ev);
			close(ev->fd);
		}
		break;

	case EVENT_CALLBACK:
		DEBUG("EVENT_CALLBACK: fd=%d", ev->fd);
		if (eventfd_read(ev->fd, &val) != 0) {
			WARN("eventfd_gettime: error=%s", strerror(errno));
			break;
		}

		if (!ev->fn(ev->fn_arg))
			close(ev->fd);
		else
			eventfd_write(ev->fd, 1);
		break;

	case EVENT_SIGNAL:
		if (read(ev->fd, &sfd_siginfo, sizeof(sfd_siginfo))
		    < (ssize_t)sizeof(sfd_siginfo)) {
			WARN("read: error=%s", strerror(errno));
			break;
		}

		siginfo.si_code = sfd_siginfo.ssi_code;
		siginfo.si_signo = sfd_siginfo.ssi_signo;
		siginfo.si_pid = sfd_siginfo.ssi_pid;
		siginfo.si_uid = sfd_siginfo.ssi_uid;
		siginfo.si_status = sfd_siginfo.ssi_status;

		DEBUG("EVENT_SIGNAL: fd=%d si_code=%d si_signo=%d",
		    ev->fd, siginfo.si_code, siginfo.si_signo);

		if (!ev->signal_fn(&siginfo, ev->fn_arg))
			pg_eventloop_remove_event(ev);

		break;

	default:
		PANIC("Invalid event type %d", ev->type);
	}
}
