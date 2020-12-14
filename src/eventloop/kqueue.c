//
// Created by jakub on 14.12.2020.
//

#include <sys/types.h>
#include <sys/param.h>
#include <sys/event.h>
#include <signal.h>
#include "internal.h"
#include "eventloop.h"

#define EVENTLOOP_MAXEVENTS	16

enum pg_eventloop_event_type
{
	EVENT_FD,
	EVENT_TIMER,
	EVENT_CALLBACK,
	EVENT_SIGNAL
};

struct pg_eventloop_event
{
	struct pg_eventloop *loop;
	enum pg_eventloop_event_type type;
	struct kevent kev;
	pg_eventloop_callback_t fn;
	pg_eventloop_signal_callback_t signal_fn;
	void *fn_arg;
	TAILQ_ENTRY(eventloop_event) link;
};

struct pg_eventloop
{
	int kqueue_fd;
	bool quit;
};

static void pg_eventloop_handle_event(struct kevent *kev);

static int pg_eventloop_timer_id = 0;
static int pg_eventloop_user_id = 0;

struct pg_eventloop *
pg_eventloop_create(void)
{
	struct pg_eventloop *loop;

	loop = xcalloc(1, sizeof(*loop));

	loop->kqueue_fd = kqueue();
	if (loop->kqueue_fd < 0)
		PANIC_ERRNO("kqueue");

	return (loop);
}

void
pg_eventloop_destroy(struct pg_eventloop *loop)
{

}

void *
pg_eventloop_add_fd(struct pg_eventloop *loop, int fd, pg_eventloop_callback_t fn,
    enum pg_eventloop_fd_filter filter, void *arg)
{
	struct eventloop_event *ev;
	int evfilt;

	ev = calloc(1, sizeof(*ev));
	ev->type = EVENT_FD;
	ev->fn = fn;
	ev->fn_arg = arg;
	ev->loop = loop;

	switch (filter) {
		case EVENTLOOP_FD_READABLE:
			evfilt = EVFILT_READ;
			break;

		case EVENTLOOP_FD_WRITEABLE:
			evfilt = EVFILT_WRITE;
			break;

		default:
			PANIC("Invalid filter value: %d", filter);
	}

	EV_SET(&ev->kev, fd, evfilt, EV_ADD | EV_ENABLE, 0, 0, ev);
	if (kevent(loop->kqueue_fd, &ev->kev, 1, NULL, 0, NULL) != 0)
		PANIC_ERRNO("kevent");

	return (ev);
}

void *
pg_eventloop_add_timer(struct pg_eventloop *loop, int timeout_ms,
    pg_eventloop_callback_t fn, void *arg)
{
	struct eventloop_event *ev;

	ev = xcalloc(1, sizeof(*ev));
	ev->type = EVENT_TIMER;
	ev->loop = loop;
	ev->fn = fn;
	ev->fn_arg = arg;

	EV_SET(&ev->kev, ++eventloop_timer_id,
	       EVFILT_TIMER, EV_ADD | EV_ENABLE, 0,
	       timeout_ms, ev);

	if (kevent(loop->kqueue_fd, &ev->kev, 1, NULL, 0, NULL) != 0)
		PANIC_ERRNO("kevent");

	return (ev);
}

void *
pg_eventloop_add_callback(struct pg_eventloop *loop, pg_eventloop_callback_t fn,
    void *arg)
{
	struct pg_eventloop_event *ev;
	struct kevent trigger;

	ev = xcalloc(1, sizeof(*ev));
	ev->type = EVENT_CALLBACK;
	ev->fn = fn;
	ev->fn_arg = arg;
	ev->loop = loop;

	EV_SET(&ev->kev, ++eventloop_user_id, EVFILT_USER,
	    EV_ADD | EV_ENABLE, 0, 0, ev);

	EV_SET(&trigger, eventloop_user_id, EVFILT_USER, 0, NOTE_TRIGGER,
	    0, ev);

	if (kevent(loop->kqueue_fd, &ev->kev, 1, NULL, 0, NULL) != 0)
		PANIC_ERRNO("kevent");

	if (kevent(loop->kqueue_fd, &trigger, 1, NULL, 0, NULL) != 0)
		PANIC_ERRNO("kevent");

	return (ev);
}

void *
pg_eventloop_add_signal(struct pg_eventloop *loop, int signo,
    pg_eventloop_signal_callback_t fn, void *arg)
{
	struct pg_eventloop_event *ev;

	ev = xcalloc(1, sizeof(*ev));
	ev->type = EVENT_SIGNAL;
	ev->signal_fn = fn;
	ev->fn_arg = arg;
	ev->loop = loop;

	EV_SET(&ev->kev, ++eventloop_user_id, EVFILT_SIGNAL,
	    EV_ADD | EV_ENABLE, 0, 0, ev);

	if (kevent(loop->kqueue_fd, &ev->kev, 1, NULL, 0, NULL) != 0)
		PANIC_ERRNO("kevent");

	return (ev);
}

void
pg_eventloop_remove_event(void *event)
{
	struct pg_eventloop_event *ev = event;

	EV_SET(&ev->kev, ev->kev.ident, ev->kev.filter, EV_DELETE, 0, 0, NULL);
	if (kevent(ev->loop->kqueue_fd, &ev->kev, 1, NULL, 0, NULL) != 0) {
		if (errno != EBADF && errno != ENOENT)
			PANIC_ERRNO("kevent");
	}
}

int
pg_eventloop_run(struct eventloop *loop)
{
	struct kevent kev[EVENTLOOP_MAXEVENTS];
	int ret;
	int i;

	while (!loop->quit) {
		ret = kevent(loop->kqueue_fd, NULL, 0, kev,
		    EVENTLOOP_MAXEVENTS, NULL);
		if (ret < 0) {
			if (errno == EINTR)
				continue;

			return (-1);
		}

		DEBUG("kevent returned %d", ret);

		for (i = 0; i < ret; i++)
			pg_eventloop_handle_event(&kev[i]);
	}

	return (0);
}

void
pg_eventloop_quit(struct pg_eventloop *loop)
{

	loop->quit = true;
}

static void
pg_eventloop_handle_event(struct kevent *kev)
{
	struct pg_eventloop_event *ev;
	struct kevent trigger;
	struct timespec ts = { 0, 0 };
	siginfo_t siginfo;
	sigset_t set;
	int signo;
	int status;
	int ret;

	DEBUG("processing event %p", kev);

	ev = kev->udata;

	switch (ev->type) {
	case EVENT_FD:
		DEBUG("EVENT_FD: fd=%d", ev->kev.ident);
		if (!ev->fn(ev->fn_arg))
			pg_eventloop_remove_event(ev);
		break;

	case EVENT_TIMER:
		DEBUG("EVENT_TIMER");
		if (!ev->fn(ev->fn_arg))
			pg_eventloop_remove_event(ev);
		break;

	case EVENT_CALLBACK:
		DEBUG("EVENT_CALLBACK");

		if (!ev->fn(ev->fn_arg)) {
			pg_eventloop_remove_event(ev);
		} else {
			EV_SET(&trigger, ev->kev.ident, EVFILT_USER, 0,
			       NOTE_TRIGGER, 0, ev);
			if (kevent(ev->loop->kqueue_fd, &trigger, 1, NULL, 0,
				   NULL) != 0)
				PANIC_ERRNO("kevent");
		}
		break;

	case EVENT_SIGNAL:
		sigemptyset(&set);
		sigaddset(&set, kev->data);

		signo = sigtimedwait(&set, &siginfo, &ts);
		if (signo < 0)
			PANIC_ERRNO("sigtimedwait");

		DEBUG("EVENT_SIGNAL: si_code=%d si_signo=%d si_pid=%d",
		    siginfo.si_code, siginfo.si_signo, siginfo.si_pid);

		if (!ev->signal_fn(&siginfo, ev->fn_arg))
			pg_eventloop_remove_event(ev);
		break;

	default:
		PANIC("Invalid event type %d", ev->type);
	}
}
