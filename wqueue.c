#include <sys/queue.h>
#include <stdio.h>
#include <stdlib.h>

#include "wqueue.h"
#include "peer.h"
#include "debug.h"


INTERNAL_LINKAGE void
wq_init (struct wqueue_head *wh)
{
	STAILQ_INIT(wh);
}


/* add entry "e" to wqueue pointed by "wh" */
INTERNAL_LINKAGE void
wq_append (struct wqueue_head *wh, struct wqueue_entry *e)
{
	STAILQ_INSERT_TAIL(wh, e, next);
}


INTERNAL_LINKAGE int
wq_send(struct wqueue_head *wh, char *buf, uint16_t buf_len)
{
	struct wqueue_entry *e;

	e = malloc(sizeof(struct wqueue_entry));
	e->msg = malloc(buf_len);
	e->msg_len = buf_len;
	memcpy(e->msg, buf, buf_len);

	wq_append(wh, e);

	return 0;
}


INTERNAL_LINKAGE int
wq_receive (struct wqueue_head *wh, char *buf, uint16_t buf_len)
{
	int ret;
	struct wqueue_entry *e;

	_assert(buf != NULL, "%s", "buf parameter must be != NULL\n");

	if (!STAILQ_EMPTY(wh)) {
		e = STAILQ_FIRST(wh);
		_assert(e->msg_len <= buf_len, "message len (%u) is bigger than buffer(%u)\n", e->msg_len, buf_len);
		memcpy(buf, e->msg, e->msg_len);
		ret = e->msg_len;
		STAILQ_REMOVE_HEAD(wh, next);
		free(e->msg);
		free(e);
	} else {
		ret = -1;			/* queue is empty */
	}

	return ret;
}


/* peek first element from queue without removing it */
INTERNAL_LINKAGE int
wq_peek (struct wqueue_head *wh, char *buf, uint16_t buf_len)
{
	int ret;
	struct wqueue_entry *e;

	_assert(buf != NULL, "%s", "buf parameter must be != NULL\n");

	if (!STAILQ_EMPTY(wh)) {
		e = STAILQ_FIRST(wh);
		_assert(e->msg_len <= buf_len, "message len (%u) is bigger than buffer(%u)\n", e->msg_len, buf_len);
		memcpy(buf, e->msg, e->msg_len);
		ret = e->msg_len;
	} else {
		ret = -1;			/* queue is empty */
	}

	return ret;
}


/* count number of elements */
INTERNAL_LINKAGE int
wq_no_elements (struct wqueue_head *wh)
{
	int ret;
	struct wqueue_entry *i;

	ret = 0;
	if (!STAILQ_EMPTY(wh)) {
		STAILQ_FOREACH(i, wh, next) {
			ret++;
		}
	}

	return ret;
}
