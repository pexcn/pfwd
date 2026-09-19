#include "../util/compat.h"
#include "us_loop.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/timerfd.h>

struct us_loop *us_loop_new(unsigned max_events, unsigned defer_cap)
{
	struct us_loop *l;

	if (max_events == 0)
		max_events = 1;
	if (defer_cap == 0)
		defer_cap = 1;

	l = calloc(1, sizeof(*l));
	if (!l)
		return nullptr;

	l->epfd = epoll_create1(EPOLL_CLOEXEC);
	l->events = calloc(max_events, sizeof(*l->events));
	l->defer = calloc(defer_cap, sizeof(*l->defer));
	if (l->epfd < 0 || !l->events || !l->defer) {
		us_loop_free(l);
		return nullptr;
	}

	l->max_events = max_events;
	l->defer_cap = defer_cap;
	return l;
}

void us_loop_free(struct us_loop *l)
{
	if (!l)
		return;
	if (l->epfd >= 0)
		close(l->epfd);
	free(l->events);
	free(l->defer);
	free(l);
}

int us_loop_add(struct us_loop *l, int fd, uint32_t events, union ev_token tok)
{
	struct epoll_event ev = { .events = events, .data.u64 = tok.u64 };

	return epoll_ctl(l->epfd, EPOLL_CTL_ADD, fd, &ev);
}

int us_loop_mod(struct us_loop *l, int fd, uint32_t events, union ev_token tok)
{
	struct epoll_event ev = { .events = events, .data.u64 = tok.u64 };

	return epoll_ctl(l->epfd, EPOLL_CTL_MOD, fd, &ev);
}

int us_loop_del(struct us_loop *l, int fd)
{
	return epoll_ctl(l->epfd, EPOLL_CTL_DEL, fd, nullptr);
}

int us_loop_run(struct us_loop *l, int timeout_ms)
{
	l->n_events = epoll_wait(l->epfd, l->events, (int)l->max_events,
				 timeout_ms);
	if (l->n_events < 0) {
		if (errno == EINTR) {
			l->n_events = 0;
			return 0;
		}
		return -1;
	}
	return l->n_events;
}

void us_loop_defer_free(struct us_loop *l, void *obj,
			void (*fn)(void *obj, void *ctx), void *ctx)
{
	/* Cannot happen while defer_cap covers the pool, since an object is
	 * queued at most once. Flushing early is still safe: the generation
	 * check alone rejects stale events. */
	if (l->defer_n == l->defer_cap)
		us_loop_flush_deferred(l);

	l->defer[l->defer_n++] = (struct us_defer){
		.obj = obj,
		.fn = fn,
		.ctx = ctx,
	};
}

void us_loop_flush_deferred(struct us_loop *l)
{
	for (unsigned i = 0; i < l->defer_n; i++)
		l->defer[i].fn(l->defer[i].obj, l->defer[i].ctx);
	l->defer_n = 0;
}

int us_loop_timer_new(struct us_loop *l, unsigned interval_ms,
		      union ev_token tok)
{
	struct itimerspec its;
	int fd;

	fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
	if (fd < 0)
		return -1;

	its.it_interval.tv_sec = interval_ms / 1000u;
	its.it_interval.tv_nsec = (long)(interval_ms % 1000u) * 1000000L;
	its.it_value = its.it_interval;

	if (timerfd_settime(fd, 0, &its, nullptr) != 0 ||
	    us_loop_add(l, fd, EPOLLIN, tok) != 0) {
		close(fd);
		return -1;
	}

	return fd;
}
