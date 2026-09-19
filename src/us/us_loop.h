#ifndef PORTFWD_US_LOOP_H
#define PORTFWD_US_LOOP_H

#include <stdint.h>
#include <sys/epoll.h>

enum ev_kind {
	EV_NONE = 0,
	EV_SIGNAL,
	EV_TIMER,
	EV_LISTENER_TCP,
	EV_LISTENER_UDP,
	EV_CONN_CLIENT,
	EV_CONN_UPSTREAM,
	EV_UDP_UPSTREAM,
};

/* Packed into epoll_event.data.u64. Never a raw pointer: an event that was
 * already queued when its object was released must resolve to NULL rather
 * than to a recycled slot. See the design manual, 4.7 and 10.2. */
union ev_token {
	uint64_t u64;
	struct {
		uint32_t slot;
		uint16_t generation16;
		uint8_t  kind;
		uint8_t  _pad;
	} f;
};

static_assert(sizeof(union ev_token) == sizeof(uint64_t),
	      "ev_token must fit in epoll_event.data.u64");

static inline union ev_token ev_token_make(uint8_t kind, uint32_t slot,
					   uint32_t generation)
{
	union ev_token t = {
		.f = {
			.slot = slot,
			.generation16 = (uint16_t)generation,
			.kind = kind,
		},
	};

	return t;
}

/* Objects released during a batch of events are parked here and handed back to
 * their pool only once the whole batch has been dispatched, so that a stale
 * event later in the same batch cannot land on a recycled slot. */
struct us_defer {
	void  *obj;
	void (*fn)(void *obj, void *ctx);
	void  *ctx;
};

struct us_loop {
	int                 epfd;
	struct epoll_event *events;
	unsigned            max_events;
	int                 n_events;

	struct us_defer    *defer;
	unsigned            defer_cap;
	unsigned            defer_n;
};

/* defer_cap must be at least the number of objects that can be released in a
 * single batch, i.e. the capacity of the pool feeding the loop. */
struct us_loop *us_loop_new(unsigned max_events, unsigned defer_cap);
void us_loop_free(struct us_loop *l);

int  us_loop_add(struct us_loop *l, int fd, uint32_t events, union ev_token tok);
int  us_loop_mod(struct us_loop *l, int fd, uint32_t events, union ev_token tok);
int  us_loop_del(struct us_loop *l, int fd);

/* Waits and stores the batch in l->events / l->n_events. Returns the number of
 * ready fds, 0 on timeout or EINTR, -1 on a real error. */
int  us_loop_run(struct us_loop *l, int timeout_ms);

void us_loop_defer_free(struct us_loop *l, void *obj,
			void (*fn)(void *obj, void *ctx), void *ctx);
void us_loop_flush_deferred(struct us_loop *l);

/* Creates an armed periodic timerfd and registers it. Returns the fd. */
int  us_loop_timer_new(struct us_loop *l, unsigned interval_ms,
		       union ev_token tok);

#endif /* PORTFWD_US_LOOP_H */
