#ifndef PORTFWD_US_WORKER_H
#define PORTFWD_US_WORKER_H

/* Per-worker context, shared by us_backend.c and the data-plane modules.
 * Workers share nothing: one epoll, one object pool, one set of counters
 * each, so nothing in here needs locking or atomics. */

#include "../addr.h"
#include "../backend.h"
#include "us_loop.h"
#include "us_pool.h"

struct us_listener {
	int      fd;
	int      socktype;   /* SOCK_STREAM | SOCK_DGRAM */
	unsigned rule_idx;
};

/* Addresses formatted once at startup, so that the connection-level error
 * paths never call addr_format() or inet_ntop(). */
struct us_rule_str {
	char local[ADDR_STR_MAX];
	char remote[ADDR_STR_MAX];
};

struct us_worker {
	const struct fwd_config *cfg;
	struct us_loop          *loop;
	struct us_listener      *listeners;
	unsigned                 n_listeners;
	struct us_rule_str      *rule_str;

	struct pool              conns;
	uint32_t                 pipe_capacity;  /* as measured at startup */
	unsigned                 pipe_resize:1;  /* F_SETPIPE_SZ per pipe  */
	unsigned                 have_tcp:1;

	int                      timer_fd;
	unsigned                 ticks;
	uint32_t                 sweep_cursor;

	uint64_t                 now_ms;         /* refreshed once per batch */
	struct fwd_stats         stats;
};

#endif /* PORTFWD_US_WORKER_H */
