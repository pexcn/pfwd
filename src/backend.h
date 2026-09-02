#ifndef PORTFWD_BACKEND_H
#define PORTFWD_BACKEND_H

#include <stdint.h>

#include "config.h"
#include "probe.h"

/* Snapshot of the counters a data plane keeps. Hot paths only increment
 * these; nothing here is formatted or logged per packet. */
struct fwd_stats {
	uint64_t tcp_conns_total;
	uint64_t tcp_conns_active;
	uint64_t tcp_bytes_c2u;
	uint64_t tcp_bytes_u2c;
	uint64_t tcp_pool_exhausted;
	uint64_t tcp_connect_failed;

	uint64_t udp_sessions_total;
	uint64_t udp_sessions_active;
	uint64_t udp_pkts_in;
	uint64_t udp_pkts_out;
	uint64_t udp_bytes_in;
	uint64_t udp_bytes_out;
	uint64_t udp_sess_exhausted;

	uint64_t errors;
};

struct fwd_backend {
	const char *name;

	/* Validate config against this backend's constraints and the running
	 * kernel. Must not mutate any system state. Called before fork(). */
	int (*probe)(const struct fwd_config *cfg, struct probe_report *rep);

	/* Install whatever is needed (rules, sysctl, listeners).
	 * Called once in the parent for nftables, once per worker for userspace. */
	int (*setup)(const struct fwd_config *cfg, void **state);

	/* Run until shutdown is requested via the signal fd. */
	int (*run)(void *state, int sigfd);

	/* Undo everything setup() did. Must be idempotent and must not fail
	 * silently: every unwind error is logged at WARN. */
	void (*teardown)(void *state);

	/* Optional. Fill in a stats snapshot. NULL if unsupported. */
	int (*stats)(void *state, struct fwd_stats *out);
};

extern const struct fwd_backend backend_userspace;
#ifdef ENABLE_NFTABLES
extern const struct fwd_backend backend_nftables;
#endif

#endif /* PORTFWD_BACKEND_H */
