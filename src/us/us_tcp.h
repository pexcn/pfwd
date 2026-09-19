#ifndef PORTFWD_US_TCP_H
#define PORTFWD_US_TCP_H

#include "us_worker.h"

#include <stddef.h>

enum conn_state {
	CONN_CONNECTING,   /* upstream connect() in flight        */
	CONN_ESTABLISHED,  /* both directions open                */
	CONN_HALF_C2U,     /* client->upstream closed, other open */
	CONN_HALF_U2C,     /* upstream->client closed, other open */
	CONN_CLOSING,      /* queued on the deferred-free list    */
};

/* One unidirectional pump: src -> pipe -> dst. */
struct pump {
	int      pipe_r;        /* read end  (pipe -> dst)     */
	int      pipe_w;        /* write end (src -> pipe)     */
	uint32_t inflight;      /* bytes currently in the pipe */
	uint8_t  src_eof;       /* src returned 0 on splice    */
	uint8_t  dst_shutdown;  /* shutdown(dst, SHUT_WR) done */
	uint64_t bytes;         /* cumulative, for stats       */
};

struct conn {
	int          client_fd;
	int          upstream_fd;
	uint32_t     client_events;    /* last epoll mask installed, 0 = not registered */
	uint32_t     upstream_events;

	struct pump  c2u;              /* client   -> upstream */
	struct pump  u2c;              /* upstream -> client   */

	uint8_t      state;            /* enum conn_state */
	uint8_t      rule_idx;
	uint16_t     _pad;
	uint32_t     generation;
	uint32_t     slot;

	uint64_t     last_activity_ms;
	struct conn *free_next;
};

/* Opens, binds and (for SOCK_STREAM) listens. Shared with the UDP listener
 * until us_udp.c arrives in M2. */
int  us_listener_open(const struct fwd_rule *rule, const struct fwd_config *cfg,
		      int socktype, char *err, size_t errlen);

/* Measures the usable pipe capacity once, so that the pumps never have to ask
 * the kernel again. */
int  us_tcp_worker_init(struct us_worker *w, char *err, size_t errlen);

void us_tcp_on_listener(struct us_worker *w, int listen_fd, uint8_t rule_idx);
void us_tcp_on_event(struct us_worker *w, struct conn *c, int is_upstream,
		     uint32_t ev);
void us_tcp_conn_close(struct us_worker *w, struct conn *c);

/* Incremental scan for --tcp-idle-timeout; a no-op when it is 0. */
void us_tcp_idle_sweep(struct us_worker *w, uint64_t now_ms, unsigned quota);

/* Closes every live connection; used on the shutdown path. */
void us_tcp_close_all(struct us_worker *w);

#endif /* PORTFWD_US_TCP_H */
