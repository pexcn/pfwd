/* Userspace TCP data plane: accept, non-blocking upstream connect, two splice
 * pumps per connection and the half-close state machine of manual 6.1.
 *
 * Nothing below the accept path formats a string, logs, or allocates: the
 * pumps only move bytes and bump counters. The epoll masks are derived from
 * the in-pipe byte counts (manual 10.1) so that a stalled peer makes the loop
 * go quiet instead of spinning on level-triggered readiness. */

#include "../util/compat.h"
#include "us_tcp.h"
#include "../log.h"

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

/* Detect a dead peer that never sent a FIN, without second-guessing an idle
 * but healthy connection. See manual 10.5. */
#define TCP_KEEPALIVE_IDLE_S  600
#define TCP_KEEPALIVE_INTVL_S 60
#define TCP_KEEPALIVE_CNT     3

static struct log_rl rl_accept  = LOG_RL_INIT;
static struct log_rl rl_pool    = LOG_RL_INIT;
static struct log_rl rl_connect = LOG_RL_INIT;

static void close_fd(int *fd)
{
	if (*fd >= 0) {
		close(*fd);
		*fd = -1;
	}
}

int us_listener_open(const struct fwd_rule *rule, const struct fwd_config *cfg,
		     int socktype, char *err, size_t errlen)
{
	int fd, on = 1;

	fd = socket(sa_family_of(&rule->local),
		    socktype | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		snprintf(err, errlen, "socket: %s", strerror(errno));
		return -1;
	}
#ifdef PF_NEED_MANUAL_NONBLOCK
	pf_set_nonblock(fd);
#endif
#ifdef PF_NEED_MANUAL_CLOEXEC
	pf_set_cloexec(fd);
#endif

	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

	if (cfg->workers > 1) {
		if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on)) != 0) {
			snprintf(err, errlen, "SO_REUSEPORT: %s", strerror(errno));
			close(fd);
			return -1;
		}
	}

	if (is_v6(&rule->local)) {
		int v6only = cfg->v6only ? 1 : 0;

		if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only,
			       sizeof(v6only)) != 0 && cfg->v6only) {
			snprintf(err, errlen, "IPV6_V6ONLY: %s", strerror(errno));
			close(fd);
			return -1;
		}
	}

	if (bind(fd, &rule->local.sa, sizeof_sockaddr(&rule->local)) != 0) {
		snprintf(err, errlen, "bind: %s", strerror(errno));
		close(fd);
		return -1;
	}

	if (socktype == SOCK_STREAM && listen(fd, SOMAXCONN) != 0) {
		snprintf(err, errlen, "listen: %s", strerror(errno));
		close(fd);
		return -1;
	}

	return fd;
}

int us_tcp_worker_init(struct us_worker *w, char *err, size_t errlen)
{
	unsigned want = w->cfg->pipe_size;
	int fds[2], have;

	if (pipe2(fds, O_CLOEXEC) != 0) {
		snprintf(err, errlen, "pipe2: %s", strerror(errno));
		return -1;
	}

	have = fcntl(fds[0], F_GETPIPE_SZ);
	if (have < 0) {
		snprintf(err, errlen, "F_GETPIPE_SZ: %s", strerror(errno));
		goto fail;
	}

	/* The kernel default costs no syscall per connection; only ask for a
	 * different size when the user really wants one (manual 10.6). */
	if ((unsigned)have != want) {
		if (fcntl(fds[0], F_SETPIPE_SZ, (int)want) < 0) {
			snprintf(err, errlen, "F_SETPIPE_SZ(%u): %s", want,
				 strerror(errno));
			goto fail;
		}
		have = fcntl(fds[0], F_GETPIPE_SZ);
		if (have < 0 || (unsigned)have < want) {
			snprintf(err, errlen,
				 "the kernel shrank a %u-byte pipe to %d bytes",
				 want, have);
			goto fail;
		}
		w->pipe_resize = 1;
	}

	close(fds[0]);
	close(fds[1]);
	w->pipe_capacity = (uint32_t)have;
	return 0;

fail:
	close(fds[0]);
	close(fds[1]);
	return -1;
}

static void sock_setup(int fd)
{
	int on = 1;
	int idle = TCP_KEEPALIVE_IDLE_S;
	int intvl = TCP_KEEPALIVE_INTVL_S;
	int cnt = TCP_KEEPALIVE_CNT;

	/* A forwarder does not know the payload semantics, so it must never
	 * decide to hold data back (manual 10.11). */
	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));
	setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof(on));
#ifdef TCP_KEEPIDLE
	setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(idle));
	setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &intvl, sizeof(intvl));
	setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &cnt, sizeof(cnt));
#else
	(void)idle; (void)intvl; (void)cnt;
#endif
}

static int pump_open(struct us_worker *w, struct pump *p)
{
	int fds[2];

	/* Non-blocking is not optional: a blocking pipe would stall the whole
	 * event loop as soon as one consumer falls behind. */
	if (pipe2(fds, O_NONBLOCK | O_CLOEXEC) != 0)
		return -1;

	p->pipe_r = fds[0];
	p->pipe_w = fds[1];

	if (w->pipe_resize &&
	    fcntl(p->pipe_w, F_SETPIPE_SZ, (int)w->cfg->pipe_size) < 0)
		return -1;

	return 0;
}

static uint64_t *conn_byte_stat(struct us_worker *w, struct conn *c,
				const struct pump *p)
{
	return p == &c->c2u ? &w->stats.tcp_bytes_c2u : &w->stats.tcp_bytes_u2c;
}

/* src -> pipe. Bounded by the free space in the pipe, so a single connection
 * can never monopolise the loop. */
static int pump_fill(struct us_worker *w, struct pump *p, int src_fd)
{
	while (!p->src_eof && p->inflight < w->pipe_capacity) {
		ssize_t n = splice(src_fd, nullptr, p->pipe_w, nullptr,
				   (size_t)(w->pipe_capacity - p->inflight),
				   SPLICE_F_MOVE | SPLICE_F_NONBLOCK);

		if (n > 0) {
			p->inflight += (uint32_t)n;
			continue;
		}
		if (n == 0) {
			/* EOF only: the connection stays up until the pipe has
			 * been drained (manual 6.1). */
			p->src_eof = 1;
			break;
		}
		if (errno == EINTR)
			continue;
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			break;
		return -1;
	}

	return 0;
}

/* pipe -> dst. */
static int pump_drain(struct us_worker *w, struct conn *c, struct pump *p,
		      int dst_fd)
{
	uint64_t *stat = conn_byte_stat(w, c, p);

	while (p->inflight > 0) {
		ssize_t n = splice(p->pipe_r, nullptr, dst_fd, nullptr,
				   (size_t)p->inflight,
				   SPLICE_F_MOVE | SPLICE_F_NONBLOCK);

		if (n > 0) {
			p->inflight -= (uint32_t)n;
			p->bytes += (uint64_t)n;
			*stat += (uint64_t)n;
			continue;
		}
		if (n == 0)
			break;
		if (errno == EINTR)
			continue;
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			break;
		return -1;
	}

	return 0;
}

static int conn_set_events(struct us_worker *w, struct conn *c, int fd,
			   uint32_t *cur, uint32_t want, uint8_t kind)
{
	union ev_token tok;

	/* epoll_ctl takes ep->mtx and walks a red-black tree; on a steady
	 * transfer the mask does not change between splices (manual 10.1). */
	if (want == *cur)
		return 0;

	tok = ev_token_make(kind, c->slot, c->generation);

	if (*cur == 0) {
		if (us_loop_add(w->loop, fd, want, tok) != 0)
			return -1;
	} else if (want == 0) {
		/* Unregister rather than sit on a mask of 0: EPOLLHUP and
		 * EPOLLERR are reported whatever the mask says, and a fd that
		 * has nothing left to do would wake the loop forever. */
		if (us_loop_del(w->loop, fd) != 0)
			return -1;
	} else {
		if (us_loop_mod(w->loop, fd, want, tok) != 0)
			return -1;
	}

	*cur = want;
	return 0;
}

static int conn_update_events(struct us_worker *w, struct conn *c)
{
	uint32_t cm = 0, um = 0;

	/* EPOLLRDHUP is dropped once the EOF has been seen: it stays asserted
	 * for good, and level-triggered readiness would spin on it. */
	if (!c->c2u.src_eof && c->c2u.inflight < w->pipe_capacity)
		cm |= EPOLLIN | EPOLLRDHUP;
	if (c->u2c.inflight > 0)
		cm |= EPOLLOUT;

	if (!c->u2c.src_eof && c->u2c.inflight < w->pipe_capacity)
		um |= EPOLLIN | EPOLLRDHUP;
	if (c->c2u.inflight > 0)
		um |= EPOLLOUT;

	if (conn_set_events(w, c, c->client_fd, &c->client_events, cm,
			    EV_CONN_CLIENT) != 0)
		return -1;
	return conn_set_events(w, c, c->upstream_fd, &c->upstream_events, um,
			       EV_CONN_UPSTREAM);
}

/* Propagates half-close and decides whether the connection is done. */
static void conn_after_pump(struct us_worker *w, struct conn *c)
{
	if (c->c2u.src_eof && c->c2u.inflight == 0 && !c->c2u.dst_shutdown) {
		shutdown(c->upstream_fd, SHUT_WR);
		c->c2u.dst_shutdown = 1;
	}
	if (c->u2c.src_eof && c->u2c.inflight == 0 && !c->u2c.dst_shutdown) {
		shutdown(c->client_fd, SHUT_WR);
		c->u2c.dst_shutdown = 1;
	}

	if (c->c2u.dst_shutdown && c->u2c.dst_shutdown) {
		us_tcp_conn_close(w, c);
		return;
	}

	if (c->c2u.dst_shutdown)
		c->state = CONN_HALF_C2U;
	else if (c->u2c.dst_shutdown)
		c->state = CONN_HALF_U2C;

	if (conn_update_events(w, c) != 0)
		us_tcp_conn_close(w, c);
}

static void conn_free_fn(void *obj, void *ctx)
{
	struct us_worker *w = ctx;

	pool_free(&w->conns, obj);
}

void us_tcp_conn_close(struct us_worker *w, struct conn *c)
{
	if (c->state == CONN_CLOSING)
		return;

	if (c->client_events)
		us_loop_del(w->loop, c->client_fd);
	if (c->upstream_events)
		us_loop_del(w->loop, c->upstream_fd);
	c->client_events = 0;
	c->upstream_events = 0;

	close_fd(&c->client_fd);
	close_fd(&c->upstream_fd);
	close_fd(&c->c2u.pipe_r);
	close_fd(&c->c2u.pipe_w);
	close_fd(&c->u2c.pipe_r);
	close_fd(&c->u2c.pipe_w);

	c->state = CONN_CLOSING;
	if (w->stats.tcp_conns_active)
		w->stats.tcp_conns_active--;

	/* The slot is handed back only after the current batch of events has
	 * been dispatched (manual 10.2). */
	us_loop_defer_free(w->loop, c, conn_free_fn, w);
}

static struct conn *conn_new(struct us_worker *w, int client_fd,
			     uint8_t rule_idx)
{
	struct conn *c = pool_alloc(&w->conns);

	if (!c)
		return nullptr;

	/* pool_alloc() zeroes, and 0 is a perfectly valid fd. */
	c->slot = pool_slot_of(&w->conns, c);
	c->client_fd = client_fd;
	c->upstream_fd = -1;
	c->c2u.pipe_r = c->c2u.pipe_w = -1;
	c->u2c.pipe_r = c->u2c.pipe_w = -1;
	c->state = CONN_CONNECTING;
	c->rule_idx = rule_idx;
	c->last_activity_ms = w->now_ms;

	w->stats.tcp_conns_total++;
	w->stats.tcp_conns_active++;
	return c;
}

static int conn_start(struct us_worker *w, struct conn *c)
{
	const struct fwd_rule *rule = &w->cfg->rules[c->rule_idx];
	union ev_token tok;
	int fd, rc;

	if (pump_open(w, &c->c2u) != 0 || pump_open(w, &c->u2c) != 0)
		return -1;

	sock_setup(c->client_fd);

	/* The upstream family comes from the rule, not from the listener:
	 * cross-family forwarding is just two different socket families. */
	fd = socket(sa_family_of(&rule->remote),
		    SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -1;
	c->upstream_fd = fd;
#ifdef PF_NEED_MANUAL_NONBLOCK
	pf_set_nonblock(fd);
#endif
#ifdef PF_NEED_MANUAL_CLOEXEC
	pf_set_cloexec(fd);
#endif
	sock_setup(fd);

	rc = connect(fd, &rule->remote.sa, sizeof_sockaddr(&rule->remote));
	if (rc != 0 && errno != EINPROGRESS && errno != EINTR)
		return -1;

	if (rc == 0) {
		/* Loopback upstreams routinely complete right away. */
		c->state = CONN_ESTABLISHED;
		return conn_update_events(w, c);
	}

	tok = ev_token_make(EV_CONN_CLIENT, c->slot, c->generation);
	if (us_loop_add(w->loop, c->client_fd, EPOLLRDHUP, tok) != 0)
		return -1;
	c->client_events = EPOLLRDHUP;

	tok = ev_token_make(EV_CONN_UPSTREAM, c->slot, c->generation);
	if (us_loop_add(w->loop, c->upstream_fd, EPOLLOUT, tok) != 0)
		return -1;
	c->upstream_events = EPOLLOUT;

	return 0;
}

static int do_accept(int listen_fd)
{
	static int no_accept4;
	int fd;

	if (!no_accept4) {
		fd = accept4(listen_fd, nullptr, nullptr,
			     SOCK_NONBLOCK | SOCK_CLOEXEC);
		if (fd >= 0 || errno != ENOSYS) {
#if defined(PF_NEED_MANUAL_NONBLOCK) || defined(PF_NEED_MANUAL_CLOEXEC)
			if (fd >= 0) {
				pf_set_nonblock(fd);
				pf_set_cloexec(fd);
			}
#endif
			return fd;
		}
		no_accept4 = 1;
	}

	fd = accept(listen_fd, nullptr, nullptr);
	if (fd >= 0) {
		pf_set_nonblock(fd);
		pf_set_cloexec(fd);
	}
	return fd;
}

void us_tcp_on_listener(struct us_worker *w, int listen_fd, uint8_t rule_idx)
{
	/* The one place that loops to EAGAIN: level-triggered readiness would
	 * otherwise cost one epoll_wait per accepted connection. */
	for (;;) {
		struct conn *c;
		int fd = do_accept(listen_fd);

		if (fd < 0) {
			if (errno == EINTR || errno == ECONNABORTED)
				continue;
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				return;
			/* EMFILE and friends: back off until the next event. */
			log_emit_rl(&rl_accept, LOG_ERROR,
				    "accept on tcp/%s failed: %s",
				    w->rule_str[rule_idx].local, strerror(errno));
			return;
		}

		c = conn_new(w, fd, rule_idx);
		if (!c) {
			/* Closing right away resets the client, which is the
			 * honest answer when we are out of capacity. */
			close(fd);
			w->stats.tcp_pool_exhausted++;
			log_emit_rl(&rl_pool, LOG_ERROR,
				    "connection pool exhausted (--max-conns %u), rejecting tcp/%s",
				    w->cfg->max_conns,
				    w->rule_str[rule_idx].local);
			continue;
		}

		if (conn_start(w, c) != 0) {
			w->stats.tcp_connect_failed++;
			log_emit_rl(&rl_connect, LOG_INFO,
				    "upstream %s: %s",
				    w->rule_str[rule_idx].remote,
				    strerror(errno));
			us_tcp_conn_close(w, c);
		}
	}
}

/* Returns 1 when the connection just became established and the caller should
 * go on to pump, 0 when there is nothing more to do this event. */
static int conn_on_connecting(struct us_worker *w, struct conn *c,
			      int is_upstream, uint32_t ev)
{
	socklen_t len = sizeof(int);
	int soerr = 0;

	if (!is_upstream) {
		/* The client gave up before the upstream answered. */
		if (ev & (EPOLLERR | EPOLLHUP | EPOLLRDHUP))
			us_tcp_conn_close(w, c);
		return 0;
	}

	if (!(ev & (EPOLLOUT | EPOLLERR | EPOLLHUP)))
		return 0;

	if (getsockopt(c->upstream_fd, SOL_SOCKET, SO_ERROR, &soerr, &len) != 0)
		soerr = errno;
	if (soerr == 0 && (ev & (EPOLLERR | EPOLLHUP)))
		soerr = ECONNRESET;

	if (soerr != 0) {
		/* No retry, no health check: the client is told the truth
		 * about the upstream (manual 10.5). */
		w->stats.tcp_connect_failed++;
		log_emit_rl(&rl_connect, LOG_INFO, "upstream %s: %s",
			    w->rule_str[c->rule_idx].remote, strerror(soerr));
		us_tcp_conn_close(w, c);
		return 0;
	}

	c->state = CONN_ESTABLISHED;
	return 1;
}

void us_tcp_on_event(struct us_worker *w, struct conn *c, int is_upstream,
		     uint32_t ev)
{
	struct pump *in, *out;
	uint32_t rd, wr;
	int self, peer;

	/* Queued for release earlier in this same batch. */
	if (c->state == CONN_CLOSING)
		return;

	if (c->state == CONN_CONNECTING && !conn_on_connecting(w, c, is_upstream, ev))
		return;

	if (ev & EPOLLERR) {
		us_tcp_conn_close(w, c);
		return;
	}

	if (is_upstream) {
		in = &c->u2c;
		out = &c->c2u;
		self = c->upstream_fd;
		peer = c->client_fd;
	} else {
		in = &c->c2u;
		out = &c->u2c;
		self = c->client_fd;
		peer = c->upstream_fd;
	}

	rd = ev & (EPOLLIN | EPOLLRDHUP | EPOLLHUP);
	wr = ev & (EPOLLOUT | EPOLLHUP);

	/* Read then push, or push then refill: either way one event moves a
	 * whole pipe-load without another trip through epoll_wait. */
	if (rd && (pump_fill(w, in, self) != 0 ||
		   pump_drain(w, c, in, peer) != 0)) {
		us_tcp_conn_close(w, c);
		return;
	}
	if (wr && (pump_drain(w, c, out, self) != 0 ||
		   pump_fill(w, out, peer) != 0)) {
		us_tcp_conn_close(w, c);
		return;
	}

	c->last_activity_ms = w->now_ms;
	conn_after_pump(w, c);
}

void us_tcp_idle_sweep(struct us_worker *w, uint64_t now_ms, unsigned quota)
{
	uint64_t limit = (uint64_t)w->cfg->tcp_idle_timeout_s * 1000u;

	if (limit == 0 || w->conns.nslots == 0)
		return;

	/* Incremental, so that a large pool never turns one tick into a
	 * visible stall (manual 10.4). */
	for (unsigned i = 0; i < quota; i++) {
		struct conn *c;

		if (w->sweep_cursor >= w->conns.nslots)
			w->sweep_cursor = 0;

		c = pool_slot_obj(&w->conns, w->sweep_cursor++);
		if (!c || c->state == CONN_CLOSING)
			continue;
		if (now_ms - c->last_activity_ms >= limit)
			us_tcp_conn_close(w, c);
	}
}

void us_tcp_close_all(struct us_worker *w)
{
	for (uint32_t i = 0; i < w->conns.nslots; i++) {
		struct conn *c = pool_slot_obj(&w->conns, i);

		if (c && c->state != CONN_CLOSING)
			us_tcp_conn_close(w, c);
	}
	us_loop_flush_deferred(w->loop);
}
