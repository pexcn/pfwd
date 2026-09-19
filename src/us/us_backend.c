/* Userspace backend: startup probes, listener setup and the worker event
 * loop. The TCP data plane lives in us_tcp.c; UDP arrives in M2. */

#include "../util/compat.h"
#include "../backend.h"
#include "../log.h"
#include "../sig.h"
#include "us_tcp.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>

#define US_MAX_EVENTS   1024u
#define US_TICK_MS      1000u

/* fd cost of one live object, per manual 9.1. */
#define FDS_PER_CONN    6u   /* 2 sockets + 2 pipes */
#define FDS_PER_SESSION 1u
#define FDS_MISC       16u   /* epoll, timerfd, signalfd, stdio, slack */

#define PIPE_PAGES_SOFT "/proc/sys/fs/pipe-user-pages-soft"
#define PIPE_MAX_SIZE   "/proc/sys/fs/pipe-max-size"

static void proto_counts(const struct fwd_config *cfg, unsigned *n_tcp,
			 unsigned *n_udp)
{
	*n_tcp = 0;
	*n_udp = 0;

	for (unsigned i = 0; i < cfg->n_rules; i++) {
		if (cfg->rules[i].err_kind != RULE_ERR_NONE)
			continue;
		if (cfg->rules[i].proto & FWD_TCP)
			(*n_tcp)++;
		if (cfg->rules[i].proto & FWD_UDP)
			(*n_udp)++;
	}
}

/* U1: fd budget. */
static void us_probe_fd_budget(const struct fwd_config *cfg,
			       struct probe_report *rep)
{
	unsigned n_tcp, n_udp;
	unsigned long need;
	struct rlimit rl;

	proto_counts(cfg, &n_tcp, &n_udp);
	need = FDS_MISC + n_tcp + n_udp;
	if (n_tcp)
		need += (unsigned long)cfg->max_conns * FDS_PER_CONN;
	if (n_udp)
		need += (unsigned long)cfg->udp_max_sessions * FDS_PER_SESSION;

	if (getrlimit(RLIMIT_NOFILE, &rl) != 0) {
		probe_addf(rep, "fd budget", PROBE_WARN,
			   "check the limit yourself with 'ulimit -n'",
			   "cannot read RLIMIT_NOFILE: %s", strerror(errno));
		return;
	}

	if (rl.rlim_cur != RLIM_INFINITY && (unsigned long)rl.rlim_cur < need) {
		if (rl.rlim_max != RLIM_INFINITY &&
		    (unsigned long)rl.rlim_max < need) {
			probe_addf(rep, "fd budget", PROBE_FATAL,
				   "raise the hard limit (ulimit -Hn) or lower --max-conns / --udp-max-sessions",
				   "RLIMIT_NOFILE hard limit %llu is below the required %lu fds for max-conns=%u + udp-max-sessions=%u",
				   (unsigned long long)rl.rlim_max, need,
				   cfg->max_conns, cfg->udp_max_sessions);
			return;
		}

		rl.rlim_cur = rl.rlim_max;
		if (setrlimit(RLIMIT_NOFILE, &rl) != 0) {
			probe_addf(rep, "fd budget", PROBE_FATAL,
				   "raise the soft limit yourself (ulimit -n) or lower --max-conns",
				   "cannot raise the RLIMIT_NOFILE soft limit to %llu: %s",
				   (unsigned long long)rl.rlim_max,
				   strerror(errno));
			return;
		}
		LOG_I("raised the RLIMIT_NOFILE soft limit to %llu (%lu fds required)",
		      (unsigned long long)rl.rlim_max, need);
	}

	probe_addf(rep, "fd budget", PROBE_OK, nullptr, "%lu fds required", need);
}

/* U2: pipe page budget. A kernel over its per-uid quota does not fail
 * F_SETPIPE_SZ, it silently hands out one-page pipes; see manual 7.2. */
static void us_probe_pipe_pages(const struct fwd_config *cfg,
				struct probe_report *rep)
{
	unsigned long page, pages_per_conn, required, fit_conns, fit_pipe;
	long soft = 0, maxsize = 0;
	char hint[256];
	int fds[2], have;

	page = (unsigned long)PF_MAX(sysconf(_SC_PAGESIZE), 4096L);
	pages_per_conn = 2ul * ((cfg->pipe_size + page - 1ul) / page);
	required = (unsigned long)cfg->workers * cfg->max_conns * pages_per_conn;

	/* 0 means "no limit". */
	if (probe_read_sysctl_long(PIPE_PAGES_SOFT, &soft) == 0 && soft > 0 &&
	    required > (unsigned long)soft) {
		fit_conns = (unsigned long)soft / (cfg->workers * pages_per_conn);
		fit_pipe = ((unsigned long)soft * page) /
			   ((unsigned long)cfg->workers * cfg->max_conns * 2ul);
		fit_pipe -= fit_pipe % page;

		snprintf(hint, sizeof(hint),
			 "raise it (sysctl -w fs.pipe-user-pages-soft=%lu), or lower --max-conns to %lu, or lower --pipe-size to %lu",
			 required * 2ul, fit_conns ? fit_conns : 1ul,
			 fit_pipe ? fit_pipe : page);
		probe_addf(rep, "pipe page budget", PROBE_FATAL, hint,
			   "--max-conns %u with --pipe-size %u requires %lu pipe pages, but fs.pipe-user-pages-soft is %ld. The kernel would silently shrink new pipes to a single page, collapsing splice throughput.",
			   cfg->max_conns, cfg->pipe_size, required, soft);
		return;
	}

	/* U3 covers this; asking anyway would only add a confusing EPERM. */
	if (probe_read_sysctl_long(PIPE_MAX_SIZE, &maxsize) == 0 &&
	    (long)cfg->pipe_size > maxsize)
		return;

	/* Arithmetic is not enough: measure what the kernel actually gives. */
	if (pipe2(fds, O_CLOEXEC) != 0) {
		probe_addf(rep, "pipe page budget", PROBE_FATAL,
			   "check the process fd limit and fs.pipe-user-pages-hard",
			   "cannot create a pipe: %s", strerror(errno));
		return;
	}

	have = fcntl(fds[0], F_GETPIPE_SZ);
	if (have >= 0 && (unsigned)have != cfg->pipe_size &&
	    fcntl(fds[0], F_SETPIPE_SZ, (int)cfg->pipe_size) >= 0)
		have = fcntl(fds[0], F_GETPIPE_SZ);
	close(fds[0]);
	close(fds[1]);

	if (have < 0) {
		probe_addf(rep, "pipe page budget", PROBE_FATAL,
			   "lower --pipe-size, or raise fs.pipe-user-pages-soft",
			   "cannot size a pipe to %u bytes: %s", cfg->pipe_size,
			   strerror(errno));
		return;
	}
	if ((unsigned)have < cfg->pipe_size) {
		probe_addf(rep, "pipe page budget", PROBE_FATAL,
			   "raise fs.pipe-user-pages-soft, or lower --max-conns / --pipe-size",
			   "the kernel silently shrank a %u-byte pipe to %d bytes; splice would move %d bytes per call instead of %u",
			   cfg->pipe_size, have, have, cfg->pipe_size);
		return;
	}

	probe_addf(rep, "pipe page budget", PROBE_OK, nullptr,
		   "%lu pages needed, %d bytes per pipe measured", required, have);
}

/* U3: pipe max size. */
static void us_probe_pipe_max(const struct fwd_config *cfg,
			      struct probe_report *rep)
{
	long maxsize = 0;

	if (probe_read_sysctl_long(PIPE_MAX_SIZE, &maxsize) != 0) {
		probe_add(rep, "pipe max size", PROBE_OK,
			  "fs.pipe-max-size is not exposed by this kernel", nullptr);
		return;
	}

	if ((long)cfg->pipe_size > maxsize) {
		probe_addf(rep, "pipe max size", PROBE_FATAL,
			   "lower --pipe-size or raise fs.pipe-max-size",
			   "--pipe-size %u exceeds fs.pipe-max-size (%ld)",
			   cfg->pipe_size, maxsize);
		return;
	}

	probe_addf(rep, "pipe max size", PROBE_OK, nullptr,
		   "--pipe-size %u, fs.pipe-max-size %ld", cfg->pipe_size, maxsize);
}

static int us_probe(const struct fwd_config *cfg, struct probe_report *rep)
{
	unsigned bind_failures = 0;
	unsigned v6_dual = 0;
	unsigned n_tcp, n_udp;

	proto_counts(cfg, &n_tcp, &n_udp);

	if (cfg->workers > 1) {
		int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
		int on = 1;

		if (fd < 0 ||
		    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on)) != 0)
			probe_add(rep, "SO_REUSEPORT", PROBE_FATAL,
				  "SO_REUSEPORT is not supported by this kernel; --workers must be 1",
				  "run with --workers 1");
		else
			probe_add(rep, "SO_REUSEPORT", PROBE_OK, nullptr, nullptr);
		if (fd >= 0)
			close(fd);

		probe_add(rep, "workers", PROBE_FATAL,
			  "multiple worker processes are not implemented yet (milestone M4)",
			  "run with --workers 1");
	}

	if (n_udp)
		probe_add(rep, "udp data plane", PROBE_WARN,
			  "the userspace UDP data plane is not implemented yet (milestone M2); UDP listeners are bound but forward nothing",
			  "drop the udp protocol from the rule until M2 lands");

	if (cfg->nft_opts_set)
		probe_add(rep, "nftables options", PROBE_WARN,
			  "--no-sysctl / --nft-* / --no-flowtable / --no-hw-offload are ignored in userspace mode",
			  "drop the options, or switch to --mode nftables");

	us_probe_fd_budget(cfg, rep);
	if (n_tcp) {
		us_probe_pipe_pages(cfg, rep);
		us_probe_pipe_max(cfg, rep);
	}

	for (unsigned i = 0; i < cfg->n_rules; i++) {
		const struct fwd_rule *rule = &cfg->rules[i];
		char err[128];

		if (rule->err_kind != RULE_ERR_NONE)
			continue;

		if (is_v6(&rule->local) && !cfg->v6only &&
		    addr_is_wildcard(&rule->local))
			v6_dual++;

		for (unsigned p = 0; p < 2; p++) {
			int socktype = p == 0 ? SOCK_STREAM : SOCK_DGRAM;
			unsigned bit = p == 0 ? FWD_TCP : FWD_UDP;
			int fd;

			if (!(rule->proto & bit))
				continue;

			fd = us_listener_open(rule, cfg, socktype, err, sizeof(err));
			if (fd < 0) {
				char buf[ADDR_STR_MAX];

				if (addr_format(&rule->local, buf, sizeof(buf)) < 0)
					buf[0] = '\0';
				probe_addf(rep, "bind test", PROBE_FATAL,
					   "stop whatever owns the port, or pick another local port",
					   "cannot bind %s/%s: %s",
					   p == 0 ? "tcp" : "udp", buf, err);
				bind_failures++;
				continue;
			}
			close(fd);
		}
	}

	if (!bind_failures)
		probe_add(rep, "bind test", PROBE_OK, "all listeners bindable",
			  nullptr);

	if (v6_dual) {
		long bindv6only = 0;

		probe_read_sysctl_long("/proc/sys/net/ipv6/bindv6only",
				       &bindv6only);
		probe_addf(rep, "IPV6_V6ONLY", PROBE_OK, nullptr,
			   "%u wildcard IPv6 listener%s will accept IPv4-mapped traffic (bindv6only=%ld, overridden per socket)",
			   v6_dual, v6_dual == 1 ? "" : "s", bindv6only);
	}

	return rep->n_fatal ? -1 : 0;
}

static unsigned count_listeners(const struct fwd_config *cfg)
{
	unsigned n = 0;

	for (unsigned i = 0; i < cfg->n_rules; i++) {
		if (cfg->rules[i].proto & FWD_TCP)
			n++;
		if (cfg->rules[i].proto & FWD_UDP)
			n++;
	}
	return n;
}

static void us_teardown(void *state)
{
	struct us_worker *w = state;

	if (!w)
		return;

	if (w->loop) {
		us_tcp_close_all(w);
		if (w->timer_fd >= 0) {
			us_loop_del(w->loop, w->timer_fd);
			close(w->timer_fd);
			w->timer_fd = -1;
		}
	}

	for (unsigned i = 0; i < w->n_listeners; i++) {
		if (w->listeners[i].fd >= 0)
			close(w->listeners[i].fd);
	}

	pool_fini(&w->conns);
	us_loop_free(w->loop);
	free(w->listeners);
	free(w->rule_str);
	free(w);
}

static int us_setup(const struct fwd_config *cfg, void **state)
{
	struct us_worker *w;
	unsigned n_tcp, n_udp;
	char err[128];

	proto_counts(cfg, &n_tcp, &n_udp);

	w = calloc(1, sizeof(*w));
	if (!w)
		return -1;
	w->cfg = cfg;
	w->timer_fd = -1;
	w->have_tcp = n_tcp != 0;
	w->now_ms = pf_now_ms();

	w->listeners = calloc(count_listeners(cfg) + 1u, sizeof(*w->listeners));
	w->rule_str = calloc(cfg->n_rules + 1u, sizeof(*w->rule_str));
	if (!w->listeners || !w->rule_str)
		goto fail;

	/* One slab for the whole worker; the forwarding path never allocates. */
	if (w->have_tcp) {
		if (pool_init(&w->conns, cfg->max_conns, sizeof(struct conn),
			      offsetof(struct conn, generation),
			      offsetof(struct conn, free_next)) != 0) {
			LOG_E("cannot allocate the connection pool (%u slots)",
			      cfg->max_conns);
			goto fail;
		}
		if (us_tcp_worker_init(w, err, sizeof(err)) != 0) {
			LOG_E("cannot set up the splice pipes: %s", err);
			goto fail;
		}
	}

	w->loop = us_loop_new(US_MAX_EVENTS, cfg->max_conns + 8u);
	if (!w->loop) {
		LOG_E("cannot create the event loop: %s", strerror(errno));
		goto fail;
	}

	for (unsigned i = 0; i < cfg->n_rules; i++) {
		const struct fwd_rule *rule = &cfg->rules[i];

		if (addr_format(&rule->local, w->rule_str[i].local,
				sizeof(w->rule_str[i].local)) < 0 ||
		    addr_format(&rule->remote, w->rule_str[i].remote,
				sizeof(w->rule_str[i].remote)) < 0) {
			LOG_E("rule #%u: cannot format addresses", i + 1);
			goto fail;
		}

		for (unsigned p = 0; p < 2; p++) {
			int socktype = p == 0 ? SOCK_STREAM : SOCK_DGRAM;
			const char *pname = p == 0 ? "tcp" : "udp";
			unsigned bit = p == 0 ? FWD_TCP : FWD_UDP;
			int fd;

			if (!(rule->proto & bit))
				continue;

			fd = us_listener_open(rule, cfg, socktype, err, sizeof(err));
			if (fd < 0) {
				LOG_E("failed to bind %s/%s: %s", pname,
				      w->rule_str[i].local, err);
				goto fail;
			}

			w->listeners[w->n_listeners++] = (struct us_listener){
				.fd = fd,
				.socktype = socktype,
				.rule_idx = i,
			};
			LOG_I("listening on %s/%s -> %s", pname,
			      w->rule_str[i].local, w->rule_str[i].remote);
		}
	}

	*state = w;
	return 0;

fail:
	us_teardown(w);
	return -1;
}

static int us_stats(void *state, struct fwd_stats *out)
{
	struct us_worker *w = state;

	*out = w->stats;
	return 0;
}

static void log_stats(const struct us_worker *w)
{
	LOG_I("stats: tcp conns=%llu active=%llu c2u=%llu u2c=%llu exhausted=%llu connect-failed=%llu; "
	      "udp sessions=%llu active=%llu in=%llu out=%llu",
	      (unsigned long long)w->stats.tcp_conns_total,
	      (unsigned long long)w->stats.tcp_conns_active,
	      (unsigned long long)w->stats.tcp_bytes_c2u,
	      (unsigned long long)w->stats.tcp_bytes_u2c,
	      (unsigned long long)w->stats.tcp_pool_exhausted,
	      (unsigned long long)w->stats.tcp_connect_failed,
	      (unsigned long long)w->stats.udp_sessions_total,
	      (unsigned long long)w->stats.udp_sessions_active,
	      (unsigned long long)w->stats.udp_pkts_in,
	      (unsigned long long)w->stats.udp_pkts_out);
}

/* Returns 1 when a shutdown signal arrived. */
static int handle_signal(struct us_worker *w, int sigfd)
{
	int signo;

	while ((signo = sig_drain(sigfd)) > 0) {
		if (signo == SIGUSR1) {
			log_stats(w);
			continue;
		}
		if (sig_is_shutdown(signo)) {
			LOG_I("%s received, shutting down", sig_name(signo));
			return 1;
		}
	}
	return 0;
}

static void handle_timer(struct us_worker *w)
{
	uint64_t expirations;

	if (read(w->timer_fd, &expirations, sizeof(expirations)) !=
	    (ssize_t)sizeof(expirations))
		return;

	w->ticks++;
	us_tcp_idle_sweep(w, w->now_ms, w->conns.nslots / 8u + 64u);

	if (w->cfg->stats_interval_s &&
	    w->ticks % w->cfg->stats_interval_s == 0)
		log_stats(w);
}

static int us_run(void *state, int sigfd)
{
	struct us_worker *w = state;
	int rc = 0;

	if (us_loop_add(w->loop, sigfd, EPOLLIN,
			ev_token_make(EV_SIGNAL, 0, 0)) != 0) {
		LOG_E("epoll_ctl(signal fd): %s", strerror(errno));
		return -1;
	}

	for (unsigned i = 0; i < w->n_listeners; i++) {
		/* UDP listeners stay out of the loop until M2: registering
		 * them with no handler would spin on level-triggered
		 * readiness as soon as a datagram arrived. */
		if (w->listeners[i].socktype != SOCK_STREAM)
			continue;
		if (us_loop_add(w->loop, w->listeners[i].fd, EPOLLIN,
				ev_token_make(EV_LISTENER_TCP, i, 0)) != 0) {
			LOG_E("epoll_ctl(listener): %s", strerror(errno));
			return -1;
		}
	}

	if (w->cfg->tcp_idle_timeout_s || w->cfg->stats_interval_s) {
		w->timer_fd = us_loop_timer_new(w->loop, US_TICK_MS,
						ev_token_make(EV_TIMER, 0, 0));
		if (w->timer_fd < 0) {
			LOG_E("cannot create the tick timer: %s", strerror(errno));
			return -1;
		}
	}

	for (;;) {
		int n = us_loop_run(w->loop, -1);

		if (n < 0) {
			LOG_E("epoll_wait: %s", strerror(errno));
			rc = -1;
			break;
		}

		w->now_ms = pf_now_ms();

		for (int i = 0; i < n; i++) {
			union ev_token tok = { .u64 = w->loop->events[i].data.u64 };
			uint32_t ev = w->loop->events[i].events;
			struct conn *c;

			switch (tok.f.kind) {
			case EV_SIGNAL:
				if (handle_signal(w, sigfd))
					goto done;
				break;
			case EV_TIMER:
				handle_timer(w);
				break;
			case EV_LISTENER_TCP:
				us_tcp_on_listener(w, w->listeners[tok.f.slot].fd,
						   (uint8_t)w->listeners[tok.f.slot].rule_idx);
				break;
			case EV_CONN_CLIENT:
			case EV_CONN_UPSTREAM:
				/* A stale event, from a connection released
				 * earlier, resolves to NULL. */
				c = pool_resolve(&w->conns, tok.f.slot,
						 tok.f.generation16);
				if (!c)
					break;
				us_tcp_on_event(w, c,
						tok.f.kind == EV_CONN_UPSTREAM, ev);
				break;
			default:
				break;
			}
		}

		us_loop_flush_deferred(w->loop);
	}

done:
	us_loop_flush_deferred(w->loop);
	return rc;
}

const struct fwd_backend backend_userspace = {
	.name     = "userspace",
	.probe    = us_probe,
	.setup    = us_setup,
	.run      = us_run,
	.teardown = us_teardown,
	.stats    = us_stats,
};
