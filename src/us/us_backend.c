/* M0 skeleton: opens the listeners so that binding errors surface at startup
 * and `ss -tlnp` shows the sockets, then parks on the signal fd. The accept /
 * splice / recvmmsg data plane arrives in M1 and M2. */

#include "../util/compat.h"
#include "../backend.h"
#include "../log.h"
#include "../sig.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>

struct us_listener {
	int      fd;
	int      socktype;   /* SOCK_STREAM | SOCK_DGRAM */
	unsigned rule_idx;
};

struct us_state {
	const struct fwd_config *cfg;
	struct us_listener      *listeners;
	unsigned                 n_listeners;
	struct fwd_stats         stats;
};

static int listener_open(const struct fwd_rule *rule,
			 const struct fwd_config *cfg, int socktype,
			 char *err, size_t errlen)
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

/* U4: SO_REUSEPORT, U6: bind test, U7: dual-stack listeners. */
static int us_probe(const struct fwd_config *cfg, struct probe_report *rep)
{
	unsigned bind_failures = 0;
	unsigned v6_dual = 0;

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

	if (cfg->nft_opts_set)
		probe_add(rep, "nftables options", PROBE_WARN,
			  "--no-sysctl / --nft-* / --no-flowtable / --no-hw-offload are ignored in userspace mode",
			  "drop the options, or switch to --mode nftables");

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

			fd = listener_open(rule, cfg, socktype, err, sizeof(err));
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
	struct us_state *st = state;

	if (!st)
		return;

	for (unsigned i = 0; i < st->n_listeners; i++) {
		if (st->listeners[i].fd >= 0)
			close(st->listeners[i].fd);
	}
	free(st->listeners);
	free(st);
}

static int us_setup(const struct fwd_config *cfg, void **state)
{
	struct us_state *st;

	st = calloc(1, sizeof(*st));
	if (!st)
		return -1;
	st->cfg = cfg;

	st->listeners = calloc(count_listeners(cfg) + 1u, sizeof(*st->listeners));
	if (!st->listeners) {
		free(st);
		return -1;
	}

	for (unsigned i = 0; i < cfg->n_rules; i++) {
		const struct fwd_rule *rule = &cfg->rules[i];
		char lbuf[ADDR_STR_MAX], rbuf[ADDR_STR_MAX];

		if (addr_format(&rule->local, lbuf, sizeof(lbuf)) < 0 ||
		    addr_format(&rule->remote, rbuf, sizeof(rbuf)) < 0) {
			LOG_E("rule #%u: cannot format addresses", i + 1);
			goto fail;
		}

		for (unsigned p = 0; p < 2; p++) {
			int socktype = p == 0 ? SOCK_STREAM : SOCK_DGRAM;
			const char *pname = p == 0 ? "tcp" : "udp";
			unsigned bit = p == 0 ? FWD_TCP : FWD_UDP;
			char err[128];
			int fd;

			if (!(rule->proto & bit))
				continue;

			fd = listener_open(rule, cfg, socktype, err, sizeof(err));
			if (fd < 0) {
				LOG_E("failed to bind %s/%s: %s", pname, lbuf, err);
				goto fail;
			}

			st->listeners[st->n_listeners++] = (struct us_listener){
				.fd = fd,
				.socktype = socktype,
				.rule_idx = i,
			};
			LOG_I("listening on %s/%s -> %s", pname, lbuf, rbuf);
		}
	}

	*state = st;
	return 0;

fail:
	us_teardown(st);
	return -1;
}

static int us_stats(void *state, struct fwd_stats *out)
{
	struct us_state *st = state;

	*out = st->stats;
	return 0;
}

static void log_stats(const struct us_state *st)
{
	LOG_I("stats: tcp conns=%llu active=%llu c2u=%llu u2c=%llu; "
	      "udp sessions=%llu active=%llu in=%llu out=%llu",
	      (unsigned long long)st->stats.tcp_conns_total,
	      (unsigned long long)st->stats.tcp_conns_active,
	      (unsigned long long)st->stats.tcp_bytes_c2u,
	      (unsigned long long)st->stats.tcp_bytes_u2c,
	      (unsigned long long)st->stats.udp_sessions_total,
	      (unsigned long long)st->stats.udp_sessions_active,
	      (unsigned long long)st->stats.udp_pkts_in,
	      (unsigned long long)st->stats.udp_pkts_out);
}

static int us_run(void *state, int sigfd)
{
	struct us_state *st = state;
	struct epoll_event ev = { .events = EPOLLIN, .data.fd = sigfd };
	int ep;
	int rc = 0;

	ep = epoll_create1(EPOLL_CLOEXEC);
	if (ep < 0) {
		LOG_E("epoll_create1: %s", strerror(errno));
		return -1;
	}
	if (epoll_ctl(ep, EPOLL_CTL_ADD, sigfd, &ev) != 0) {
		LOG_E("epoll_ctl(signal fd): %s", strerror(errno));
		close(ep);
		return -1;
	}

	for (;;) {
		struct epoll_event out[8];
		int n = epoll_wait(ep, out, (int)PF_ARRAY_LEN(out), -1);

		if (n < 0) {
			if (errno == EINTR)
				continue;
			LOG_E("epoll_wait: %s", strerror(errno));
			rc = -1;
			break;
		}

		for (int i = 0; i < n; i++) {
			int signo;

			if (out[i].data.fd != sigfd)
				continue;

			while ((signo = sig_drain(sigfd)) > 0) {
				if (signo == SIGUSR1) {
					log_stats(st);
					continue;
				}
				if (sig_is_shutdown(signo)) {
					LOG_I("%s received, shutting down",
					      sig_name(signo));
					goto done;
				}
			}
		}
	}

done:
	close(ep);
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
