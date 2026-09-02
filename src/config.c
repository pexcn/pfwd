#include "util/compat.h"
#include "config.h"
#include "log.h"

#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
	OPT_UDP_TIMEOUT = 0x100,
	OPT_UDP_MAX_SESSIONS,
	OPT_TCP_IDLE_TIMEOUT,
	OPT_MAX_CONNS,
	OPT_PIPE_SIZE,
	OPT_BATCH_SIZE,
	OPT_STATS_INTERVAL,
	OPT_V6ONLY,
	OPT_NO_SYSCTL,
	OPT_NFT_TABLE,
	OPT_NFT_DEVICES,
	OPT_NO_FLOWTABLE,
	OPT_NO_HW_OFFLOAD,
	OPT_RUN_DIR,
	OPT_CHECK,
};

static const struct option long_opts[] = {
	{ "mode",             required_argument, nullptr, 'm' },
	{ "forward",          required_argument, nullptr, 'f' },
	{ "workers",          required_argument, nullptr, 'w' },
	{ "daemonize",        no_argument,       nullptr, 'd' },
	{ "pidfile",          required_argument, nullptr, 'P' },
	{ "log-level",        required_argument, nullptr, 'l' },
	{ "log-target",       required_argument, nullptr, 'L' },
	{ "udp-timeout",      required_argument, nullptr, OPT_UDP_TIMEOUT },
	{ "udp-max-sessions", required_argument, nullptr, OPT_UDP_MAX_SESSIONS },
	{ "tcp-idle-timeout", required_argument, nullptr, OPT_TCP_IDLE_TIMEOUT },
	{ "max-conns",        required_argument, nullptr, OPT_MAX_CONNS },
	{ "pipe-size",        required_argument, nullptr, OPT_PIPE_SIZE },
	{ "batch-size",       required_argument, nullptr, OPT_BATCH_SIZE },
	{ "stats-interval",   required_argument, nullptr, OPT_STATS_INTERVAL },
	{ "v6only",           no_argument,       nullptr, OPT_V6ONLY },
	{ "no-sysctl",        no_argument,       nullptr, OPT_NO_SYSCTL },
	{ "nft-table",        required_argument, nullptr, OPT_NFT_TABLE },
	{ "nft-devices",      required_argument, nullptr, OPT_NFT_DEVICES },
	{ "no-flowtable",     no_argument,       nullptr, OPT_NO_FLOWTABLE },
	{ "no-hw-offload",    no_argument,       nullptr, OPT_NO_HW_OFFLOAD },
	{ "run-dir",          required_argument, nullptr, OPT_RUN_DIR },
	{ "check",            no_argument,       nullptr, OPT_CHECK },
	{ "version",          no_argument,       nullptr, 'v' },
	{ "help",             no_argument,       nullptr, 'h' },
	{}
};

static void usage(FILE *out, const char *argv0)
{
	fprintf(out,
"portfwd " PORTFWD_VERSION " - TCP/UDP port forwarder with two data planes\n"
"\n"
"Usage: %s [global options] -f RULE [-f RULE ...]\n"
"\n"
"RULE := <proto>/<local-addr>:<port>-><remote-addr>:<port>\n"
"        e.g.  tcp/0.0.0.0:1022->192.168.1.7:22\n"
"              udp/[::]:1701->192.168.1.7:1701\n"
"              tcp,udp/[::]:80->[2001:db8::2]:80\n"
"\n"
"Global options:\n"
"  -m, --mode {userspace|nftables}   data plane implementation (required)\n"
"  -f, --forward RULE                forward rule; repeatable\n"
"  -w, --workers N|auto              number of worker processes (default: %u)\n"
"  -d, --daemonize                   detach from controlling terminal\n"
"  -P, --pidfile PATH                write pid file\n"
"  -l, --log-level {error|warn|info|debug|trace}   (default: info)\n"
"  -L, --log-target {stderr|syslog}  (default: stderr, or syslog when daemonized)\n"
"      --udp-timeout SECONDS         UDP session idle timeout (default: %u)\n"
"      --udp-max-sessions N          per-worker session cap (default: %u)\n"
"      --tcp-idle-timeout SECONDS    0 disables (default: %u)\n"
"      --max-conns N                 per-worker TCP connection cap (default: %u)\n"
"      --pipe-size BYTES             splice pipe capacity (default: %u)\n"
"      --batch-size N                recvmmsg/sendmmsg batch (default: %u)\n"
"      --stats-interval SECONDS      periodic stats snapshot, 0 disables (default: 0)\n"
"      --v6only                      force IPV6_V6ONLY on [::] listeners\n"
"      --run-dir PATH                runtime state directory (default: %s)\n"
"      --no-sysctl                   nftables mode: do not touch /proc/sys\n"
"      --nft-table NAME              nftables table name (default: %s)\n"
"      --nft-devices dev[,dev...]    flowtable ingress devices (default: autodetect)\n"
"      --no-flowtable                disable flowtable fast path\n"
"      --no-hw-offload               disable 'flags offload' probing\n"
"      --check                       run capability probe, print report, exit\n"
"  -v, --version\n"
"  -h, --help\n",
		argv0, DEF_WORKERS, DEF_UDP_TIMEOUT_S, DEF_UDP_MAX_SESSIONS,
		DEF_TCP_IDLE_TIMEOUT_S, DEF_MAX_CONNS, DEF_PIPE_SIZE,
		DEF_BATCH_SIZE, DEF_RUN_DIR, DEF_NFT_TABLE);
}

const char *config_proto_str(unsigned proto)
{
	if ((proto & (FWD_TCP | FWD_UDP)) == (FWD_TCP | FWD_UDP))
		return "tcp,udp";
	if (proto & FWD_TCP)
		return "tcp";
	if (proto & FWD_UDP)
		return "udp";
	return "?";
}

const char *config_mode_str(enum fwd_mode mode)
{
	return mode == MODE_NFTABLES ? "nftables" : "userspace";
}

static int parse_uint(const char *s, unsigned *out, unsigned lo, unsigned hi)
{
	char *end;
	unsigned long v;

	if (!s || !*s)
		return -1;
	errno = 0;
	v = strtoul(s, &end, 0);
	if (errno != 0 || *end != '\0' || v > UINT_MAX)
		return -1;
	if (v < lo || v > hi)
		return -1;
	*out = (unsigned)v;
	return 0;
}

static unsigned workers_auto(void)
{
	long n = sysconf(_SC_NPROCESSORS_ONLN);

	if (n < 1)
		n = 1;
	return PF_MIN((unsigned)n, WORKERS_AUTO_MAX);
}

static int parse_proto(const char *s, size_t len, unsigned *out)
{
	unsigned proto = 0;
	const char *p = s;
	const char *end = s + len;

	while (p < end) {
		const char *comma = memchr(p, ',', (size_t)(end - p));
		size_t n = comma ? (size_t)(comma - p) : (size_t)(end - p);

		if (n == 3 && memcmp(p, "tcp", 3) == 0)
			proto |= FWD_TCP;
		else if (n == 3 && memcmp(p, "udp", 3) == 0)
			proto |= FWD_UDP;
		else
			return -1;

		p += n + (comma ? 1 : 0);
	}

	if (proto == 0)
		return -1;
	*out = proto;
	return 0;
}

/* Fills rule->err instead of failing hard, so that the probe stage can report
 * every broken rule at once. */
static void parse_rule(const char *spec, struct fwd_rule *r)
{
	char local[ADDR_STR_MAX + 64], remote[ADDR_STR_MAX + 64];
	char errbuf[128];
	const char *slash, *arrow;
	size_t n;
	int rc;

	memset(r, 0, sizeof(*r));
	r->spec = spec;

	slash = strchr(spec, '/');
	if (!slash) {
		r->err_kind = RULE_ERR_SYNTAX;
		snprintf(r->err, sizeof(r->err),
			 "missing '<proto>/' prefix; expected "
			 "<tcp|udp|tcp,udp>/<local>:<port>-><remote>:<port>");
		return;
	}
	if (parse_proto(spec, (size_t)(slash - spec), &r->proto) < 0) {
		r->err_kind = RULE_ERR_SYNTAX;
		snprintf(r->err, sizeof(r->err),
			 "unknown protocol; expected 'tcp', 'udp' or 'tcp,udp'");
		return;
	}

	arrow = strstr(slash + 1, "->");
	if (!arrow) {
		r->err_kind = RULE_ERR_SYNTAX;
		snprintf(r->err, sizeof(r->err), "missing '->' separator");
		return;
	}

	n = (size_t)(arrow - (slash + 1));
	if (n == 0 || n >= sizeof(local)) {
		r->err_kind = RULE_ERR_SYNTAX;
		snprintf(r->err, sizeof(r->err), "malformed local address");
		return;
	}
	memcpy(local, slash + 1, n);
	local[n] = '\0';

	if (strlen(arrow + 2) >= sizeof(remote)) {
		r->err_kind = RULE_ERR_SYNTAX;
		snprintf(r->err, sizeof(r->err), "malformed remote address");
		return;
	}
	strcpy(remote, arrow + 2);

	rc = addr_parse_ex(local, &r->local, AF_UNSPEC, errbuf, sizeof(errbuf));
	if (rc != ADDR_OK) {
		r->err_kind = rc == ADDR_ERR_RESOLVE ? RULE_ERR_RESOLVE
						     : RULE_ERR_SYNTAX;
		if (rc == ADDR_ERR_RESOLVE)
			snprintf(r->err, sizeof(r->err),
				 "cannot resolve local host '%s': %s",
				 local, errbuf);
		else
			snprintf(r->err, sizeof(r->err),
				 "local address '%s': %s", local, errbuf);
		return;
	}
	rc = addr_parse_ex(remote, &r->remote, AF_UNSPEC, errbuf, sizeof(errbuf));
	if (rc != ADDR_OK) {
		r->err_kind = rc == ADDR_ERR_RESOLVE ? RULE_ERR_RESOLVE
						     : RULE_ERR_SYNTAX;
		if (rc == ADDR_ERR_RESOLVE)
			snprintf(r->err, sizeof(r->err),
				 "cannot resolve upstream host '%s': %s",
				 remote, errbuf);
		else
			snprintf(r->err, sizeof(r->err),
				 "upstream address '%s': %s", remote, errbuf);
		return;
	}

	r->cross_family = sa_family_of(&r->local) != sa_family_of(&r->remote);

	char lbuf[ADDR_STR_MAX];

	if (addr_format(&r->local, lbuf, sizeof(lbuf)) < 0)
		lbuf[0] = '\0';
	snprintf(r->label, sizeof(r->label), "%s/%s", config_proto_str(r->proto),
		 lbuf);
}

static int rules_append(struct fwd_config *cfg, const char *spec)
{
	struct fwd_rule *tmp;

	tmp = realloc(cfg->rules, (cfg->n_rules + 1) * sizeof(*tmp));
	if (!tmp)
		return -1;
	cfg->rules = tmp;
	parse_rule(spec, &cfg->rules[cfg->n_rules]);
	cfg->n_rules++;
	return 0;
}

static int nft_devices_set(struct fwd_config *cfg, const char *list)
{
	char *copy = strdup(list);
	char *save = nullptr;
	char **devs = nullptr;
	unsigned n = 0;

	if (!copy)
		return -1;

	for (char *tok = strtok_r(copy, ",", &save); tok;
	     tok = strtok_r(nullptr, ",", &save)) {
		char **grown = realloc(devs, (n + 1) * sizeof(*devs));

		if (!grown)
			goto fail;
		devs = grown;
		devs[n] = strdup(tok);
		if (!devs[n])
			goto fail;
		n++;
	}

	free(copy);
	cfg->nft_devices = devs;
	cfg->n_nft_devices = n;
	return 0;

fail:
	for (unsigned i = 0; i < n; i++)
		free(devs[i]);
	free(devs);
	free(copy);
	return -1;
}

static void config_defaults(struct fwd_config *cfg)
{
	memset(cfg, 0, sizeof(*cfg));
	cfg->mode = MODE_USERSPACE;
	cfg->workers = DEF_WORKERS;
	cfg->max_conns = DEF_MAX_CONNS;
	cfg->udp_max_sessions = DEF_UDP_MAX_SESSIONS;
	cfg->udp_timeout_s = DEF_UDP_TIMEOUT_S;
	cfg->tcp_idle_timeout_s = DEF_TCP_IDLE_TIMEOUT_S;
	cfg->pipe_size = DEF_PIPE_SIZE;
	cfg->batch_size = DEF_BATCH_SIZE;
	cfg->nft_table = DEF_NFT_TABLE;
	cfg->run_dir = DEF_RUN_DIR;
	cfg->log_level = LOG_INFO;
	cfg->log_target = LOG_TARGET_STDERR;
}

/* Returns 0 on success, 1 when the program should exit(0) (--help/--version),
 * -1 on a usage error. */
int config_parse_argv(int argc, char **argv, struct fwd_config *cfg)
{
	int c;

	config_defaults(cfg);

	while ((c = getopt_long(argc, argv, "m:f:w:dP:l:L:vh", long_opts,
				nullptr)) != -1) {
		switch (c) {
		case 'm':
			if (strcmp(optarg, "userspace") == 0) {
				cfg->mode = MODE_USERSPACE;
			} else if (strcmp(optarg, "nftables") == 0) {
				cfg->mode = MODE_NFTABLES;
			} else {
				LOG_E("unknown mode '%s'; expected 'userspace' or 'nftables'",
				      optarg);
				return -1;
			}
			cfg->mode_set = 1;
			break;
		case 'f':
			if (rules_append(cfg, optarg) < 0) {
				LOG_E("out of memory while parsing rules");
				return -1;
			}
			break;
		case 'w':
			if (strcmp(optarg, "auto") == 0)
				cfg->workers = workers_auto();
			else if (parse_uint(optarg, &cfg->workers, 1, 1024) < 0) {
				LOG_E("--workers must be 'auto' or an integer in 1..1024");
				return -1;
			}
			break;
		case 'd':
			cfg->daemonize = 1;
			break;
		case 'P':
			cfg->pidfile = optarg;
			break;
		case 'l':
			cfg->log_level = log_level_parse(optarg);
			if (cfg->log_level < 0) {
				LOG_E("unknown log level '%s'; expected error|warn|info|debug|trace",
				      optarg);
				return -1;
			}
			break;
		case 'L':
			cfg->log_target = log_target_parse(optarg);
			if (cfg->log_target < 0) {
				LOG_E("unknown log target '%s'; expected stderr|syslog",
				      optarg);
				return -1;
			}
			cfg->log_target_set = 1;
			break;
		case OPT_UDP_TIMEOUT:
			if (parse_uint(optarg, &cfg->udp_timeout_s, 1, 86400) < 0) {
				LOG_E("--udp-timeout must be an integer in 1..86400");
				return -1;
			}
			break;
		case OPT_UDP_MAX_SESSIONS:
			if (parse_uint(optarg, &cfg->udp_max_sessions, 1, 1u << 22) < 0) {
				LOG_E("--udp-max-sessions must be an integer in 1..4194304");
				return -1;
			}
			break;
		case OPT_TCP_IDLE_TIMEOUT:
			if (parse_uint(optarg, &cfg->tcp_idle_timeout_s, 0, 86400) < 0) {
				LOG_E("--tcp-idle-timeout must be an integer in 0..86400");
				return -1;
			}
			break;
		case OPT_MAX_CONNS:
			if (parse_uint(optarg, &cfg->max_conns, 1, 1u << 22) < 0) {
				LOG_E("--max-conns must be an integer in 1..4194304");
				return -1;
			}
			break;
		case OPT_PIPE_SIZE:
			if (parse_uint(optarg, &cfg->pipe_size, 4096, 1u << 26) < 0) {
				LOG_E("--pipe-size must be an integer in 4096..67108864");
				return -1;
			}
			break;
		case OPT_BATCH_SIZE:
			if (parse_uint(optarg, &cfg->batch_size, 1, 1024) < 0) {
				LOG_E("--batch-size must be an integer in 1..1024");
				return -1;
			}
			break;
		case OPT_STATS_INTERVAL:
			if (parse_uint(optarg, &cfg->stats_interval_s, 0, 86400) < 0) {
				LOG_E("--stats-interval must be an integer in 0..86400");
				return -1;
			}
			break;
		case OPT_V6ONLY:
			cfg->v6only = 1;
			break;
		case OPT_NO_SYSCTL:
			cfg->no_sysctl = 1;
			cfg->nft_opts_set = 1;
			break;
		case OPT_NFT_TABLE:
			if (!*optarg || strlen(optarg) >= 64) {
				LOG_E("--nft-table name must be 1..63 characters");
				return -1;
			}
			cfg->nft_table = optarg;
			cfg->nft_opts_set = 1;
			break;
		case OPT_NFT_DEVICES:
			if (nft_devices_set(cfg, optarg) < 0) {
				LOG_E("cannot parse --nft-devices '%s'", optarg);
				return -1;
			}
			cfg->nft_opts_set = 1;
			break;
		case OPT_NO_FLOWTABLE:
			cfg->no_flowtable = 1;
			cfg->nft_opts_set = 1;
			break;
		case OPT_NO_HW_OFFLOAD:
			cfg->no_hw_offload = 1;
			cfg->nft_opts_set = 1;
			break;
		case OPT_RUN_DIR:
			cfg->run_dir = optarg;
			break;
		case OPT_CHECK:
			cfg->check_only = 1;
			break;
		case 'v':
			printf("portfwd %s\n", PORTFWD_VERSION);
			return 1;
		case 'h':
			usage(stdout, argv[0]);
			return 1;
		default:
			usage(stderr, argv[0]);
			return -1;
		}
	}

	if (optind < argc) {
		LOG_E("unexpected operand '%s'", argv[optind]);
		return -1;
	}

	if (cfg->daemonize && !cfg->log_target_set)
		cfg->log_target = LOG_TARGET_SYSLOG;

	return 0;
}

int config_validate(const struct fwd_config *cfg)
{
	int rc = 0;

	if (!cfg->mode_set) {
		LOG_E("--mode is required; expected 'userspace' or 'nftables'");
		rc = -1;
	}
	if (cfg->n_rules == 0) {
		LOG_E("at least one -f/--forward rule is required");
		rc = -1;
	}
	if (cfg->workers == 0) {
		LOG_E("--workers must be at least 1");
		rc = -1;
	}
	if (cfg->pipe_size % 4096u != 0)
		LOG_W("--pipe-size %u is not a multiple of the page size; the kernel will round it up",
		      cfg->pipe_size);

	return rc;
}

void config_dump(const struct fwd_config *cfg, int level)
{
	if (!log_enabled(level))
		return;

	log_emit(level,
		 "config: mode=%s workers=%u max-conns=%u udp-max-sessions=%u "
		 "udp-timeout=%us tcp-idle-timeout=%us pipe-size=%u batch-size=%u",
		 config_mode_str(cfg->mode), cfg->workers, cfg->max_conns,
		 cfg->udp_max_sessions, cfg->udp_timeout_s,
		 cfg->tcp_idle_timeout_s, cfg->pipe_size, cfg->batch_size);

	for (unsigned i = 0; i < cfg->n_rules; i++) {
		const struct fwd_rule *r = &cfg->rules[i];
		char l[ADDR_STR_MAX], u[ADDR_STR_MAX];

		if (r->err[0])
			continue;
		if (addr_format(&r->local, l, sizeof(l)) < 0 ||
		    addr_format(&r->remote, u, sizeof(u)) < 0)
			continue;
		log_emit(level, "rule #%u: %s/%s->%s%s", i + 1,
			 config_proto_str(r->proto), l, u,
			 r->cross_family ? " (cross-family)" : "");
	}
}

void config_free(struct fwd_config *cfg)
{
	for (unsigned i = 0; i < cfg->n_nft_devices; i++)
		free(cfg->nft_devices[i]);
	free(cfg->nft_devices);
	free(cfg->rules);
	cfg->nft_devices = nullptr;
	cfg->rules = nullptr;
	cfg->n_nft_devices = 0;
	cfg->n_rules = 0;
}
