#include "util/compat.h"
#include "probe.h"
#include "log.h"

#include <errno.h>
#include <libgen.h>
#include <limits.h>
#include <arpa/inet.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/socket.h>

void probe_add(struct probe_report *r, const char *name,
	       enum probe_severity sev, const char *detail, const char *hint)
{
	struct probe_entry *e;

	if (sev == PROBE_FATAL)
		r->n_fatal++;
	else if (sev == PROBE_WARN)
		r->n_warn++;

	if (r->n >= PF_ARRAY_LEN(r->entries)) {
		r->n_dropped++;
		return;
	}

	e = &r->entries[r->n++];
	e->name = name;
	e->sev = sev;
	snprintf(e->detail, sizeof(e->detail), "%s", detail ? detail : "");
	snprintf(e->hint, sizeof(e->hint), "%s", hint ? hint : "");
}

void probe_addf(struct probe_report *r, const char *name,
		enum probe_severity sev, const char *hint, const char *fmt, ...)
{
	char detail[256];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(detail, sizeof(detail), fmt, ap);
	va_end(ap);

	probe_add(r, name, sev, detail, hint);
}

int probe_have_capability(int cap)
{
	FILE *f;
	char line[256];
	int found = -1;

	f = fopen("/proc/self/status", "re");
	if (!f)
		return geteuid() == 0 ? 1 : -1;

	while (fgets(line, sizeof(line), f)) {
		unsigned long long mask;

		if (sscanf(line, "CapEff: %llx", &mask) == 1) {
			found = (int)((mask >> cap) & 1u);
			break;
		}
	}
	fclose(f);

	if (found < 0)
		return geteuid() == 0 ? 1 : -1;
	return found;
}

long probe_read_sysctl_long(const char *path, long *out)
{
	FILE *f = fopen(path, "re");
	long v;

	if (!f)
		return -1;
	if (fscanf(f, "%ld", &v) != 1) {
		fclose(f);
		return -1;
	}
	fclose(f);
	*out = v;
	return 0;
}

static int dir_writable(const char *path)
{
	return access(path, W_OK | X_OK) == 0;
}

/* C1: rule syntax */
static void probe_rule_syntax(const struct fwd_config *cfg,
			      struct probe_report *r)
{
	unsigned bad = 0;

	for (unsigned i = 0; i < cfg->n_rules; i++) {
		const struct fwd_rule *rule = &cfg->rules[i];

		if (rule->err_kind == RULE_ERR_SYNTAX) {
			probe_addf(r, "rule syntax", PROBE_FATAL,
				   "see the RULE grammar in --help",
				   "invalid forward rule '%s': %s", rule->spec,
				   rule->err);
			bad++;
			continue;
		}
		if (rule->err_kind != RULE_ERR_NONE)
			continue;

		if (port_of_sockaddr(&rule->local) == 0) {
			probe_addf(r, "rule syntax", PROBE_FATAL, nullptr,
				   "invalid forward rule '%s': listen port must be non-zero",
				   rule->spec);
			bad++;
		}
		if (port_of_sockaddr(&rule->remote) == 0) {
			probe_addf(r, "rule syntax", PROBE_FATAL, nullptr,
				   "invalid forward rule '%s': upstream port must be non-zero",
				   rule->spec);
			bad++;
		}
	}

	if (!bad)
		probe_addf(r, "rule syntax", PROBE_OK, nullptr, "%u rule%s parsed",
			   cfg->n_rules, cfg->n_rules == 1 ? "" : "s");
}

/* C2: duplicate listeners */
static void probe_duplicate_listeners(const struct fwd_config *cfg,
				      struct probe_report *r)
{
	unsigned bad = 0;

	for (unsigned i = 0; i < cfg->n_rules; i++) {
		const struct fwd_rule *a = &cfg->rules[i];

		if (a->err_kind != RULE_ERR_NONE)
			continue;

		for (unsigned j = i + 1; j < cfg->n_rules; j++) {
			const struct fwd_rule *b = &cfg->rules[j];
			unsigned overlap;
			char buf[ADDR_STR_MAX];

			if (b->err_kind != RULE_ERR_NONE)
				continue;

			overlap = a->proto & b->proto;
			if (!overlap || !addr_equal(&a->local, &b->local))
				continue;

			if (addr_format(&a->local, buf, sizeof(buf)) < 0)
				buf[0] = '\0';
			probe_addf(r, "duplicate listeners", PROBE_FATAL,
				   "each (proto, address, port) triple may be listed only once",
				   "duplicate listener %s/%s defined by rules #%u and #%u",
				   config_proto_str(overlap), buf, i + 1, j + 1);
			bad++;
		}
	}

	if (!bad)
		probe_add(r, "duplicate listeners", PROBE_OK, "no overlap", nullptr);
}

/* C3: remote resolvable */
static void probe_remote_resolvable(const struct fwd_config *cfg,
				    struct probe_report *r)
{
	unsigned bad = 0;

	for (unsigned i = 0; i < cfg->n_rules; i++) {
		const struct fwd_rule *rule = &cfg->rules[i];

		if (rule->err_kind != RULE_ERR_RESOLVE)
			continue;
		probe_add(r, "remote resolvable", PROBE_FATAL, rule->err,
			  "use a literal IP address, or ensure /etc/resolv.conf is populated before startup");
		bad++;
	}

	if (!bad)
		probe_add(r, "remote resolvable", PROBE_OK, nullptr, nullptr);
}

/* C4: privileged port */
static void probe_privileged_port(const struct fwd_config *cfg,
				  struct probe_report *r)
{
	long unpriv_start = 1024;
	unsigned bad = 0;
	int cap;

	if (geteuid() == 0) {
		probe_add(r, "privileged port", PROBE_OK, "running as uid 0",
			  nullptr);
		return;
	}

	probe_read_sysctl_long("/proc/sys/net/ipv4/ip_unprivileged_port_start",
			       &unpriv_start);
	cap = probe_have_capability(CAP_BIT_NET_BIND_SERVICE);

	for (unsigned i = 0; i < cfg->n_rules; i++) {
		const struct fwd_rule *rule = &cfg->rules[i];
		unsigned port;

		if (rule->err_kind != RULE_ERR_NONE)
			continue;
		port = ntohs(port_of_sockaddr(&rule->local));
		if ((long)port >= unpriv_start || cap == 1)
			continue;

		probe_addf(r, "privileged port",
			   cap == 0 ? PROBE_FATAL : PROBE_WARN,
			   "run as root, or: setcap cap_net_bind_service=+ep /usr/sbin/portfwd",
			   "binding to port %u requires root or CAP_NET_BIND_SERVICE",
			   port);
		bad++;
	}

	if (!bad)
		probe_add(r, "privileged port", PROBE_OK, nullptr, nullptr);
}

/* C5: IPv6 availability */
static void probe_ipv6_available(const struct fwd_config *cfg,
				 struct probe_report *r)
{
	unsigned need_v6 = 0;
	unsigned idx = 0;
	int fd;

	for (unsigned i = 0; i < cfg->n_rules; i++) {
		const struct fwd_rule *rule = &cfg->rules[i];

		if (rule->err_kind != RULE_ERR_NONE)
			continue;
		if (is_v6(&rule->local) || is_v6(&rule->remote)) {
			need_v6 = 1;
			idx = i + 1;
			break;
		}
	}

	if (!need_v6) {
		probe_add(r, "ipv6 available", PROBE_OK, "no IPv6 rule", nullptr);
		return;
	}

	fd = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		probe_addf(r, "ipv6 available", PROBE_FATAL,
			   "load the ipv6 module, or rebuild the kernel with CONFIG_IPV6",
			   "rule #%u requires IPv6 but the kernel has no AF_INET6 support (%s)",
			   idx, strerror(errno));
		return;
	}
	close(fd);
	probe_add(r, "ipv6 available", PROBE_OK, nullptr, nullptr);
}

/* C6: run dir writable (only meaningful for the nftables sysctl refcount) */
static void probe_run_dir(const struct fwd_config *cfg, struct probe_report *r)
{
	struct stat st;

	if (cfg->mode != MODE_NFTABLES || cfg->no_sysctl) {
		probe_addf(r, "run dir writable", PROBE_OK, nullptr,
			   "not required in %s mode", config_mode_str(cfg->mode));
		return;
	}

	if (stat(cfg->run_dir, &st) == 0 && S_ISDIR(st.st_mode) &&
	    dir_writable(cfg->run_dir)) {
		probe_addf(r, "run dir writable", PROBE_OK, nullptr, "%s",
			   cfg->run_dir);
		return;
	}

	if (mkdir(cfg->run_dir, 0755) == 0 || errno == EEXIST) {
		if (dir_writable(cfg->run_dir)) {
			probe_addf(r, "run dir writable", PROBE_OK, nullptr, "%s",
				   cfg->run_dir);
			return;
		}
	}

	probe_addf(r, "run dir writable", PROBE_WARN,
		   "concurrent instances may interfere; consider --no-sysctl",
		   "sysctl refcounting unavailable (%s: %s); falling back to conservative restore",
		   cfg->run_dir, strerror(errno));
}

/* C7: pidfile writable */
static void probe_pidfile(const struct fwd_config *cfg, struct probe_report *r)
{
	char buf[PATH_MAX];
	const char *dir;

	if (!cfg->pidfile) {
		probe_add(r, "pidfile writable", PROBE_OK, "no pid file requested",
			  nullptr);
		return;
	}

	snprintf(buf, sizeof(buf), "%s", cfg->pidfile);
	dir = dirname(buf);

	if (dir_writable(dir)) {
		probe_addf(r, "pidfile writable", PROBE_OK, nullptr, "%s",
			   cfg->pidfile);
		return;
	}

	probe_addf(r, "pidfile writable", PROBE_FATAL,
		   "point --pidfile at a writable directory, or drop the option",
		   "cannot create pid file '%s': %s", cfg->pidfile,
		   strerror(errno));
}

int probe_run_common(const struct fwd_config *cfg, struct probe_report *r)
{
	probe_rule_syntax(cfg, r);
	probe_duplicate_listeners(cfg, r);
	probe_remote_resolvable(cfg, r);
	probe_privileged_port(cfg, r);
	probe_ipv6_available(cfg, r);
	probe_run_dir(cfg, r);
	probe_pidfile(cfg, r);

	return r->n_fatal ? -1 : 0;
}

static void print_problem(const struct probe_entry *e)
{
	fprintf(stderr, "[%s] %s: %s\n",
		e->sev == PROBE_FATAL ? "FATAL" : "WARN ", e->name, e->detail);
	if (e->hint[0])
		fprintf(stderr, "        hint: %s\n", e->hint);
}

void probe_report_print(const struct probe_report *r)
{
	for (unsigned i = 0; i < r->n; i++)
		if (r->entries[i].sev != PROBE_OK)
			print_problem(&r->entries[i]);

	if (r->n_dropped)
		fprintf(stderr, "[WARN ] probe report: %u further entries were dropped\n",
			r->n_dropped);
}

void probe_report_print_full(const struct probe_report *r)
{
	static const char *const sev_str[] = { "OK  ", "WARN", "FATAL" };

	for (unsigned i = 0; i < r->n; i++) {
		const struct probe_entry *e = &r->entries[i];

		printf("probe: %-28s %-5s %s\n", e->name, sev_str[e->sev],
		       e->detail);
		if (e->hint[0] && e->sev != PROBE_OK)
			printf("        hint: %s\n", e->hint);
	}

	printf("\nresult: %u fatal, %u warning%s -- configuration is %s\n",
	       r->n_fatal, r->n_warn, r->n_warn == 1 ? "" : "s",
	       r->n_fatal ? "NOT usable" : "usable");
}
