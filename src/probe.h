#ifndef PORTFWD_PROBE_H
#define PORTFWD_PROBE_H

#include "config.h"

enum probe_severity { PROBE_OK, PROBE_WARN, PROBE_FATAL };

struct probe_entry {
	const char         *name;
	enum probe_severity sev;
	char                detail[256];   /* human-readable, English */
	char                hint[256];     /* what the user should do about it */
};

struct probe_report {
	struct probe_entry entries[32];
	unsigned           n;
	unsigned           n_fatal;
	unsigned           n_warn;
	unsigned           n_dropped;      /* entries that did not fit */
};

void probe_add(struct probe_report *r, const char *name,
	       enum probe_severity sev, const char *detail, const char *hint);
void probe_addf(struct probe_report *r, const char *name,
		enum probe_severity sev, const char *hint, const char *fmt, ...)
	__attribute__((format(printf, 5, 6)));

int  probe_run_common(const struct fwd_config *cfg, struct probe_report *r);

/* Prints WARN and FATAL entries only, in the "[FATAL] name: detail" form. */
void probe_report_print(const struct probe_report *r);

/* Prints every entry plus the result line; used by --check. */
void probe_report_print_full(const struct probe_report *r);

/* Shared helpers, also used by the backends' own probes. */
int  probe_have_capability(int cap);   /* 1 yes, 0 no, -1 unknown */
long probe_read_sysctl_long(const char *path, long *out); /* 0 ok, -1 error */

#define CAP_BIT_NET_BIND_SERVICE 10
#define CAP_BIT_NET_ADMIN        12

#endif /* PORTFWD_PROBE_H */
