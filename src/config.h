#ifndef PORTFWD_CONFIG_H
#define PORTFWD_CONFIG_H

#include "addr.h"

#define PORTFWD_VERSION "0.1.0"

enum fwd_proto { FWD_TCP = 1u << 0, FWD_UDP = 1u << 1 };
enum rule_err  { RULE_ERR_NONE = 0, RULE_ERR_SYNTAX, RULE_ERR_RESOLVE };
enum fwd_mode  { MODE_USERSPACE, MODE_NFTABLES };

struct fwd_rule {
	union sockaddr_inx  local;        /* listen / DNAT match address */
	union sockaddr_inx  remote;       /* upstream / DNAT target      */
	unsigned            proto;        /* bitmask of enum fwd_proto   */
	unsigned            cross_family; /* computed: local.family != remote.family */
	char                label[32];    /* for logs and nft comments   */

	const char         *spec;         /* original CLI text, for diagnostics */
	int                 err_kind;     /* enum rule_err                       */
	char                err[192];     /* non-empty when the rule failed to parse */
};

struct fwd_config {
	enum fwd_mode       mode;
	struct fwd_rule    *rules;
	unsigned            n_rules;

	unsigned            workers;          /* resolved, never 0            */
	unsigned            max_conns;        /* per worker                   */
	unsigned            udp_max_sessions; /* per worker                   */
	unsigned            udp_timeout_s;
	unsigned            tcp_idle_timeout_s; /* 0 = disabled               */
	unsigned            pipe_size;
	unsigned            batch_size;
	unsigned            stats_interval_s;  /* 0 = disabled                */

	unsigned            v6only:1;
	unsigned            daemonize:1;
	unsigned            no_sysctl:1;
	unsigned            no_flowtable:1;
	unsigned            no_hw_offload:1;
	unsigned            check_only:1;
	unsigned            mode_set:1;
	unsigned            log_target_set:1;
	unsigned            nft_opts_set:1;

	const char         *pidfile;
	const char         *run_dir;
	const char         *nft_table;
	char              **nft_devices;
	unsigned            n_nft_devices;
	int                 log_level;
	int                 log_target;
};

/* Defaults, kept here so --help and the probe messages can quote them. */
#define DEF_WORKERS            1u
#define DEF_MAX_CONNS          4096u
#define DEF_UDP_MAX_SESSIONS   8192u
#define DEF_UDP_TIMEOUT_S      60u
#define DEF_TCP_IDLE_TIMEOUT_S 0u
#define DEF_PIPE_SIZE          65536u
#define DEF_BATCH_SIZE         32u
#define DEF_NFT_TABLE          "portfwd"
#define DEF_RUN_DIR            "/run/portfwd"
#define WORKERS_AUTO_MAX       4u

int  config_parse_argv(int argc, char **argv, struct fwd_config *cfg);
void config_free(struct fwd_config *cfg);
int  config_validate(const struct fwd_config *cfg);  /* mode-independent checks */
void config_dump(const struct fwd_config *cfg, int level);

const char *config_proto_str(unsigned proto);
const char *config_mode_str(enum fwd_mode mode);

#endif /* PORTFWD_CONFIG_H */
