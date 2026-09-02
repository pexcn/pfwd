#include "util/compat.h"
#include "backend.h"
#include "config.h"
#include "log.h"
#include "probe.h"
#include "sig.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

static const struct fwd_backend *backend_lookup(enum fwd_mode mode)
{
	switch (mode) {
	case MODE_USERSPACE:
		return &backend_userspace;
	case MODE_NFTABLES:
#ifdef ENABLE_NFTABLES
		return &backend_nftables;
#else
		return nullptr;
#endif
	}
	return nullptr;
}

static void probe_backend_availability(const struct fwd_config *cfg,
				       const struct fwd_backend *be,
				       struct probe_report *rep)
{
	if (be) {
		probe_addf(rep, "mode", PROBE_OK, nullptr, "%s backend selected",
			   be->name);
		return;
	}
#ifdef ENABLE_NFTABLES
	probe_addf(rep, "mode", PROBE_FATAL, "use --mode userspace",
		   "no backend for mode '%s'", config_mode_str(cfg->mode));
#else
	(void)cfg;
	probe_add(rep, "mode", PROBE_FATAL,
		  "the nftables backend is not available in this build",
		  "rebuild with ENABLE_NFTABLES=1, or use --mode userspace");
#endif
}

static int daemonize(void)
{
	pid_t pid;
	int fd;

	pid = fork();
	if (pid < 0)
		return -1;
	if (pid > 0)
		_exit(0);

	if (setsid() < 0)
		return -1;

	pid = fork();
	if (pid < 0)
		return -1;
	if (pid > 0)
		_exit(0);

	if (chdir("/") != 0)
		return -1;
	umask(0027);

	fd = open("/dev/null", O_RDWR | O_CLOEXEC);
	if (fd < 0)
		return -1;
	dup2(fd, STDIN_FILENO);
	dup2(fd, STDOUT_FILENO);
	dup2(fd, STDERR_FILENO);
	if (fd > STDERR_FILENO)
		close(fd);

	return 0;
}

static int pidfile_write(const char *path)
{
	char buf[32];
	int fd, n;

	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
	if (fd < 0) {
		LOG_E("cannot create pid file '%s': %s", path, strerror(errno));
		return -1;
	}

	n = snprintf(buf, sizeof(buf), "%ld\n", (long)getpid());
	if (n < 0 || write(fd, buf, (size_t)n) != n) {
		LOG_E("cannot write pid file '%s': %s", path, strerror(errno));
		close(fd);
		unlink(path);
		return -1;
	}
	close(fd);
	return 0;
}

static void pidfile_remove(const char *path)
{
	if (path && unlink(path) != 0 && errno != ENOENT)
		LOG_W("cannot remove pid file '%s': %s", path, strerror(errno));
}

int main(int argc, char **argv)
{
	struct fwd_config cfg;
	struct probe_report rep = {};
	const struct fwd_backend *be;
	void *state = nullptr;
	int sigfd = -1;
	int rc;

	log_init(LOG_INFO, LOG_TARGET_STDERR, "portfwd");

	rc = config_parse_argv(argc, argv, &cfg);
	if (rc != 0) {
		config_free(&cfg);
		return rc > 0 ? 0 : 1;
	}

	log_init(cfg.log_level, cfg.log_target, "portfwd");

	if (config_validate(&cfg) != 0) {
		config_free(&cfg);
		return 1;
	}

	be = backend_lookup(cfg.mode);
	probe_backend_availability(&cfg, be, &rep);
	probe_run_common(&cfg, &rep);
	if (be && be->probe)
		be->probe(&cfg, &rep);

	if (cfg.check_only) {
		probe_report_print_full(&rep);
		config_free(&cfg);
		return rep.n_fatal ? 1 : 0;
	}

	probe_report_print(&rep);
	if (rep.n_fatal) {
		config_free(&cfg);
		return 1;
	}

	/* Block first: no window in which a signal can kill us or a child
	 * before the signal fd exists. */
	if (sig_block() != 0) {
		LOG_E("cannot block signals: %s", strerror(errno));
		config_free(&cfg);
		return 1;
	}

	if (cfg.daemonize && daemonize() != 0) {
		LOG_E("cannot daemonize: %s", strerror(errno));
		config_free(&cfg);
		return 1;
	}

	if (cfg.pidfile && pidfile_write(cfg.pidfile) != 0) {
		config_free(&cfg);
		return 1;
	}

	sigfd = sig_setup();
	if (sigfd < 0) {
		LOG_E("cannot set up signal handling: %s", strerror(errno));
		pidfile_remove(cfg.pidfile);
		config_free(&cfg);
		return 1;
	}

	LOG_I("portfwd %s starting (mode=%s, pid=%ld)", PORTFWD_VERSION,
	      config_mode_str(cfg.mode), (long)getpid());
	config_dump(&cfg, LOG_DEBUG);

	rc = be->setup(&cfg, &state);
	if (rc != 0) {
		LOG_E("%s backend setup failed", be->name);
		sig_teardown(sigfd);
		pidfile_remove(cfg.pidfile);
		config_free(&cfg);
		return 1;
	}

	rc = be->run(state, sigfd);

	be->teardown(state);
	sig_teardown(sigfd);
	pidfile_remove(cfg.pidfile);
	LOG_I("portfwd stopped");

	config_free(&cfg);
	log_fini();
	return rc == 0 ? 0 : 1;
}
