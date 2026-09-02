#include "util/compat.h"
#include "sig.h"
#include "log.h"

#include <errno.h>
#include <signal.h>
#include <string.h>

#ifdef PF_HAVE_SIGNALFD
#  include <sys/signalfd.h>
#endif

static const int handled[] = { SIGTERM, SIGINT, SIGQUIT, SIGHUP, SIGUSR1 };

/* Only used by the self-pipe fallback. */
static volatile sig_atomic_t selfpipe_wfd = -1;

static void selfpipe_handler(int signo)
{
	unsigned char byte = (unsigned char)signo;
	int fd = selfpipe_wfd;

	if (fd >= 0)
		(void)!write(fd, &byte, 1);
}

int sig_block(void)
{
	sigset_t set;

	sigemptyset(&set);
	for (unsigned i = 0; i < PF_ARRAY_LEN(handled); i++)
		sigaddset(&set, handled[i]);

	if (sigprocmask(SIG_BLOCK, &set, nullptr) != 0)
		return -1;

	signal(SIGPIPE, SIG_IGN);
	return 0;
}

static int sig_setup_selfpipe(void)
{
	int fds[2];
	struct sigaction sa = {};
	sigset_t set;

	if (pipe(fds) != 0)
		return -1;
	pf_set_nonblock(fds[0]);
	pf_set_nonblock(fds[1]);
	pf_set_cloexec(fds[0]);
	pf_set_cloexec(fds[1]);
	selfpipe_wfd = fds[1];

	sa.sa_handler = selfpipe_handler;
	sa.sa_flags = SA_RESTART;
	sigfillset(&sa.sa_mask);

	sigemptyset(&set);
	for (unsigned i = 0; i < PF_ARRAY_LEN(handled); i++) {
		sigaction(handled[i], &sa, nullptr);
		sigaddset(&set, handled[i]);
	}

	/* The handler must actually run, so unblock what sig_block() blocked. */
	sigprocmask(SIG_UNBLOCK, &set, nullptr);
	return fds[0];
}

int sig_setup(void)
{
	sig_block();

#ifdef PF_HAVE_SIGNALFD
	sigset_t set;
	int fd;

	sigemptyset(&set);
	for (unsigned i = 0; i < PF_ARRAY_LEN(handled); i++)
		sigaddset(&set, handled[i]);

	fd = signalfd(-1, &set, SFD_NONBLOCK | SFD_CLOEXEC);
	if (fd >= 0)
		return fd;

	LOG_W("signalfd() unavailable (%s); falling back to a self-pipe",
	      strerror(errno));
#endif
	return sig_setup_selfpipe();
}

int sig_drain(int fd)
{
#ifdef PF_HAVE_SIGNALFD
	if (selfpipe_wfd < 0) {
		struct signalfd_siginfo si;
		ssize_t n = read(fd, &si, sizeof(si));

		if (n == (ssize_t)sizeof(si))
			return (int)si.ssi_signo;
		return 0;
	}
#endif
	unsigned char byte;
	ssize_t n = read(fd, &byte, 1);

	return n == 1 ? (int)byte : 0;
}

void sig_teardown(int fd)
{
	if (fd >= 0)
		close(fd);
	if (selfpipe_wfd >= 0) {
		close(selfpipe_wfd);
		selfpipe_wfd = -1;
	}
}

int sig_is_shutdown(int signo)
{
	/* SIGHUP does not reload anything in this version: it exits. */
	return signo == SIGTERM || signo == SIGINT || signo == SIGQUIT ||
	       signo == SIGHUP;
}

const char *sig_name(int signo)
{
	switch (signo) {
	case SIGTERM: return "SIGTERM";
	case SIGINT:  return "SIGINT";
	case SIGQUIT: return "SIGQUIT";
	case SIGHUP:  return "SIGHUP";
	case SIGUSR1: return "SIGUSR1";
	default:      return "signal";
	}
}
