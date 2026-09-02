#ifndef PORTFWD_SIG_H
#define PORTFWD_SIG_H

/* Blocks the signals we handle. Call before fork()/daemonize() so that no
 * child can be killed by a signal we intend to deliver through the fd. */
int  sig_block(void);

/* Returns a readable fd: signalfd, or the read end of a self-pipe. */
int  sig_setup(void);

/* Returns the signal number, or 0 when the wakeup was spurious. */
int  sig_drain(int fd);

void sig_teardown(int fd);

/* True when the delivered signal means "shut down". */
int  sig_is_shutdown(int signo);

const char *sig_name(int signo);

#endif /* PORTFWD_SIG_H */
