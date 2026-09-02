#ifndef PORTFWD_UTIL_COMPAT_H
#define PORTFWD_UTIL_COMPAT_H

/* Feature macros and small portability shims shared by every module.
 * Must be included before any system header that depends on _GNU_SOURCE. */

#ifndef _GNU_SOURCE
#  define _GNU_SOURCE 1
#endif

#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>

#if defined(__has_include)
#  if __has_include(<sys/signalfd.h>)
#    define PF_HAVE_SIGNALFD 1
#  endif
#else
#  define PF_HAVE_SIGNALFD 1
#endif

#ifndef SOCK_NONBLOCK
#  define SOCK_NONBLOCK 0
#  define PF_NEED_MANUAL_NONBLOCK 1
#endif
#ifndef SOCK_CLOEXEC
#  define SOCK_CLOEXEC 0
#  define PF_NEED_MANUAL_CLOEXEC 1
#endif

#define PF_ARRAY_LEN(a) (sizeof(a) / sizeof((a)[0]))

#define PF_MIN(a, b) ((a) < (b) ? (a) : (b))
#define PF_MAX(a, b) ((a) > (b) ? (a) : (b))

static inline uint64_t pf_now_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000);
}

static inline int pf_set_nonblock(int fd)
{
	int fl = fcntl(fd, F_GETFL, 0);
	if (fl < 0)
		return -1;
	return fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

static inline int pf_set_cloexec(int fd)
{
	int fl = fcntl(fd, F_GETFD, 0);
	if (fl < 0)
		return -1;
	return fcntl(fd, F_SETFD, fl | FD_CLOEXEC);
}

static inline uint32_t pf_next_pow2(uint32_t v)
{
	if (v < 2)
		return 1;
	v--;
	v |= v >> 1;
	v |= v >> 2;
	v |= v >> 4;
	v |= v >> 8;
	v |= v >> 16;
	return v + 1;
}

#endif /* PORTFWD_UTIL_COMPAT_H */
