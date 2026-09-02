#include "util/compat.h"

/* <syslog.h> defines LOG_INFO/LOG_DEBUG as macros that collide with our own
 * level names. Capture the priorities we need, then drop the macros before
 * pulling in log.h. This file is the only one that touches syslog. */
#include <syslog.h>
enum {
	SYSPRIO_ERR     = LOG_ERR,
	SYSPRIO_WARNING = LOG_WARNING,
	SYSPRIO_INFO    = LOG_INFO,
	SYSPRIO_DEBUG   = LOG_DEBUG,
};
#undef LOG_ERR
#undef LOG_WARNING
#undef LOG_INFO
#undef LOG_DEBUG

#include "log.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <time.h>

int log_level_current = LOG_INFO;

static int log_target_current = LOG_TARGET_STDERR;
static int syslog_opened;

static const char *const level_names[] = {
	"ERROR", "WARN", "INFO", "DEBUG", "TRACE"
};

static const int syslog_prio[] = {
	SYSPRIO_ERR, SYSPRIO_WARNING, SYSPRIO_INFO, SYSPRIO_DEBUG, SYSPRIO_DEBUG
};

static_assert(PF_ARRAY_LEN(level_names) == LOG_TRACE + 1,
	      "level name table is out of sync with the level enum");
static_assert(PF_ARRAY_LEN(syslog_prio) == LOG_TRACE + 1,
	      "syslog priority table is out of sync with the level enum");

const char *log_level_name(int level)
{
	if (level < LOG_ERROR || level > LOG_TRACE)
		return "?";
	return level_names[level];
}

int log_level_parse(const char *name)
{
	for (unsigned i = 0; i < PF_ARRAY_LEN(level_names); i++)
		if (strcasecmp(name, level_names[i]) == 0)
			return (int)i;
	return -1;
}

int log_target_parse(const char *name)
{
	if (strcasecmp(name, "stderr") == 0)
		return LOG_TARGET_STDERR;
	if (strcasecmp(name, "syslog") == 0)
		return LOG_TARGET_SYSLOG;
	return -1;
}

void log_init(int level, int target, const char *ident)
{
	log_level_current = level;
	log_target_current = target;

	if (target == LOG_TARGET_SYSLOG && !syslog_opened) {
		openlog(ident ? ident : "portfwd", LOG_PID, LOG_DAEMON);
		syslog_opened = 1;
	}
}

void log_set_level(int level)
{
	log_level_current = level;
}

void log_fini(void)
{
	if (syslog_opened) {
		closelog();
		syslog_opened = 0;
	}
}

__attribute__((format(printf, 2, 0)))
static void log_vemit(int level, const char *fmt, va_list ap)
{
	char msg[1024];

	vsnprintf(msg, sizeof(msg), fmt, ap);

	if (log_target_current == LOG_TARGET_SYSLOG) {
		syslog(syslog_prio[level], "%s", msg);
		return;
	}

	struct timespec ts;
	struct tm tm;
	char stamp[32];

	clock_gettime(CLOCK_REALTIME, &ts);
	localtime_r(&ts.tv_sec, &tm);
	strftime(stamp, sizeof(stamp), "%Y-%m-%dT%H:%M:%S", &tm);
	fprintf(stderr, "%s.%03ld [%s] %s\n", stamp, ts.tv_nsec / 1000000,
		level_names[level], msg);
}

void log_emit(int level, const char *fmt, ...)
{
	va_list ap;

	if (!log_enabled(level))
		return;

	va_start(ap, fmt);
	log_vemit(level, fmt, ap);
	va_end(ap);
}

#define LOG_RL_BURST     10u
#define LOG_RL_REFILL_MS 1000u

void log_emit_rl(struct log_rl *rl, int level, const char *fmt, ...)
{
	uint64_t now = pf_now_ms();
	uint32_t suppressed;
	char msg[1024];
	va_list ap;

	if (!log_enabled(level))
		return;

	if (rl->last_ms == 0) {
		rl->last_ms = now;
		rl->tokens = LOG_RL_BURST;
	} else if (now > rl->last_ms) {
		uint64_t gained = (now - rl->last_ms) / LOG_RL_REFILL_MS;

		if (gained > 0) {
			rl->last_ms += gained * LOG_RL_REFILL_MS;
			rl->tokens = (uint32_t)PF_MIN(LOG_RL_BURST,
						      rl->tokens + gained);
		}
	}

	if (rl->tokens == 0) {
		rl->suppressed++;
		return;
	}
	rl->tokens--;

	suppressed = rl->suppressed;
	rl->suppressed = 0;

	va_start(ap, fmt);
	vsnprintf(msg, sizeof(msg), fmt, ap);
	va_end(ap);

	if (suppressed)
		log_emit(level, "%s (%u similar messages suppressed)", msg,
			 suppressed);
	else
		log_emit(level, "%s", msg);
}
