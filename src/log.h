#ifndef PORTFWD_LOG_H
#define PORTFWD_LOG_H

#include <stdint.h>

enum { LOG_ERROR = 0, LOG_WARN, LOG_INFO, LOG_DEBUG, LOG_TRACE };
enum { LOG_TARGET_STDERR = 0, LOG_TARGET_SYSLOG };

void log_init(int level, int target, const char *ident);
void log_set_level(int level);
void log_fini(void);

void log_emit(int level, const char *fmt, ...)
	__attribute__((format(printf, 2, 3)));

/* Token-bucket limited variant for per-connection / per-session errors.
 * 10 tokens, refilled at 1/sec; suppressed messages are counted and reported
 * on the next message that does get through. */
struct log_rl {
	uint64_t last_ms;
	uint32_t tokens;
	uint32_t suppressed;
};

#define LOG_RL_INIT { .last_ms = 0, .tokens = 0, .suppressed = 0 }

void log_emit_rl(struct log_rl *rl, int level, const char *fmt, ...)
	__attribute__((format(printf, 3, 4)));

/* Parse helpers for the CLI. Return -1 on an unknown name. */
int log_level_parse(const char *name);
int log_target_parse(const char *name);
const char *log_level_name(int level);

extern int log_level_current;

static inline int log_enabled(int level)
{
	return level <= log_level_current;
}

#define LOG_E(...) log_emit(LOG_ERROR, __VA_ARGS__)
#define LOG_W(...) log_emit(LOG_WARN,  __VA_ARGS__)
#define LOG_I(...) log_emit(LOG_INFO,  __VA_ARGS__)

#ifdef NDEBUG_TRACE
#  define LOG_D(...) ((void)0)
#  define LOG_T(...) ((void)0)
#else
#  define LOG_D(...) do { if (log_enabled(LOG_DEBUG)) log_emit(LOG_DEBUG, __VA_ARGS__); } while (0)
#  define LOG_T(...) do { if (log_enabled(LOG_TRACE)) log_emit(LOG_TRACE, __VA_ARGS__); } while (0)
#endif

#endif /* PORTFWD_LOG_H */
