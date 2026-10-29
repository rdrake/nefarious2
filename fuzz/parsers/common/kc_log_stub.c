/*
 * kc_log_stub.c - a libkc log adapter that formats every message the way
 * ircd_kc_adapter.c does (vsnprintf into a bounded buffer), so format /
 * argument mismatches in libkc log calls are exercised under the
 * sanitizers instead of being skipped by a NULL log-ops table.
 */
#include <kc/kc_log.h>
#include <stdarg.h>
#include <stdio.h>

static void fuzz_kc_log(enum kc_log_level level, const char *fmt, ...)
  __attribute__((format(printf, 2, 3)));

static void fuzz_kc_log(enum kc_log_level level, const char *fmt, ...)
{
  char buf[1024];
  va_list ap;
  (void)level;
  va_start(ap, fmt);
  vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);
  __asm__ volatile("" : : "r"(buf) : "memory");
}

static const struct kc_log_ops fuzz_kc_log_ops = { fuzz_kc_log };

const struct kc_log_ops *kc_get_log_ops(void);
const struct kc_log_ops *kc_get_log_ops(void) { return &fuzz_kc_log_ops; }
