/*
 * ircd_stubs.c - minimal ircd symbols for standalone fuzz builds, in the
 * spirit of ircd/test/test_stub.c.  Every definition is weak so a harness
 * that #includes a source defining one of them still links.
 *
 * log_write() deliberately does not format: ircd formats carry ircd-only
 * conversions (%C, %H, ...) that libc vsnprintf would misread.
 */
#include "config.h"
#include "client.h"
#include "ircd_log.h"
#include "s_debug.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

__attribute__((weak)) struct Client me;
__attribute__((weak)) int log_inassert;

__attribute__((weak)) void
log_write(enum LogSys subsys, enum LogLevel severity, unsigned int flags,
          const char *fmt, ...)
{
  (void)subsys; (void)severity; (void)flags; (void)fmt;
}

__attribute__((weak)) void
debug(int level, const char *form, ...)
{
  (void)level; (void)form;
}

__attribute__((weak)) int
exit_client(struct Client *cptr, struct Client *victim, struct Client *killer,
            const char *comment)
{
  (void)cptr; (void)victim; (void)killer; (void)comment;
  return 0;
}
