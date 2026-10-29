/*
 * webpush_mute_harness.c - CBMC proofs for ircd/webpush_mute.c
 *
 * The real module is #included unmodified; strtoull gets a faithful
 * glibc-equivalent body (common/strtoull_model.h).  Each harness_* is
 * an independent entry point (run.sh passes --function).
 *
 * VALUE_MAX bounds the mute-list string, TARGET_MAX the target.
 */
#include <stdlib.h>
#include <limits.h>
#include <time.h>
#include "../common/cbmc_util.h"
#include "../common/strtoull_model.h"

#include "../../../ircd/webpush_mute.c"

#ifndef VALUE_MAX
#define VALUE_MAX 8
#endif
#ifndef TARGET_MAX
#define TARGET_MAX 2
#endif

static int eq_never(const char *a, size_t alen, const char *b, size_t blen)
{
  (void)a; (void)alen; (void)b; (void)blen;
  return 0;
}

/* H1  memory safety + totality of webpush_mute_check over every value
 *     string of length <= VALUE_MAX, every target <= TARGET_MAX, every
 *     time_t.  Result is boolean. */
void harness_check_safe(void)
{
  char value[VALUE_MAX + 1], target[TARGET_MAX + 1];
  time_t now = (time_t)nondet_ll();
  int r;

  NONDET_CSTR(value, VALUE_MAX);
  NONDET_CSTR(target, TARGET_MAX);
  r = webpush_mute_check(value, target, now);
  __CPROVER_assert(r == 0 || r == 1, "check is boolean");
  /* NULL handling is total */
  __CPROVER_assert(webpush_mute_check(0, target, now) == 0, "NULL value");
  __CPROVER_assert(webpush_mute_check(value, 0, now) == 0, "NULL target");
}

/* H2  monotonicity in time: a target muted at now2 is muted at every
 *     earlier now1 (mutes only ever lapse as time advances). */
void harness_check_monotone(void)
{
  char value[VALUE_MAX + 1], target[TARGET_MAX + 1];
  time_t now1 = (time_t)nondet_ll(), now2 = (time_t)nondet_ll();

  NONDET_CSTR(value, VALUE_MAX);
  NONDET_CSTR(target, TARGET_MAX);
  __CPROVER_assume(now1 <= now2);
  if (webpush_mute_check(value, target, now2))
    __CPROVER_assert(webpush_mute_check(value, target, now1),
                     "muted later => muted earlier");
}

/* H3  exact-instant boundary: a single entry `t:D` (D = 1..4 decimal
 *     digits, no sign) is NOT muting when now == D, and IS muting when
 *     now == D - 1 (D > 0).  `until` is exclusive. */
void harness_check_boundary(void)
{
  char value[2 + 4 + 1];
  unsigned ndig = nondet_unsigned(), i;
  long long d = 0;

  __CPROVER_assume(ndig >= 1 && ndig <= 4);
  value[0] = 't';
  value[1] = ':';
  for (i = 0; i < 4; i++) {
    char c = nondet_char();
    if (i < ndig) {
      __CPROVER_assume(c >= '0' && c <= '9');
      d = d * 10 + (c - '0');
      value[2 + i] = c;
    } else
      value[2 + i] = '\0';
  }
  value[6] = '\0';
  __CPROVER_assume(d > 0);
  __CPROVER_assert(webpush_mute_check(value, "t", (time_t)d) == 0,
                   "until == now: expired");
  __CPROVER_assert(webpush_mute_check(value, "t", (time_t)(d - 1)) == 1,
                   "until == now + 1: muted");
}

/* H4  the stated contract for large `until`: an unsigned decimal until
 *     token that is strictly in the future mutes.  Tokens are drawn up
 *     to 20 digits (the width where they leave the long long range). */
void harness_check_large_until(void)
{
  char value[2 + 20 + 1];
  unsigned i;
  time_t now = (time_t)nondet_ll();
  unsigned long long d = 0;
  int ovf = 0;

  value[0] = 't';
  value[1] = ':';
  for (i = 0; i < 20; i++) {
    char c = nondet_char();
    __CPROVER_assume(c >= '0' && c <= '9');
    if (d > (ULLONG_MAX - (unsigned)(c - '0')) / 10ULL)
      ovf = 1;
    else
      d = d * 10ULL + (unsigned)(c - '0');
    value[2 + i] = c;
  }
  value[22] = '\0';
  __CPROVER_assume(now >= 0);
  /* the token is a future instant (mathematically: ovf => > 2^64 > now) */
  if (ovf || d > (unsigned long long)now)
    __CPROVER_assert(webpush_mute_check(value, "t", now) == 1,
                     "a future until mutes");
}

/* H5  prune: memory safety; out NUL-terminated inside outlen; result in
 *     {-1,0,1}; and SEMANTIC PRESERVATION -- for every target T the
 *     pruned list answers check() exactly like the original (prune only
 *     removes what check already ignores). */
void harness_prune_preserves(void)
{
  char value[VALUE_MAX + 1], target[TARGET_MAX + 1];
  char out[VALUE_MAX + 2];
  size_t outlen = nondet_size_t();
  time_t now = (time_t)nondet_ll();
  int r;

  NONDET_CSTR(value, VALUE_MAX);
  NONDET_CSTR(target, TARGET_MAX);
  __CPROVER_assume(outlen >= 1 && outlen <= sizeof(out));
  r = webpush_mute_prune(value, 0, now, out, outlen);
  __CPROVER_assert(r >= -1 && r <= 1, "prune result range");
  if (r >= 0) {
    __CPROVER_assert(strnlen(out, outlen) < outlen, "out terminated in outlen");
    __CPROVER_assert(webpush_mute_check(out, target, now)
                     == webpush_mute_check(value, target, now),
                     "prune preserves check() for every target");
    if (r == 0)
      __CPROVER_assert(strcmp(out, value) == 0,
                       "returns 0 (unchanged) only when out == value");
  } else {
    __CPROVER_assert(out[0] == '\0', "-1 leaves out empty");
  }
}

/* H6  prune with drop_target D (D != "*"): every other target T keeps
 *     its answer, and D itself is then only muted through a live global
 *     '*' entry. */
void harness_prune_drop(void)
{
  char value[VALUE_MAX + 1], target[TARGET_MAX + 1], drop[TARGET_MAX + 1];
  char out[VALUE_MAX + 2];
  time_t now = (time_t)nondet_ll();
  int r;

  NONDET_CSTR(value, VALUE_MAX);
  NONDET_CSTR(target, TARGET_MAX);
  NONDET_CSTR(drop, TARGET_MAX);
  __CPROVER_assume(strcmp(drop, "*") != 0);
  r = webpush_mute_prune(value, drop, now, out, sizeof(out));
  __CPROVER_assert(r >= 0, "result always fits a buffer longer than value");
  if (strcmp(target, drop) != 0)
    __CPROVER_assert(webpush_mute_check(out, target, now)
                     == webpush_mute_check(value, target, now),
                     "dropping D leaves other targets alone");
  __CPROVER_assert(webpush_mute_check(out, drop, now)
                   == webpush_mute_check_cmp(value, drop, now, eq_never),
                   "D is muted afterwards only via a live '*' entry");
}
