/*
 * webpush_expiry_harness.c - CBMC proofs for ircd/webpush_expiry.c
 *
 * The real module is #included unmodified; strtoull has a faithful
 * glibc-equivalent body (common/strtoull_model.h).
 */
#include <stdlib.h>
#include <limits.h>
#include <time.h>
#include "../common/cbmc_util.h"
#include "../common/strtoull_model.h"
#include "../common/libc_models.h"

#include "../../../ircd/webpush_expiry.c"

#ifndef REC_MAX
#define REC_MAX 10
#endif

/* E1  memory safety + totality of webpush_armed_at on every string of
 *     length <= REC_MAX (every byte value, '|' included). */
void harness_armed_at_safe(void)
{
  char rec[REC_MAX + 1];
  NONDET_CSTR(rec, REC_MAX);
  (void)webpush_armed_at(rec);
  __CPROVER_assert(webpush_armed_at(0) == 0, "NULL is 0");
}

/* E2  header contract: the result is a timestamp or 0 -- never
 *     negative ("negative timestamps are malformed, not ancient"). */
void harness_armed_at_nonneg(void)
{
  char rec[REC_MAX + 1];
  NONDET_CSTR(rec, REC_MAX);
  __CPROVER_assert(webpush_armed_at(rec) >= 0, "armed_at never negative");
}

/* E3  the record format actually written by m_webpush.c:
 *     "endpoint|p256dh|auth|armed|keyid" (snprintf "%s|%s|%s|%lld|%s").
 *     For a 10-digit armed stamp and a key id of KEYID_MAX bytes from the
 *     base64url alphabet, armed_at must return the stamp.  (Production key
 *     ids are 87 bytes -- WEBPUSH_KEY_ID_LEN 88 -- so any KEYID_MAX >= 14
 *     covers the failing shape.) */
#ifndef KEYID_MAX
#define KEYID_MAX 16
#endif
void harness_armed_at_keyed_record(void)
{
  char rec[6 + 10 + 1 + KEYID_MAX + 1];
  long long want = 0;
  unsigned i, klen = nondet_unsigned();

  memcpy(rec, "e|p|a|", 6);
  for (i = 0; i < 10; i++) {
    char c = nondet_char();
    __CPROVER_assume(c >= '0' && c <= '9');
    if (i == 0) __CPROVER_assume(c != '0');
    rec[6 + i] = c;
    want = want * 10 + (c - '0');
  }
  rec[16] = '|';
  __CPROVER_assume(klen <= KEYID_MAX);
  for (i = 0; i < KEYID_MAX; i++) {
    char c = nondet_char();
    __CPROVER_assume((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
                     || (c >= '0' && c <= '9') || c == '-' || c == '_');
    rec[17 + i] = i < klen ? c : '\0';
  }
  rec[17 + KEYID_MAX] = '\0';
  __CPROVER_assert(webpush_armed_at(rec) == want,
                   "armed_at reads the 4th field of a keyed record");
}

/* E4  webpush_expired: no signed overflow for ANY armed/now/max_age
 *     (armed + max_age is computed in long long). */
void harness_expired_total(void)
{
  long long armed = nondet_ll(), max_age = nondet_ll();
  time_t now = (time_t)nondet_ll();
  int r = webpush_expired(armed, now, max_age);
  __CPROVER_assert(r == 0 || r == 1, "boolean");
}

/* E5  the same, restricted to the realistic domain: armed is a unix
 *     second no later than year 3000, max_age a feature int (>= 0, <=
 *     INT_MAX), now any time_t.  Then: monotone in now, exact boundary
 *     (expired at now == armed + max_age, not one second earlier),
 *     disabled windows/timestampless records never expire. */
void harness_expired_props(void)
{
  long long armed = nondet_ll(), max_age = nondet_ll();
  time_t now1 = (time_t)nondet_ll(), now2 = (time_t)nondet_ll();

  __CPROVER_assume(armed <= 32503680000LL);       /* 3000-01-01 */
  __CPROVER_assume(max_age <= INT_MAX);
  __CPROVER_assume(now1 <= now2);

  if (armed <= 0 || max_age <= 0) {
    __CPROVER_assert(!webpush_expired(armed, now2, max_age), "never expires");
    return;
  }
  if (webpush_expired(armed, now1, max_age))
    __CPROVER_assert(webpush_expired(armed, now2, max_age), "monotone in now");
  __CPROVER_assert(webpush_expired(armed, (time_t)(armed + max_age), max_age),
                   "expired exactly at armed + max_age");
  __CPROVER_assert(!webpush_expired(armed, (time_t)(armed + max_age - 1), max_age),
                   "live one second before");
}
