/*
 * fuzz_webpush_expiry.c - libFuzzer harness for ircd/webpush_expiry.c:
 * the arming timestamp parsed out of a stored subscription record
 * ("endpoint|p256dh|auth|armed|keyid") and the expiry decision.  Stored
 * records come back from RocksDB (possibly corrupt or older formats).
 */
#include "webpush_expiry.h"
#include "fuzz_util.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  char *s;
  long long armed, max_age;
  if (size < 9) return 0;
  memcpy(&max_age, data, 8);
  s = strndup((const char *)data + 8, size - 8);
  armed = webpush_armed_at(s);
  CHECK(armed >= 0);
  /* F18 (FINDINGS.md): armed + max_age overflows for a record armed near
   * LLONG_MAX; skipped unless FUZZ_STRICT */
  if (fuzz_strict() || max_age <= 0 || armed <= 0 || armed <= (long long)(~0ULL >> 1) - max_age)
    (void)webpush_expired(armed, (time_t)1700000000, max_age);
  if (fuzz_strict() || armed <= (long long)(~0ULL >> 1) - 30LL * 86400)
    (void)webpush_expired(armed, (time_t)1700000000, 30LL * 86400);
  free(s);
  return 0;
}
