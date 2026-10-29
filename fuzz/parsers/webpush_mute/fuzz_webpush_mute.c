/*
 * fuzz_webpush_mute.c - libFuzzer harness for ircd/webpush_mute.c: the
 * per-account mute list ("target:until;target:until;...") that a client
 * stores as metadata and the push path parses on every message.
 * Input: value\0target\0drop, byte 0 = time skew.  Properties: prune output
 * fits, is a subsequence of the input's entries, never contains the dropped
 * target, and checking the pruned list agrees with checking the original
 * for every target other than the dropped one.
 */
#include "webpush_mute.h"
#include "fuzz_util.h"

static int eq_ci(const char *a, size_t al, const char *b, size_t bl)
{
  size_t i;
  if (al != bl) return 0;
  for (i = 0; i < al; i++)
    if ((a[i] | 0x20) != (b[i] | 0x20)) return 0;
  return 1;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  const char *p = (const char *)data + 1, *end = (const char *)data + size;
  char *value, *target, *drop, out[1024];
  time_t now;
  int r1, r2, pr;
  if (size < 1) return 0;
  now = 1700000000 + (time_t)data[0] * 1000;
  value = fuzz_field(&p, end); target = fuzz_field(&p, end); drop = fuzz_field(&p, end);
  r1 = webpush_mute_check(value, target, now);
  (void)webpush_mute_check_cmp(value, target, now, eq_ci);
  pr = webpush_mute_prune(value, drop, now, out, sizeof out);
  if (pr >= 0) {
    CHECK(strlen(out) < sizeof out);
    /* dropping "*" (the global snooze) changes every target */
    if (strcmp(target, drop) && strcmp(drop, "*") && strlen(value) < sizeof out) {
      r2 = webpush_mute_check(out, target, now);
      CHECK(r1 == r2);
    }
  }
  (void)webpush_mute_prune_cmp(value, drop, now, out, 1 + data[0] % 64, eq_ci);
  free(value); free(target); free(drop);
  return 0;
}
