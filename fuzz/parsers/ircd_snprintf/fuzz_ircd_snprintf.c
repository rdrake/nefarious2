/*
 * fuzz_ircd_snprintf.c - libFuzzer harness for ircd/ircd_snprintf.c, the
 * formatter behind every line the ircd sends.  The format is fixed (as in
 * the ircd) and the arguments come from the input: strings with arbitrary
 * bytes, widths and precisions (including negative ones through '*'),
 * integers, a buffer size.  Differential oracle: for the conversions that
 * mean the same thing to libc (%s %d %u %x %X %o %c %ld %lu %lld %llu %%
 * with flags/width/precision) ircd_snprintf must produce exactly what
 * snprintf produces, and return the same length.  The ircd-only %C (a
 * client's name) is exercised for memory safety.
 */
#include "config.h"
#include "client.h"
#include "ircd_snprintf.h"
#include "fuzz_util.h"

struct fmt { const char *f; int kind; };
/* kind: 0 = one string, 1 = width+string, 2 = prec+string, 3 = ints,
 *       4 = width+prec+string, 5 = char+string */
static const struct fmt fmts[] = {
  { "%s", 0 }, { "<%-20s>", 0 }, { "[%20s]", 0 }, { "%.5s|%s", 0 },
  { "%*s", 1 }, { "%-*s.", 1 }, { "%.*s", 2 }, { "%*.*s", 4 },
  { "%d %u %x %X %o", 3 }, { "%ld %lu %lld %llu %%", 3 }, { "%+d % d %05d %-5d|", 3 },
  { "%#x %#o %.3d %10.4u", 3 }, { "%c%s", 5 }, { "%s :%s", 0 },
};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  const char *p = (const char *)data + 6, *end = (const char *)data + size;
  const struct fmt *F;
  char *s1, *s2, a[600], b[600];
  int w, pr, ra = 0, rb = 0, iv;
  size_t bs;
  if (size < 6) return 0;
  F = &fmts[data[0] % (sizeof fmts / sizeof fmts[0])];
  w = (int)(signed char)data[1] * 4;
  pr = (int)(signed char)data[2] * 2;
  bs = 1 + (data[3] | (data[4] << 8)) % sizeof a;
  iv = (int)(((unsigned)data[5] << 24) | ((unsigned)data[1] << 16) | ((unsigned)data[2] << 8) | data[3]);
  s1 = fuzz_field(&p, end);
  s2 = fuzz_field(&p, end);
  switch (F->kind) {
  case 0:
    ra = ircd_snprintf(0, a, bs, F->f, s1, s2);
    rb = snprintf(b, bs, F->f, s1, s2);
    break;
  case 1:
    ra = ircd_snprintf(0, a, bs, F->f, w, s1);
    rb = snprintf(b, bs, F->f, w, s1);
    break;
  case 2:
    ra = ircd_snprintf(0, a, bs, F->f, pr, s1);
    rb = snprintf(b, bs, F->f, pr, s1);
    break;
  case 4:
    ra = ircd_snprintf(0, a, bs, F->f, w, pr, s1);
    rb = snprintf(b, bs, F->f, w, pr, s1);
    break;
  case 5:
    ra = ircd_snprintf(0, a, bs, F->f, (int)(unsigned char)data[5], s1);
    rb = snprintf(b, bs, F->f, (int)(unsigned char)data[5], s1);
    break;
  case 3:
    if (F->f[1] == 'l') {
      long l = (long)iv * 977; unsigned long ul = (unsigned long)l;
      long long ll = (long long)l * 31; unsigned long long ull = (unsigned long long)ll;
      ra = ircd_snprintf(0, a, bs, F->f, l, ul, ll, ull);
      rb = snprintf(b, bs, F->f, l, ul, ll, ull);
    } else {
      ra = ircd_snprintf(0, a, bs, F->f, iv, (unsigned)iv, (unsigned)iv, (unsigned)iv, (unsigned)iv);
      rb = snprintf(b, bs, F->f, iv, (unsigned)iv, (unsigned)iv, (unsigned)iv, (unsigned)iv);
    }
    break;
  }
  CHECK(strlen(a) < bs);
  if (!fuzz_strict() && ((F->kind == 5 && data[5] == 0) ||
                          (strchr(F->f, '#') && iv == 0) ||
                          (strstr(F->f, "%05d") && iv < 0))) {
    /* %c of NUL: both stop the visible string there.  %#x / %#o of 0:
     * the ircd prints "0x0" / "00" where C prints "0" (noted in
     * FINDINGS.md); "%05d" of a negative number pads 5 digits after the
     * sign where C counts the sign in the width */
  } else if (strcmp(a, b) || ra != rb) {
    fprintf(stderr, "fmt \"%s\" bs %zu w %d pr %d\n ircd [%s] %d\n libc [%s] %d\n",
            F->f, bs, w, pr, a, ra, b, rb);
    abort();
  }
  {
    /* %C: the client's name */
    static struct Client c;
    memset(&c, 0, sizeof c);
    strncpy(cli_name(&c), s1, NICKLEN);
    (void)ircd_snprintf(0, a, bs, "%C %s", &c, s2);
    CHECK(strlen(a) < bs);
  }
  free(s1); free(s2);
  return 0;
}
