/* Bounded-exhaustive check of the REAL ircd/dbuf.c across a DBufBuffer
 * boundary, under ASan+UBSan.  dbuf.c only distinguishes EOL bytes
 * ('\r', '\n') from others, so the alphabet {a, b, \r, \n} covers every
 * control path while 'a'/'b' still check that the right bytes are
 * copied.  For each filler offset K (data starting 0..4 bytes before the
 * end of block 1), each string of length 0..7 split at every point into
 * two dbuf_put calls, and each caller length L in 1..9:
 *   - DBufLength == 1 + len after the puts;
 *   - dbuf_getmsg returns the first non-empty line (leading CR/LF
 *     skipped) NUL-terminated, or 0 when no complete line fits in L-1;
 *   - repeated getmsg drains every line in order and the remaining
 *     DBufLength matches the reference. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "../../../ircd/dbuf.c"

int feature_int(enum Feature f) { (void)f; return 1 << 24; }
int feature_bool(enum Feature f) { (void)f; return 0; }
void flush_connections(struct Client *c) { (void)c; }
void *DoMalloc(size_t s, const char *t, const char *f, int l)
{ (void)t; (void)f; (void)l; return malloc(s); }
const unsigned int IRCD_CharAttrTab[256] = {
  ['\n' - CHAR_MIN] = NTL_EOL, ['\r' - CHAR_MIN] = NTL_EOL };

int log_inassert;
void log_write(enum LogSys s, enum LogLevel l, unsigned int f, const char *fmt, ...)
{ (void)s; (void)l; (void)f; fprintf(stderr, "assert: %s\n", fmt); abort(); }

static int eol(char c) { return c == '\n' || c == '\r'; }
static const char A[] = "ab\r\n";
static long checks, bad;

static void one(const char *s, int n, int cut, int K, unsigned L)
{
  struct DBuf d = { 0, 0, 0 };
  static char filler[DBUF_SIZE];
  char ref[16], out[16];
  int rn = 0, i, pos;
  memset(filler, 'x', sizeof filler);
  filler[K - 1] = '\n';
  dbuf_put(&d, filler, K);
  dbuf_delete(&d, K - 1);
  dbuf_put(&d, s, cut);
  dbuf_put(&d, s + cut, n - cut);
  checks++;
  if (DBufLength(&d) != (unsigned)(1 + n)) { bad++; printf("len K=%d\n", K); }
  ref[rn++] = '\n';
  memcpy(ref + rn, s, n); rn += n;
  pos = 0;
  for (;;) {   /* drain lines, comparing each with the reference */
    int i0 = pos, p;
    unsigned r;
    while (i0 < rn && eol(ref[i0])) i0++;
    for (p = i0; p < rn && !eol(ref[p]); p++) ;
    r = dbuf_getmsg(&d, out, L);
    checks++;
    if (p < rn && (unsigned)(p - i0) < L) {
      if (r != (unsigned)(p - i0) || memcmp(out, ref + i0, r) || out[r]) {
        bad++; printf("line mismatch K=%d n=%d cut=%d L=%u\n", K, n, cut, L);
        break;
      }
      pos = p;
      while (pos < rn && eol(ref[pos])) pos++;     /* getmsg flushes EOLs */
      if (DBufLength(&d) != (unsigned)(rn - pos)) {
        bad++; printf("remaining length K=%d n=%d\n", K, n); break;
      }
    } else {
      if (r != 0) { bad++; printf("expected 0 K=%d n=%d L=%u\n", K, n, L); }
      break;
    }
  }
  DBufClear(&d);
  (void)i;
}

int main(void)
{
  char s[8];
  int K, n, cut, idx[8], i;
  unsigned L;
  for (K = DBUF_SIZE - 4; K <= DBUF_SIZE; K++)
    for (n = 0; n <= 7; n++) {
      for (i = 0; i < n; i++) idx[i] = 0;
      for (;;) {
        for (i = 0; i < n; i++) s[i] = A[idx[i]];
        for (cut = 0; cut <= n; cut++)
          for (L = 1; L <= 9; L++)
            one(s, n, cut, K, L);
        for (i = 0; i < n && ++idx[i] == 4; i++) idx[i] = 0;
        if (i == n) break;
      }
    }
  printf("dbuf boundary: %ld checks, %ld mismatches\n", checks, bad);
  return bad != 0;
}
