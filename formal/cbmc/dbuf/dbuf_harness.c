/*
 * dbuf_harness.c - CBMC proofs for ircd/dbuf.c (#included unmodified).
 *
 * Stubs: feature_int (buffer pool), feature_bool (no Ferguson flusher),
 * flush_connections, DoMalloc/DoFree (malloc), and the character
 * attribute table, of which dbuf.c reads only the NTL_EOL bit
 * (table_gen.c: markString(NTL_EOL, "\n\r")).
 *
 * The data path crosses a DBufBuffer boundary: a filler of K bytes
 * (K symbolic, near DBUF_SIZE) is put and all but its final '\n' deleted,
 * so the bytes under test start a few bytes before the end of the first
 * 2048-byte block.
 */
#include <stdlib.h>
#include <limits.h>
#include "../common/cbmc_util.h"
#include "../../../ircd/dbuf.c"

#ifndef AMAX
#define AMAX 4
#endif
#ifndef LMAX
#define LMAX 10
#endif

int feature_int(enum Feature f) { (void)f; return 1 << 20; }
int feature_bool(enum Feature f) { (void)f; return 0; }
void flush_connections(struct Client *c) { (void)c; }
void *DoMalloc(size_t s, const char *t, const char *f, int l)
{ (void)t; (void)f; (void)l; return malloc(s); }
const unsigned int IRCD_CharAttrTab[256] = {
  ['\n' - CHAR_MIN] = NTL_EOL, ['\r' - CHAR_MIN] = NTL_EOL };

static int is_eol(char c) { return c == '\n' || c == '\r'; }

static char filler[DBUF_SIZE];

/* D1  put/put/getmsg across a block boundary, arbitrary bytes:
 *     memory safety; DBufLength bookkeeping; and dbuf_getmsg returns the
 *     first non-empty line exactly (leading CR/LF skipped, NUL-terminated,
 *     strictly shorter than the caller's length), or 0 when there is no
 *     complete line that fits. */
void harness_getmsg(void)
{
  static struct DBuf dyn;
  char a[AMAX], b[AMAX], out[LMAX], s[1 + 2 * AMAX];
  unsigned la = nondet_unsigned(), lb = nondet_unsigned(), L = nondet_unsigned();
  unsigned K = nondet_unsigned(), n, i, i0, p, r;

#ifdef KFIX
  K = KFIX;              /* run.sh runs each boundary offset separately */
#else
  __CPROVER_assume(K >= DBUF_SIZE - 3 && K <= DBUF_SIZE);
#endif
  __CPROVER_assume(la <= AMAX && lb <= AMAX && L >= 1 && L <= LMAX);
  for (i = 0; i < AMAX; i++) { a[i] = nondet_char(); b[i] = nondet_char(); }
  memset(filler, 'x', sizeof(filler));
  filler[K - 1] = '\n';

  __CPROVER_assert(dbuf_put(&dyn, filler, K) == 1, "filler put");
  dbuf_delete(&dyn, K - 1);
  __CPROVER_assert(DBufLength(&dyn) == 1, "length after delete");
  __CPROVER_assert(dbuf_put(&dyn, a, la) == 1, "put a");
  __CPROVER_assert(dbuf_put(&dyn, b, lb) == 1, "put b");
  n = 1 + la + lb;
  __CPROVER_assert(DBufLength(&dyn) == n, "length bookkeeping");

  s[0] = '\n';
  for (i = 0; i < la; i++) s[1 + i] = a[i];
  for (i = 0; i < lb; i++) s[1 + la + i] = b[i];
  for (i0 = 0; i0 < n && is_eol(s[i0]); i0++)
    ;
  for (p = i0; p < n && !is_eol(s[p]); p++)
    ;

  r = dbuf_getmsg(&dyn, out, L);
  if (p < n && p - i0 < L) {
    __CPROVER_assert(r == p - i0, "returns the first line's length");
    for (i = 0; i < r; i++)
      __CPROVER_assert(out[i] == s[i0 + i], "line content");
    __CPROVER_assert(out[r] == '\0', "NUL-terminated");
  } else {
    __CPROVER_assert(r == 0, "no complete line that fits => 0");
  }
}
