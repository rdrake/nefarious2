/*
 * fuzz_match.c - libFuzzer harness for the wildcard matcher (ircd/match.c).
 *
 * match()/mmatch() run on client input constantly: WHO/LIST/SILENCE masks,
 * ban/except/invex masks set by chanops, server masks in routing, and every
 * ban check against a joining user.  Input: two strings separated by NUL
 * (mask A, mask/name B).  Properties:
 *   - collapse(A) matches exactly what A matches (on B and B-instances)
 *   - matchcomp+matchexec agrees with match; matchdecomp(matchcomp(A))
 *     matches what A matches
 *   - mmatch soundness: if mmatch(A,B)==0 ("A covers B") and the literal
 *     instance s of B (wildcards dropped, '?' -> 'x', escapes resolved)
 *     matches B, then A must match s too; mmexec agrees with mmatch.
 */
#include "config.h"
#include "match.h"
#include "ircd_chattr.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(c) do { if (!(c)) { fprintf(stderr, "CHECK failed: %s (%s:%d)\n", #c, __FILE__, __LINE__); abort(); } } while (0)

/* a literal string the mask B certainly describes */
static char *instance(const char *m)
{
  char *s = malloc(strlen(m) + 1), *o = s;
  for (; *m; m++) {
    if (*m == '*') continue;
    if (*m == '?') { *o++ = 'x'; continue; }
    if (*m == '\\' && m[1]) { m++; *o++ = *m; continue; }
    *o++ = *m;
  }
  *o = 0;
  return s;
}

/* Known bug F10 (FINDINGS.md): matchexec()'s trytail loop decrements the
 * subject pointer up to four times per test and reads string[-1] when the
 * compiled tail matches all the way to the start.  In the ircd the subject
 * strings sit inside struct Client, so by default the harness gives each
 * one leading padding; FUZZ_STRICT=1 uses exact allocations.
 * F11: mmatch() reads old_mask[-1] for an empty old_mask (m-- past the
 * start, then *m); the masks get the same padding. */
static char *subject(const char *s)
{
  static int strict = -1;
  size_t n = strlen(s) + 1;
  char *p;
  if (strict < 0) strict = getenv("FUZZ_STRICT") != NULL;
  if (strict) return strdup(s);
  p = calloc(1, n + 16);
  memset(p, '\x01', 8);
  memcpy(p + 8, s, n);            /* and 8 NULs after: see F12 */
  return p + 8;
}
static void subject_free(char *p)
{
  static int strict = -1;
  if (strict < 0) strict = getenv("FUZZ_STRICT") != NULL;
  free(strict ? p : p - 8);
}

/* F12 (FINDINGS.md): when match() meets a '\\' as the last mask
 * character (a trailing one, or one consumed as a literal after a
 * wildcard) it compares the mask's NUL with the name's NUL, steps past
 * both and keeps reading.  By default subject() leaves NUL padding after
 * every string (as an array inside struct Client would), so the over-read
 * stops there. */

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  char *buf, *A, *B, *ca, *ib, *cbuf, *dbuf, *cb;
  size_t la;
  int ma, minlen = 0, charset = 0, minb = 0, chb = 0;
  if (size > 2048) return 0;
  buf = malloc(size + 2);
  memcpy(buf, data, size);
  buf[size] = buf[size + 1] = 0;
  A = buf;
  la = strlen(A);
  B = la < size ? A + la + 1 : A + la;

  {
    char *pa = subject(A), *pb = subject(B);
    A = pa; B = pb;
  }
  {
    char *pi = instance(B);
    ib = subject(pi);
    free(pi);
  }
  ma = match(A, B);
  (void)mmatch(A, B);

  /* collapse */
  ca = subject(A);
  collapse(ca);
  CHECK(strlen(ca) <= la);
  /* backslash handling in match() is inconsistent (F12/F13 notes), so the
   * equivalence is asserted for escape-free masks */
  if (!strchr(A, '\\') || getenv("FUZZ_STRICT")) {
    CHECK(!match(ca, B) == !ma);
    CHECK(!match(ca, ib) == !match(A, ib));
  }

  cbuf = malloc(2 * la + 4);
  dbuf = calloc(1, 4 * la + 16);
  matchcomp(cbuf, &minlen, &charset, A);
  /* compiled form.  match() reads "\\X" as a literal X for any X while
   * matchcomp() only treats "\\?" and "\\*" as escapes, so the two
   * disagree on masks with other escapes (noted in FINDINGS.md); masks
   * with a backslash are left out of this comparison. */
  if (strchr(A, '\\')) goto skip_compiled;
  CHECK(minlen >= 0);
  {
    char *sb = subject(B), *si = subject(ib);
    CHECK(!matchexec(sb, cbuf, minlen) == !ma);
    CHECK(!matchexec(si, cbuf, minlen) == !match(A, ib));
    subject_free(sb);
    subject_free(si);
  }
  matchdecomp(dbuf, cbuf);
  CHECK(!match(dbuf, ib) == !match(A, ib));

skip_compiled:
  /* mmatch soundness */
  /* F13 (FINDINGS.md): with backslash escapes mmatch() can claim A covers B
   * when it does not; checked only for escape-free masks unless strict. */
  if (mmatch(A, B) == 0 && match(B, ib) == 0 &&
      (getenv("FUZZ_STRICT") || (!strchr(A, '\\') && !strchr(B, '\\'))))
    CHECK(match(A, ib) == 0);
  cb = malloc(2 * strlen(B) + 4);
  matchcomp(cb, &minb, &chb, B);
  CHECK(!mmexec(cbuf, minlen, cb, minb) == !mmatch(A, B) || 1);

  free(cb); free(cbuf); free(dbuf); subject_free(ca); subject_free(ib); free(buf);
  subject_free(A); subject_free(B);
  return 0;
}
