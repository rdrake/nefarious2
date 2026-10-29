/*
 * chathistory_presence_harness.c - CBMC proofs for the pure interval core
 * of ircd/chathistory_presence.c.
 *
 * The real chathistory_presence.c is #included unmodified, so the
 * file-static core (record_union_close, record_apply_join/part,
 * record_was_present, record_next_visible, record_norm_ms,
 * presence_norm_time, effective_max_intervals) is called directly.  The
 * only stub is feature_int(): it returns the per-record interval cap,
 * CAP, which the harness keeps small so the explored records are small;
 * every loop in the core is bounded by count <= cap.  Storage (db_*),
 * the HLC, channels and clients are never reached.
 *
 * Time domain ("realistic"): stamps in [1, T_MAX] with T_MAX = 2^62,
 * i.e. packed HLC up to ms ~ 7e13 (year ~4200).  Harnesses suffixed
 * _any_time drop that restriction to expose wire-reachable overflow.
 */
#include <stdint.h>
#include <string.h>
#include "../common/cbmc_util.h"

/* memmove model for this module (defined below, after the struct).
 * Every memmove in the interval core moves whole struct
 * presence_interval elements inside r->intervals, so an element-wise
 * model is exact; that precondition is asserted.  (CBMC's byte-level
 * built-in over the 4 KB record exhausted memory.) */
static void *cbmc_memmove_iv(void *d, const void *s, size_t n);
#define memmove(d, s, n) cbmc_memmove_iv((d), (s), (n))

#include "../../../ircd/chathistory_presence.c"

static void *cbmc_memmove_iv(void *d, const void *s, size_t n)
{
  struct presence_interval *dd = (struct presence_interval *)d;
  const struct presence_interval *ss = (const struct presence_interval *)s;
  size_t i, w = n / sizeof(struct presence_interval);
  __CPROVER_assert(n % sizeof(struct presence_interval) == 0,
                   "memmove model: whole intervals only");
  __CPROVER_assert(__CPROVER_r_ok(s, n) && __CPROVER_w_ok(d, n),
                   "memmove: source readable, destination writable");
  if (dd > ss) {           /* overlap-safe like memmove */
    for (i = w; i > 0; i--)
      dd[i - 1] = ss[i - 1];
  } else {
    for (i = 0; i < w; i++)
      dd[i] = ss[i];
  }
  return d;
}

#ifndef CAP
#define CAP 3
#endif
#define T_MAX ((int64_t)1 << 62)
#define C PRESENCE_COALESCE_TIME

int feature_int(enum Feature f) { (void)f; return CAP; }

int64_t nondet_i64(void);

static int64_t t_in_domain(void)
{
  int64_t t = nondet_i64();
  __CPROVER_assume(t >= 1 && t <= T_MAX);
  return t;
}

/* Well-formed record: count <= cap; each closed interval start <= end;
 * sorted and separated by MORE than the coalesce gap (anything closer
 * would have been merged); open_since 0 or a stamp.  This is the
 * invariant record_union_close is meant to maintain. */
static int wf(const struct presence_record *r, unsigned cap)
{
  unsigned i;
  if (r->count > cap)
    return 0;
  for (i = 0; i < r->count; i++) {
    if (r->intervals[i].start < 1 || r->intervals[i].end > T_MAX
        || r->intervals[i].start > r->intervals[i].end)
      return 0;
    if (i + 1 < r->count && !(r->intervals[i].end + C < r->intervals[i + 1].start))
      return 0;
  }
  return 1;
}

static void nondet_wf_record(struct presence_record *r, unsigned maxcount)
{
  unsigned i;
  /* no memset: slots >= count stay nondeterministic (the code may only
   * read [0, count) and write [0, count]) */
  r->count = (uint8_t)nondet_unsigned();
  __CPROVER_assume(r->count <= maxcount);
  for (i = 0; i < CAP; i++) {
    r->intervals[i].start = nondet_i64();
    r->intervals[i].end = nondet_i64();
  }
  r->open_since = nondet_int() & 1 ? 0 : t_in_domain();
  __CPROVER_assume(wf(r, CAP));
}

static int in_new(int64_t t, int64_t s, int64_t e)
{
  if (e < s) e = s;
  return t >= s && t <= e;
}

static int64_t dist(int64_t t, int64_t s, int64_t e)
{
  return t < s ? s - t : (t > e ? t - e : 0);
}

/* U1  record_union_close keeps the record well-formed, never touches the
 *     open marker, and is memory safe (any well-formed record, any
 *     in-domain [start, end], including end < start). */
void harness_union_wf(void)
{
  struct presence_record r;
  int64_t s = t_in_domain(), e = t_in_domain(), open;
  nondet_wf_record(&r, CAP);
  open = r.open_since;
  record_union_close(&r, s, e);
  __CPROVER_assert(wf(&r, CAP), "union keeps the record well-formed");
  __CPROVER_assert(r.open_since == open, "open marker untouched");
}

/* U2  SOUNDNESS (the fail-safe claim: "you never gain visibility into a
 *     span you weren't present for"): every instant visible afterwards
 *     was visible before, or lies in the new window, or lies inside a
 *     coalesced gap -- within C (30 s) of something that was covered. */
void harness_union_sound(void)
{
  struct presence_record r, r0;
  int64_t s = t_in_domain(), e = t_in_domain(), t = t_in_domain(), d;
  unsigned i;
  nondet_wf_record(&r, CAP);
  r0 = r;
  record_union_close(&r, s, e);
  if (record_was_present(&r, t) && !record_was_present(&r0, t) && !in_new(t, s, e)) {
    d = dist(t, s, e < s ? s : e);
    for (i = 0; i < r0.count; i++) {
      int64_t di = dist(t, r0.intervals[i].start, r0.intervals[i].end);
      if (di < d) d = di;
    }
    __CPROVER_assert(d <= C, "new visibility only inside a <= 30 s coalesced gap");
  }
}

/* U3  COMPLETENESS below the cap: when the record has room (count < cap)
 *     nothing visible before, and nothing in the new window, is lost. */
void harness_union_complete_below_cap(void)
{
  struct presence_record r, r0;
  int64_t s = t_in_domain(), e = t_in_domain(), t = t_in_domain();
  nondet_wf_record(&r, CAP - 1);
  r0 = r;
  record_union_close(&r, s, e);
  if (record_was_present(&r0, t) || in_new(t, s, e))
    __CPROVER_assert(record_was_present(&r, t), "no loss below the cap");
}

/* U4  AT the cap the header promises FIFO: "the oldest closed interval is
 *     dropped".  So an instant that stops being visible must be OLDER
 *     than everything the record still holds. */
void harness_union_cap_drops_oldest(void)
{
  struct presence_record r, r0;
  int64_t s = t_in_domain(), e = t_in_domain(), t = t_in_domain();
  nondet_wf_record(&r, CAP);
  __CPROVER_assume(r.count == CAP);
  r0 = r;
  record_union_close(&r, s, e);
  if ((record_was_present(&r0, t) || in_new(t, s, e)) && !record_was_present(&r, t))
    __CPROVER_assert(r.count > 0 && t < r.intervals[0].start,
                     "only instants older than every retained window are lost");
}

/* U5  idempotence and order independence (claimed in the comment above
 *     record_union_close: "idempotent and order-independent -- the
 *     properties the PN replication flood needs"), below the cap:
 *       union(union(r,A),A) == union(r,A)            (structurally)
 *       union(union(r,A),B) ~ union(union(r,B),A)    (same visible set) */
void harness_union_idem_comm(void)
{
  struct presence_record r, ra, rab, rb, rba;
  int64_t as = t_in_domain(), ae = t_in_domain();
  int64_t bs = t_in_domain(), be = t_in_domain(), t = t_in_domain();
  nondet_wf_record(&r, CAP - 2);
  ra = r;
  record_union_close(&ra, as, ae);
  rab = ra;
  record_union_close(&rab, as, ae);
  __CPROVER_assert(memcmp(&rab, &ra, sizeof(ra)) == 0, "idempotent");
  rab = ra;
  record_union_close(&rab, bs, be);
  rb = r;
  record_union_close(&rb, bs, be);
  rba = rb;
  record_union_close(&rba, as, ae);
  __CPROVER_assert(record_was_present(&rab, t) == record_was_present(&rba, t),
                   "order independent");
}

/* U6  record_apply_join / record_apply_part: join is idempotent (keeps
 *     the first start); part closes into the closed list and clears the
 *     open marker; an instant in [open, max(open, when)] is visible
 *     afterwards when the record had room. */
void harness_join_part(void)
{
  struct presence_record r;
  int64_t j1 = t_in_domain(), j2 = t_in_domain(), p = t_in_domain(), t = t_in_domain();
  nondet_wf_record(&r, CAP - 1);
  r.open_since = 0;
  record_apply_join(&r, j1);
  record_apply_join(&r, j2);
  __CPROVER_assert(r.open_since == j1, "join idempotent: first start kept");
  if (t >= j1)
    __CPROVER_assert(record_was_present(&r, t), "open interval visible from its start on");
  record_apply_part(&r, p);
  __CPROVER_assert(r.open_since == 0, "part clears the open marker");
  __CPROVER_assert(wf(&r, CAP), "part keeps the record well-formed");
  if (t >= j1 && t <= (p < j1 ? j1 : p))
    __CPROVER_assert(record_was_present(&r, t), "the closed visit stays visible");
}

/* N1  record_next_visible is exact (it drives the history walk's seek):
 *     forward: result == t when visible; otherwise the smallest visible
 *     instant > t, or -1 when nothing after t is visible.  Reverse is the
 *     mirror image.  Checked against a symbolic probe instant u. */
void harness_next_visible(void)
{
  struct presence_record r;
  int64_t t = t_in_domain(), u = t_in_domain(), n;
  int rev = nondet_int() & 1;
  nondet_wf_record(&r, CAP);
  n = record_next_visible(&r, t, rev);
  if (record_was_present(&r, t)) {
    __CPROVER_assert(n == t, "visible: answer is t itself");
    return;
  }
  if (n >= 0)
    __CPROVER_assert(record_was_present(&r, n), "answer is visible");
  if (!rev) {
    __CPROVER_assert(n == -1 || n > t, "forward answer lies after t");
    if (u > t && (n == -1 || u < n))
      __CPROVER_assert(!record_was_present(&r, u), "nothing visible before the answer");
  } else {
    __CPROVER_assert(n == -1 || n < t, "reverse answer lies before t");
    if (u < t && u > n)
      __CPROVER_assert(!record_was_present(&r, u), "nothing visible after the answer");
  }
}

/* T1  presence_norm_time over EVERY int64 (it is applied to stamps read
 *     from disk and to PN start/end parsed off the S2S wire with
 *     strtoull): no undefined behaviour, and its output is a packed stamp
 *     that is >= 0 whenever the input was > 0 (a positive wire value must
 *     never come out negative and so cover all of history). */
void harness_norm_time_any(void)
{
  int64_t v = nondet_i64(), o;
  o = presence_norm_time(v);
  if (v > 0)
    __CPROVER_assert(o > 0, "positive in, positive out");
}

/* T2  PN ingest (m_markread.c: start/end = presence_norm_time((int64_t)
 *     strtoull(parv))); rejected only when 0) followed by
 *     record_union_close: whatever a peer sends, the merged window must
 *     not reach back before the earliest time the peer could plausibly
 *     vouch for -- here: a valid-looking end (realistic domain) must not
 *     yield visibility at an instant before 2020 (packed). */
void harness_pn_ingest_any(void)
{
  struct presence_record r;
  uint64_t ws = (uint64_t)nondet_i64(), we = (uint64_t)nondet_i64();
  int64_t start, end, t;
  const int64_t y2020 = PRESENCE_TIME_FROM_MS(1577836800000LL);
  memset(&r, 0, sizeof(r));
  start = presence_norm_time((int64_t)ws);
  end = presence_norm_time((int64_t)we);
  __CPROVER_assume(start != 0 && end != 0);          /* the handler's check */
  __CPROVER_assume(end >= y2020 && end <= T_MAX);     /* a sane end stamp  */
  record_union_close(&r, start, end);
  t = nondet_i64();
  __CPROVER_assume(t >= 1 && t < y2020);
  __CPROVER_assert(!record_was_present(&r, t),
                   "a PN line cannot open visibility before 2020");
}

/* T3  record_union_close on an ARBITRARY (possibly corrupt / replicated)
 *     record and arbitrary int64 window: memory safety only (count is
 *     uint8_t, the array has 256 slots), plus overflow of end + C. */
void harness_union_any_time(void)
{
  struct presence_record r;
  unsigned i;
  memset(&r, 0, sizeof(r));
  r.count = (uint8_t)nondet_unsigned();
  __CPROVER_assume(r.count <= CAP);
  for (i = 0; i < CAP; i++) {
    r.intervals[i].start = nondet_i64();
    r.intervals[i].end = nondet_i64();
  }
  record_union_close(&r, nondet_i64(), nondet_i64());
}

/* T4  record_norm_ms on an arbitrary record of ANY count (0..255): memory
 *     safe (loads from disk only size-check the blob, not count). */
void harness_norm_record_any(void)
{
  static struct presence_record r;
  r.count = (uint8_t)nondet_unsigned();
  r.open_since = nondet_i64();
  (void)record_norm_ms(&r);
  (void)record_was_present(&r, nondet_i64());
}
