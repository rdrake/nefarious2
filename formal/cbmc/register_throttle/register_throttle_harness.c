/*
 * register_throttle_harness.c - CBMC proofs for ircd/register_throttle.c
 *
 * The real module is #included unmodified.  Like the cmocka build, the
 * table geometry is shrunk with -DREG_THROTTLE_TABLE_BITS /
 * -DREG_THROTTLE_BUCKET_DEPTH so collisions and LRU eviction are inside
 * the explored state space; RT_CALLS bounds the call sequence.  The
 * memory-safety harness also runs at the production geometry (6 bits x 4).
 *
 * Time domain: unless stated, `now` values are the realistic range
 * [0, 2^40] (year ~36800) and non-decreasing across a sequence.
 */
#include <limits.h>
#include "../common/cbmc_util.h"
#include "../../../ircd/register_throttle.c"

#ifndef RT_CALLS
#define RT_CALLS 4
#endif
#define T_MAX (1LL << 40)

static void nondet_ip(struct irc_in_addr *a)
{
  int i;
  for (i = 0; i < 8; i++)
    a->in6_16[i] = (unsigned short)nondet_unsigned();
}

/* Havoc the whole module state, constrained only by what the module can
 * itself produce (in_use entries carry 1 <= attempts, last <= T_MAX). */
static void havoc_state(void)
{
  int b, i;
  for (b = 0; b < REG_THROTTLE_TABLE_SIZE; b++)
    for (i = 0; i < REG_THROTTLE_BUCKET_DEPTH; i++) {
      struct reg_throttle_entry *e = &reg_table[b][i];
      nondet_ip(&e->addr);
      e->last = (time_t)nondet_ll();
      e->attempts = nondet_int();
      e->in_use = nondet_int() & 1;
      __CPROVER_assume(e->last >= 0 && e->last <= T_MAX);
      __CPROVER_assume(e->attempts >= 0);
    }
  reg_global_start = (time_t)nondet_ll();
  reg_global_count = nondet_int();
  __CPROVER_assume(reg_global_start >= 0 && reg_global_start <= T_MAX);
  __CPROVER_assume(reg_global_count >= 0);
}

/* R1  memory safety and totality of reg_throttle_check /
 *     reg_throttle_expire from an ARBITRARY reachable-or-not table, for
 *     any address, any limits, and any now in the realistic domain.
 *     (Run at the production geometry as well as the shrunken one.) */
void harness_safety(void)
{
  struct irc_in_addr ip;
  time_t now = (time_t)nondet_ll();
  int limit = nondet_int(), period = nondet_int(), glim = nondet_int();
  enum reg_throttle_result r;

  havoc_state();
  nondet_ip(&ip);
  __CPROVER_assume(now >= 0 && now <= T_MAX);
  r = reg_throttle_check(nondet_int() & 1 ? &ip : 0, now, limit, period, glim);
  __CPROVER_assert(r == REG_THROTTLE_OK || r == REG_THROTTLE_IP
                   || r == REG_THROTTLE_GLOBAL, "result in range");
  reg_throttle_expire(now, nondet_int());
}

/* R1b the same with an UNRESTRICTED now (any time_t, e.g. a negative or
 *     near-LLONG_MAX clock): exposes whether `now - last` can overflow. */
void harness_safety_any_time(void)
{
  struct irc_in_addr ip;
  time_t now = (time_t)nondet_ll();
  havoc_state();
  nondet_ip(&ip);
  (void)reg_throttle_check(&ip, now, nondet_int(), nondet_int(), nondet_int());
}

/* R2  "a refusal by EITHER limiter records nothing in EITHER limiter":
 *     on any non-OK result the whole module state is bit-identical. */
static struct reg_throttle_entry snap_table[REG_THROTTLE_TABLE_SIZE][REG_THROTTLE_BUCKET_DEPTH];
void harness_refusal_records_nothing(void)
{
  struct irc_in_addr ip;
  time_t now = (time_t)nondet_ll(), gs;
  int gc;
  enum reg_throttle_result r;

  havoc_state();
  nondet_ip(&ip);
  __CPROVER_assume(now >= 0 && now <= T_MAX);
  memcpy(snap_table, reg_table, sizeof(reg_table));
  gs = reg_global_start;
  gc = reg_global_count;
  r = reg_throttle_check(&ip, now, nondet_int(), nondet_int(), nondet_int());
  if (r != REG_THROTTLE_OK) {
    __CPROVER_assert(memcmp(snap_table, reg_table, sizeof(reg_table)) == 0,
                     "refusal leaves the per-IP table untouched");
    __CPROVER_assert(gs == reg_global_start && gc == reg_global_count,
                     "refusal leaves the global window untouched");
  }
}

/* R3  per-IP bound, single client: starting from a clean table, a
 *     sequence of RT_CALLS attempts from one address (any limit >= 1,
 *     period >= 1, global cap off) at non-decreasing times all inside one
 *     period-long span gets at most `limit` OKs; counters never exceed
 *     the limit; and once `period` has elapsed since the last counted
 *     attempt the client is let back in. */
void harness_per_ip_bound(void)
{
  struct irc_in_addr ip;
  int limit = nondet_int(), period = nondet_int();
  time_t t0 = (time_t)nondet_ll(), t = 0, last_ok = -1;
  int k, oks = 0;

  reg_throttle_clear();
  nondet_ip(&ip);
  __CPROVER_assume(limit >= 1 && limit <= 3);
  __CPROVER_assume(period >= 1);
  __CPROVER_assume(t0 >= 0 && t0 <= T_MAX);
  t = t0;
  for (k = 0; k < RT_CALLS; k++) {
    time_t step = (time_t)nondet_ll();
    __CPROVER_assume(step >= 0 && step < period);
    if (k) t += step;
    __CPROVER_assume(t - t0 < period);
    if (reg_throttle_check(&ip, t, limit, period, 0) == REG_THROTTLE_OK) {
      oks++;
      last_ok = t;
    }
    __CPROVER_assert(oks <= limit, "at most `limit` OKs inside one period");
  }
  /* a refused client gets back in `period` after its last counted try */
  __CPROVER_assert(reg_throttle_check(&ip, last_ok + period, limit, period, 0)
                   == REG_THROTTLE_OK, "recovers one period after last count");
}

/* R4  the same bound under interleaved traffic from OTHER addresses
 *     (same tiny table: 1 bucket x DEPTH slots).  Expected to FAIL by
 *     design: LRU eviction hands an evicted address fresh budget
 *     ("evicting a live entry merely grants that IP fresh budget"); the
 *     counterexample shows how many distinct /64s that takes. */
void harness_per_ip_bound_with_neighbours(void)
{
  struct irc_in_addr victim, other;
  int limit = 1, period = 100;
  time_t t = 1000;
  int k, oks = 0;

  reg_throttle_clear();
  nondet_ip(&victim);
  for (k = 0; k < RT_CALLS; k++) {
    int is_victim = nondet_int() & 1;
    nondet_ip(&other);
    t += 1;
    if (reg_throttle_check(is_victim ? &victim : &other, t, limit, period, 0)
        == REG_THROTTLE_OK && is_victim)
      oks++;
    __CPROVER_assert(oks <= limit, "victim address gets <= limit OKs per period");
  }
}

/* R5  global cap: from a clean state, with non-decreasing time, the
 *     global counter never exceeds global_limit, and within ANY span
 *     shorter than `period` at most 2*global_limit attempts pass (fixed
 *     window: a burst may straddle one window edge, never two). */
void harness_global_bound(void)
{
  int glim = nondet_int(), period = nondet_int();
  time_t t0 = (time_t)nondet_ll(), t;
  int k, oks = 0;

  reg_throttle_clear();
  __CPROVER_assume(glim >= 1 && glim <= 2);
  __CPROVER_assume(period >= 1);
  __CPROVER_assume(t0 >= 0 && t0 <= T_MAX);
  t = t0;
  for (k = 0; k < RT_CALLS; k++) {
    time_t step = (time_t)nondet_ll();
    __CPROVER_assume(step >= 0 && step < period);
    t += step;
    __CPROVER_assume(t - t0 < period);
    if (reg_throttle_check(0, t, 0, period, glim) == REG_THROTTLE_OK)
      oks++;
    __CPROVER_assert(reg_global_count <= glim, "global counter bounded");
    __CPROVER_assert(oks <= 2 * glim, "<= 2*global_limit per period span");
  }
}

/* R6  clock stepped BACKWARDS (NTP step, VM restore): the global window
 *     must still reopen once `period` has really elapsed since the clock
 *     came back.  Expected to FAIL: the window is anchored at the future
 *     start and `now - start >= period` stays false until wall time
 *     catches up with start + period. */
void harness_global_clock_step_back(void)
{
  int glim = 1, period = 60;
  time_t t_future = 1000000, back = nondet_ll(), t;

  reg_throttle_clear();
  __CPROVER_assume(back >= 1 && back <= 100000);
  /* the cap is consumed at a (wrong, future) clock */
  __CPROVER_assume(reg_throttle_check(0, t_future, 0, period, glim) == REG_THROTTLE_OK);
  /* clock steps back, then a full period passes */
  t = t_future - back + period;
  __CPROVER_assert(reg_throttle_check(0, t, 0, period, glim) == REG_THROTTLE_OK,
                   "global window reopens a period after a backward step");
}
