/*
 * webpush_attention_harness.c - CBMC proofs for ircd/webpush_attention.c
 * (real module #included unmodified).
 */
#include <limits.h>
#include "../common/cbmc_util.h"
#include "../../../ircd/webpush_attention.c"

#ifndef NCONN
#define NCONN 2
#endif

static void nondet_conn(struct webpush_conn_state *c)
{
  c->held = nondet_int();
  c->away = nondet_int();
  c->last_msg = nondet_ll();
}

/* A1  totality / no UB for ANY field values, now and idle. */
void harness_attending_total(void)
{
  struct webpush_conn_state c;
  long long now = nondet_ll(), idle = nondet_ll();
  int r;
  nondet_conn(&c);
  r = webpush_conn_attending(&c, now, idle);
  __CPROVER_assert(r == 0 || r == 1, "boolean");
  __CPROVER_assert(webpush_conn_attending(0, now, idle) == 0, "NULL attends not");
}

/* A2  the header contract, on the realistic domain (last_msg and now are
 *     unix seconds <= year 3000, idle a feature int):
 *     - held or away never attends
 *     - idle <= 0: every connected, present connection attends
 *     - idle > 0: attends iff 0 < last_msg and now - last_msg < idle
 *     - monotone: an attending connection stops attending as time passes,
 *       never the reverse
 *     - webpush_unattended(c, n) == no element attends; n == 0 unattended */
void harness_attention_contract(void)
{
  struct webpush_conn_state c[NCONN];
  long long now1 = nondet_ll(), now2 = nondet_ll(), idle = nondet_ll();
  int n = nondet_int(), i, any = 0;

  __CPROVER_assume(n >= 0 && n <= NCONN);
  __CPROVER_assume(idle <= INT_MAX);
  __CPROVER_assume(now1 >= 0 && now1 <= now2 && now2 <= 32503680000LL);
  for (i = 0; i < NCONN; i++) {
    nondet_conn(&c[i]);
    __CPROVER_assume(c[i].last_msg <= 32503680000LL);
  }
  for (i = 0; i < n; i++) {
    int a = webpush_conn_attending(&c[i], now1, idle);
    if (c[i].held || c[i].away)
      __CPROVER_assert(!a, "held/away never attends");
    else if (idle <= 0)
      __CPROVER_assert(a, "idle rule off: present attends");
    else
      __CPROVER_assert(a == (c[i].last_msg > 0 && now1 - c[i].last_msg < idle),
                       "idle rule: spoke within the window");
    if (webpush_conn_attending(&c[i], now2, idle))
      __CPROVER_assert(a, "attending later => attending earlier");
    any |= a;
  }
  __CPROVER_assert(webpush_unattended(c, n, now1, idle) == !any,
                   "unattended == no connection attends");
  __CPROVER_assert(webpush_unattended(c, 0, now1, idle) == 1, "n == 0 unattended");
}
