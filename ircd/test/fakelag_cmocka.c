/*
 * fakelag_cmocka.c - the post-registration fake-lag credit and the
 * shared pool behind it.
 *
 * fakelag_charge() absorbs a charge into the credit before the lag clock
 * is charged.  The credit is one-shot: it only ever decreases.
 * fakelag_spend() then draws on the pool through the allowance;
 * fakelag_pool_take() and fakelag_grant() (ircd/fakelag.c) run against
 * the stubs below.
 */
#include "config.h"

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <string.h>
#include <cmocka.h>

#include "fakelag.h"
#include "class.h"
#include "client.h"
#include "ircd_features.h"
#include "struct.h"

/* Stubs for what ircd/fakelag.c calls. */
time_t CurrentTime;
static int stub_grace = 20, stub_pool = 0, stub_borrow = 0, stub_factor = -1;

int feature_int(enum Feature feat)
{
  switch (feat) {
  case FEAT_POSTREG_GRACE:  return stub_grace;
  case FEAT_FAKELAG_POOL:   return stub_pool;
  case FEAT_FAKELAG_BORROW: return stub_borrow;
  default:                  return 0;
  }
}

unsigned int ircrandom(void)
{
  return 0x9e3779b9u;
}

static struct Client *stub_factor_asked;   /* who get_lag_factor() was asked about */

int get_lag_factor(struct Client *cptr)
{
  /* The real one asserts a local client (class.c). */
  assert_ptr_equal(cli_from(cptr), cptr);
  stub_factor_asked = cptr;
  return stub_factor;
}

static void test_no_credit_charges_in_full(void **state)
{
  int credit = 0;
  (void)state;
  assert_int_equal(fakelag_charge(&credit, 2), 2);
  assert_int_equal(credit, 0);
}

static void test_credit_absorbs_whole_charge(void **state)
{
  int credit = 20;
  (void)state;
  assert_int_equal(fakelag_charge(&credit, 2), 0);
  assert_int_equal(credit, 18);
}

static void test_credit_absorbs_part_of_a_charge(void **state)
{
  int credit = 1;
  (void)state;
  assert_int_equal(fakelag_charge(&credit, 3), 2);
  assert_int_equal(credit, 0);
}

static void test_credit_is_one_shot(void **state)
{
  int credit = 20;
  int i, charged = 0;
  (void)state;
  /* Ten 2-second commands ride on the credit, the eleventh pays. */
  for (i = 0; i < 10; i++)
    charged += fakelag_charge(&credit, 2);
  assert_int_equal(charged, 0);
  assert_int_equal(credit, 0);
  assert_int_equal(fakelag_charge(&credit, 2), 2);
  assert_int_equal(credit, 0);
}

static void test_zero_or_negative_lag_charges_nothing(void **state)
{
  int credit = 5;
  (void)state;
  assert_int_equal(fakelag_charge(&credit, 0), 0);
  assert_int_equal(fakelag_charge(&credit, -1), 0);
  assert_int_equal(credit, 5);
}

/* --- fakelag_spend(): the charge order ------------------------------ */

static int fake_pool;
static int fake_take(int want)
{
  int got = want < fake_pool ? want : fake_pool;
  fake_pool -= got;
  return got;
}

static void test_spend_without_allowance_is_charge(void **state)
{
  int c1 = 3, c2 = 3, borrow = 0;
  (void)state;
  fake_pool = 100;
  assert_int_equal(fakelag_spend(&c1, &borrow, 0, 0, fake_take, 5),
                   fakelag_charge(&c2, 5));
  assert_int_equal(c1, c2);
  assert_int_equal(fake_pool, 100);
}

static void test_spend_credit_then_pool_then_clock(void **state)
{
  int credit = 1, borrow = 3;
  (void)state;
  fake_pool = 100;
  /* 1 from the credit, 3 from the pool, 1 to the clock. */
  assert_int_equal(fakelag_spend(&credit, &borrow, 50, 40, fake_take, 5), 1);
  assert_int_equal(credit, 0);
  assert_int_equal(borrow, 0);
  assert_int_equal(fake_pool, 97);
}

static void test_spend_credit_covers_pool_untouched(void **state)
{
  int credit = 10, borrow = 60;
  (void)state;
  fake_pool = 100;
  assert_int_equal(fakelag_spend(&credit, &borrow, 50, 40, fake_take, 2), 0);
  assert_int_equal(credit, 8);
  assert_int_equal(borrow, 60);
  assert_int_equal(fake_pool, 100);
}

static void test_spend_capped_by_pool(void **state)
{
  int credit = 0, borrow = 60;
  (void)state;
  fake_pool = 1;
  assert_int_equal(fakelag_spend(&credit, &borrow, 50, 40, fake_take, 2), 1);
  assert_int_equal(borrow, 59);
  assert_int_equal(fake_pool, 0);
}

static void test_spend_allowance_live_through_its_last_second(void **state)
{
  int credit = 0, borrow = 60;
  (void)state;
  fake_pool = 100;
  assert_int_equal(fakelag_spend(&credit, &borrow, 50, 50, fake_take, 2), 0);
  assert_int_equal(borrow, 58);
}

static void test_spend_lapsed_allowance_is_dropped(void **state)
{
  int credit = 0, borrow = 60;
  (void)state;
  fake_pool = 100;
  assert_int_equal(fakelag_spend(&credit, &borrow, 50, 51, fake_take, 2), 2);
  assert_int_equal(borrow, 0);
  assert_int_equal(fake_pool, 100);
}

/* --- fakelag_pool_take(): refill and settle ------------------------- */

static int pool_setup(void **state)
{
  (void)state;
  fakelag_test_reset();
  stub_grace = 20;
  stub_pool = 600;
  stub_borrow = 60;
  stub_factor = -1;
  CurrentTime = 1000000;
  return 0;
}

static void test_pool_starts_empty_and_fills_in_a_minute(void **state)
{
  (void)state;
  assert_int_equal(fakelag_pool_take(10), 0);
  CurrentTime += 30;
  assert_int_equal(fakelag_pool_take(1000), 300);
  CurrentTime += 60;
  assert_int_equal(fakelag_pool_take(1000), 600);
}

static void test_pool_long_gap_credits_one_cap(void **state)
{
  (void)state;
  stub_pool = 100000;               /* the largest cap: a day * cap overflows int */
  fakelag_pool_take(0);
  CurrentTime += 86400;
  assert_int_equal(fakelag_pool_take(1000000), 100000);
  CurrentTime += 365 * 86400;
  assert_int_equal(fakelag_pool_take(1000000), 100000);
  fakelag_pool_take(1000000);       /* drained */
  CurrentTime += 21475;             /* 21475 * 100000 is past INT_MAX */
  assert_int_equal(fakelag_pool_take(1000000), 100000);
}

static void test_pool_never_exceeds_cap(void **state)
{
  (void)state;
  fakelag_pool_take(0);
  CurrentTime += 60;
  fakelag_pool_take(0);             /* full */
  CurrentTime += 60;
  fakelag_pool_take(0);             /* another minute settled on a full pool */
  assert_int_equal(fakelag_pool_take(100000), 600);
}

static void test_pool_raised_cap_credits_at_most_one_cap(void **state)
{
  (void)state;
  stub_pool = 0;
  fakelag_pool_take(0);
  CurrentTime += 3600;
  stub_pool = 600;
  assert_int_equal(fakelag_pool_take(100000), 600);
}

static void test_pool_backward_step_adds_nothing(void **state)
{
  (void)state;
  fakelag_pool_take(0);
  CurrentTime += 60;
  assert_int_equal(fakelag_pool_take(600), 600);   /* drained */
  CurrentTime -= 3600;
  assert_int_equal(fakelag_pool_take(10), 0);
  CurrentTime += 6;                                /* 6 s at 10/s */
  assert_int_equal(fakelag_pool_take(1000), 60);
}

static void test_pool_carries_remainder(void **state)
{
  int i, got = 0;
  (void)state;
  stub_pool = 100;                  /* 1.67 s per second */
  fakelag_pool_take(0);
  for (i = 0; i < 60; i++) {
    CurrentTime += 1;
    got += fakelag_pool_take(1000);
  }
  assert_int_equal(got, 100);
}

static void test_pool_lowered_cap_clamps(void **state)
{
  (void)state;
  fakelag_pool_take(0);
  CurrentTime += 60;
  fakelag_pool_take(0);             /* 600 banked */
  stub_pool = 50;                   /* lowered with no time passing */
  assert_int_equal(fakelag_pool_take(1000), 50);
}

/* --- fakelag_grant() ------------------------------------------------- */

struct grant_fixture {
  struct Client cli;
  struct Connection con;
  struct User user;
};

/** A local client, logged in to @a account unless it is NULL. */
static struct Client *mkacct(struct grant_fixture *f, const char *account)
{
  memset(f, 0, sizeof(*f));
  cli_connect(&f->cli) = &f->con;
  cli_from(&f->cli) = &f->cli;      /* a local client */
  cli_user(&f->cli) = &f->user;
  if (account) {
    SetAccount(&f->cli);
    strncpy(f->user.account, account, ACCOUNTLEN);
  }
  return &f->cli;
}

static struct Client *mkclient(struct grant_fixture *f, int account)
{
  return mkacct(f, account ? "alice" : NULL);
}

static void test_grant_pool_off_is_today(void **state)
{
  struct grant_fixture f;
  struct Client *c = mkclient(&f, 1);
  (void)state;
  stub_pool = 0;
  fakelag_grant(c);
  assert_int_equal(cli_lagcredit(c), 20);
  assert_int_equal(cli_lagborrow(c), 0);
}

static void test_grant_anonymous_gets_nothing(void **state)
{
  struct grant_fixture f;
  struct Client *c = mkclient(&f, 0);
  (void)state;
  fakelag_grant(c);
  assert_int_equal(cli_lagcredit(c), 0);
  assert_int_equal(cli_lagborrow(c), 0);
}

static void test_grant_arms_allowance(void **state)
{
  struct grant_fixture f;
  struct Client *c = mkclient(&f, 1);
  (void)state;
  fakelag_grant(c);
  assert_int_equal(cli_lagcredit(c), 20);
  assert_int_equal(cli_lagborrow(c), 60);
  assert_int_equal(cli_lagborrow_until(c), CurrentTime + 30);
  assert_ptr_equal(stub_factor_asked, c);
}

static void test_grant_lag_off_class_borrows_nothing(void **state)
{
  struct grant_fixture f;
  struct Client *c = mkclient(&f, 1);
  (void)state;
  stub_factor = 0;
  fakelag_grant(c);
  assert_int_equal(cli_lagcredit(c), 20);
  assert_int_equal(cli_lagborrow(c), 0);
}

static void test_grant_clears_revived_allowance(void **state)
{
  struct grant_fixture f;
  struct Client *c = mkclient(&f, 1);
  (void)state;
  fakelag_grant(c);
  cli_lagcredit(c) -= 5;             /* partly spent, then held */
  stub_grace = 0;                    /* rehashed off before the revive */
  fakelag_grant(c);
  assert_int_equal(cli_lagcredit(c), 0);
  assert_int_equal(cli_lagborrow(c), 0);
  assert_int_equal(cli_lagborrow_until(c), 0);
}

static void test_grant_borrow_clamped(void **state)
{
  struct grant_fixture f;
  struct Client *c = mkclient(&f, 1);
  (void)state;
  stub_borrow = 1000000;
  fakelag_grant(c);
  assert_int_equal(cli_lagborrow(c), 600);
}

/* One allowance per account per minute: a reconnect loop or a second
 * device of the same account gets the grace alone, as today. */
static void test_grant_same_account_within_gap_grace_only(void **state)
{
  struct grant_fixture f1, f2;
  struct Client *a = mkacct(&f1, "alice"), *b;
  (void)state;
  fakelag_grant(a);
  CurrentTime += 59;
  b = mkacct(&f2, "alice");
  fakelag_grant(b);
  assert_int_equal(cli_lagcredit(b), 20);
  assert_int_equal(cli_lagborrow(b), 0);
  assert_int_equal(cli_lagborrow_until(b), 0);
}

static void test_grant_same_account_after_gap(void **state)
{
  struct grant_fixture f1, f2;
  struct Client *a = mkacct(&f1, "alice"), *b;
  (void)state;
  fakelag_grant(a);
  CurrentTime += 60;
  b = mkacct(&f2, "alice");
  fakelag_grant(b);
  assert_int_equal(cli_lagborrow(b), 60);
}

static void test_grant_gap_is_per_account(void **state)
{
  struct grant_fixture f1, f2;
  struct Client *a = mkacct(&f1, "alice"), *b = mkacct(&f2, "bob");
  (void)state;
  fakelag_grant(a);
  fakelag_grant(b);
  assert_int_equal(cli_lagborrow(a), 60);
  assert_int_equal(cli_lagborrow(b), 60);
}

static void test_grant_gap_ignores_case(void **state)
{
  struct grant_fixture f1, f2;
  struct Client *a = mkacct(&f1, "Alice"), *b = mkacct(&f2, "aLICE");
  (void)state;
  fakelag_grant(a);
  fakelag_grant(b);
  assert_int_equal(cli_lagborrow(b), 0);
}

static void test_grant_gap_clock_back_lends(void **state)
{
  struct grant_fixture f1, f2;
  struct Client *a = mkacct(&f1, "alice"), *b;
  (void)state;
  fakelag_grant(a);
  CurrentTime -= 5;
  b = mkacct(&f2, "alice");
  fakelag_grant(b);
  assert_int_equal(cli_lagborrow(b), 60);
}

/* With the pool off nothing is lent, so nothing starts the gap. */
static void test_grant_pool_off_starts_no_gap(void **state)
{
  struct grant_fixture f1, f2;
  struct Client *a = mkacct(&f1, "alice"), *b;
  (void)state;
  stub_pool = 0;
  fakelag_grant(a);
  stub_pool = 600;
  b = mkacct(&f2, "alice");
  fakelag_grant(b);
  assert_int_equal(cli_lagborrow(b), 60);
}

/* The drain from the live test: one account reconnecting every two
 * seconds for a minute, spending all it can each time, takes one
 * allowance from a full pool, not all of it. */
static void test_reconnect_loop_takes_one_allowance(void **state)
{
  struct grant_fixture f0, f;
  struct Client *first = mkacct(&f0, "warm"), *c;
  int i, k, taken = 0;
  (void)state;
  fakelag_grant(first);
  CurrentTime += 60;                /* pool full: 600 */
  for (k = 0; k < 30; k++, CurrentTime += 2) {
    c = mkacct(&f, "mallory");
    fakelag_grant(c);
    for (i = 0; i < 40; i++)
      taken += 2 - fakelag_spend(&cli_lagcredit(c), &cli_lagborrow(c),
                                 cli_lagborrow_until(c), CurrentTime,
                                 fakelag_pool_take, 2);
  }
  /* Each connect absorbs its own 20 s of grace; the pool gives the rest. */
  assert_int_equal(taken - 30 * 20, 60);
}

/* A lone logged-in client: 80 s of credit for 2 s commands is 40 of
 * them before the clock moves at all.  The pool's clock starts at the
 * first grant, so a client a minute after the first finds it full. */
static void test_burst_with_pool(void **state)
{
  struct grant_fixture f0, f;
  struct Client *first = mkclient(&f0, 1);
  struct Client *c;
  int i, free_cmds = 0;
  (void)state;
  fakelag_grant(first);
  CurrentTime += 60;
  c = mkclient(&f, 1);
  fakelag_grant(c);
  for (i = 0; i < 50; i++)
    if (fakelag_spend(&cli_lagcredit(c), &cli_lagborrow(c),
                      cli_lagborrow_until(c), CurrentTime,
                      fakelag_pool_take, 2) == 0)
      free_cmds++;
  assert_int_equal(free_cmds, 40);
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_no_credit_charges_in_full),
    cmocka_unit_test(test_credit_absorbs_whole_charge),
    cmocka_unit_test(test_credit_absorbs_part_of_a_charge),
    cmocka_unit_test(test_credit_is_one_shot),
    cmocka_unit_test(test_zero_or_negative_lag_charges_nothing),
    cmocka_unit_test(test_spend_without_allowance_is_charge),
    cmocka_unit_test(test_spend_credit_then_pool_then_clock),
    cmocka_unit_test(test_spend_credit_covers_pool_untouched),
    cmocka_unit_test(test_spend_capped_by_pool),
    cmocka_unit_test(test_spend_allowance_live_through_its_last_second),
    cmocka_unit_test(test_spend_lapsed_allowance_is_dropped),
    cmocka_unit_test_setup(test_pool_starts_empty_and_fills_in_a_minute, pool_setup),
    cmocka_unit_test_setup(test_pool_long_gap_credits_one_cap, pool_setup),
    cmocka_unit_test_setup(test_pool_never_exceeds_cap, pool_setup),
    cmocka_unit_test_setup(test_pool_raised_cap_credits_at_most_one_cap, pool_setup),
    cmocka_unit_test_setup(test_pool_backward_step_adds_nothing, pool_setup),
    cmocka_unit_test_setup(test_pool_carries_remainder, pool_setup),
    cmocka_unit_test_setup(test_pool_lowered_cap_clamps, pool_setup),
    cmocka_unit_test_setup(test_grant_pool_off_is_today, pool_setup),
    cmocka_unit_test_setup(test_grant_anonymous_gets_nothing, pool_setup),
    cmocka_unit_test_setup(test_grant_arms_allowance, pool_setup),
    cmocka_unit_test_setup(test_grant_lag_off_class_borrows_nothing, pool_setup),
    cmocka_unit_test_setup(test_grant_clears_revived_allowance, pool_setup),
    cmocka_unit_test_setup(test_grant_borrow_clamped, pool_setup),
    cmocka_unit_test_setup(test_burst_with_pool, pool_setup),
    cmocka_unit_test_setup(test_grant_same_account_within_gap_grace_only, pool_setup),
    cmocka_unit_test_setup(test_grant_same_account_after_gap, pool_setup),
    cmocka_unit_test_setup(test_grant_gap_is_per_account, pool_setup),
    cmocka_unit_test_setup(test_grant_gap_ignores_case, pool_setup),
    cmocka_unit_test_setup(test_grant_gap_clock_back_lends, pool_setup),
    cmocka_unit_test_setup(test_grant_pool_off_starts_no_gap, pool_setup),
    cmocka_unit_test_setup(test_reconnect_loop_takes_one_allowance, pool_setup),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
