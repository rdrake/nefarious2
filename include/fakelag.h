/*
 * IRC - Internet Relay Chat, include/fakelag.h
 *
 * Fake-lag credit: a registration-time allowance of seconds that absorbs
 * the first charges to the connection's lag clock (cli_since) instead of
 * being subtracted from the clock.  A clock set below "now" does not
 * survive: read_packet() pulls cli_since up to the last read time on
 * every read, which erased the old POSTREG_GRACE on the first command
 * after 001.  Spending the credit at charge time keeps it one-shot and
 * bounded, and the read-time floor can no longer touch it.
 *
 * Fake-lag pool (FAKELAG_POOL, FAKELAG_BORROW; ircd/fakelag.c): a
 * server-wide budget of lag-seconds, refilled over a minute, that a
 * logged-in connection may draw on for 30 seconds after
 * registration once its own credit is spent.  A two-level token bucket:
 * a lone reconnecting client gets a much bigger connect burst, and under
 * a reconnect storm the pool runs dry and everyone falls back to the
 * credit alone.  See doc/design/fakelag-htb.md.
 */
#ifndef INCLUDED_fakelag_h
#define INCLUDED_fakelag_h

#include <sys/types.h>

struct Client;

/** Apply a fake-lag charge against a credit.
 * @param[in,out] credit Unspent credit in seconds; reduced by what it absorbs.
 * @param[in] lag Seconds this command would add to the clock.
 * @return The seconds the clock is actually charged.
 */
static inline int fakelag_charge(int *credit, int lag)
{
  if (lag <= 0)
    return 0;
  if (*credit > 0) {
    int absorbed = *credit < lag ? *credit : lag;
    *credit -= absorbed;
    lag -= absorbed;
  }
  return lag;
}

/** Spend a fake-lag charge: the connection's own credit first, then the
 * shared pool through the connection's allowance while it is live, and
 * whatever is left goes to the clock.  Pure, so the order is testable.
 * @param[in,out] credit The connection's own credit (POSTREG_GRACE).
 * @param[in,out] borrow Seconds the connection may still draw on the pool;
 *   zeroed once the allowance has lapsed.
 * @param[in] until Last second the allowance is live.
 * @param[in] now The current time.
 * @param[in] take Draws up to the given seconds from the pool, returns
 *   what it got.
 * @param[in] lag Seconds this command would add to the clock.
 * @return The seconds the clock is actually charged.
 */
static inline int fakelag_spend(int *credit, int *borrow, time_t until,
                                time_t now, int (*take)(int), int lag)
{
  lag = fakelag_charge(credit, lag);
  if (lag > 0 && *borrow > 0) {
    if (now <= until) {
      int got = take(lag < *borrow ? lag : *borrow);
      *borrow -= got;
      lag -= got;
    } else
      *borrow = 0;
  }
  return lag;
}

extern int fakelag_pool_take(int want);
extern void fakelag_grant(struct Client *cptr);
#ifdef CMOCKA_TEST
extern void fakelag_test_reset(void);
#endif

#endif /* INCLUDED_fakelag_h */
