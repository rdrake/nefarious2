/*
 * IRC - Internet Relay Chat, ircd/fakelag.c
 *
 * The fake-lag pool: a server-wide budget of lag-seconds behind the
 * post-registration credit.  See include/fakelag.h and
 * doc/design/fakelag-htb.md.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 1, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */
#include "config.h"

#include "fakelag.h"
#include "class.h"
#include "client.h"
#include "ircd.h"
#include "ircd_chattr.h"
#include "ircd_features.h"
#include "ircd_string.h"
#include "random.h"

#include <string.h>

/** Seconds after registration the allowance stays live. */
#define FAKELAG_BORROW_TTL 30
/** An account borrows at most FAKELAG_BORROW per this many seconds, the
 * pool's refill time, however many times it registers. */
#define FAKELAG_WINDOW     60
/** Slots in the table of account budgets (a power of two), and how many a
 * lookup tries before it gives up and lends nothing. */
#define FAKELAG_SLOTS      1024
#define FAKELAG_PROBE      16
/** Clamps on the features, so the refill math stays in int. */
#define FAKELAG_POOL_MAX   100000
#define FAKELAG_BORROW_MAX 600

static int    pool;       /**< Lag-seconds available to lend. */
static int    pool_rem;   /**< Refill carried over, in 1/60 s. */
static time_t pool_last;  /**< When the pool was last settled; 0 = never. */

/** What an account has borrowed in its current window.  An entry is
 * made at the account's first actual draw, compared by name, and never
 * reused while its window is open, so no account can push another out.
 * When every slot a name may use is open, that name borrows nothing. */
struct budget {
  char   account[ACCOUNTLEN + 1]; /**< Account name; "" = free. */
  time_t start;                   /**< When the window opened. */
  int    used;                    /**< Seconds borrowed in it. */
};
static struct budget budgets[FAKELAG_SLOTS];
static unsigned int  budget_seed;   /**< Keeps the slots unguessable. */
static const char   *charging;      /**< Account fakelag_charge_client() is on. */

/** Clamp @a v to [0, @a hi]. */
static int clamp(int v, int hi)
{
  if (v < 0)
    return 0;
  if (v > hi)
    return hi;
  return v;
}

/** Settle the pool to now, refilling it to its cap over 60 seconds, then
 * take up to @a want seconds from it.  Settled only when drawn on: a long
 * gap, a forward clock step or a raised cap credits at most one cap, and
 * a backward step adds nothing.  The pool starts empty and begins to
 * fill at the first grant that could draw on it.
 * @param[in] want Seconds wanted.
 * @return Seconds taken.
 */
int fakelag_pool_take(int want)
{
  int cap = clamp(feature_int(FEAT_FAKELAG_POOL), FAKELAG_POOL_MAX);
  time_t dt = (pool_last && CurrentTime > pool_last)
              ? CurrentTime - pool_last : 0;
  int got;

  pool_last = CurrentTime;
  if (dt > 60)
    dt = 60;
  pool_rem += (int)dt * cap;          /* at most 60 * FAKELAG_POOL_MAX */
  pool += pool_rem / 60;
  pool_rem %= 60;
  if (pool >= cap) {
    pool = cap;
    pool_rem = 0;
  }
  if (want <= 0)
    return 0;
  got = want < pool ? want : pool;
  pool -= got;
  return got;
}

/** Is @a b's window still open?  A window that opened in the future (the
 * clock stepped back) restarts now, keeping what was borrowed in it. */
static int budget_open(struct budget *b)
{
  if (!b->account[0])
    return 0;
  if (CurrentTime < b->start)
    b->start = CurrentTime;
  return CurrentTime - b->start < FAKELAG_WINDOW;
}

/** Find @a account's budget, or the slot its first draw would take.
 * Names compare as the server compares them (ircd_strcmp()).
 * @param[in] account The account name.
 * @return Its open budget; a closed or free slot for it (account[0] is
 *   then 0 or another name); NULL when every slot it may use is open. */
static struct budget *budget_find(const char *account)
{
  struct budget *spare = NULL;
  unsigned int h, i;
  const char *p;

  if (!budget_seed)
    budget_seed = ircrandom() | 1;
  h = 2166136261u ^ budget_seed;               /* FNV-1a over the fold */
  for (p = account; *p; p++)
    h = (h ^ (unsigned char)ToLower(*p)) * 16777619u;
  h ^= h >> 16;                                /* mix the high bits down */
  h *= 0x85ebca6bu;
  h ^= h >> 13;
  for (i = 0; i < FAKELAG_PROBE; i++) {
    struct budget *b = &budgets[(h + i) & (FAKELAG_SLOTS - 1)];
    int open = budget_open(b);

    if (open && !ircd_strcmp(b->account, account))
      return b;
    if (!open && !spare)
      spare = b;
  }
  return spare;
}

/** The pool, through the budget of the account being charged. */
static int take_for_account(int want)
{
  int cap = clamp(feature_int(FEAT_FAKELAG_BORROW), FAKELAG_BORROW_MAX);
  struct budget *b = budget_find(charging);
  int mine, room, got;

  if (!b)
    return 0;
  mine = b->account[0] && !ircd_strcmp(b->account, charging)
         && budget_open(b);
  room = cap - (mine ? b->used : 0);
  if (room <= 0)
    return 0;
  got = fakelag_pool_take(want < room ? want : room);
  if (got > 0) {
    if (!mine) {
      ircd_strncpy(b->account, charging, sizeof(b->account));
      b->start = CurrentTime;
      b->used = 0;
    }
    b->used += got;
  }
  return got;
}

/** Charge @a lag to @a cptr: its grace, then the pool through its
 * allowance and its account's budget, then its clock.
 * @param[in] cptr The local client the line came from.
 * @param[in] lag Seconds the line costs.
 * @return Seconds to add to the client's clock.
 */
int fakelag_charge_client(struct Client *cptr, int lag)
{
  /* Logged out since the grant (services can do that): no account to
   * charge a draw to, so the allowance goes. */
  if (cli_lagborrow(cptr) > 0 && (!IsAccount(cptr) || !cli_account(cptr)[0]))
    cli_lagborrow(cptr) = 0;
  charging = cli_account(cptr);
  return fakelag_spend(&cli_lagcredit(cptr), &cli_lagborrow(cptr),
                       cli_lagborrow_until(cptr), CurrentTime,
                       take_for_account, lag);
}

/** Grant the post-registration credit, and the pool allowance when the
 * pool is on.  Called at the end of every registration path (fresh
 * registration, held-session revive, alias attach).
 *
 * Modern clients burst init commands (MONITOR, METADATA SUB, WHO,
 * CHATHISTORY...) right after 001, and the ~10 s cli_since headroom covers
 * only ~5 of them.  The credit raises that initial budget; every command
 * is still charged (credit, not exemption), and recvQ byte caps still
 * bound the wire.  It is not a clock set below now: read_packet() floors
 * the clock to the last read time and would erase that.
 * @param[in] cptr The client that keeps the socket: on a revive that is
 *   the ghost, not the freed incoming client.
 */
void fakelag_grant(struct Client *cptr)
{
  int grace = feature_int(FEAT_POSTREG_GRACE);

  /* A revived ghost may still carry credit from its last life. */
  cli_lagcredit(cptr) = 0;
  cli_lagborrow(cptr) = 0;
  cli_lagborrow_until(cptr) = 0;

  /* Authenticated clients only: an anonymous connection (the
   * drive-by/WS-flood surface) keeps the classic ~5-command burst. */
  if (grace <= 0 || !IsAccount(cptr))
    return;
  cli_lagcredit(cptr) = grace;

  /* A class with fake lag off never spends it: lend nothing.  What the
   * account may still borrow this minute is checked at each draw. */
  if (feature_int(FEAT_FAKELAG_POOL) <= 0 || get_lag_factor(cptr) == 0)
    return;
  fakelag_pool_take(0);   /* start the pool's clock at the first grant */
  cli_lagborrow(cptr) = clamp(feature_int(FEAT_FAKELAG_BORROW),
                              FAKELAG_BORROW_MAX);
  cli_lagborrow_until(cptr) = CurrentTime + FAKELAG_BORROW_TTL;
}

#ifdef CMOCKA_TEST
/** Empty the pool, forget when it was last settled and every budget. */
void fakelag_test_reset(void)
{
  pool = 0;
  pool_rem = 0;
  pool_last = 0;
  memset(budgets, 0, sizeof(budgets));
}
#endif
