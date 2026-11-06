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
#include "ircd_features.h"

/** Seconds after registration the allowance stays live. */
#define FAKELAG_BORROW_TTL 30
/** Clamps on the features, so the refill math stays in int. */
#define FAKELAG_POOL_MAX   100000
#define FAKELAG_BORROW_MAX 600

static int    pool;       /**< Lag-seconds available to lend. */
static int    pool_rem;   /**< Refill carried over, in 1/60 s. */
static time_t pool_last;  /**< When the pool was last settled; 0 = never. */

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

  /* A class with fake lag off never spends it: lend nothing. */
  if (feature_int(FEAT_FAKELAG_POOL) <= 0 || get_lag_factor(cptr) == 0)
    return;
  fakelag_pool_take(0);   /* start the pool's clock at the first grant */
  cli_lagborrow(cptr) = clamp(feature_int(FEAT_FAKELAG_BORROW),
                              FAKELAG_BORROW_MAX);
  cli_lagborrow_until(cptr) = CurrentTime + FAKELAG_BORROW_TTL;
}

#ifdef CMOCKA_TEST
/** Empty the pool and forget when it was last settled. */
void fakelag_test_reset(void)
{
  pool = 0;
  pool_rem = 0;
  pool_last = 0;
}
#endif
