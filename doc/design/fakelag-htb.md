# A shared budget for the connect burst

Status: v4, implemented on this branch, 2026-11-06. Base: evilnet
`ircv3.2-upgrade` @ b3b9eb5d (line numbers below are from that tip; the fake lag
code is unchanged since 9c24ead6).

History: v1 (borrow on every command) was red-teamed by Claude, v2 (a pool
behind the connect grace) by Codex, v3 by Fable. v4 keeps v2's shape, draws on
the pool only for seconds actually spent, and fixes what the reviews found. The
findings and what became of each are at the end.

## Problem

Every non-oper command from a registered client is charged
`lag = lagmin + len / lagfactor` seconds (defaults 2 and 120; `len` counts from
the first parameter when there is one, so tags and the command token are
usually free) onto `cli_since`
(`ircd/parse.c` L1658-1671). `read_packet()` parses the next line only while
`cli_since - CurrentTime < 10` (`ircd/s_bsd.c` L1693), and that check comes
before the charge. Each socket read with data pulls `cli_since` up to now
(L1313-1314), so idle time never banks; leftover lines are retried on a 2 s
timer (L1746). In practice: about 5 short commands at once, then one every 2 s.

Lines before 001 are free: a fresh `Connection` is zeroed, so the cached
`con_lag_factor` is 0 and `get_lag_factor()` returns it (`class.c` L388), and
`parse.c` L1658 requires `lagfactor > 0`. `register_user` resets the cache to -2
(`s_user.c` L626-627), so charging starts at 001 with the clock at about now.

`POSTREG_GRACE` (default 20) gives a logged-in connection a one-shot credit at
registration (`con_lagcredit`), which `fakelag_charge()` (`include/fakelag.h`)
spends before the clock. That raises the post-001 burst to about 15 short
commands.

A phone needs more, because it reconnects a lot (network changes, the OS
killing a backgrounded socket), and each reconnect re-sends its post-001 work:
one JOIN, `CHATHISTORY TARGETS`, a history fetch and read marker per channel,
MONITOR, METADATA SUB, a push renewal. With 15 channels that is 30-plus
commands, so the catch-up still dribbles in at one command per 2 s for most of a
minute.

The grace cannot just be made bigger. It is the same size for every connection,
so after a restart or a netsplit heal a big grace is a big burst from everyone at
once.

## Idea

A shared budget that backs the connect grace when the server can spare it. It
is a two-level token bucket. The parent is a server-wide pool of lag-seconds that
refills over a minute. Each logged-in registration gets an *allowance* that lets
it draw on that pool for 30 s, after its own grace runs out.

- A lone reconnecting phone gets `POSTREG_GRACE` plus up to `FAKELAG_BORROW`
  (suggested 60) more, 80 s of credit: about 45 short commands at once (40 on
  the credits, 5 on the clock).
- The pool is charged only for seconds actually spent. A one-channel client
  that needs 6 s takes nothing from the pool. Two phones that connect together
  draw side by side instead of the first taking a whole share.
- Once the pool is empty, connections get today's grace, never less.
- The allowance lapses 30 s after registration. The point is the connect burst;
  a connection cannot sit on it.
- The pool starts empty and fills over a minute, so a restart (when IPcheck's
  clone throttle is still off, `IPCHECK_CLONE_DELAY`, default 600 s) lends
  nothing to the first wave.

It is an opportunistic boost for a quiet server, not storm control. The
guaranteed part, `POSTREG_GRACE` for each connection, is today's behaviour and
unchanged.

This is not v1 again. v1 borrowed only the overshoot above the 10 s gate, which
can never let another line through. Here the allowance absorbs whole charges the
way the grace already does, so the clock stays low and the gate stays open.

## Code

New per-connection state (`include/client.h`): `con_lagborrow` (int, seconds of
allowance left) and `con_lagborrow_until` (time_t). A new `Connection` is zeroed
(`alloc_connection`, `list.c` L255).

`include/fakelag.h` gains a pure helper, so the whole charge order can be
unit-tested:

```c
/** Spend @a lag: the grace first, then the pool through the allowance
 * while it is live, the rest to the clock.  @a take is the pool. */
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
```

The charge site keeps its single-statement shape under the existing multiline
guard (`parse.c` L1670-1671):

```c
    if (!cli_ml_batch_id(cptr)[0])
      cli_since(cptr) += fakelag_spend(&cli_lagcredit(cptr),
                                       &cli_lagborrow(cptr),
                                       cli_lagborrow_until(cptr), CurrentTime,
                                       fakelag_pool_take, lag);
```

With `con_lagborrow` at 0 this is `fakelag_charge()` exactly, as today.

The grace is spent before the pool on purpose: the grace is the connection's own,
and the pool is shared.

The pool lives in a new `ircd/fakelag.c`:

```c
#define FAKELAG_BORROW_TTL 30          /* s the allowance stays live */
#define FAKELAG_POOL_MAX   100000      /* clamps keep the math in int */
#define FAKELAG_BORROW_MAX 600

static int    pool;                    /* lag-seconds available */
static int    pool_rem;                /* refill remainder, in 1/60 s */
static time_t pool_last;               /* 0 = not started */

static int clamp(int v, int hi) { return v < 0 ? 0 : v > hi ? hi : v; }

/** Settle the pool to now (refill to its cap over 60 s), then take up to
 * @a want seconds. */
int fakelag_pool_take(int want)
{
  int cap = clamp(feature_int(FEAT_FAKELAG_POOL), FAKELAG_POOL_MAX);
  time_t dt = (pool_last && CurrentTime > pool_last) ? CurrentTime - pool_last : 0;
  int got;

  pool_last = CurrentTime;
  if (dt > 60)
    dt = 60;
  pool_rem += (int)dt * cap;           /* <= 6e6 */
  pool += pool_rem / 60;
  pool_rem %= 60;
  if (pool >= cap) {
    pool = cap;
    pool_rem = 0;
  }
  got = want < pool ? want : pool;
  pool -= got;
  return got;
}

/** Grant the post-registration credit to @a cptr, the client that keeps
 * the socket (the ghost, on a revive). */
void fakelag_grant(struct Client *cptr)
{
  int grace = feature_int(FEAT_POSTREG_GRACE);

  cli_lagborrow(cptr) = 0;             /* a revived ghost's old allowance */
  cli_lagborrow_until(cptr) = 0;
  if (grace <= 0 || !IsAccount(cptr))
    return;
  cli_lagcredit(cptr) = grace;         /* exactly today's three blocks */
  if (feature_int(FEAT_FAKELAG_POOL) <= 0 || get_lag_factor(cptr) == 0)
    return;
  fakelag_pool_take(0);                /* start the pool's clock */
  cli_lagborrow(cptr) = clamp(feature_int(FEAT_FAKELAG_BORROW), FAKELAG_BORROW_MAX);
  cli_lagborrow_until(cptr) = CurrentTime + FAKELAG_BORROW_TTL;
}
```

The pool settles only when someone draws on it. It starts empty, and its clock
starts at the first grant that could draw on it (`fakelag_grant()` settles it). A long gap, a clock step forward, or the cap being raised
from 0 after a quiet spell all credit at most one cap. When the clock steps
back, `dt` is 0 and the pool resyncs. The remainder carries over, so a cap that
is not a multiple of 60 refills at its true rate.

The pool is gated on `POSTREG_GRACE > 0`: with the grace at 0 nobody gets an
allowance. `get_lag_factor()` is valid on the ghost at the revive site:
`bounce_revive` moves the confs over and resets the cache
(`bouncer_session.c` L8761-8768).

| File | Change |
| --- | --- |
| `include/fakelag.h` | `fakelag_spend()`; prototypes for `fakelag_pool_take()` and `fakelag_grant()`. `fakelag_charge()` unchanged. |
| `ircd/fakelag.c` (new), `ircd/Makefile.in` | The pool, `fakelag_pool_take()`, `fakelag_grant()`, and `fakelag_test_reset()` under `#ifdef CMOCKA_TEST`. |
| `include/client.h` | `con_lagborrow`, `con_lagborrow_until`, accessors. |
| `ircd/parse.c` L1671 | `fakelag_spend()` at the charge site, still under the multiline guard. |
| `ircd/s_user.c` L822-828 | Becomes `fakelag_grant(ghost)`, **not** `sptr`: on a revive the incoming `sptr` has been freed and the ghost keeps the socket. |
| `ircd/s_user.c` L1115-1120, `ircd/bouncer_session.c` L12868-12873 | Become `fakelag_grant(sptr)`. |
| `ircd/ircd_features.c` (beside `POSTREG_GRACE`, L1348), `include/ircd_features.h` (after `FEAT_POSTREG_GRACE`, same order), `doc/readme.features` | `F_I(FAKELAG_POOL, 0, 0, 0)` (cap, lag-seconds, refills in 60 s) and `F_I(FAKELAG_BORROW, 0, 0, 0)` (allowance per registration). |
| `ircd/test/fakelag_cmocka.c`, `ircd/test/Makefile.in` | Cases below. `fakelag_test.o` is built from `../fakelag.c` the way the IPcheck test builds its source (`test/Makefile.in` L280-296). |

That comes to about 200 lines, with the tests about half of it.

**Off means off.** With `FAKELAG_POOL = 0` no allowance is ever set, so
`fakelag_spend()` is `fakelag_charge()`, and `fakelag_grant()` sets exactly what
the three inline blocks set today. That requires the right client at each site.

Suggested start for AfterNET: `FAKELAG_POOL = 600` (ten full allowances,
refilling at 10 s per second) and `FAKELAG_BORROW = 60`.

## Tests

`fakelag_spend()` is pure, so its cases need nothing stubbed but a fake `take`.
The `fakelag.c` cases stub `CurrentTime`, `feature_int` and `get_lag_factor`,
use a stack `struct Client` and `struct Connection` (`IsAccount` is a flag test),
and call `fakelag_test_reset()` between cases.

- Spend order: the grace first, then the allowance (and the pool), then the clock.
  A whole charge is absorbed while credit lasts. Partial spillover into the next
  stage. A lapsed allowance is zeroed and not spent. With the allowance at 0,
  the result matches `fakelag_charge()` exactly.
- Grant: pool off, the grant is exactly `POSTREG_GRACE` and the allowance is 0.
  An anonymous connection gets nothing. A class with lag factor 0 gets the grace
  but no allowance. A second grant to the same client (a revive) clears the old
  allowance.
- Pool: it starts empty. After 60 s it holds the cap. A draw takes at most what
  is there. A long gap, a forward step or a raised cap credits at most one cap.
  A step back adds nothing. A cap of 100 refills 100 in 60 s, with the remainder
  carried.
- The existing `fakelag_charge()` cases stay as they are.

The gate itself does not change, so it needs no new unit test. The end-to-end
check is live: against the dev ircd with user fake lag on, send 40 short lines
right after 001 (`tools/irc-ws-probe.mjs` in Seance), with the pool on and off,
and time the last reply. Then do the same with Seance's
`tools/scenarios/connect-fakelag.mjs`, 15 channels, once Seance knows about the
credit (next section).

## Measured

Built on this branch, against a local ircd with an iauth stub that logs every
client in (`POSTREG_GRACE` 20). A client sends 40 `PING`s right after 001; the
time is from 001 to each `PONG`.

| | Replies under 1 s | Last reply |
| --- | --- | --- |
| Pool off (today) | 14 | 52 s |
| `FAKELAG_POOL` 600, `FAKELAG_BORROW` 60, pool full | 40 | 0 s |
| Same, 20 clients connecting at once | 9 clients got all 40; the rest got 14 to 28 | 0 to 52 s; nobody worse than today |

## Live tests

An ASan + UBSan build of this branch, `BOUNCER_ENABLE` and auto-resume on,
behind an iauth stub that logs each client into the account named by its
ident. `FAKELAG_POOL` 600, `FAKELAG_BORROW` 60, `POSTREG_GRACE` 20; each
client sends 40 `PING`s and counts the replies within a second of sending.
No sanitizer report in any run.

| Case | Pool on | Pool off |
| --- | --- | --- |
| Fresh login | 40 | 14 |
| Revive of a held session after a dropped socket (resumes its channels) | 40 | 15 |
| Alias attach, a second device on a live session (the first stays up) | 40 | 15 |

- Draining: one account reconnecting about twice a second, each time sending
  40, empties the pool within seconds; other users then get 15, today's
  figure. The same with a new account and address each time. The clone
  limit did not slow the loop. This is the designed floor, not a bug, but it
  means one determined account can deny the pool to everyone else; a
  per-account allowance cooldown would close it if that matters.
- Rehash: with the pool turned off, a client that registered while it was on
  gets 15; raising the cap after a minute credits one cap; lowering it to 100
  with 2800 banked clamps the pool, and the next client gets 45 (10 + 5 + 30).
- Two linked servers: each server's pool is its own. With 20 clients bursting
  on each at once, 6 and 8 got all 40 and nobody got fewer than 15; a remote
  user's 40 channel messages all crossed the link. After a netsplit, 20
  clients reconnecting to the survivor: 8 got all 40, the rest at least 15,
  the slowest done in 30 s against today's 52.

## Checked by tools

- ASan + UBSan and valgrind over the unit tests, and ASan + UBSan over a live
  ircd running the probe and a 20-client storm: no reports.
- gcc `-fanalyzer` and cppcheck: clean. scan-build: the same 115 warnings as
  the base commit, none new.
- CBMC, with bounds, pointer, signed-overflow and conversion checks, on any
  input and any state the code can leave: no overflow; the pool stays in
  `[0, cap]` and the remainder in `[0, 60)`; a backward clock step adds nothing;
  `fakelag_spend()` charges between 0 and the line's lag, never grows a credit,
  conserves every second, equals `fakelag_charge()` with no allowance, and
  draws nothing after the window.
- The refill rate, for every run length, in z3 over exact integers (sound
  because CBMC proved there is no overflow). With `P = 60*pool + remainder`,
  one settle never lends plus banks more than `min(gap, 60) * cap`. `P` starts
  at 0 and never goes negative, so over any run the pool lends at most
  `cap * elapsed / 60`, and at most one cap per settle. CBMC alone could not
  close this: the divide by 60 times out even with the gap fixed.
  Mutants of the refill divisor, the backward-step test, the take and the full
  test are all caught. Dropping the 60 s clamp on the gap survives, because the
  cap clamp already bounds the refill; the clamp is there to stop the overflow,
  which the unit tests and CBMC catch.

## The client has to know

Seance never sends past its own model of the server's clock (`FakeLagClock`,
`client/js/irc/fakelag.ts`). It ignores `POSTREG_GRACE` because the server does
not advertise it, so a bigger credit changes nothing for Seance on its own.
Clients that just blast (most desktop clients) benefit at once, and the probe
above shows the server side without any Seance change.

For the Seance half of the demo, the simplest honest option is a per-network
setting in Seance's `config.json` (say `fakeLagCredit: 20`) that the network
sets to match its server. Seance's nefarious2 profile then starts the clock
with that credit after a SASL registration.

Getting the borrowed part as well needs the server to say what it granted, for
example one `NOTE` after 001 under a vendor cap. That is new protocol surface,
so it stays out of this change until the pool proves itself.

## Known limits

- **First come, first served.** There is no per-account limit. One account
  with several devices or bouncer aliases gets an allowance for each
  registration. IPcheck bounds reconnects per address after its startup delay,
  but not when `IPCHECK_SASL_REFUND` (default off) refunds SASL revives
  (`s_user.c` L786-787). With that on, a single flapping logged-in address can
  draw the whole refill. Whoever drains the pool only brings everyone else back
  to today's behaviour.
- **Bigger bursts into channels.** A logged-in revive that is already in its
  channels (no JOIN needed) can now send about 40 PRIVMSGs at once instead of
  about 15. That is bounded by the pool, at roughly 10 such bursts a minute
  server-wide with the suggested settings. Target limiting and channel modes
  still apply.
- **Registration only.** A client that logs in after 001 gets neither the
  grace (as today) nor an allowance.
- **Not every line is charged.** Unknown and shunned commands skip the charge,
  and so do lines inside a multiline batch, while a multiline close charges the
  clock directly (`m_batch.c` L695). So "about 45 commands" assumes short
  ordinary commands.
- **A clock step back still freezes clients.** That happens today too: their
  `cli_since` is left in the future. The pool's own handling only keeps the pool
  from locking up.
- **Per server.** Each server has its own pool. Fake lag is local and never
  crosses P10.
- **Upstream ircu behaviour.** It is off by default, and it needs evilnet's
  agreement before it goes anywhere but a fork.

## Not in scope

- Borrowing for a client that wakes from the background *without* reconnecting.
  The allowance lapses 30 s after registration.
- Per-class or per-account pools.
- Folding the multiline, METADATA, BATCH and WebSocket control-frame meters
  into one hierarchy.
- Advertising the credit to clients.

## Review findings and what became of them

v1, Claude red team:

| Finding | Outcome |
| --- | --- |
| The gate checks before the charge, so borrowing that only trims the overshoot back to 10 can never let another line through | v1 dropped. v2 and v3 borrow at grant time. |
| Spending the grace after the clock cut today's 15-command burst to 5, even with the new features off | Today's order is kept. |
| The allowance started empty, so a reconnecting phone never benefited | The top-up is granted at registration. |
| The `BORROW/60` refill truncated to 0 | That math is gone. |

v2, Codex:

| # | Finding | Outcome |
| --- | --- | --- |
| 1 | Granting to `sptr` on a revive uses a freed client | Fixed: the revive site grants to `ghost`. |
| 2 | Borrowed credit never expires, so connections can stockpile it | Fixed: the top-up is a separate credit with a 30 s expiry. |
| 3 | A restart starts the pool full while IPcheck's clone throttle is still off | Fixed: the pool starts empty. Reframed as a boost, not storm control. |
| 4 | One account can take several top-ups | Accepted and documented. |
| 5 | Classes with fake lag off still drain the pool | Fixed: no top-up when `get_lag_factor() == 0`. Opers stay eligible (`MFLG_SLOW` still charges them). |
| 6 | A rate change applies retroactively | Fixed: the pool is settled on every call. The separate rate knob was cut, since the pool refills in 60 s. |
| 7 | Signed overflow | Fixed: the features are clamped and `dt` is clamped to 60. |
| 8 | A clock step back can mint refill, and clients still freeze | The refill is bounded to one cap per step. The client freeze is pre-existing and documented. |
| 9 | The byte count, unknown and shunned commands, and multiline were described inaccurately | Corrected. |
| 10 | The existing test does not pin a 15-command burst, and the gate needs live testing | The claim is corrected, and the live probe was added. |
| 11 | Pre-registration and logging in after 001 | Documented. |
| 12 | The scope and claims were overstated, the advertisement protocol was premature, and assuming 20 s on the client is unsafe | Renamed, the protocol is out of scope, and Seance gets a per-network setting instead. |

v3, Fable:

| # | Finding | Outcome |
| --- | --- | --- |
| 1 | Pasting the charge-site rewrite in literally would put only its first line under the brace-less multiline `if` | Fixed: the order moves into `fakelag_spend()` in the header, and the call site stays a single statement. This also makes the charge order unit-testable. |
| 2 | Lines before 001 are charged, so a pipelined SASL connect reaches 001 with no headroom left | Rejected. A zeroed `Connection` caches lag factor 0 until `register_user` resets it (`class.c` L388, `s_user.c` L626-627), and nothing else resets the cache before 001, so pre-registration lines are free. Now stated in Problem. |
| 3 | The grant's early returns leave a revived ghost's old allowance in place | Fixed: `fakelag_grant()` clears both fields first. The gating on `POSTREG_GRACE` is documented. |
| 4 | Per-settle truncation loses refill, and "does not credit the past" is false when nothing settles | Fixed: the remainder is carried in 1/60 s. The claim and the test now say "at most one cap". |
| 5 | A flat take at grant time wastes the pool on clients that need little, opers included | Fixed: the allowance draws on the pool lazily at the charge site, for seconds actually spent. The stockpiling and expiry questions from v2 go away with it. |
| 6 | Spend the top-up before the grace | Not taken. With lazy draws, spending the shared pool before a connection's own grace would cost the server for nothing. |
| 7 | `IPCHECK_SASL_REFUND`, and bigger PRIVMSG bursts | Added to Known limits. |
| 8 | The tests need a build rule, more stubs and a reset, and the size estimate was low | Fixed in the file list and Tests. The estimate is now about 200 lines. |
| 9 | Nits: `len` counts the command when there are no parameters; where the features go | Fixed. |
