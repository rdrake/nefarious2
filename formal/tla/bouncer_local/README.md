# BouncerLocal: TLA+ model of the single-server bouncer session lifecycle

`BouncerLocal.tla` models one account with one session slot
(`FEAT_BOUNCER_MAX_SESSIONS = 1`) on one server, plus one optional remote alias `R`
(BX C / BX X / relayed KILL) and one optional stale roster entry `STALE` (a persisted
remote alias that `bounce_db_restore` puts back and whose Client never returns). Every
action is one synchronous C call path, including the full `exit_client` cascade, so each
action is atomic. Each action's guard and effect were read from the C code on
`ircv3.2-upgrade`, and the spec cites file:line for each one.

## What is modelled

| Model variable | C state |
|---|---|
| `st[c]` none/user/ghost/alias | live Client, `IsBouncerHold`, `IsBouncerAlias` |
| `ss`, `hs`, `al` | `hs_state`, `hs_client`, `hs_aliases[]` (set; `hs_alias_count` = size) |
| `holdT`, `promT` | `t_active(&hs_hold_timer)`, `t_active(&hs_promote_timer)` |
| `db`, `gnum` | persisted record present, `hs_ghost_numeric[0]` |
| `ap[c]` | `cli_user(c)->alias_primary` |
| `nk[c]` | nick (`"N"` = session nick; otherwise the client's own nick) |
| `acct`, `tls`, `bc` | `IsAccount`, TLS socket, connection class `CRFLAG_BOUNCER` |
| `meta`, `ovr`, `zc` | `draft/persistence/hold` metadata, `hs_hold_override`, primary in a +Z channel |

The actions are:

* **register_user**: Try 1 revive (including the +Z refusal and a socket failure after
  the ACTIVE flip), Try 2 relay-only revive, and `bounce_auto_resume` with all of its
  branches: opt-out, held local attach, orphan discard, orphan reclaim, alias local/remote,
  reject, and create.
* **Disconnects**: primary QUIT (m_quit, including the local-only promote and the deferred
  cross-server promote), dead link / WS close (s_bsd), ping timeout (ircd.c), and alias quit.
* **Timers**: `bounce_hold_expire` and `bounce_finish_cross_server_promote`.
* **KILL**: a local oper KILL (no `FLAG_KILLED`) and a server-relayed KILL (`FLAG_KILLED`).
  Both cover a primary, a ghost and an alias.
* **Deauth**: `bounce_account_deauth_apply`, plus the callers' ghost exit.
* **Commands**: BOUNCER SET HOLD on/off, SET SESSION HOLD, PERSISTENCE DETACH/SET OFF,
  oper BOUNCER RESUME and DISCONNECT.
* **Peers**: BX C (including the session move), BX X, and the EB stale-alias prune.

## Abstractions and limits

* There is one account and one session slot, so multi-session (profile) interactions are
  not covered. Keycloak-id gating is not modelled: every login is assumed to be the same
  user.
* The remote side is shallow. Once R is promoted to primary, the peer's own lifecycle
  (its hold, its BS D/BS X) is not modelled. A KILL whose primary is remote is out of scope
  for `KillEndsSession`.
* Time is abstract. The hold re-arm and decay are stutter steps. The 0-tick promote timer
  always fires before a hold timer of 1 s or more (`HoldExpire` requires `~promT`).
* Channels are reduced to the single +Z flag, and nick collision handling is reduced to
  "registration picks a free nick". The UserStats, legacy-face, burst and CHECK paths are
  not modelled.
* `bounce_session_transition` is not modelled. It is not yet on any call path.

## Properties

* **Safety**:
  * `HoldingOK`: HOLDING implies a local ghost and an armed hold timer.
  * `ActiveOK`: ACTIVE implies a live primary.
  * `GhostAnchored`: every ghost has a HOLDING session and a timer.
  * `AliasInSession`
  * `NoOrphanAlias`: an alias has a live `alias_primary`.
  * `AliasPrimaryOK`: assert_invariant -7.
  * `EntriesResolve`: assert_invariant -6.
  * `DestroyedClean`: a destroyed session has no timers and no record.
  * `NickUnique`
  * `NoUAF`: nothing writes to a freed session.
  * `NoDetachedPrimary`: a promoted alias is never left untracked.
  * `KillEndsSession`: a KILL of a member whose primary is local tears down the session.
* **Liveness** (`FairSpec` = weak fairness on the hold and promote timers):
  * `HoldingResolves`: HOLDING leads to not-HOLDING.
  * `GhostResolves`: a ghost eventually goes away, without assuming the user ever returns.

## Running

```sh
./run_all.sh                   # every *.cfg; each writes <cfg>.out
./run_all.sh F2_ResumeUAF.cfg  # one config
```

To run TLC directly:

```sh
java -XX:+UseParallelGC -cp /opt/tla/tla2tools.jar tlc2.TLC -workers 4 -deadlock -config Clean.cfg BouncerLocal.tla
```

The `F*` configs each switch on one trigger constant, and TLC prints a counterexample.
`Clean*` switches every trigger off.

## Results (TLC 2, 4 workers)

| Config | Outcome |
|---|---|
| `Clean.cfg` (2 local + R, every invariant) | **no error**, 79,120 distinct states, depth 16 |
| `Clean3.cfg` (3 local + R, symmetry) | **no error**, 1,695,728 distinct states, depth 21 (~5 min) |
| `LiveClean.cfg` (`HoldingResolves`, `GhostResolves`) | **no error** (79,120 states) |
| `F1_AttachPlusZTimer` | `HoldingOK`, `GhostAnchored`, liveness violated (2 steps) |
| `F2_ResumeUAF` | `NoUAF` (3 steps); with aliases, `NoDetachedPrimary` |
| `F3_HoldOffWhileHeld` | `AliasInSession`, `GhostAnchored`, `NoOrphanAlias`, `GhostResolves` |
| `F4_QuitHoldDisabled` | `ActiveOK`, `AliasPrimaryOK`, `NickUnique` |
| `F5_StaleRosterExpire` | `HoldingOK` (1 step), `HoldingResolves` |
| `F6_ReviveFailLate` | `GhostAnchored`, `GhostResolves` |
| `F7_OperDisconnect` | `GhostAnchored` |
| `F8_LocalKillAlias` | `KillEndsSession` |
| `F9_Deauth` | `GhostAnchored`, `NoOrphanAlias` (plausible only; see below) |

"Clean" means the following trigger constants are all FALSE: `ReviveCanFail`,
`StaleRoster`, `PlusZ`, `OperCmds`, `UserCmds`, `DeauthOn`, `OperKillAlias`.
`DefaultHold` stays TRUE, which is the feature default. Under those settings every
invariant and both liveness properties hold within the bounds: create, revive, alias
attach, quit/drop/ping hold, local/remote promote, deferred promote, hold expiry, BX C
session move, BX X, and both KILL paths.

## Findings

Each one is a confirmed C path unless it says otherwise. Full traces are in `F*.out`.

* **F1, attach +Z refusal kills the hold timer.** `bounce_attach` deletes
  `hs_hold_timer` (bouncer_session.c:1925-1927) *before* the +Z/plaintext gate returns -1
  (1932-1944). The path is: a plaintext SASL login for a session whose ghost is in a +Z
  channel; the revive refuses (5693-5710); `bounce_auto_resume` attaches at 1433 and is
  refused; the login falls through to plain registration. The ghost is then held with no
  timer and keeps its nick and channels until the user returns over TLS, is KILLed, or the
  server restarts.
* **F2, `bounce_attach` exits the ghost while the session is still HOLDING.** The ghost
  exit is at 1967-1968. It goes through exit_one_client's generic branch (s_misc.c:637-683):
  * With no aliases, `bounce_destroy` frees the session, and `bounce_attach` then writes
    1979+ and `m_bouncer.c:177` broadcasts from freed memory (**use-after-free**).
  * With aliases, an alias is promoted (s_misc.c:665-670), and `bounce_attach` then
    overwrites `hs_client` (two primaries).

  This is reachable through oper `BOUNCER RESUME` (m_bouncer.c:170). Through
  register_user, revive's gates mirror attach's, so it is not reachable (model: only via
  the oper command).
* **F3, BOUNCER SET HOLD off / PERSISTENCE SET OFF / DETACH only destroy the record.**
  This is m_bouncer.c:774-781, m_persistence.c:290-300 and m_persistence.c:862-875. The
  comments say the destroy "disconnects all aliases", but nothing is exited. When it runs
  from an alias while the session is HOLDING (`bounce_get_session` follows the alias to the
  ghost; `hs_enforced` was cleared at hold, bouncer_session.c:5537), the ghost is left with
  no session and no timer, and holds the nick forever. The aliases stay sessionless and are
  orphaned (`alias_primary` = NULL) when the primary leaves. A later SET HOLD on from such
  an alias calls `bounce_create` on an alias (m_bouncer.c:739), which gives a session whose
  `hs_client` is an alias.
* **F4, primary QUIT/dead-link with hold disabled while aliases exist.** m_quit.c:140 and
  s_bsd.c:2001 skip the promote, then s_misc.c:684-711 leaves the session ACTIVE with
  `hs_client` = NULL. The aliases are orphaned and the nick is free in the hash. The next
  login reclaims the session as primary (bouncer_session.c:1484) and leaves the old aliases
  pointing nowhere. A later promote `hAddClient`s the stale alias nick (5044) and can
  duplicate a nick another user took meanwhile. Ping timeout does promote here
  (ircd.c:762-772), which is inconsistent with the other two paths. The trigger is
  `hs_hold_override = 0`, hold metadata set to 0 after attach, or a session created on a
  bouncer-class port and continued from a normal-class one with `DEFAULT_HOLD = 0`.
* **F5, hold expiry when every roster entry is stale.** `bounce_promote_alias` fails at
  bouncer_session.c:746-772. The ghost exits without its hold flag, the second promote at
  s_misc.c:665-670 fails, and s_misc.c:723 nulls `hs_client`. The session is left HOLDING
  with no client and no timer, and the record is not deleted. The auto_resume discard
  condition (1373-1380) never matches because the ghost numeric and the alias entries are
  still set, so every later login registers without a session until a peer EB prunes the
  entry. The trigger is a restored record with remote aliases (3651-3671) and no peer
  burst before expiry.
* **F6, revive socket failure after the state flip.** bouncer_session.c:5719-5727 flips the
  state, and 5813-5838 then fails. The session is ACTIVE with an `IsBouncerHold` ghost and
  no timer (assert_invariant -5). The failed temp is attached as an alias of the ghost. It is
  recovered only by the user's next login (Try 2, s_user.c:543-555).
* **F7, oper BOUNCER DISCONNECT.** m_bouncer.c:451-453 destroys only the record. A held
  ghost then has no timer and holds the nick forever.
* **F8, local oper /KILL of a local alias kills only that connection.** `do_kill` sets no
  `FLAG_KILLED` for a local victim (m_kill.c:134-144), and the hook at m_kill.c:179-184 only
  matches `hs_client`. This contradicts skill invariant #6 ("KILL of any alias ends the
  session"). A relayed KILL does end it (s_misc.c:357-372).
* **F9 (plausible), deauth of a single client destroys every session of the account.**
  This is bouncer_session.c:7238-7248. A held ghost that was not the deauth target keeps its
  hold flag, its account and no timer (7274 checks only `acptr`). Live aliases are left
  sessionless. This is harmless only if services and the webhook deauth *every* client of
  the account, which they do on deletion. Any per-client AC U (a logout) would strand the
  ghost.
