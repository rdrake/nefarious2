# Bouncer P10 protocol change proposals

2026-10-29. Exported from the Claude doc of the same name (that copy is the
editable one). Findings are traced in `formal/tla/bouncer_converge/README.md`
and the ledger is `formal/FINDINGS.md`.

Five P10 changes fix the cross-server bouncer bugs found by TLA+ model
checking. All are additive and gated per peer, and they leave legacy and
older fork servers on today's behaviour.

## At a glance

Only P1 and P3 put anything new on the wire. P2, P4 and P5 change what a
server sends using existing tokens, so they ship as ordinary fixes.

| Proposal | Fixes | Wire change | Older fork peer | Legacy peer (X3, ircu) |
| --- | --- | --- | --- | --- |
| P1 Hold marker on N | A, G (and plausible S, N) | New `,H` compact-tag segment + server flag `H` | Ignores `,H`; links to it keep today's rules | Never receives tags; unaffected |
| P2 Burst BS A/C/D sourced from the primary's server | E, M | None: only the message source changes | Already resolves it correctly | Never receives BS; unaffected |
| P3 Keycloak id ahead of BS C | K | New `BS K` subtoken | Ignores unknown BS subtokens | Never receives BS; unaffected |
| P4 Retire before rename | S′ | None (fallback: member-aware BS X behind flag `H`) | Unchanged | Gets a normal Q |
| P5 Announce a ghost rebind | I | None: Q for the ghost + forward the N | Understands both | Understands both |

**Severity of what each fixes:**
- **High:** A, E, G and S′. They respectively KILL a live user, create a second primary, leave sessions that never expire, and destroy a surviving session.
- **Medium:** K, I and M.

All of these are confirmed by both the TLA+ model and an independent code review.

## How a change rolls out safely

The fork already has four extension points that older peers tolerate.

| Extension point | Where | What an older peer does | Used by |
| --- | --- | --- | --- |
| Server flag letter in `SERVER` (`+hs6ovrF`) | `set_server_flags`, m_server.c:489; re-announced for remote servers, s_serv.c:285 | Ignores an unknown letter | P1 (new flag `H`) |
| Compact-tag segment on S2S lines (`,S`, `,M`, `,C`) | parse.c:1872–1927 | Skips an unknown segment silently (parse.c:1927) | P1 (`,H`) |
| BS subtoken | `bounce_handle_bs`, bouncer_session.c:4855 | Ignores an unknown subtoken (`default: break`) | P3 (`BS K`) |
| `BX U key=value` | bouncer_session.c:9638–9700 | Ignores an unknown key | Already used for `cc=`, `ta=`, `kcid=`, `la=`, `aw=` |

Two constraints shape the choices:
- **`BS C` cannot grow.** It is positional and ends in a trailing `:channels` field, so a field cannot be appended without older peers misparsing it (parc checks at bouncer_session.c:4232–4244). New session data therefore rides a separate subtoken.
- **`,S<sessid>` must not be overloaded.** An older peer copies the whole segment as the session id.

Legacy peers (X3, vanilla ircu) receive no BS or BX at all (`bounce_burst`, bouncer_session.c:3880) and no compact tags.

## P1 — Hold marker on N (fixes A and G)

A held ghost and a live login are indistinguishable on the wire today.

**Bug A.** S1 holds a ghost of c1. During the split, c1 logs in on S2 with the same nick. On heal, `N` is sent before `BS C` (s_serv.c:341–529):
1. S2's split-merge (D.2, m_nick.c:570–637) demotes the live user under the incoming N, which is really the ghost.
2. S1 refuses the rebind (bouncer_session.c:6331–6351) and falls back to classic collision. The older timestamp wins, so S1 KILLs the live user, and that KILL tears down the session (m_kill.c:143).
3. S1's later `BS C` retire (bouncer_session.c:4394–4403) ends its own held session too.

This is the ordinary failover pattern.

**Bug G.** The same session is held on both sides. Each side's sessid-authorized rebind drops its own ghost, timer and record (bouncer_session.c:6379–6457). The session ends ACTIVE with no real primary and never expires.

**Wire change.**
- **Server flag `H`** in `SERVER`: "I send `,H` and apply the rules below." It is propagated for remote servers like `F`.
- **Segment `,H`** on the `N` of a client that is a held ghost (`IsBouncerHold`), sent only toward `H` peers, the same way `,S` is armed. Example: `@A<time><msgid>,S<sessid>,H N …`.

**Receiver rules (only between two `H` servers).** An N from an `H` peer without `,H` is known live. An N from a non-`H` peer gets today's rules.
1. **Live beats held.** On a same-nick collision for the same account, with Keycloak ids matching or one missing:
   - the ghost's home exits its ghost with a Q ("Bouncer session moved", invariant 7, never FLAG_KILLED) and accepts the live N;
   - the live side drops the `,H` N without a KILL.
   
   Both sides decide from wire-visible facts, as `bounce_converge_peer_wins` does.
2. **No demote under a held N.** D.2 never demotes a live local primary under an N marked `,H`.
3. **No rebind to a held N.** For ghost against ghost, the older one stays, and the younger one's home exits it with a Q.

**Impact.**
- **Bandwidth:** two bytes per held-ghost N, in bursts only.
- **Mixed links:** these keep today's behaviour.
- **What users see:** after a heal the live login keeps its connection.

## P2 — Burst session lines sourced from the primary's server (fixes E and M)

**Bug E.** `bounce_burst` sends `BS A <account> <sessid> <XXX>` from `&me` (bouncer_session.c:3946–3952). The receiver builds the numeric as `cli_yxx(sptr)` + XXX (bouncer_session.c:4590). For a primary behind the hub, that resolves to no client:
- the leaf's replica gets no primary and no Keycloak id, and nothing repairs it (bouncer_session.c:1066–1077, 9664, 1812);
- a later login reclaims the session as a second primary (bouncer_session.c:1486–1494).

Any leaf that links through a hub hits this.

**Bug M.** The same `&me` source makes the hub the replica's `hs_origin` (bouncer_session.c:4477). SQUIT cleanup matches on origin, and only for the directly split server (s_misc.c:971, bouncer_session.c:5296). After a split more than one hop away, the replica stays ACTIVE with no primary.

**Change (no new token).**
1. Send burst `BS C/O/A/D` with `cli_user(hs_client)->server` as the source. The receiver's existing prefix logic then resolves the right client, and `hs_origin` becomes the real server. Invariant 3 holds.
2. SQUIT cleanup decides by the servers of `hs_client` and of every alias, across all servers that `exit_downlinks` removes.

**Impact.** Older fork receivers benefit immediately. This is a sender-side fix, so upgrade hubs first.

## P3 — The Keycloak id ahead of BS C (fixes K)

**Bug K.**
1. An account is re-created in Keycloak during a split, and both users take the same nick.
2. The younger id's primary is refused at N time on one side.
3. On that side, `bounce_peer_session_primary` (bouncer_session.c:1196–1210) finds nothing, so the gate (bouncer_session.c:4372–4383) passes.
4. The rename (bouncer_session.c:4419–4429) merges the two users' sessions there.

The other side keeps them apart.

**Wire change.** `BS K <account> <sessid> <kc-id>`, sent immediately before each `BS C`, both in the burst and on live broadcast.
- The receiver records the id against `(account, sessid)`. The BS C gate compares recorded ids: if they differ, nothing is merged, renamed or retired.
- A missing id never vetoes.
- `BX U kcid=` is unchanged. It is keyed by a client numeric, so it can't help when the primary was refused.

**Impact.**
- Older fork peers ignore it and keep today's one-sided gate.
- Cost: one line per session per burst.

## P4 — Retire before rename (fixes S′)

**Bug S′.** This needs three servers and a held-versus-held heal through a hub.
1. The renames move the losing record under the winner's sessid (bouncer_session.c:4419–4431).
2. The classic collision KILLs the younger ghost.
3. `bounce_kill_session` (s_misc.c:643–664) broadcasts `BS X` with the renamed id.
4. `BS X` is keyed by sessid alone (bouncer_session.c:4753–4757), so it destroys the winner everywhere and orphans its ghost.

This is deterministic when the older ghost also has the lower sessid.

**Preferred change (no wire change).**
- When BS C convergence retires our held session, the local ghost exits with a Q first and our record is destroyed. Only then is the winner's replica built.
- A record is never renamed while its primary is a local held ghost.
- Defensively, `bounce_kill_session` sends BS X only when the killed client is still the primary under the record's original id.

**Fallback (behind flag `H`).** `BS X <account> <sessid> <YYXXX>`: an `H` receiver destroys the session only if that member is the current primary. A session token alone is not enough, because merged records keep different tokens.

**Before implementing:** re-run `formal/tla/bouncer_converge` with config `repro/Sprime_rename_bsx_3srv.cfg` with the preferred change modelled.

## P5 — Announce a ghost rebind (fixes I)

**Bug I.** The rebind returns early (m_nick.c:532–537) after freeing the ghost's numeric (bouncer_session.c:6383). No Q goes onward and the N is not forwarded, so servers beyond the rebinder keep a phantom.

**Change (no new token).** After a successful rebind, toward every link except the one the N arrived on:
1. send a Q for the ghost's old numeric (invariant 7);
2. forward the N with its `,S` hint (invariant 5).

## Changes that need no protocol change

### Cross-server, local decisions

| Bug | Severity | Change | Key code |
| --- | --- | --- | --- |
| B — a rename leaves two live primaries | Medium | `BS A` never displaces a live local primary | bouncer_session.c:4605, 1225–1255 |
| C — a demote strands the loser's other aliases | Medium | Repoint every sibling and re-emit `BX C` | bouncer_session.c:6583–6584, 8895–8898 |
| D — a hub runs the split-merge for a remote primary | Medium | D.2 only where the primary is `MyConnect` | m_nick.c:570–573; bouncer_session.c:6551–6554 |
| R (plausible) — orphan reclaim races a peer's BS C | Low | Same `bounce_peer_has_inbound_data()` deferral as the create path | bouncer_session.c:1486–1497, 1545 |

### Single-server lifecycle

These share one root cause: the record is destroyed while its clients remain. The fix is one teardown helper:
- aliases exit with `exit_client`, which sends BX X (invariants 6, 12);
- a local held ghost gets `ClearBouncerHold` then `exit_client`, which sends a Q (invariant 7);
- the `BS X` receiver also exits its own local held ghost. This is a receiver-side change to an existing token.

| Bug | Severity | Who | Change / status |
| --- | --- | --- | --- |
| F2 — `BOUNCER RESUME` frees the session, then writes it | High (UAF) | Oper | Fixed in PR #9 |
| F1 — +Z plaintext login cancels the hold timer | Medium | Any user | Fixed in PR #9; the duplicate nick it exposed is fixed in PR #10 |
| F6 — a failed revive leaves the session ACTIVE | Low | Rare | Fixed in PR #9 |
| F3 — `SET HOLD off` / `PERSISTENCE SET OFF` / `DETACH` / `MODE -b` destroy only the record | Medium | Any user | Teardown helper (pending decision) |
| F4 — the primary quits with hold off and skips the promote | Medium | Any user | Promote before exit, as ircd.c:762–772 does |
| F5 — hold expiry with only stale aliases leaves a zombie | Medium | Restart topology | When promote fails, clear the roster and destroy |
| F7 — `BOUNCER DISCONNECT` leaves a held ghost | Low | Oper | Teardown helper |
| F9 (plausible) — a per-client deauth strands another ghost | Low | Depends on X3 | Treat every local held ghost of the account alike |

## Rollout order

1. **Local fixes.** P2, P4 (preferred), P5, B/C/D/R, and the teardown helper. Upgrading hubs first gives the most benefit.
2. **P3 `BS K`.** Each upgraded server's half of the gate is correct immediately.
3. **P1 flag `H` + `,H`.** Effective per link, where both ends announce `H`.
4. **Optional P4 fallback.** Only if the model re-run requires it.

X3 and vanilla ircu need no change at any step.

**Test cases:**
- **P1:** split, drop the user on S1, log in on S2, heal; the live client must survive.
- **P2:** a 3-server chain with the leaf linking last, a login on the leaf, then a split of the primary's server.
- **P3:** an account re-created in Keycloak during a split; the sessions must stay apart.

## Decisions needed

- [ ] Approve the wire changes P1 (`H` + `,H`) and P3 (`BS K`).
- [ ] Confirm the letters `H` and `K` are free in every fork branch.
- [ ] P1 rule 1: does "live beats held" require an exact Keycloak-id match, or is it enough that one is missing?
- [ ] `SET HOLD off` / `DETACH` run from an alias: promote that alias first, or refuse?
- [ ] Does X3 send `AC U` per client on logout? This decides F9.
