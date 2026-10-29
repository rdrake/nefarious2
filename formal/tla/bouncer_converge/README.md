# Bouncer cross-server convergence: TLA+ model

TLA+ models of how 2–3 Nefarious servers converge on one bouncer session per
account through link, burst, netsplit and SQUIT. The models cover the P10 `N`,
`BS C/A/D/X`, `BX C/X/P`, `KILL` and `EB` handling. Every guard and effect in
`BouncerConverge.tla` was transliterated from the C on branch `ircv3.2-upgrade`
and is cited as `file:line` in the spec comments:

| prefix | file |
|---|---|
| `BS:` | `ircd/bouncer_session.c` |
| `NK:` | `ircd/m_nick.c` |
| `MI:` | `ircd/s_misc.c` |
| `SV:` | `ircd/s_serv.c` |
| `CV:` | `ircd/bouncer_converge.c` |
| `RA:` | `ircd/bouncer_rebind_auth.c` |

No C source was changed.

## Files

| file | what |
|---|---|
| `TieBreak.tla/.cfg` | Exhaustive check of `bounce_converge_peer_wins` (CV:16-33) over {NULL, "", "a", "b"} × {held, live} |
| `BouncerConverge.tla` | The protocol model (single record variable `w`; handlers are pure `World -> World` functions so kill → destroy → broadcast cascades compose) |
| `clean/*.cfg` | Configurations that check clean with the model patches (`Fixes`) switched on |
| `repro/*.cfg` | One configuration per finding: every model patch is on **except** that finding's, so the counterexample is attributable to it |
| `run_all.sh` | Runs every config and prints one result line each |
| `run.sh <cfg> [trace.json]` | Runs one config and dumps the counterexample as JSON |
| `trace.py <trace.json>` | Prints a compact, per-step summary of a JSON counterexample |

## What is modelled

- **Servers** S1..S`NS` on the chain 1–2–3, with FIFO per-direction link queues. Links come up with a full burst (`server_finish_burst` order: `N` for every non-alias user, held ghosts included, with the `,S` sessid hint; then `bounce_burst`'s `BS C`, `BS A`, alias `BX C`; then `EB`). Links go down with SQUIT cleanup at every server of each side: `bounce_prepare_squit_promotions` / `execute` keyed on the SQUIT victim, then `exit_downlinks` → `exit_one_client` session logic.
- **One account**. Clients carry home server, nick, `lastnick` (TS), and Keycloak id. Each server has its own view of each client (present / alias flag / `cli_session_id` / `alias_primary`) and its own session record (sessid, token, ACTIVE/HOLDING, `hs_client`, alias roster, `hs_kc_id`, `hs_origin`).
- **Local events** (bounded): SASL login per `bounce_auto_resume` (create with its inbound-data deferral, revive, local and remote alias, orphan reclaim, id-conflict end-stale and refuse); primary disconnect (immediate local promote, else hold with `BS D`); alias quit (`BX X`); hold expiry; and the deferred cross-server promote timer.
- **Receivers**: `ms_nick` collision handling (ghost rebind with origin/sessid authorization and id veto, D.2 split-merge, classic TS collision with the same-account override); BS C (token match, cross-sessid id gate, state-first retire, sessid rename); BS A and BS D with `bounce_hs_client_assign_checked`; BS X; BX C with account fallback, id gate, convert-in-place and "session move"; BX X; BX P with sibling repointing; KILL with the alias→primary cascade; and EB, which relays, clears the burst flag of the bursting server and runs `bounce_post_burst_reconcile`.

### Abstractions and limits

- One account, one session record per server (the C's `as_sessions` head; several profiles per account are not modelled). Channels, caps, away, snomask, oper, BS U/O/T, BX U fields other than `kcid=`, and legacy (non-IRCv3) peers are omitted.
- Numerics are client ids. A wire XXX that the receiver prefixes with the wrong server resolves to "no client", so XXX collisions with an unrelated client are not explored.
- "Same user@host" is irrelevant for same-account collisions because NK:820-840 forces `differ=1`.
- The promote winner is the lowest client id (abstracts the activity rule). Burst gating (`BurstGated`, SV:307-317) is not modelled: bursts go out at link time.
- SQUIT is applied atomically at every server of each side. `IsBurstOrBurstAck(sptr)` is approximated as "this server has not yet seen `sptr`'s EB".
- `QuietEnv = TRUE` lets environment events (logins, disconnects, link changes) fire only when no message is in flight and no promote timer is pending. That separates protocol bugs from timing races; `QuietEnv = FALSE` interleaves everything.
- `Fixes` is a set of **model-only** patches, one letter per confirmed finding, so TLC can look past a known bug. They are suggestions of the fix shape, not proven designs.

### Properties

- `KcBound` (always): no session record has a primary or alias of another Keycloak id (invariant 16).
- `KcAgree` (always): records with the same sessid never carry two ids.
- `NoLiveLoss` (always): convergence never tears down a connection the user still has open (KILL, session-kill, or BX X/BX P of a live client).
- `NoBadDemote` (always): no live primary is demoted under an N that its sender announced as held; no server demotes a remote primary; no fabricated alias numeric.
- `Agree` (at quiescence, meaning all links up, queues empty, all EBs seen, no promote pending): every server has the session with the same sessid and the same primary; at most one non-alias identity; every open connection is a member everywhere; no phantom clients.
- `AgreeState` (at quiescence): replicas agree on ACTIVE/HOLDING.
- `NoZombie` (whenever nothing is in flight, links may be down): no session record without a primary, and no alias without one.
- `Settles` (liveness, weak fairness on delivery and the promote timer): `<>[](AllUp => Quiescent)`.

## How to run

```sh
cd formal/tla/bouncer_converge
./run_all.sh                                   # everything (~4 min on 4 cores)
./run.sh repro/A_held_vs_live.cfg /tmp/a.json  # one config, JSON trace
python3 trace.py /tmp/a.json                   # readable counterexample
java -cp /opt/tla/tla2tools.jar tlc2.TLC -config TieBreak.cfg TieBreak
```

## Results

TLC 2.x, 4 workers. Every run finishes in under a minute except `Sprime` and `MC2_kc_racy` (about 40 s each).

**Clean, with the model patches on** (`Fixes` = every letter below that has a model patch):

| config | servers | env | bounds | properties | distinct states | depth |
|---|---|---|---|---|---|---|
| `TieBreak` | – | – | exhaustive over 4 ids × 2 states, both argument orders | `Antisym` | 1 | – |
| `clean/MC2_fixed_c3` | 2 | quiet | 3 logins, 3 link events, 2 disconnects | all safety | 16,800 | 35 |
| `clean/MC2_fixed_live` | 2 | quiet | 2 logins, 3 link events, 2 disconnects | all safety + `AgreeState` + `Settles` | 2,238 | 31 |
| `clean/MC2_kc_racy` | 2 | racy | 3 logins, ids {1,2}, 3 link events, 2 disconnects | `KcBound`, `KcAgree` | 319,502 | 29 |
| `clean/MC3_split_heal_fixed` | 3 | quiet | start split, 2 logins, 3 link events, 1 disconnect | all safety | 10,714 | 33 |
| `clean/MC3_linked_split_fixed` | 3 | quiet | start linked, split + heal | all safety + `Settles` | 7,287 | 32 |

**Reproductions** (every patch on except the named one; `baseline_nofix` has none):

| config | violated | distinct states / depth |
|---|---|---|
| `repro/baseline_nofix` | `NoBadDemote` (= A) | 132 / 8 |
| `repro/A_held_vs_live` | `NoBadDemote`, then `NoLiveLoss` | 161 / 9 |
| `repro/B_rename_bsa` | `Agree` | 1,033 / 14 |
| `repro/C_sibling_alias` | `Agree` | 8,567 / 18 |
| `repro/D_hub_d2` | `NoBadDemote` | 1,925 / 13 |
| `repro/E_burst_bsa_prefix` | `Agree` | 4,120 / 16 |
| `repro/G_ghost_ghost` | `Agree` | 16,267 / 27 |
| `repro/I_rebind_silent` | `Agree` | 6,215 / 27 |
| `repro/J_replica_state` | `AgreeState` | 7,076 / 29 |
| `repro/K_kc_rename` (unpatched, quiet) | `KcAgree` | 2,556 / 8 |
| `repro/M_multihop_squit` | `NoZombie` | 82 / 14 |
| `repro/N_hub_midburst_collision` (racy) | `NoLiveLoss` | 5,907 / 10 |
| `repro/R_reclaim_race` (racy) | `NoZombie` | 254 / 10 |
| `repro/S_stale_retire` (racy) | `Agree` | 915 / 17 |
| `repro/Sprime_rename_bsx_3srv` (quiet, 3 servers) | `Agree` | 334,691 / 37 |

Without any patch, per-server `KcBound` never failed: `bounce_hs_client_assign_checked` and the BX C id gate hold. Only the cross-server `KcAgree` fails (K).

### Tie-break (`bounce_converge_peer_wins`)

Antisymmetric for every combination. When the two records differ, exactly one side yields. When the sessid is the same, nobody retires, whatever the states. Live beats held in both directions. One edge: NULL and `""` normalise to the same id (CV:20-23), so two *different* records with NULL and `""` ids are both kept. That is harmless in practice because sessids are UUIDv7.

The pure function is sound. The convergence bugs come from what each side feeds it: a local *current* state against a peer's state *as of burst time* (S), and from the rules around it (rename, BS A, BS X).

## Findings

Severity is about the user-visible effect. **Confirmed** means TLC produced the
trace and the path was then re-read in the C. **Plausible** means the path is in
the C but needs a timing window.

### Confirmed

**A. Held ghost beats a live login at N-time; the live user is KILLed (High).**
Trace (2 servers): during a split, c1's connection to S1 drops and becomes a held ghost with the older TS. S2 had dropped its clientless replica at SQUIT (BS:5339-5356). c2 logs in on S2 and gets a new sessid. On heal both bursts send `N` before `BS C` (SV:423-431, then SV:529).
- **S2** sees N(c1). Hold state is not on the wire (NK:324-327 comment), so D.2 (NK:570-640) demotes the live c2 under the *ghost* c1 and broadcasts BX C.
- **S1** sees N(c2). Rebind is refused because origin ≠ S2 and sessid ≠ (BS:6327-6357). D.2 is skipped for a local hold (NK:571). Classic collision applies with `differ` forced to 1 (NK:820-840), the older TS wins, and S1 sends `KILL c2` (NK:857, 890). c2's connection dies.
- **S1**'s later BS C state-first retire (BS:4394-4410) kills its own held session (`BS X`) and builds an ACTIVE replica of S2's session, whose primary was just killed.

Net result: both connections are gone and every server keeps an ACTIVE session with no primary. That zombie then feeds K and R.
Fix: carry hold state on the wire (an N umode or `,S` flag, or send `BS C` before `N`). The ghost's home should retire its held session and accept a live same-id N. D.2 must never demote under an announced-held N.

**B. Cross-sessid rename leaves two live primaries (Medium).** Two sessions are live on either side with different nicks, so D.2 never fires. The rename side (BS:4419-4455) then takes the peer's `BS A`, which installs the peer's primary as `hs_client` (BS:4605). The local live primary becomes a stray: it is neither primary nor alias, and on quit it is not held. `bounce_post_burst_reconcile` skips the session because `hs_client` is not `MyConnect` (BS:1812-1814). The peer still sees the stray's pre-rename `cli_session_id`, which is only set at introduction (list.c:276-281), so it finds no candidate either. Same-sid held/held with different nicks leaves an orphan ghost the same way.
Fix: BS A must not displace a live local primary. On rename, re-announce the members' sessid, or reconcile by account plus token.

**C. Demotion strands sibling aliases (Medium).** `bounce_finish_live_primary_demote` repoints only the demoted client (BS:6579-6584), and so does BX C convert-in-place (BS:8920-8970). The loser's other aliases keep `alias_primary` = an alias (invariant -7). Their burst `BX C` named a primary the winner refused, so it is only forwarded (BS:8895-8899), and the winning side never learns those aliases.
Fix: repoint the siblings and re-emit BX C with the new primary.

**D. A hub runs D.2 against a remote primary (Medium).** There is no `MyConnect(acptr)` check (NK:570-588, BS:6472-6564). The alias entry and BX C numeric are built with `cli_yxx(&me)` (BS:6551-6552, 6634-6635), so the hub fabricates a numeric, files a bogus roster entry with `ba_server = hub` (which makes `session_has_local_holder` true), and sends legacy peers a QUIT for a client it does not own. The equal-TS tie-break also uses the hub's prefix (NK:606-612).
Fix: run D.2 only on the primary's home. The hub installs the winner and waits for the home's BX C.

**E. Burst `BS A` for a relayed session resolves to nothing on the leaf (High, 3+ servers).** `bounce_burst` sends only the primary's XXX, from `&me` (BS:3945-3952). The receiver prefixes the sender's YY (BS:4587-4591), so for any session whose primary is behind the hub, the new leaf's replica gets `hs_client = NULL`. Nothing repairs it: `kcid=`, `cc=` and `ta=` require `hs_client == who` (BS:9652-9690), and `hs_origin` is the hub. Consequences:
- a login on the leaf takes the orphan-reclaim path (BS:1486-1497) and becomes a second primary;
- the replica stays without an id (enables K);
- D.2 is skipped there (NK:587), so collisions fall to classic KILL.

Fix: send the full YYXXX, as `kcid=` already does (BS:3959).

**G. Same session held on both sides: mutual rebind erases both ghosts (High).** This needs a primary held on one side and the SQUIT-promoted alias held on the other. Each side's sessid-authorized rebind (BS:6327-6357) "rebinds" its ghost to the other side's ghost. Each one silently drops its own numeric (BS:6383), cancels the hold timer (BS:6379) and deletes the DB record (BS:6457). The result is an ACTIVE session with cross-referenced phantom primaries and no expiry.
Fix: never rebind to a held N. For ghost vs ghost, the older ghost stays and the younger one exits silently.

**I. Rebind is not propagated (Medium, 3+ servers).** The rebind returns 0 (NK:527-537) with no BX X/Q for the ghost numeric and no forwarding of the N. Servers beyond the rebinder keep a phantom ghost and never learn the new primary.

**K. Invariant 16: sessions of two Keycloak ids merged by rename (Medium; deterministic, 2 servers).** The BS C id gate looks for the peer session's primary (BS:4374-4385 via BS:1182-1196). With the same nick, the D.2 id-skip (NK:576-586) falls to classic collision, so the younger id's primary is refused on one side. On that side the gate finds nothing and the rename (BS:4419-4429) files the other id's session under this sessid. The opposite side does find the primary and keeps them apart, so the gate is asymmetric.
Fix: put `hs_kc_id` on BS C and gate on it.

**M. Netsplit cleanup keyed on `hs_origin` (Medium).** `bounce_prepare_squit_promotions` matches only the directly squitted server (BS:5296). `hs_origin` is the BS C *sender*: a hub, for bursted replicas. It is not updated when `hs_client` moves via BS A (BS:4605). After a multi-hop split, the replica stays ACTIVE with `hs_client = NULL` (MI:683-684), is never destroyed, and its local aliases are never promoted. A later login reclaims it as a second primary. Conversely, a stale origin can make a survivor promote an alias over a live primary on its own side; the BX P then exits that live primary.
Fix: decide by the servers of `hs_client` and the aliases, across everything `exit_downlinks` removes.

**S′. `BS X <sessid>` after a rename destroys the surviving session (High, deterministic with 3 servers).** In a held-vs-held heal through a hub, the hub and the far server rename to the winning sessid. The classic collision then KILLs the younger ghost, which runs `bounce_kill_session` (BS:2184-2215, MI:643-664) and broadcasts `BS X` with the *renamed* id. The winner's session is destroyed everywhere and its ghost is orphaned, holding the nick. A token-keyed `BS X` (model patch `X`) is not enough on its own, because merged records keep different tokens. Retiring one member must not destroy a merged session.

### Plausible (narrow timing windows; path confirmed in C, trace found by TLC in racy mode)

- **S.** A hold during the burst window makes the BS C state rule retire a session on a stale "active" claim (BS:4394-4410). The `BS X` then hits the peer's renamed copy.
- **R.** Orphan reclaim (BS:1486-1497) lacks the `bounce_peer_has_inbound_data()` deferral of the create path (BS:1545-1552). A login between a peer's `BS C` and its `N` becomes a second primary. `BS D` / `BS A` (BS:4692-4717, 4605) then overwrite the other side's live primary.
- **N.** A hub that is mid-burst on one link gets an `N` from another link before the session's `BS C`. With no session record, D.2 is skipped and classic collision KILLs the younger live user.
- **H.** `bounce_burst` sends alias `BX C` only for ACTIVE sessions (BS:3975). A HOLDING session that has a remote alias waiting for its deferred promote (m_quit.c:146-158) loses that alias for a server linking in that tick.
- **J (low).** A bare replica keeps HOLDING after a same-token "active" burst: the token branch acts only for local holders (BS:4268-4337), and burst `BS A` keeps state (BS:4646).
