# Stateful fuzz harness plan

2026-10-29. Repo copy of the Claude doc "Stateful fuzz harness plan".

The plan: build each interesting server state once, then fork a copy for
every input. Setup and teardown drop out of the per-input cost, and the
fuzzer starts deep in the bouncer, chathistory and batch code instead of at
registration.

## Goal and how we'll measure it

The goal is more useful executions per CPU-second, measured as coverage of
the deep handlers, not raw speed. Today's campaigns did not record execs/s,
so the first step is a baseline.

| Metric | Baseline (capture in phase 0) | Target |
| --- | --- | --- |
| Execs/s per core, client harness | Unknown | 10× baseline |
| Wall time per input spent in setup + teardown | Unknown (estimate: most of it) | Under 10% |
| Edges after 1 h on 4 cores | ~25,400 at 15 min, then plateau | Keeps rising past 1 h |
| Line coverage of bouncer_session.c, m_chathistory.c, m_batch.c, m_metadata.c | Unknown | Reported per file; each up by a measured margin |
| Fork mode / freelist patch needed | Yes | No |

The targets are hypotheses to check against the phase 0 numbers.

## Where the time goes today

In `fuzz/client/fuzz_client.c` (branch `fuzz/client-protocol`), every input:

1. **Replays a prelude.**
   - Client B (when the mode byte asks for it) connects over a socketpair and runs `CAP LS`, a full `CAP REQ`, SASL PLAIN, `NICK`, `USER`, `CAP END` and `JOIN #fuzz`.
   - Client A does the same, optionally plus `OPER` and `JOIN`.
   - That's about 15–20 parsed commands, each with replies, through the real event loop.
2. **Runs the mutated lines.** Only this step is what the fuzzer is exploring.
3. **Tears everything down.**
   - `fz_kill_sessions` twice, `exit_client` on both clients, and `fz_sweep_clients` over `GlobalClientList`.
   - `fz_pump(4)` so held sessions, deferred destroys and timers settle.
4. **Writes to real on-disk RocksDB**, and any state the teardown misses leaks into the next input. That's why the campaign uses libFuzzer `-fork` mode and needs `freelist.patch`, which disables object reuse.

The mode byte also limits depth. A held bouncer session, an open multiline
batch or a populated history only exist if the mutated bytes happen to build
them first, which is rare.

## Core design: build once, fork per input

1. **Process start.** Run today's `LLVMFuzzerInitialize` work once: config, features, hashes, listener and history storage.
2. **State build.** `FUZZ_STATE=<name>` picks a builder from the state library. The builder drives the real code (socketpairs, the event loop, the fake services link) to that state, then pumps until the loop is quiet.
3. **Fork point.** Call AFL++'s deferred fork server (`__AFL_INIT()`). Everything above runs once per campaign.
4. **Per input, in the child.**
   - Decode the input into actions: lines from A, B or the linked server, clock advances, drops, reconnects.
   - Pump the loop, run the invariant oracles, and `_exit(0)`. Nothing needs tearing down.
5. **One AFL++ instance per state** (`-M`/`-S`), each with its own corpus. Instances are rotated across the cores, weighted toward states whose coverage is still growing.

Why AFL++ rather than libFuzzer for the whole-ircd harnesses: libFuzzer runs
every input in one process, so it needs the very teardown this design removes.
AFL++ forks each input from a snapshot and supports ASan and UBSan. The
standalone parser harnesses stay on libFuzzer.

`replay_main.c` builds the same state and replays one input without forking,
which is what the PR validation steps use.

## The state library

| State | Built by | Reaches |
| --- | --- | --- |
| `unreg` | One connected, unregistered socket | Registration, CAP, SASL, PASS/WEBIRC, websocket handshake |
| `user` | A registered with all caps; B registered in `#fuzz` | Messaging, modes, WHO/WHOIS, MONITOR, METADATA, TAGMSG, SETNAME |
| `oper` | `user` with A opered | TRACE, CHECK, KILL, REHASH paths, BOUNCER oper subcommands |
| `history` | `user` with about 200 stored messages, a redaction and read markers in `#fuzz` and a DM | CHATHISTORY selectors, REDACT, MARKREAD, event-playback replay |
| `batch-open` | `user` with a `draft/multiline` batch open on A | Multiline lines, concat, limits, batch end/abort |
| `bnc-active` | A with a bouncer session plus a second connection as an alias | Alias commands, session caps/away, BOUNCER subcommands, promote on quit |
| `bnc-held` | `bnc-active` after A's primary drops (held ghost, timer armed) | Revive, resume, attach, SET HOLD/DETACH, hold expiry via the clock |
| `bnc-plain-z` | `bnc-held` with the ghost in a +Z channel | TLS refusal paths (F1, the duplicate-nick bug) |
| `linked` | A fake P10 peer linked after its burst, with remote users, a remote bouncer session and channels | The P10 harness: N/BURST/BS/BX/MD/MR against real state |
| `mid-burst` | A fake peer linked with its burst unfinished | Burst-window races: convergence gates, D.2, BS C before N |

The builders port the fake services link and SASL logic from
`formal/repro/bouncer-live/h.py` to C.

## Prerequisites that make fork-per-input safe

A forked child copies the parent's memory, but not its other threads, and it
shares kernel objects (epoll sets, files) with the parent. Every change below
is fuzz-build-only, behind `#ifdef FUZZING` or a configure switch.

| Area | Problem under fork | Change for the fuzz build |
| --- | --- | --- |
| Event engine | An epoll set is shared after fork | Use `engine_poll.c`, which keeps its state in user memory |
| Storage | On-disk RocksDB is shared by every child, and its flush/compaction threads don't exist in the child | An in-memory backend behind the `db_*` abstraction |
| Worker threads | `thread_pool.c` (async crypt, OPER, SETHOST, WEBIRC) and the async log writer have no threads in the child, so their work never completes | Run pool jobs inline and log synchronously. The startup init threads (`ircd.c:1324–1340`) must finish before the fork point |
| Time | `CurrentTime` and the HLC read the wall clock | A virtual clock drives `hlc_wall_clock_ms` |
| Keycloak / webpush | Network calls | Keep today's `--wrap` stubs |
| Services (X3) | Accounts and logins | An in-process fake services peer (SASL relay, `AC R`) |
| DNS, ident, GeoIP | Network and file lookups | `NODNS`, `NOIDENT`, GeoIP off |

With these changes no state outlives a child, so `freelist.patch` can go.

## Structured inputs

**Encoding.** An input is a list of actions, 2–10 bytes each:
- **actor:** A, B, A's alias, the linked server, or the clock;
- **op:** an index into a command table generated from `msgtab` (client commands, P10 tokens, BS/BX subcommands), plus specials: drop, reconnect, advance-clock, raw bytes;
- **args:** typed slots (nick, channel, account, msgid, batch ref, timestamp, CAP name, mode string, free text). Each slot either picks from pools the state publishes, or holds literal bytes.

The decoder renders each action into a real line and sends it through the
same socket path as today.

**Mutator.** An AFL++ custom mutator (`afl_custom_fuzz`) works at the action level:
- insert, drop, duplicate, swap or splice whole actions;
- re-pick a slot from its pool;
- flip a slot between pool and literal;
- mutate a literal's bytes.

About 1 action in 20 stays fully raw, so line, tag and escape parsing keep
their coverage.

**Seeds.** Each state's seeds are its regression reproducers (the F-series, the
fuzz `crashes/` folders, the `formal/repro` scripts converted to actions) plus
a few normal sessions per command family.

## Invariant oracles

After each input the child runs cheap whole-state checks and calls `abort()`
on a violation, so logic bugs show up as crashes.

| Invariant | Would have caught |
| --- | --- |
| Every registered local client is the one `FindClient(cli_name)` returns | The duplicate nick in PR #10 |
| A HOLDING session has a held local ghost and an armed hold timer | F1, F5, F6 |
| An ACTIVE session's `hs_client` is live and points back to it; no freed session is reachable | F2, F4 |
| Every held ghost belongs to a session | F3, F7 |
| An alias's `alias_primary` is its session's primary, and the roster count matches | Convergence bug C |
| The `UserStats` opers/invisible counts equal a recount of the `FLAG_COUNTED_*` flags | Invariant 9 regressions |
| Channel membership is symmetric | General corruption |
| HLC stamps minted in one input strictly increase | PR #1 |

These are the same invariants the `formal/tla/bouncer_local` model checks.
Put them in `fuzz_invariants.c`, shared with `replay_main.c` and the cmocka
suites.

## Phases

Efforts are rough estimates in focused days. Each phase pays off on its own.

| Phase | Deliverable | Effort | Exit criterion |
| --- | --- | --- | --- |
| 0. Baseline | Execs/s, a per-input time split, and edges/coverage at 15 min and 1 h for the client and P10 harnesses | 0.5 | Numbers recorded in `fuzz/BASELINE.md` |
| 1. Fork-safe build | The `FUZZING` build: poll engine, in-memory db, inline thread pool, synchronous log, virtual HLC clock | 2–3 | cmocka and today's harness pass; `freelist.patch` dropped |
| 2. Fork server | An AFL++ deferred fork server around the `user` prelude; children `_exit`; replay updated | 1–2 | At least 5× baseline execs/s on the same corpus; replays reproduce |
| 3. Invariant oracles | `fuzz_invariants.c`, run per input and in replay | 1–2 | The F1, F2 and PR #10 reproducers trip it on the unfixed branch |
| 4. State library | All ten builders, a fake services peer in C, one instance per state | 3–4 | Every state is reached and stable; per-state coverage reported |
| 5. Structured inputs | Encoding, decoder, custom mutator, converted seeds | 3–5 | Coverage of the deep files beyond phase 4's plateau |
| 6. P10 port | The `linked` and `mid-burst` states drive the P10 harness | 2–3 | Burst and BS/BX handlers covered from real states |

Total: about 13–20 focused days. Phases 0–3 (about a week) capture most of
the speedup and add the oracles.

## Risks and open questions

- **Fork cost under ASan.** If it dominates in phase 2, run most instances with UBSan plus the oracles, and keep one ASan instance per state.
- **The fuzz build drifts from production.** Confirm every reproducer on a normal ASan build, and keep the `FUZZING` changes to `#ifdef` blocks in one or two files.
- **Storage bugs move out of view.** The in-memory backend won't find RocksDB encoding bugs, so the record decoders keep their own libFuzzer harnesses.
- **Oracle false alarms.** Some invariants only hold once the loop is quiet, so check after a final pump. For states caught mid-transition, check only the invariants that hold at every step.
- **State builders can rot.** Each builder asserts its end state and fails the campaign loudly if it doesn't reach it.
- **Open: AFL++ alone, or also LibAFL?** LibAFL's in-process snapshot restore may beat fork. Decide after phase 2's numbers.
- **Open: one box round-robin, or one cloud session per state group?** Decide after phase 4.
