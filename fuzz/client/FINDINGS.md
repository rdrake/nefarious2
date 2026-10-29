# Client-protocol fuzzing — findings

Target: Nefarious IRCd (`ircv3.2-upgrade` fork), the **client** protocol — the
untrusted client→server input surface. Harness, build and run instructions are
in `README.md`; this file lists confirmed issues plus the campaign statistics.

Status legend: **CONFIRMED** = reproduced in a plain ASan build (no libFuzzer,
no fuzz-only freelist patch); **KNOWN/EXCLUDED** = a sanitizer report that is a
harness/toolchain artifact or already triaged elsewhere, not a server bug.

---

## F-1 — Stack-buffer-overflow in `do_trace()` when a bouncer session is held  (CONFIRMED)

* **Severity:** Medium (oper-triggered out-of-bounds stack write / memory
  corruption; the triggering state is created by any unprivileged user).
* **Where:** `ircd/m_trace.c:186` (and the symmetric `:188`), in `do_trace()`:
  ```c
  if (doall) {
    for (acptr = GlobalClientList; acptr; acptr = cli_next(acptr)) {
      if (IsUser(acptr))
        link_u[cli_fd(cli_from(acptr))]++;      /* <-- line 186 */
      else if (IsServer(acptr))
        link_s[cli_fd(cli_from(acptr))]++;      /* <-- line 188 */
    }
  }
  ```
  `link_u` / `link_s` are `int[MAXCONNECTIONS]` stack arrays.

* **Root cause.** A bouncer session that goes into **HOLD** keeps its ghost
  `Client` in `GlobalClientList` as a fully-registered user (`STAT_USER`,
  `IsUser()` true) while its connection is gone. `bounce_hold_client()`
  (`ircd/bouncer_session.c`) calls `close_connection()` (`ircd/s_bsd.c`), which
  sets `cli_fd(cptr) = -1` and clears the `LocalClientArray` slot, but the
  ghost is deliberately **left in `GlobalClientList`** (it stays N-visible to
  peers for the hold window, default `BOUNCER_SESSION_HOLD` = 4 h).

  `do_trace()`'s `doall` accounting walk assumes every `IsUser` entry has a
  valid forwarding fd: it indexes `link_u[cli_fd(cli_from(acptr))]`. For a held
  ghost `cli_from(ghost) == ghost` and `cli_fd(ghost) == -1`, so the code
  evaluates `link_u[-1]++` — a write one `int` before the array. Nothing in the
  loop guards `cli_fd(...) < 0` (or `>= MAXCONNECTIONS`).

* **Reachability (real client/server, not a harness artifact).**
  1. Any user connects on a bouncer-enabled connection class and disconnects
     (or the session is otherwise put in HOLD). This is normal, unprivileged
     behaviour — `BOUNCER_ENABLE`/`CRFLAG_BOUNCER` and a client that attaches a
     session is all it takes; the ghost then lives in `GlobalClientList` for
     hours.
  2. An **IRC operator** runs `/TRACE` (or `/TRACE <wildcard>` — any form that
     makes `doall`/`wilds` true). Opers reach `do_trace()` unconditionally via
     `mo_trace()`. Regular users are gated out by `FEAT_HIS_TRACE` (default
     TRUE, confirmed at `ircd/ircd_features.c:1054`); with `HIS_TRACE` FALSE a
     plain user triggers it too, and a server can reach it via `ms_trace()`.
  3. The walk hits the held ghost and writes `link_u[-1]`.

  The harness state (a held ghost sitting in `GlobalClientList`) is exactly the
  server's own documented hold behaviour — not something only the harness can
  construct. The only harness-specific detail is *how* the ghost is created
  (socketpair drop); a real TCP drop reaches the identical `bounce_hold_client`
  → `close_connection` path.

* **Reproducer.** Two inputs in one process (`fuzz/client/crashes/01-trace-held-ghost/`):
  input 1 establishes and holds a session, input 2 is an oper `TRACE`.
  * `01_hold.bin`  base64 `B1FVSVQgOmhvbGQK`  — mode `0x07` (register+SASL as
    `fuzzacct`), line `QUIT :hold`.
  * `02_trace.bin` base64 `F1RSQUNFCg==`      — mode `0x17` (register+SASL+OPER),
    line `TRACE`.
  Run (the sweep that normally clears held ghosts between inputs is disabled so
  the ghost survives into the second input, mirroring a long-lived server hold):
  ```
  ASAN_OPTIONS=detect_leaks=0 FUZZ_CLIENT_NOSWEEP=1 FUZZ_CLIENT_TMP=$PWD/tmp \
    out/fuzz_client_plain crashes/01-trace-held-ghost/01_hold.bin \
                          crashes/01-trace-held-ghost/02_trace.bin
  ```

* **Confirmed outside the fuzz config.** The **plain ASan build**
  (`out/fuzz_client_plain`, no libFuzzer instrumentation, no freelist patch)
  reports:
  ```
  ==ERROR: AddressSanitizer: stack-buffer-overflow ... in do_trace
    #0 do_trace ircd/m_trace.c
    #1 mo_trace ircd/m_trace.c:341
  ```
  The UBSan build reports `m_trace.c:186:9: runtime error: index -1 out of
  bounds for type 'int[4096]'`. So it is a genuine out-of-bounds stack access,
  not a freelist/UBSan-only artifact. (Whether the write lands in a redzone or
  silently corrupts the adjacent `link_s`/frame slot depends on stack layout;
  ASan places a redzone there and traps.)

* **Suggested fix.** Skip fd-less entries in the accounting walk — a held ghost
  (and any `cli_from` with `cli_fd < 0`) is not a direct local link and must not
  be counted:
  ```c
  if (doall) {
    for (acptr = GlobalClientList; acptr; acptr = cli_next(acptr)) {
      int fd = cli_fd(cli_from(acptr));
      if (fd < 0 || fd >= MAXCONNECTIONS)
        continue;                     /* held bouncer ghost, no direct link */
      if (IsUser(acptr))      link_u[fd]++;
      else if (IsServer(acptr)) link_s[fd]++;
    }
  }
  ```
  (A held ghost has no local socket, so excluding it from the direct-connection
  tally is also semantically correct.)

---

## Known / excluded (not server bugs)

### K-1 — `-fsanitize=function` abort in `ircd/m_cap.c` (toolchain/UB-cast, excluded)
`capab_sort` / `capab_search` / `subcmd_search` are passed to `qsort`/`bsearch`
through a `(bqcmp)` function-pointer cast (around `ircd/m_cap.c:479,498,872`).
Clang's `-fsanitize=function` (part of `-fsanitize=undefined`) flags the
indirect call through an incompatible function-pointer type on the first `CAP`
command (and possibly at init). This is a pre-existing, already-triaged issue
with a fix in progress on a separate branch (confirmed by the parent session).
It is **not** a memory-safety or logic bug in the client path, and the
function-type check would mask real findings, so every build here is compiled
with `-fno-sanitize=function` (see `build.sh`). Listed for completeness only.

### Harness-level allocations (not leaks in the server)
* RocksDB's `rocksdb_list_column_families` leaks a few bytes once per store at
  `DB::Open` (3 allocations, ~3 B total) — a one-time init cost in the
  RocksDB C API, not per-command; suppressed via `lsan.supp`. Not a
  per-command/unbounded (DoS) leak.
* Fuzzing runs with `detect_leaks=0`: the harness intentionally lets a few
  per-run objects (e.g. the `make_client` `Connection` of a client it exits
  through the ghost-hold path) be reclaimed by process teardown rather than
  chasing them each iteration. No per-command unbounded growth was observed
  (RSS held flat across millions of execs).

---

## Campaign statistics

<!-- Filled in from the final run; see work/campaign.log and coverage below. -->
* Fuzzer: libFuzzer + ASan + UBSan (`-fno-sanitize-recover=undefined`,
  `-fno-sanitize=function`), `-fork=$(nproc)` (4 cores), `-max_len=8192`,
  dictionary `client.dict`, seeds from `gen_seeds.py` + committed `corpus/`.
* See the "Coverage" section at the bottom for edges covered and the handlers
  that remained uncovered.
