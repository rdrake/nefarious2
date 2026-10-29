# Verification findings ledger

State as of 2026-10-29. Every finding below was found by a tool and then
confirmed independently (a live reproduction, an ASan harness, or an
adversarial code review) before any fix. PR numbers refer to
rdrake/nefarious2, base `ircv3.2-upgrade`. "Upstream" means
evilnet/nefarious2 `master`.

## Hand-off: how to resume

Written 2026-10-29 at wrap-up, when cloud credits ran out. Everything a new
session needs is on GitHub (rdrake/nefarious2); nothing lives only in the old
container.

### Next steps, in priority order

1. **C1: pre-auth WebSocket handshake hang** (CBMC section below). Fix, add a cmocka case, validate live, open a PR. It's a small fix with the highest impact.
2. **Fuzz findings, highest severity first.** Read each `fuzz/*` branch's `FINDINGS.md` (table below). Start with:
   - config F10: v8 bouncer records are dropped at boot, i.e. data loss on upgrade;
   - p10's `base64toip` heap overflow;
   - client `BOUNCER ORESET` use-after-free and the `/TRACE` stack overflow;
   - parsers F25 (DNS);
   - config F7 (crule frees an uninitialised pointer) and F3 (DNSBL infinite loop).
3. **CBMC C2–C7.**
4. **Bouncer F3/F4/F5/F7/F9 and the cross-server proposals.** Both are blocked on the maintainer's decisions (bottom of this file; also `PROTOCOL-PROPOSALS.md`).
5. **The stateful fuzzing plan** (`STATEFUL-FUZZ-PLAN.md`), as time allows.

### Process this work followed (keep it)

- **Validate independently before fixing.** Reproduce on a sanitizer build, live where possible, or with an ASan harness linking the real object. Try to refute the claim, not just confirm it. A tool's report alone is not enough.
- **Check upstream.** For each finding, record whether evilnet/nefarious2 `master` also has it. Fixes for upstream ones are candidates to send upstream later. The GitHub API isn't available for evilnet from these sessions; use `git ls-remote` / `git fetch` of `refs/heads/master` and `refs/pull/*/head` instead.
- **One logical PR per fix.** Branch `fix/<topic>` from `ircv3.2-upgrade` and open the PR against `ircv3.2-upgrade`. Never push to `ircv3.2-upgrade` itself. Each PR states the before/after evidence and the upstream status.
- **Commit messages:** explain the bug path and the evidence. No model names.

### Rebuilding the test environment (Ubuntu container)

- **Dependencies:**
  ```
  apt-get install -y librocksdb-dev libzstd-dev libcmocka-dev libcurl4-openssl-dev libjansson-dev libssl-dev libgit2-dev libmaxminddb-dev libgeoip-dev flex bison autoconf automake cppcheck cbmc libclang-rt-18-dev
  pip install z3-solver
  ```
  For TLA+, download `tla2tools.jar` (v1.8.0).
- **Sanitizer build:** `git archive <branch> | tar -x -C <dir>`, then `autoreconf -fi`, then configure with `CC=gcc CFLAGS="-g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer" LDFLAGS="-fsanitize=address,undefined"` and `--enable-debug --with-maxcon=4096 --with-rocksdb=/usr --with-zstd=/usr --enable-keycloak`.
  - The cmocka suite needs `make -C ircd/test LDFLAGS="-fsanitize=address,undefined" test-cmocka`.
- **Running ircd as root:** it refuses unless faked. Use `formal/repro/common/fakeuid.c` as an LD_PRELOAD shim, with gcc's libasan first: `LD_PRELOAD="$(gcc -print-file-name=libasan.so) fakeuid.so"`.
- **Harnesses:** `formal/repro/README.md` lists one per finding.

### Pitfalls already hit

- **clang `-fsanitize=function`** aborts on the first CAP until PR #3 merges. Use gcc, or `-fno-sanitize=function`.
- **TLC `states/` directories** are huge. `formal/.gitignore` excludes them, so keep it when committing under `formal/`.
- **Force-pushes are blocked** by the session's safety classifier. Fix mistakes with a follow-up commit or in the PR text. For example, PR #1's commit message says `HLC_MAX_FORWARD_MS` defaults to 0, but the default is 60000; the PR body corrects it.
- **Test client timing** (`formal/repro/bouncer-live`) is occasionally flaky. Re-run a surprising result before believing it.

## Fixed in open PRs

| PR | Finding | Severity / trigger | Found by | Confirmed by | Upstream |
|---|---|---|---|---|---|
| #1 | HLC logical counter wraps at 65535 with the same `physical_ms`, so stamps go backwards and msgids duplicate (65536 ≡ 0 mod 4096) | Medium; busy network while the clock is pinned (peer ahead ≤ `HLC_MAX_FORWARD_MS`, default 60 s, or an NTP step back) | CBMC (`cbmc/crdt_hlc`) | Repro: 134,464 duplicates per 200k msgids before, 0 after | No (fork-only) |
| #2 | `cmd == CMD_PRIVATE` is a comma expression, so it is always true; the user's own JOIN/PART/NICK echo carries a different msgid from history; `complete_redact_fed` leaves the client msgid armed | Low–Medium; every labeled JOIN/NICK and +D JOIN/PART | clang `-Wstring-compare` | Live two-client test | No |
| #3 | `m_cap.c` qsort/bsearch comparators are called through an incompatible function type (UB); clang UBSan aborts on the first CAP | Low (UB); blocks sanitizer testing | UBSan at runtime | Live CAP test | **Yes** |
| #4 | Test-only: `kc_jwt_cmocka` one-byte heap overflow; `ircd_crypt_cmocka` leak | Tests | ASan on cmocka | All 40 suites clean | n/a |
| #5 | `geoip_continent_name_by_code` reads one past the table for an unknown code; "AN" (Antarctica) is missing | Medium; legacy GeoIP "AN", P10 `MARK … GEOIP` from any server, IAuth | cppcheck | ASan using the real `ircd_geoip.o` | **Yes** |
| #6 | `@batch=r PRIVMSG #c` with no text: `strcpy(…, NULL)` crashes the server | **High; any registered client** | Clang Static Analyzer | Live crash, then fixed | No |
| #7 | `parse_server` treats `000` as numeric 0 with `mptr == NULL` and crashes; crule arg overflow; IAuth `strtol(NULL)`; IAuth `eol[-1]` | **High (000): any linked server**; Low for the rest | Clang Static Analyzer | Live fake-P10 link; ASan harnesses | **Yes** |
| #8 | A rehash during an outbound server handshake frees the Connect block, then `attach_conf` uses it | Medium; oper/SIGHUP/gitsync rehash racing a handshake | Clang Static Analyzer | Live: autoconnect, stall, SIGHUP | **Yes** |
| #9 | Bouncer F2 (`BOUNCER RESUME` frees the session, then writes it); F1 (+Z plaintext login cancels the hold timer); F6 (failed revive leaves the session ACTIVE) | High (F2, oper); Medium (F1, any user); Low (F6) | TLA+ (`tla/bouncer_local`) | Live ASan with a fake services server; F6 by fault injection | No |
| #10 | A refused resume registers the login under the ghost's nick (two clients with the same nick) | Medium; any user (plaintext login, +Z ghost) | Live reproduction of F1 | Live | No |

## Confirmed, not yet fixed

### Single-server bouncer: waiting on a design decision

These share one root cause: the session record is destroyed while its
clients remain. All are fork-only.

| ID | Finding | Status |
|---|---|---|
| F3 | `SET HOLD off`, `PERSISTENCE SET OFF`, `DETACH` and `MODE -b` destroy only the record; the ghost holds its nick forever | Confirmed (code review) |
| F4 | Primary quits with hold off while aliases exist; promotion is skipped, the session is left ACTIVE with no primary, and a duplicate nick is possible | Confirmed |
| F5 | Hold expiry when every roster alias is stale leaves a zombie record that blocks session creation | Confirmed |
| F7 | `BOUNCER DISCONNECT` leaves a held ghost | Confirmed (oper, own account) |
| F9 | A per-client deauth can strand another ghost | Plausible; depends on X3 `AC U` behaviour |
| F8 | `/KILL` of an alias | **Refuted**: `/KILL nick` resolves to the primary |

**Proposed fix:** one teardown helper used by every teardown path (in the
proposals doc).
**Decision needed:** when `SET HOLD off` or `DETACH` is run from an alias,
promote that alias first, or refuse the command?

### Cross-server bouncer protocol (`tla/bouncer_converge`)

All are confirmed by adversarial code review, and all are fork-only.

- **High:** A, E, G, S′.
- **Medium:** B, C, D, I, K, M.
- **Plausible:** S, R, N, H, J.

The fixes are in the proposals doc. Two need wire changes:
- **P1:** server flag `H` and a `,H` segment on `N`.
- **P3:** a new `BS K` subtoken.

**Decision needed:** approve the wire changes.

### Other

| Finding | Severity | Upstream | Notes |
|---|---|---|---|
| Adaptive hold grows during decay when `BOUNCER_MAX_HOLD < BOUNCER_SESSION_HOLD` | Low (misconfig) | No | Z3 counterexample (`z3/bouncer_hold_int.py`); fix: floor at min(base, earned) |
| DNS AAAA/A answers copied without checking `rd_length` against the datagram end (`ircd_res.c` `proc_answer`) | Low–Medium (resolver or spoofed reply) | Yes | Code reading; handed to the parsers fuzz campaign to confirm |
| `s_bsd.c` server read loop: `dolen <= 0` returns before the `dolen == 0` over-long-line branch, so that branch is dead | Info | Yes (ircu) | GCC `-Wduplicated-cond` |

## CBMC pure-module findings (`formal/cbmc/`, `run_pure_modules.sh`)

Each finding below was found by CBMC (unless the row says otherwise) and
confirmed by replaying the counterexample against the real source under
gcc ASan+UBSan (`confirm*.c` in each module directory). None has been
fixed or independently re-validated yet.

| # | Severity | Finding | Location | Who can trigger it | Suggested fix |
|---|---|---|---|---|---|
| C1 | **Critical** | **Pre-auth infinite loop:** a `Sec-WebSocket-Protocol` header with no supported token (e.g. `chat`, or empty) never advances the scan pointer, so the single-threaded ircd hangs | `websocket.c:188-207` `parse_ws_handshake`, reached from `websocket_handshake` (`:374`) | Anyone who can connect to a WebSocket or auto-detect listener, before registration; added in 069c0d8 | Bound the scan by the line end and always advance `p`; add a cmocka case |
| C2 | Medium | **Keyed webpush subscriptions never expire.** `webpush_armed_at` takes everything after the 3rd `\|`; a real record has an 87-character key there, so the field is ≥24 bytes and the function returns 0. Bursts send armed=0, which receivers re-stamp as now | `webpush_expiry.c:34-35`; `m_webpush.c:300,1240,1906` | Every keyed subscription | Read only to the next `\|` (`strcspn`) |
| C3 | Medium-low | **Per-IP REGISTER limit bypass.** IPv6 /64s that land in the same bucket (plain XOR hash) evict each other (LRU), so 100 of 100 attempts pass in 100 s; only the global cap applies | `register_throttle.c` | Anyone with a /56 | Refuse when the bucket is full, or use a keyed hash |
| C4 | Low-medium | **Presence cap drops a newer window** when the record is full and the new window starts earliest, even if it ends latest; a member present the whole time can become invisible. Fails safe (history hidden, not leaked) | `chathistory_presence.c:650-651` | Linked-server PN timing | Drop the oldest window, as the header says |
| C5 | Low | **PN accepts non-positive or overflowing stamps:** `-1` or ≥2^63 store the window `[-1, now]`; 2^47–1e15 overflow the shift (UB) | `m_markread.c:469-471`, `chathistory_presence.c:336` | A linked server only | After normalising, require `0 < start <= end` |
| C6 | Low | **Signed overflows from peer input:** `armed+max_age` (`webpush_expiry.c:56`), `last_msg+idle` (`webpush_attention.c:18`), `end+coalesce` (`chathistory_presence.c:637,672`). Also: `webpush_armed_at` can return negatives; mute `until` ≥2^63 or `": -5"` is misread; `webpush_mute_prune` reports "unchanged" after pruning; a clock step back pins the REGISTER window | various | Peer input; the user's own metadata | Saturating arithmetic and range checks |
| C7 | Low | **WebSocket fragments** (found by reading `s_bsd.c`, not by CBMC): fragmented messages skip `recv_classify`, so a 16 KB line gets past the per-class caps; `frag_data[16384]='\0'` writes one byte past `con_ws_frag_buf` (benign only by layout) | `s_bsd.c:1445-1470`, `client.h:510` | WebSocket clients | Classify reassembled lines; size the buffer +1 |
| C8 | Info | Fragmented control frames are accepted (RFC 6455 §5.5 forbids them); `account_id_from_uuid` accepts hyphens in any position | `websocket.c`, `account_id.c` | n/a | Optional |

**Verified clean, within the stated bounds:**
- webpush mute, expiry and attention contracts and monotonicity;
- register_throttle memory safety, and its per-IP and global caps for a single client;
- account_id contract, and the exact UUID round trip;
- recv_classify against a reference model, regardless of where the input is split;
- exit_reason;
- chathistory_presence union safety, idempotence and order-independence;
- WebSocket `decode_frame`/`encode_frame` memory safety.

dbuf exhausted CBMC's memory; it was instead checked bounded-exhaustively under ASan (23.7M cases, 0 mismatches).

## Fuzzing campaigns

Each campaign pushes harnesses, scripts, minimized reproducer files, a corpus
and a `FINDINGS.md` to its own branch. Counts as of 18:46 UTC:

| Branch | Findings file | Entries |
| --- | --- | --- |
| `fuzz/client-protocol` | `fuzz/client/FINDINGS.md` | 6 |
| `fuzz/p10-server` | `fuzz/p10/FINDINGS.md` | 13 |
| `fuzz/parsers` | `fuzz/parsers/FINDINGS.md`; reproducers and `reproduce.sh` in `fuzz/parsers/findings/` | 28 |
| `fuzz/config-records` | `fuzz/config/FINDINGS.md`; reproducers in `fuzz/config/repro/` | 14 |

**Highlights reported by the campaigns (not yet independently validated here):**
- **client:** `/TRACE` with a held ghost reads `link_u[-1]`; `BOUNCER ORESET` on your own account is a use-after-free; `MARKREAD` with a high byte reads past the `ToLower` table.
- **p10:** a heap overflow in `base64toip`.
- **parsers:** F25, the DNS A/AAAA data is copied without checking `rd_length` (`ircd_res.c:711` and `:719`), which confirms the suspicion above.
- **config/records:**
    - F10, the frozen v8 bouncer record layout uses the live `BOUNCER_MAX_ALIASES`, so v8 sessions are dropped at boot;
    - F7, `crule_parse` frees an uninitialised pointer;
    - F3, a DNSBL infinite loop.

**Next step for each finding:** validate it independently, check whether upstream has it, then open a fix PR. Same process as the PRs above.

## Verified clean

- **CBMC:**
  - `bounce_converge_peer_wins` is antisymmetric, so both sides always agree and live beats held;
  - the rebind auth and Keycloak-id join gate (invariant 16);
  - the deauth locality rules (B-2);
  - the BX U field map is a bijection;
  - `hlc_compare` is a strict total order.
- **Z3:** the adaptive hold is monotone, bounded and timer-correct when `MAX_HOLD >= SESSION_HOLD`.
- **TLA+:** with the bug triggers off, all safety and liveness properties hold within the bounds (`tla/*/README.md`).
- **Sanitizers:** all 40 cmocka suites pass under ASan+UBSan (with #4).

## Decisions waiting on the maintainer

1. Approve wire changes P1 and P3.
2. Confirm the letters `H` (server flag) and `K` (BS subtoken) are free.
3. P1 rule: does "live beats held" require the Keycloak ids to match exactly?
4. `SET HOLD off` / `DETACH` from an alias: promote it or refuse?
5. Does X3 send `AC U` per client on logout? This decides F9.

## Where everything is

| Item | Location |
|---|---|
| Models | `formal/` on branch `formal/verification-models` (`cbmc/`, `tla/`, `z3/`), each with run scripts |
| Live reproductions | `formal/repro/` |
| Protocol proposals | `formal/PROTOCOL-PROPOSALS.md`; an editable copy is the Claude doc "Bouncer P10 protocol change proposals" |
| Fix branches | `fix/*`, one per PR |
| Stateful fuzzing plan | `formal/STATEFUL-FUZZ-PLAN.md`; an editable copy is the Claude doc "Stateful fuzz harness plan" |
