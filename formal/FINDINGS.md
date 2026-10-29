# Verification findings ledger

State as of 2026-10-29. Every finding below was found by a tool and then
confirmed independently (a live reproduction, an ASan harness, or an
adversarial code review) before any fix. PR numbers refer to
rdrake/nefarious2, base `ircv3.2-upgrade`. "Upstream" means
evilnet/nefarious2 `master`.

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

## Fuzzing campaigns (in progress)

Each campaign runs in its own cloud session and pushes harnesses, corpora
and `FINDINGS.md` to its branch:

- **`fuzz/client-protocol`:** 3 bugs so far.
  - Oper `/TRACE` with a held ghost reads `link_u[-1]` (stack overflow).
  - `BOUNCER ORESET` on the oper's own account is a use-after-free.
  - `MARKREAD` with a byte ≥ 0x80 reads past the `sm_hash` `ToLower` table.
- **`fuzz/p10-server`:** `base64toip` heap overflow, plus more being minimized.
- **`fuzz/parsers`:** 8+ logged.
- **`fuzz/config-records`:** in progress.

None of these have been independently validated or fixed yet.

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
