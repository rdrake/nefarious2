# CBMC: ircd/register_throttle.c

Real module `#include`d unmodified; table geometry shrunk with the
module's own override macros (as the cmocka build does):
`SMALL` = 1 bucket x 2 slots; `harness_safety` also at 4 buckets x 4.
Module state is havoc'ed (arbitrary table contents) where noted. Run
`./run.sh`; logs in `logs/`; `confirm.c` reproduces at the production
geometry (64 x 4) with ASan/UBSan.

| Harness | Property | Bound | Result |
|---|---|---|---|
| `harness_safety` | memory safety + result range of `reg_throttle_check`/`reg_throttle_expire` from an arbitrary table, any address, any limits (incl. <= 0), any now in [0, 2^40] | 1 call, 4x4 table | VERIFIED |
| `harness_safety_any_time` | same with unrestricted `time_t now` | 1 call | **FAILS**: `now - e->last` (:102) and `now - reg_global_start` (:124) overflow for |now| ~ 2^63 -- harness-level only, not reachable with a real clock |
| `harness_refusal_records_nothing` | header: any refusal (IP or GLOBAL) leaves the entire state bit-identical | 1 call from arbitrary state | VERIFIED |
| `harness_per_ip_bound` | one address, fixed limit 1..3, period >= 1, non-decreasing times inside one period: <= limit OKs; `attempts` never exceeds limit; OK again exactly one period after the last counted attempt | 4 calls | VERIFIED |
| `harness_global_bound` | counter <= global_limit always; <= 2*global_limit OKs in any span < period (fixed window) | 5 calls | VERIFIED |
| `harness_per_ip_bound_with_neighbours` | per-IP bound under traffic from other addresses | 4 calls, 1x2 table | **FAILS** (LRU eviction) |
| `harness_global_clock_step_back` | global window reopens one period after a backward clock step | 2 calls | **FAILS** |

## Findings

1. **Per-IP limit fully bypassable by eviction (confirmed, medium-low).**
   With the production 64x4 table, 5 IPv6 /64s whose first 64 bits XOR
   to the same bucket (`reg_hash`, trivially chosen: vary the 4th
   16-bit word in steps of 64 -- any /56 holder has 256 /64s) rotate
   through REGISTER and **100 of 100** attempts pass in 100 s versus the
   intended 5 x 3. The header documents eviction as "merely grants that
   IP fresh budget", but the effect is that the per-IP limiter does not
   bound an attacker with DEPTH+1 prefixes at all; only
   FEAT_REGISTER_THROTTLE_GLOBAL (default 60/h) remains. Fix: on a full
   bucket refuse (or count against the evicted entry's /48), or use a
   keyed hash (siphash with a boot secret) so collisions cannot be chosen.
2. **Backward clock step pins the global window (confirmed, low).** After
   the clock steps back by D seconds, `now - reg_global_start >= period`
   stays false for D + period seconds, so REGISTER is refused server-wide
   (fail-closed). Fix: also reset when `now < reg_global_start`.

Verified clean otherwise: counters cannot underflow or exceed their
limits, no OOB at any geometry tried, refusals are side-effect free.
