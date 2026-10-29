# CBMC: interval core of ircd/chathistory_presence.c

## What is proved, and how the module is cut

The pure core is the file-static interval algebra on
`struct presence_record` (closed `[start,end]` windows, sorted, plus an
`open_since` marker): `record_union_close`, `record_apply_join/part`,
`record_was_present`, `record_next_visible`, `presence_norm_time`,
`effective_max_intervals`. Everything else (RocksDB, HLC, channels,
session hash, P10) is glue around it and is not reached.

The harness `#include`s the module, so the statics are called directly.
Stubs/models:
- `feature_int()` returns `CAP` (3), the per-record interval cap
  (`-DFEATURE_ANY` makes it arbitrary for `harness_cap_clamp`);
- `memmove` -> an element-wise model (every call site moves whole
  `struct presence_interval`s inside `r->intervals`; the precondition
  and readable/writable ranges are asserted);
- **one textual reduction**: `run.sh` writes
  `build/chathistory_presence_small.c` from the real file with
  `#define PRESENCE_MAX_INTERVALS 256` -> `8` (checked to occur exactly
  once). With CAP = 3 every count the code can reach is < 8, so all
  paths/comparisons are those of production; only the unused tail of
  the array disappears (the 4 KB record exhausted 6 GB in the SAT
  solver). The clamp that depends on the real 256 is proved on the
  unmodified file (`harness_cap_clamp`).

Time domain for the functional harnesses: stamps in [1, 2^62] (packed
HLC up to ~year 4200). `_any` harnesses lift that to expose wire input.
Well-formed record (`wf`): count <= cap, start <= end, sorted, and
consecutive windows separated by MORE than the 30 s coalesce gap.

| Harness | Property | Result |
|---|---|---|
| `harness_union_wf` | union keeps `wf` and never touches `open_since` (any wf record, any window incl. end < start) | VERIFIED |
| `harness_union_sound` | fail-safe: every instant visible afterwards was visible before, is in the new window, or is within 30 s of covered time (a coalesced gap) | VERIFIED |
| `harness_union_complete_below_cap` | with count < cap nothing previously visible and nothing in the new window is lost | VERIFIED |
| `harness_union_cap_drops_oldest` | at the cap only instants OLDER than every retained window may be lost ("drop-oldest FIFO") | **FAILS** (P3) |
| `harness_union_idempotent` | union(r,A) twice == once, structurally (r: wf, <= 2 windows) | VERIFIED |
| `harness_union_commutative` | A-then-B and B-then-A give the same visible set (r: wf, <= 1 window; runs with MiniSat in 9.5 GB -- CaDiCaL exceeded 6 GB) | VERIFIED |
| `harness_join_part` | join idempotent (first start kept), open interval visible from its start, part clears `open_since`, keeps `wf`, the closed visit `[join, max(join,part)]` stays visible | VERIFIED |
| `harness_next_visible` | `record_next_visible` is exact: t if visible; else the nearest visible instant after (forward) / before (reverse) t with nothing visible in between, or -1 | VERIFIED |
| `harness_cap_clamp` | for every configured value the cap is in [1,255] < 256 (the F-CH3 uint8 wrap cannot recur) | VERIFIED |
| `harness_norm_time_any` | `presence_norm_time` over all int64: no UB, positive in => positive out | **FAILS** (P2) |
| `harness_pn_ingest_any` | PN ingest exactly as m_markread.c:469-474 does it, with a sane end: cannot open visibility before 2020 | **FAILS** (P1, P2) |
| `harness_union_any_time` | union on arbitrary int64 data: memory safe | memory-safe; **`end + C` overflows** for end > INT64_MAX - 2^31 (lines 637, 672) |

Bounds: CAP = 3 (records of 0..3 windows, plus the new one), every loop
fully unwound (`--unwinding-assertions`).

## Findings (confirmed with `confirm.c`, real file, ASan+UBSan)

- **P1 PN accepts non-positive / wrapped stamps (confirmed; low).**
  m_markread.c:469-471 parses `start/end` with `strtoull`, casts to
  int64 and rejects only `== 0`. `PRESENCE <acct> <chan> -1 <now>` (or
  any value >= 2^63) yields start = -1 and `[-1, now]` is stored and
  relayed (m_markread.c:476): the account becomes "present" for the
  channel's entire history network-wide. Note the trust model: a linked
  server can already assert any well-formed window (e.g. start = 1 is
  normalised to 1 s after the epoch), so this is input validation at a
  trusted boundary, not a privilege escalation -- but a buggy peer that
  emits garbage silently disables strict presence for that account.
  Fix: after normalisation require `0 < start <= end <= now + skew`
  and drop otherwise (also in `presence_apply_close`).
- **P2 `presence_norm_time` shift overflow (confirmed UB).** For
  v in [2^47, 1e15) (~1.4e14..1e15, "milliseconds" past year 6429)
  `PRESENCE_TIME_FROM_MS(v)` (chathistory_presence.c:336) shifts out of
  range; with GCC it becomes negative, e.g. 200000000000000 ->
  -5339544073709551616, which then behaves like P1. Same for
  `presence_event_time` with an msgid whose HLC ms >= 2^47. Fix: treat
  values >= 2^47 in the ms band as invalid (return 0) and reject 0.
- **P3 cap eviction can drop a NEWER window, not the oldest (confirmed;
  low-medium, fail-safe direction).** `record_union_close` returns
  without inserting when the record is full and the new window starts
  before every retained one (`pos == 0`, line 650-651), even if it ends
  after them. That is exactly the shape `record_apply_part` produces
  when the open interval started before closed windows that arrived by
  PN from other servers. Concrete (cap 2): windows at +1h and +2h
  retained, member joined at t0 and parted at t0+2.5h -> after the part
  the member is NOT visible at t0+5000s, though present the whole time.
  The header promises "the oldest closed interval is dropped". Fix: when
  full and `pos == 0`, merge/swallow forward first (as the
  non-full path does) and then evict the oldest, or clip the new window
  to start after the oldest retained one.
- **`end + PRESENCE_COALESCE_TIME` overflow** (lines 637, 672) for
  ends near INT64_MAX: only reachable via P1/P2-style wire input; fixed
  by the same validation.

Verified clean: well-formedness preservation, soundness (no visibility
beyond the window plus 30 s coalescing), completeness below the cap,
join/part semantics, exactness of `record_next_visible` (which drives
the history walk's seek), and the cap clamp.
Not covered: retention sweep and burst sync loops (inline with DB
iteration), session hash table (FNV + `ircd_strcmp`), boot-close.
