# CBMC proofs for Nefarious pure decision modules

`./run_pure_modules.sh` runs every suite below (CBMC 5.95.1, CaDiCaL;
gcc + libssl for the concrete reproductions). `crdt_hlc/` and the
bouncer converge/rebind/deauth modules are verified separately.

Conventions (see `common/`):
- the real `ircd/*.c` file is `#include`d **unmodified** in each harness
  (one documented exception: `chathistory_presence` shrinks one array
  dimension by a checked `sed` into `build/`);
- `common/run_harness.sh` = one proof with `--bounds-check
  --pointer-check --pointer-overflow-check --signed-overflow-check
  --undefined-shift-check [--conversion-check] --unwinding-assertions`,
  6 GB memory cap, log + trace in `<module>/logs/<harness>.log`;
- `common/strtoull_model.h`, `common/libc_models.h`: bodies for libc
  functions CBMC 5.95 lacks (`strtoull`, `memchr`, `strnlen`,
  `strstr`); without them CBMC silently returns nondet values. The
  strtoull model is differentially tested against glibc;
- `<module>/confirm*.c`: every counterexample replayed against the real
  source with `-fsanitize=address,undefined` (`common/run_confirm.sh`).

| Module | README | Headline |
|---|---|---|
| webpush_mute | `webpush_mute/README.md` | prune preserves semantics, monotone in time; huge `until` read as expired |
| webpush_expiry | `webpush_expiry/README.md` | **keyed records never expire** (armed_at = 0) |
| webpush_attention | `webpush_attention/README.md` | contract verified; `last_msg + idle` overflow |
| register_throttle | `register_throttle/README.md` | refusals side-effect free, bounds hold; per-IP limit bypass by eviction; clock-step pin |
| account_id | `account_id/README.md` | round-trip exact for all 2^128 UUIDs; lax hyphen positions |
| recv_classify | `recv_classify/README.md` | counters/resume/caps verified; WS fragments bypass it (caller) |
| exit_reason | `exit_reason/README.md` | contract verified |
| chathistory_presence | `chathistory_presence/README.md` | union wf/sound/complete, next_visible exact; cap evicts newer window; PN/norm overflow |
| websocket | `websocket/README.md` | frame decoder verified; **pre-auth infinite loop in handshake** |
| dbuf | `dbuf/README.md` | CBMC did not scale (2 KB blocks); bounded-exhaustive ASan check across the block boundary: 23.7M checks clean |
