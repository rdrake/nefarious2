# CBMC: ircd/webpush_mute.c

Real module `#include`d unmodified; `strtoull` = glibc-equivalent model
(`../common/strtoull_model.h`, differentially tested), `memchr`/`strnlen`
from `../common/libc_models.h`. Run `./run.sh`; `confirm.c` replays the
findings against the real file with ASan+UBSan.

| Harness | Property | Bound | Result |
|---|---|---|---|
| `harness_check_safe` | memory safety/totality of `webpush_mute_check` on every value/target string and every `time_t`; boolean result; NULL-safe | value <= 8, target <= 2 bytes | memory-safe; `--conversion-check` flags `(long long)val` (webpush_mute.c:73) -- see M1 |
| `harness_check_monotone` | muted at now2 => muted at every now1 <= now2 | value <= 8 | VERIFIED |
| `harness_check_boundary` | `t:D` (1-4 digits) not muted at now == D, muted at D-1 (until is exclusive) | D <= 9999 | VERIFIED |
| `harness_check_large_until` | an unsigned 20-digit until token that is in the future mutes | 20 digits, any now >= 0 | **FAILS** (M1) |
| `harness_prune_preserves` | prune: memory safe, result in {-1,0,1}, `out` terminated inside `outlen`, -1 leaves `out` empty, and **for every target `check(out) == check(value)`** | value <= 6, outlen 1..8 | all VERIFIED except "returns 0 only when out == value" (M3) |
| `harness_prune_drop` | with drop target D != "*": other targets keep their answer; D is afterwards muted only through a live `*` entry; never -1 with a big enough buffer | value <= 6 | VERIFIED |

## Findings (all confirmed by `confirm.c`; all low)

- **M1 far-future `until` reads as expired.** `strtoull` result cast to
  `long long` (webpush_mute.c:73): `#c:99999999999999999999` (>= 2^63)
  becomes negative without the `neg` flag, so the mute is ignored, while
  `#c:-1` and `#c:9223372036854775807` mute. The value is the user's own
  `draft/webpush/mute` metadata (read at m_webpush.c:897), so a client
  asking for "mute forever" with a huge number gets pushes. Fix: treat
  `val > LLONG_MAX` (or ERANGE) as indefinite (or as malformed).
- **M2 leading whitespace defeats the sign test.** `#c: -5` is parsed by
  `strtoull` as -5 but `neg` checks only `until_buf[0]`, so it reads as
  expired while `#c:-5` is indefinite. Fix: reject anything but
  `[-]digits`.
- **M3 prune reports "unchanged" after dropping malformed entries.**
  `webpush_mute_prune("#a:0;junk;#b:0")` returns 0 with out
  `"#a:0;#b:0"` (header: "1 when the value changed"). No production
  caller uses prune today (only the cmocka test), so no effect yet. Fix:
  set `changed = 1` for `!e.ok` entries with `entry_len > 0`.
