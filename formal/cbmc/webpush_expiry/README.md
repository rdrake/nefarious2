# CBMC: ircd/webpush_expiry.c

Real module `#include`d unmodified; `strtoull` gets the glibc-equivalent
model in `../common/strtoull_model.h` (differentially tested against glibc
by `../common/strtoull_model_check.sh`). Run: `./run.sh` (CBMC 5.95.1,
CaDiCaL). Logs with full traces: `logs/<harness>.log`. `confirm.c`
replays each counterexample against the real file with ASan+UBSan.

| Harness | Property | Bound | Result |
|---|---|---|---|
| `harness_armed_at_safe` | memory safety of `webpush_armed_at` on every string (all byte values) | len <= 26 | memory-safe; `--conversion-check` flags `(long long)val` for values > LLONG_MAX |
| `harness_armed_at_nonneg` | header: "0 for malformed", never negative | len <= 26 | **FAILS**: `"e\|p\|a\| -5"` -> -5, `"...\|18446744073709551615"` -> -1 |
| `harness_armed_at_keyed_record` | the record shape m_webpush.c actually writes, `endpoint\|p256dh\|auth\|armed\|keyid`, yields `armed` | keyid <= 16 chars, 10-digit armed | **FAILS** for keyid >= 13 chars |
| `harness_expired_total` | no UB for any armed/now/max_age | all int64 | **FAILS**: `armed + max_age` signed overflow |
| `harness_expired_props` | realistic domain (armed <= year 3000, max_age <= INT_MAX): monotone in `now`, expired exactly at `armed+max_age`, live one second before, `armed<=0`/`max_age<=0` never expire | all values in domain | VERIFIED |

## Findings

1. **Keyed subscriptions never expire (confirmed, medium).**
   `webpush_armed_at` copies *everything* after the third `|` into a
   24-byte buffer and returns 0 if it does not fit
   (webpush_expiry.c:34-35). Since the key ring, records are
   `...|armed|keyid` (m_webpush.c:300, :1245) and the key id is the
   87-char base64url P-256 public key (WEBPUSH_KEY_ID_LEN 88), so every
   keyed record parses as armed = 0:
   - `sweep_iter_cb` (m_webpush.c:1899-1906) never expires them
     (FEAT_WEBPUSH_EXPIRE is silently disabled), and dead endpoints keep
     the keys they reference alive;
   - the `B` burst line (m_webpush.c:1531) sends armed = 0, which the
     receiver re-stamps as `CurrentTime` (m_webpush.c:1240), and
     `webpush_armed_at(existing) >= armed` (m_webpush.c:1243) is never
     true, so every netjoin re-arms every record network-wide.
   The cmocka test only uses a 5-byte trailing field ("extra").
   Fix: parse only up to the next `|` (`len = strcspn(p3 + 1, "|")`).
2. **Negative results (confirmed, low).** Leading whitespace defeats the
   `buf[0] == '-'` guard and values > LLONG_MAX wrap; the header promises 0.
   Fix: require `isdigit(buf[0])` and `val <= LLONG_MAX`.
3. **`armed + max_age` overflow (confirmed UB, low).** armed reaches this
   from peers (`B` line, `strtoull` at m_webpush.c:1211). Fix:
   `armed > now - max_age` written overflow-free (`now - armed >= max_age`
   with `armed <= now` checked first).
