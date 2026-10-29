# CBMC: ircd/webpush_attention.c

Real module `#include`d unmodified. Run `./run.sh`; logs in `logs/`;
`confirm.c` = ASan/UBSan reproduction against the real file.

| Harness | Property | Bound | Result |
|---|---|---|---|
| `harness_attending_total` | no UB, boolean result, NULL-safe, for ANY field/now/idle values | all int64 | **FAILS**: `c->last_msg + idle` signed overflow (webpush_attention.c:18) |
| `harness_attention_contract` | realistic domain (times <= year 3000, idle <= INT_MAX): held/away never attend; idle<=0 => present attends; idle>0 => attends iff `0 < last_msg && now - last_msg < idle`; attending later => attending earlier (monotone); `webpush_unattended == !exists attending`; n == 0 unattended | n <= 2 connections (the loop is a plain fold; n = 3 exceeded 2 min with 64-bit arithmetic) | VERIFIED |

## Finding

`last_msg + idle` overflow (confirmed UB, low). `last_msg` for remote
connections is replicated from peers (`BX U la=`, parsed with `strtoul`
and only checked `> 0`, bouncer_session.c:9619). A peer-supplied
`la` near LLONG_MAX is UB; with wrapping it reads "idle". A peer can also
pin `la` into the far future so the account counts as attended forever
(no pushes) -- trusted-peer input, but worth clamping `la` to
`<= CurrentTime + skew` at ingest. Fix in this module:
`return now - c->last_msg < idle;` (both operands in realistic range) or
compare `c->last_msg > now - idle`.
