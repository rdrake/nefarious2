# CBMC: ircd/recv_classify.c

Real module `#include`d unmodified with the real `client.h`, so
`cli_connect`, `con_recv_*`, `IsServer`/`IsHandshake` are the production
macros; client vs server status is nondeterministic. Run `./run.sh`.

| Harness | Property | Bound | Result |
|---|---|---|---|
| `harness_counters` | memory safety; from a fresh line, the tag/msg counters equal an independent reference split of the last unterminated line (`@` + bytes to first SPACE = tags, after it = body; no `@` = all body; CR or LF resets) | any bytes, len <= 8 | VERIFIED |
| `harness_split` | resumability: classifying `a‖b` in one call or in two (any cut, any starting state up to the caps) gives the same final state and verdict (`r1 ? r1 : r2`) | len <= 8, counters up to 8192/513 | VERIFIED |
| `harness_caps` | from any mid-line state near the caps (tag up to 8192, msg up to 513): verdict == the first cap crossing (client 4095 / server 8191 tags, 512 body), first overrun wins | len <= 8 | VERIFIED |

The counters are `unsigned int` and every caller (s_bsd.c:1204, :1218,
:1517, :1545) kills the connection on an overrun, so they cannot wrap.

## Related finding from call-site review (not a CBMC result; confirmed by reading)

Fragmented WebSocket messages bypass the classifier: the CONTINUATION/FIN
reassembly path in s_bsd.c (:1445-1470) `dbuf_put`s up to 16384 bytes
of reassembled payload without calling `recv_classify`, while complete
single frames (:1517) and plain TCP (:1545) are classified. A WebSocket
client can therefore send a 16 KB body or tag region per line, and the
classifier state is not advanced for those bytes. Low-medium (the
recvQ/flood checks still apply). Fix: call `recv_classify` on
`frag_data, frag_len` before the `dbuf_put` at s_bsd.c:1469.
