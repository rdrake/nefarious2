# CBMC: pure parsers in ircd/websocket.c

The real `websocket.c` is `#include`d unmodified (as
`ircd/test/websocket_cmocka.c` does); functions the harnesses never reach
stay bodiless. `../common/libc_models.h` supplies `strstr`/`strnlen`/
`memchr` bodies (CBMC 5.95 ships none; without them results are
meaningless). Run `./run.sh`; it also builds and runs
`confirm_subproto_hang.c`, the concrete reproduction (needs libssl).

| Harness | Property | Bound | Result |
|---|---|---|---|
| `harness_decode_frame` | `websocket_decode_frame` on arbitrary bytes and any `payload_size`: memory safe; on success ret <= frame_len, ret == header(2/4/10)+mask(4)+plen, 0 <= plen < payload_size, payload NUL-terminated and correctly unmasked, frame was masked, RSV clear, opcode known, control payload <= 125 | frame <= 12 bytes, payload_size <= 8 | VERIFIED |
| `harness_decode_len64` | 64-bit length form with all 2^64 lengths: no overflow, never consumes more than present | 14-byte frame | VERIFIED |
| `harness_encode_bounds` | `websocket_encode_frame`: 2-byte header for short frames, correct length byte, negative length refused | data <= 8 | VERIFIED |
| `harness_decode_control_fin` | RFC 6455 5.5: control frames are never fragmented (FIN set) | frame <= 8 | **FAILS** (informational) |
| `harness_handshake_terminates` | `parse_ws_handshake` terminates for every value of a `Sec-WebSocket-Protocol` header (any 2 bytes other than NUL/CR/LF); the token-scan loop is given 6 iterations, more than any terminating scan of 2 bytes needs | 2-byte header value | **FAILS**: unwinding assertion of the token-scan loop (websocket.c:188); CBMC's witness value is `"\tJ"` |

`--conversion-check` is off: it only flags the idiomatic
`(char)(byte ^ mask)`.

## Findings

1. **Pre-auth infinite loop in the WebSocket upgrade parser (confirmed,
   CRITICAL - remote DoS of the whole single-threaded ircd).**
   websocket.c:188-207: when a `Sec-WebSocket-Protocol` header holds no
   supported token, the scan reaches the line's `\r`; the separator skip
   (line 191) does not skip `\r`, the token scan (line 196) stops
   immediately at `\r`, `n == 0`, `p = e` leaves `p` unchanged, and
   `while (*p && *subproto == WS_SUBPROTO_NONE)` spins forever.
   Concrete: `confirm_subproto_hang.c` against the real file:
   `Sec-WebSocket-Protocol: chat` -> HANG (also an empty value);
   `text.ircv3.net` or `chat, text.ircv3.net` -> returns. Reached from
   `websocket_handshake()` (websocket.c:374) <- `websocket_handshake_feed`
   <- `read_packet` (s_bsd.c ~1300) for any connection on a WebSocket
   or auto-detect listener, before registration. One HTTP request
   freezes the server. Introduced with the token-boundary rewrite
   (commit 069c0d8). Fix: stop at the line end and always advance, e.g.
   `while (p < end && *subproto == WS_SUBPROTO_NONE) { skip " \t,"; if (p >= end) break; e = p; while (e < end && *e != ',' && *e != ' ' && *e != '\t') e++; ...; p = (e > p) ? e : p + 1; }`
   and add a cmocka case with an unsupported subprotocol.
2. **Fragmented control frames accepted (informational).** A PING/PONG/
   CLOSE with FIN = 0 decodes successfully; RFC 6455 5.5 requires failing
   the connection. Fix: `if (is_control && !fin) return -1;`.

## Related findings from reading the caller (s_bsd.c, not proven by CBMC)

3. **One-byte write past `con_ws_frag_buf` (confirmed by inspection, low).**
   The continuation path admits `frag_len + ws_len <= 16384`
   (s_bsd.c:1447) into `char con_ws_frag_buf[16384]` (client.h:510), then
   for a TEXT message writes `frag_data[frag_len] = '\0'` (s_bsd.c:1461)
   with `frag_len == 16384`, i.e. into the first byte of the following
   `int con_ws_frag_len`. That byte is 0 already (16384 = 0x4000 on
   either endianness), so it is benign today but is UB and breaks if the
   struct changes. Fix: limit reassembly to `< 16384` or size the buffer
   16385.
4. **Fragmented messages skip `recv_classify`** -- see
   `../recv_classify/README.md`.
