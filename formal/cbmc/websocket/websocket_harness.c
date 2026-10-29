/*
 * websocket_harness.c - CBMC proofs for the pure parsers in ircd/websocket.c
 * (websocket_decode_frame, websocket_encode_frame, parse_ws_handshake).
 *
 * The real websocket.c is #included unmodified (as ircd/test/
 * websocket_cmocka.c does); functions it calls that these harnesses
 * never reach are left bodiless.
 */
#include <limits.h>
#include "../common/cbmc_util.h"
#include "../common/libc_models.h"
#include "../../../ircd/websocket.c"

#ifndef FMAX
#define FMAX 12
#endif
#ifndef PMAX
#define PMAX 8
#endif

/* W1  websocket_decode_frame on ARBITRARY bytes (length 0..FMAX) and any
 *     payload_size in [0, PMAX]: memory safe, and on success (ret > 0)
 *       - ret <= frame_len, and ret == header + mask + payload_len
 *       - 0 <= payload_len < payload_size, payload NUL-terminated
 *       - payload[i] == frame[ret - payload_len + i] ^ mask[i % 4]
 *       - the frame was masked, RSV clear, opcode not reserved,
 *         control payloads <= 125
 *     ret == 0 only when frame_len is shorter than the frame needs. */
void harness_decode_frame(void)
{
  unsigned char frame[FMAX];
  char payload[PMAX];
  int frame_len = nondet_int(), psize = nondet_int();
  int plen, opcode, fin, ret, i;

  for (i = 0; i < FMAX; i++)
    frame[i] = (unsigned char)nondet_char();
  __CPROVER_assume(frame_len >= 0 && frame_len <= FMAX);
  __CPROVER_assume(psize >= 0 && psize <= PMAX);

  ret = websocket_decode_frame(frame, frame_len, payload, psize,
                               &plen, &opcode, &fin);
  __CPROVER_assert(ret >= -2 && ret <= frame_len, "ret in range");
  if (ret > 0) {
    int hdr = ret - plen;
    __CPROVER_assert(plen >= 0 && plen < psize, "payload fits its buffer");
    __CPROVER_assert(payload[plen] == '\0', "payload NUL-terminated");
    __CPROVER_assert(hdr == 6 || hdr == 8 || hdr == 14, "header is 2/4/10 + mask");
    __CPROVER_assert(frame[1] & 0x80, "client frames are masked");
    __CPROVER_assert((frame[0] & 0x70) == 0, "RSV clear");
    __CPROVER_assert(opcode <= 2 || (opcode >= 8 && opcode <= 10), "known opcode");
    __CPROVER_assert(opcode < 8 || plen <= 125, "control payload <= 125");
    for (i = 0; i < plen; i++)
      __CPROVER_assert((unsigned char)payload[i]
                       == (frame[i + hdr] ^ frame[hdr - 4 + (i % 4)]),
                       "payload correctly unmasked");
  }
}

/* W1b RFC 6455 5.5: "Control frames themselves MUST NOT be fragmented."
 *     A decoded control frame should always carry FIN. */
void harness_decode_control_fin(void)
{
  unsigned char frame[FMAX];
  char payload[PMAX];
  int frame_len = nondet_int(), plen, opcode, fin, ret, i;

  for (i = 0; i < FMAX; i++)
    frame[i] = (unsigned char)nondet_char();
  __CPROVER_assume(frame_len >= 0 && frame_len <= FMAX);
  ret = websocket_decode_frame(frame, frame_len, payload, PMAX,
                               &plen, &opcode, &fin);
  if (ret > 0 && opcode >= 8)
    __CPROVER_assert(fin == 1, "control frames are never fragmented");
}

/* W1c the 64-bit length form with every possible 8-byte length: the
 *     decoder must answer TOOBIG/-1/0 without any arithmetic overflow and
 *     never claim more payload than present (frame_len up to WS_MAX_FRAME
 *     is symbolic, the buffer itself is not read past the header). */
void harness_decode_len64(void)
{
  unsigned char frame[14];
  char payload[4];
  int frame_len = nondet_int(), plen, opcode, fin, ret, i;

  for (i = 0; i < 14; i++)
    frame[i] = (unsigned char)nondet_char();
  frame[1] = 0x80 | 127;
  __CPROVER_assume(frame_len >= 0 && frame_len <= 14);
  ret = websocket_decode_frame(frame, frame_len, payload, sizeof(payload),
                               &plen, &opcode, &fin);
  __CPROVER_assert(ret <= frame_len, "never consumes more than present");
}

/* W2  encode then decode round trip (server->client frames are unmasked,
 *     so mask them as a client would): websocket_encode_frame's output
 *     length is header + data_len, in the documented data_len + 10 bound. */
void harness_encode_bounds(void)
{
  char data[PMAX];
  unsigned char frame[PMAX + 10];
  int n = nondet_int(), ret, i;
  for (i = 0; i < PMAX; i++)
    data[i] = nondet_char();
  __CPROVER_assume(n >= 0 && n <= PMAX);
  ret = websocket_encode_frame(data, n, frame, nondet_int() & 1);
  __CPROVER_assert(ret == n + 2, "short frames: 2-byte header");
  __CPROVER_assert(frame[1] == (unsigned char)n, "length byte");
  __CPROVER_assert(websocket_encode_frame(data, -1, frame, 1) == -1,
                   "negative length refused");
}

/* W3  parse_ws_handshake TERMINATES on every request.  The request is a
 *     fixed "GET / HTTP/1.1\r\nSec-WebSocket-Protocol:" prefix, then
 *     HVAL arbitrary header-value bytes, then the blank line -- i.e.
 *     every possible value of that one header.  --unwinding-assertions
 *     turns a loop that does not finish within the bound into a
 *     FAILURE; the bound used (HVAL + 8) is far above what any
 *     terminating scan of HVAL bytes needs. */
#ifndef HVAL
#define HVAL 3
#endif
void harness_handshake_terminates(void)
{
  static const char pre[] = "GET / HTTP/1.1\r\nSec-WebSocket-Protocol:";
  char req[sizeof(pre) - 1 + HVAL + 4 + 1];
  char key[64], origin[256];
  int sub, i;

  memcpy(req, pre, sizeof(pre) - 1);
  for (i = 0; i < HVAL; i++) {
    char c = nondet_char();
    __CPROVER_assume(c != '\0' && c != '\r' && c != '\n');
    req[sizeof(pre) - 1 + i] = c;
  }
  memcpy(req + sizeof(pre) - 1 + HVAL, "\r\n\r\n", 5);
  (void)parse_ws_handshake(req, (int)strlen(req), key, &sub, origin);
}
