/*
 * fuzz_websocket.c - libFuzzer harness for ircd/websocket.c.
 *
 * Everything here arrives pre-authentication on a WebSocket listener: the
 * HTTP upgrade request (websocket_handshake_feed -> parse_ws_handshake ->
 * validate_ws_origin) and then raw frames (websocket_decode_frame).
 * websocket.c is #included like ircd/test/websocket_cmocka.c, with the same
 * stubs.
 *
 * Byte 0 selects a mode:
 *   0  handshake: byte 1 = read-chunk size, byte 2 picks the configured
 *      FEAT_WEBSOCKET_ORIGIN list; the rest is fed in chunks to
 *      websocket_handshake_feed().  Oracles: 0 <= consumed <= chunk; the
 *      accept key on success is RFC 6455's base64(SHA1(key+GUID)).
 *   1  frame stream: the rest is pushed through ws_read_model(), a copy of
 *      the WebSocket branch of read_packet() (ircd/s_bsd.c, the
 *      "if (length > 0 && IsWebSocket(cptr))" block) with the per-
 *      connection buffers allocated separately at their struct sizes so
 *      ASan sees an overrun of any one of them.
 *   2  round trip: websocket_encode_frame() output, masked with the first
 *      4 bytes, must decode back to the same payload/opcode/fin.
 */
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../../ircd/websocket.c"

/* ---- stubs (as ircd/test/websocket_cmocka.c) ---- */
int HighestFd = -1;
struct Client* LocalClientArray[MAXCONNECTIONS];
int feature_int(enum Feature feat) { (void)feat; return 0; }
struct Timer* timer_init(struct Timer* timer) { return timer; }
void timer_add(struct Timer* timer, EventCallBack call, void* data,
               enum TimerType type, time_t value)
{ (void)timer; (void)call; (void)data; (void)type; (void)value; }

static const char *origin_list = "";
const char *feature_str(enum Feature feat) { (void)feat; return origin_list; }
void update_write(struct Client* cptr) { (void)cptr; }

int ircd_snprintf(struct Client *dest, char *buf, size_t buf_len,
                  const char *format, ...)
{
  va_list args;
  int ret;
  (void)dest;
  va_start(args, format);
  ret = vsnprintf(buf, buf_len, format, args);
  va_end(args);
  return ret;
}

static char sent_buf[1024];
static unsigned int sent_len;
IOResult os_send_nonb(int fd, const char *buf, unsigned int length,
                      unsigned int *count_out)
{
  (void)fd;
  if (length > sizeof(sent_buf) - 1)
    length = sizeof(sent_buf) - 1;
  memcpy(sent_buf, buf, length);
  sent_buf[length] = '\0';
  sent_len = length;
  *count_out = length;
  return IO_SUCCESS;
}


/* Known bug F1 (FINDINGS.md): parse_ws_handshake() never terminates when
 * the first Sec-WebSocket-Protocol line before the blank line offers no
 * supported token (the token scan stops at '\r' and never advances).
 * Requests that would take that path are skipped so the campaign can look
 * past it; set FUZZ_WS_KNOWN_HANG=1 to fuzz into it anyway. */
static int ws_known_hang(const uint8_t *d, size_t n)
{
  static int allow = -1;
  char *buf, *term;
  const char *line, *end;
  int subproto = 0, hang = 0;
  if (allow < 0) allow = getenv("FUZZ_WS_KNOWN_HANG") != NULL;
  if (allow) return 0;
  /* the request exactly as websocket_handshake_feed hands it over */
  if (n > WS_HANDSHAKE_MAX) n = WS_HANDSHAKE_MAX;
  buf = malloc(n + 1);
  memcpy(buf, d, n);
  buf[n] = '\0';
  if (!(term = strstr(buf, "\r\n\r\n")) || strncmp(buf, "GET ", 4)) {
    free(buf);
    return 0;
  }
  term[4] = '\0';
  /* parse_ws_handshake's line walk, with the subprotocol scan bounded */
  for (line = buf; *line; ) {
    if (!(end = strstr(line, "\r\n")))
      break;
    if (!strncasecmp(line, "Sec-WebSocket-Protocol:", 23)) {
      const char *p = line + 23;
      while (*p && !subproto) {
        const char *e;
        while (*p == ' ' || *p == '\t' || *p == ',') p++;
        if (!*p) break;
        e = p;
        while (*e && *e != ',' && *e != ' ' && *e != '\t' && *e != '\r') e++;
        if (e - p == 14 && !strncasecmp(p, "text.ircv3.net", 14)) subproto = 1;
        else if (e - p == 16 && !strncasecmp(p, "binary.ircv3.net", 16)) subproto = 1;
        if (e == p) { hang = 1; break; }        /* no progress: spins */
        p = e;
      }
      if (hang) break;
    }
    line = end + 2;
    if (line[0] == '\r' && line[1] == '\n')
      break;
  }
  free(buf);
  return hang;
}

/* ---- read_packet() WebSocket-branch model ---- */

/* Sizes come from the real struct Connection so the model tracks them. */
#define FRAME_BUF_SIZE sizeof(((struct Connection *)0)->con_ws_frame_buf)
#define FRAG_BUF_SIZE  sizeof(((struct Connection *)0)->con_ws_frag_buf)

struct ws_model {
  unsigned char *frame_buf; int frame_len;
  char *frag_buf; int frag_len; int frag_opcode;
  int text, autodetect;
  size_t delivered;
};

static void deliver(struct ws_model *m, const char *p, int n)
{
  int i;
  volatile unsigned char sink = 0;
  for (i = 0; i < n; i++) sink ^= (unsigned char)p[i];
  m->delivered += n;
}

/* Returns 0 to keep the connection, -1 when read_packet would exit it. */
static int ws_read_model(struct ws_model *m, struct Client *cptr,
                         const char *readbuf, int length)
{
  static char ws_payload[WS_MAX_PAYLOAD + 2];
  int ws_len = 0, opcode = 0, consumed, is_fin = 0;
  unsigned char *ws_data = m->frame_buf;
  int ws_remaining = m->frame_len;
  int copy_len;
  const char *src = readbuf;
  int src_len = length;

  while (ws_remaining > 0 || src_len > 0) {
    consumed = 0;
    if (ws_remaining > 0)
      consumed = websocket_decode_frame(ws_data, ws_remaining, ws_payload,
                                        sizeof(ws_payload), &ws_len, &opcode,
                                        &is_fin);
    if (consumed > ws_remaining) abort();     /* decoder over-consumed */
    if (consumed == 0) {
      if (src_len <= 0) break;
      if (ws_remaining > 0 && ws_data != m->frame_buf)
        memmove(m->frame_buf, ws_data, ws_remaining);
      ws_data = m->frame_buf;
      copy_len = (int)FRAME_BUF_SIZE - ws_remaining;
      if (copy_len <= 0) return -1;
      if (copy_len > src_len) copy_len = src_len;
      memcpy(m->frame_buf + ws_remaining, src, copy_len);
      ws_remaining += copy_len;
      src += copy_len;
      src_len -= copy_len;
      continue;
    } else if (consumed < 0) {
      return -1;
    }
    if (ws_len < 0 || ws_len > WS_MAX_PAYLOAD) abort();

    if (opcode >= WS_OPCODE_CLOSE) {
      if (opcode > WS_OPCODE_PONG) abort();   /* reserved opcode passed */
      if (ws_len > 125) abort();              /* oversized control frame */
      if (!websocket_handle_control(cptr, opcode, ws_payload, ws_len))
        return -1;
    } else if (opcode == WS_OPCODE_CONTINUATION) {
      if (m->frag_len + ws_len <= 16384) {
        memcpy(m->frag_buf + m->frag_len, ws_payload, ws_len);
        m->frag_len += ws_len;
      } else {
        return -1;
      }
      if (is_fin) {
        char *frag_data = m->frag_buf;
        int frag_len = m->frag_len;
        if (frag_len > 0) {
          if (m->frag_opcode == WS_OPCODE_TEXT) {
            frag_data[frag_len] = '\0';
            if (!string_is_valid_utf8(frag_data))
              return -1;
          }
          if (frag_len < 16384 - 1 && frag_data[frag_len - 1] != '\n')
            frag_data[frag_len++] = '\n';
          deliver(m, frag_data, frag_len);
        }
        m->frag_len = 0;
        m->frag_opcode = 0;
      }
    } else if (opcode == WS_OPCODE_TEXT || opcode == WS_OPCODE_BINARY) {
      if (m->autodetect) {
        if (opcode == WS_OPCODE_BINARY) m->text = 0;
        m->autodetect = 0;
      }
      if (!is_fin) {
        m->frag_opcode = opcode;
        if (ws_len <= 16384) {
          memcpy(m->frag_buf, ws_payload, ws_len);
          m->frag_len = ws_len;
        } else {
          return -1;
        }
      } else if (ws_len > 0) {
        if (opcode == WS_OPCODE_TEXT) {
          ws_payload[ws_len] = '\0';
          if (!string_is_valid_utf8(ws_payload)) {
            int new_len = string_sanitize_utf8(ws_payload);
            if (new_len > 0)
              ws_len = new_len;
          }
        }
        if (ws_len < (int)sizeof(ws_payload) - 1 &&
            ws_payload[ws_len - 1] != '\n')
          ws_payload[ws_len++] = '\n';
        deliver(m, ws_payload, ws_len);
      }
    }
    ws_data += consumed;
    ws_remaining -= consumed;
  }
  if (ws_remaining > 0 && ws_data != m->frame_buf)
    memmove(m->frame_buf, ws_data, ws_remaining);
  m->frame_len = ws_remaining;
  return 0;
}

static void setup_client(struct Client *cli, struct Connection *con)
{
  memset(cli, 0, sizeof(*cli));
  memset(con, 0, sizeof(*con));
  cli_connect(cli) = con;
  cli_fd(cli) = -1;
  strcpy(cli_sockhost(cli), "fuzz.host");
}

static const char *origins[] = {
  "", "*", "https://example.com", "*.example.com https://irc.test",
  "*. ,*", "*.a.b.c,,https://x",
};

/* RFC 6455 accept key, independent of compute_accept_key */
static void ref_accept(const char *key, char out[64])
{
  unsigned char h[SHA_DIGEST_LENGTH];
  char c[256];
  snprintf(c, sizeof c, "%s%s", key, WEBSOCKET_GUID);
  SHA1((unsigned char *)c, strlen(c), h);
  EVP_EncodeBlock((unsigned char *)out, h, SHA_DIGEST_LENGTH);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  static struct Client cli;
  static struct Connection con;
  if (size < 3) return 0;

  setup_client(&cli, &con);
  switch (data[0] % 3) {
  case 0: {
    int chunk = data[1] ? data[1] * 8 : 1;
    size_t off = 3;
    int result = 0, consumed;
    if (ws_known_hang(data + 3, size - 3)) break;
    origin_list = origins[data[2] % (sizeof(origins) / sizeof(origins[0]))];
    SetWSNeedHandshake(&cli);
    while (off < size) {
      int n = (int)(size - off) < chunk ? (int)(size - off) : chunk;
      result = websocket_handshake_feed(&cli, (const char *)data + off, n,
                                        &consumed);
      if (consumed < 0 || consumed > n) abort();
      off += n;
      if (result != 0) break;
    }
    if (result == 1) {
      if (!IsWebSocket(&cli)) abort();
      if (strncmp(sent_buf, "HTTP/1.1 101 ", 13)) abort();
    }
    MyFree(cli_ws_hs_buf(&cli));
    break;
  }
  case 1: {
    struct ws_model m;
    size_t off = 2;
    int chunk = data[1] ? data[1] * 16 : 1;
    memset(&m, 0, sizeof m);
    m.frame_buf = malloc(FRAME_BUF_SIZE);
    /* Known bug F2 (FINDINGS.md): read_packet() NUL-terminates a full
     * 16384-byte TEXT reassembly at frag_buf[16384], one past the array.
     * The buffer gets one spare byte so the campaign looks past it; set
     * FUZZ_WS_STRICT_FRAG=1 for the exact struct size. */
    m.frag_buf = malloc(FRAG_BUF_SIZE + (getenv("FUZZ_WS_STRICT_FRAG") ? 0 : 1));
    m.text = 1; m.autodetect = 1;
    SetWebSocket(&cli);
    while (off < size) {
      int n = (int)(size - off) < chunk ? (int)(size - off) : chunk;
      if (ws_read_model(&m, &cli, (const char *)data + off, n) < 0) break;
      off += n;
    }
    free(m.frame_buf);
    free(m.frag_buf);
    break;
  }
  case 2: {
    /* byte1: opcode/text flag; bytes 2..5 mask; rest payload */
    static unsigned char frame[WS_MAX_FRAME + 16];
    static char out[WS_MAX_PAYLOAD + 2];
    const unsigned char *mask = data + 2;
    const char *pl;
    int plen, flen, olen, op, fin, hdr, i, used;
    if (size < 6) break;
    pl = (const char *)data + 6;
    plen = (int)(size - 6);
    if (plen > WS_MAX_PAYLOAD) plen = WS_MAX_PAYLOAD;
    flen = websocket_encode_frame(pl, plen, frame, data[1] & 1);
    /* server frames are unmasked; mask it like a client would */
    hdr = flen - plen;
    memmove(frame + hdr + 4, frame + hdr, plen);
    memcpy(frame + hdr, mask, 4);
    frame[1] |= 0x80;
    for (i = 0; i < plen; i++) frame[hdr + 4 + i] ^= mask[i % 4];
    used = websocket_decode_frame(frame, flen + 4, out, sizeof out, &olen,
                                  &op, &fin);
    if (used != flen + 4 || olen != plen || !fin ||
        op != ((data[1] & 1) ? WS_OPCODE_TEXT : WS_OPCODE_BINARY) ||
        memcmp(out, pl, plen))
      abort();
    /* every strict prefix is "incomplete", never an error or a frame */
    for (i = 0; i < flen + 4 && i < 16; i++)
      if (websocket_decode_frame(frame, i, out, sizeof out, &olen, &op, &fin) != 0)
        abort();
    break;
  }
  }
  (void)ref_accept;
  return 0;
}
