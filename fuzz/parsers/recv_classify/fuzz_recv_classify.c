/*
 * fuzz_recv_classify.c - libFuzzer harness for ircd/recv_classify.c, the
 * per-class tag/body length meter every client read passes through before
 * the parser (s_bsd.c read_packet and the WebSocket path).  The read is
 * split into chunks (state carries over in the Connection); property: the
 * verdict for a stream equals that of an independent line-by-line
 * reference over the same bytes, however they are chunked.
 */
#include "config.h"
#include "client.h"
#include "recv_classify.h"
#include "fuzz_util.h"

static int ref_classify(const unsigned char *b, size_t n, unsigned tagcap)
{
  size_t i = 0;
  while (i < n) {
    size_t s = i, tags = 0, msg = 0;
    while (i < n && b[i] != '\r' && b[i] != '\n') i++;
    if (s < i && b[s] == '@') {
      size_t j = s + 1;
      tags = 1;
      while (j < i && b[j] != ' ') { tags++; j++; }
      if (tags > tagcap) return RECV_CLASSIFY_TAG_OVERRUN;
      if (j < i) msg = i - j - 1;
    } else {
      msg = i - s;
    }
    if (msg > BUFSIZE) return RECV_CLASSIFY_MSG_OVERRUN;
    if (i < n) i++;
  }
  return RECV_CLASSIFY_OK;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  static struct Client cli;
  static struct Connection con;
  size_t off = 1, chunk;
  int first = RECV_CLASSIFY_OK, r;
  if (size < 1) return 0;
  memset(&cli, 0, sizeof cli);
  memset(&con, 0, sizeof con);
  cli_connect(&cli) = &con;
  if (data[0] & 1) cli_status(&cli) = STAT_SERVER;
  chunk = 1 + (data[0] >> 1) * 16;
  while (off < size) {
    size_t n = size - off < chunk ? size - off : chunk;
    r = recv_classify(&cli, (const char *)data + off, (unsigned)n);
    if (r != RECV_CLASSIFY_OK && first == RECV_CLASSIFY_OK) first = r;
    off += n;
  }
  r = ref_classify(data + 1, size - 1, (data[0] & 1) ? 8191 : 4095);
  CHECK(first == r);
  return 0;
}
