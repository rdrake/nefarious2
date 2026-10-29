/*
 * fuzz_dbuf.c - libFuzzer harness for ircd/dbuf.c, the chained receive /
 * send queue every client byte passes through (dbuf_put from the socket,
 * dbuf_getmsg to the parser).  Built like ircd/test/dbuf_cmocka.c.  The
 * input is split into puts of fuzz-chosen sizes; lines are then pulled
 * with dbuf_getmsg into a FULL_MSG_SIZE buffer (s_bsd.c's call) and
 * compared with an independent splitter over the same bytes (leading
 * CR/LF skipped, a line ends at CR or LF, an unterminated tail stays
 * queued).  dbuf_get / dbuf_map / dbuf_delete are checked against the
 * byte model too.
 */
#include "config.h"
#include "ircd_defs.h"
#include "dbuf.h"
#include "fuzz_util.h"

int feature_int(int f) { (void)f; return 1 << 20; }
int feature_bool(int f) { (void)f; return 0; }
void flush_connections(void *c) { (void)c; }

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  struct DBuf q;
  size_t off = 1, rpos = 0;
  static char line[FULL_MSG_SIZE];
  unsigned chunk;
  if (size < 1) return 0;
  memset(&q, 0, sizeof q);
  chunk = 1 + data[0] * 13;
  while (off < size) {
    unsigned n = size - off < chunk ? (unsigned)(size - off) : chunk;
    CHECK(dbuf_put(&q, (const char *)data + off, n) == 1);
    off += n;
  }
  if (data[0] & 1) {
    /* line mode */
    unsigned got;
    while ((got = dbuf_getmsg(&q, line, sizeof line)) > 0) {
      size_t s, e;
      /* reference: skip CR/LF, take to the next CR/LF */
      while (1 + rpos < size && (data[1 + rpos] == '\r' || data[1 + rpos] == '\n')) rpos++;
      s = rpos;
      e = s;
      while (1 + e < size && data[1 + e] != '\r' && data[1 + e] != '\n') e++;
      CHECK(1 + e < size);                 /* a returned line was terminated */
      CHECK(got == e - s);
      CHECK(!memcmp(line, data + 1 + s, got) && line[got] == 0);
      rpos = e;
    }
  } else {
    /* byte mode */
    char buf[700];
    unsigned len;
    const char *m;
    while (DBufLength(&q) > 0) {
      unsigned want = 1 + (DBufLength(&q) % sizeof buf), g;
      m = dbuf_map(&q, &len);
      CHECK(m && len > 0 && len <= DBufLength(&q));
      CHECK(!memcmp(m, data + 1 + rpos, len < want ? len : want));
      g = dbuf_get(&q, buf, want);
      CHECK(g > 0 && g <= want);
      CHECK(!memcmp(buf, data + 1 + rpos, g));
      rpos += g;
    }
    CHECK(rpos == size - 1);
  }
  dbuf_delete(&q, DBufLength(&q));
  return 0;
}
