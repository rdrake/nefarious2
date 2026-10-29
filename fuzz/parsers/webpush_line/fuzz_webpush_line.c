/*
 * fuzz_webpush_line.c - libFuzzer harness for ircd/webpush_line.c, which
 * renders the IRC line pushed to a user's devices (draft/webpush): every
 * field (nick, user, host, account, target, text, msgid, time) comes from
 * the message that triggered the push.  Properties: output fits outlen and
 * is NUL-terminated; it is one line (no CR/LF/NUL inside); tag values are
 * IRCv3-escaped (no raw space or ';' inside the tag section).
 */
#include "webpush_line.h"
#include "fuzz_util.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  const char *p = (const char *)data + 2, *end = (const char *)data + size;
  char *f[11], *out;
  struct webpush_line_src src;
  struct webpush_line_ml ml;
  size_t outlen;
  int i, n;
  if (size < 2) return 0;
  for (i = 0; i < 11; i++) {
    char *c;
    f[i] = fuzz_field(&p, end);
    /* the fields come from a parsed IRC line: never CR or LF */
    for (c = f[i]; *c; c++) if (*c == '\r' || *c == '\n') *c = ' ';
  }
  src.nick = f[0]; src.user = f[1]; src.host = f[2]; src.account = *f[3] ? f[3] : NULL;
  ml.batch = f[8]; ml.index = data[1] & 7; ml.sent = (data[1] >> 3) & 7; ml.total = 8; ml.concat = data[1] >> 7;
  outlen = 1 + data[0] * 8;
  out = malloc(outlen);
  n = webpush_line_message(out, outlen, &src, (data[0] & 1) ? "NOTICE" : "PRIVMSG",
                           f[4], f[5], *f[6] ? f[6] : NULL, *f[7] ? f[7] : NULL,
                           *f[8] ? &ml : NULL);
  if (n > 0) {
    CHECK((size_t)n < outlen && strlen(out) == (size_t)n);
    CHECK(!strpbrk(out, "\r\n"));
  }
  n = webpush_line_markread(out, outlen, f[9], f[4], f[7]);
  if (n > 0) CHECK((size_t)n < outlen && strlen(out) == (size_t)n);
  {
    char esc[600];
    size_t e = webpush_tag_escape(esc, sizeof esc, f[10]);
    if (e != (size_t)-1)          /* -1: did not fit (documented) */
      CHECK(e < sizeof esc && strlen(esc) == e);
    CHECK(!strpbrk(esc, " ;\r\n"));
  }
  free(out);
  for (i = 0; i < 11; i++) free(f[i]);
  return 0;
}
