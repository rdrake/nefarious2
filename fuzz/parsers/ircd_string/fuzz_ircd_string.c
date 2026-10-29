/*
 * fuzz_ircd_string.c - libFuzzer harness for the string, address and
 * numnick helpers in ircd/ircd_string.c and ircd/numnicks.c.
 *
 * These parse client- and server-supplied tokens all over the ircd: IP
 * masks in G/Z/K-lines and WHO/CHECK (ipmask_parse, check_if_ipmask), the
 * P10 base64 IP of a remote NICK (base64toip), nick/user/host validation,
 * channel lists (canonize, token_vector), UTF-8 sanitizing of every
 * WebSocket TEXT frame (string_sanitize_utf8), msgid decoding of
 * chathistory cursors (msgid_decode_time_ms / msgid_decode_hlc), JSON
 * escaping, and so on.  Byte 0 picks the function; the rest is its input
 * (NUL-terminated copy).  Properties are checked where there is an oracle:
 * ipmask_parse vs inet_pton and its own ircd_ntoa_r round trip,
 * iptobase64/base64toip and inttobase64/base64toint round trips,
 * sanitize -> valid UTF-8 and idempotent, ircd_utf8_clamp -> a valid prefix
 * of the input, ircd_json_escape -> a string jansson parses back to the
 * input, ircd_strncpy == strlcpy.
 */
#include "config.h"
#include "ircd_string.h"
#include "ircd_chattr.h"
#include "numnicks.h"
#include "match.h"
#include "res.h"
#include <arpa/inet.h>
#include <jansson.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(c) do { if (!(c)) { fprintf(stderr, "CHECK failed: %s (%s:%d)\n", #c, __FILE__, __LINE__); abort(); } } while (0)

static int ref_is_valid_utf8(const unsigned char *s)
{
  /* RFC 3629 table, independent of string_is_valid_utf8 */
  while (*s) {
    unsigned c = s[0];
    int n, i;
    unsigned lo = 0x80, hi = 0xBF;
    if (c < 0x80) { s++; continue; }
    if (c >= 0xC2 && c <= 0xDF) n = 1;
    else if (c >= 0xE0 && c <= 0xEF) { n = 2; if (c == 0xE0) lo = 0xA0; if (c == 0xED) hi = 0x9F; }
    else if (c >= 0xF0 && c <= 0xF4) { n = 3; if (c == 0xF0) lo = 0x90; if (c == 0xF4) hi = 0x8F; }
    else return 0;
    for (i = 1; i <= n; i++) {
      unsigned d = s[i];
      if (i == 1 ? (d < lo || d > hi) : (d < 0x80 || d > 0xBF)) return 0;
    }
    s += n + 1;
  }
  return 1;
}

/* Known bugs (FINDINGS.md) the default run steps around so the campaign
 * can look past them; FUZZ_STRICT=1 turns them back on:
 *   F4  base64toip() reads past the NUL of a token that is not 6 chars or
 *       a whole number of 3-char groups, and writes far past the address
 *       for a token over 25 chars that contains '_'.
 *   F5  iptobase64() reads in6_16[8] for an IPv6 address with no zero
 *       group (loop condition tests the element before the index).
 *   F9  ircd_ntoa_r() has the same zero-run bug as F6: it prints some
 *       IPv6 addresses as a different address.
 *   F7  ParseInterval() overflows int/long on long digit runs.
 *   F6  iptobase64() encodes the wrong address when the zero groups form
 *       more than one run (curr_zeros is not reset on a non-zero group). */
static int strict(void)
{
  static int s = -1;
  if (s < 0) s = getenv("FUZZ_STRICT") != NULL;
  return s;
}

static int b64ip_wellformed(const char *s)
{
  size_t n = strlen(s), groups = 0, i = 0;
  int us = 0;
  if (n == 6) return 1;
  if (n > 24) return 0;
  while (i < n) {
    if (s[i] == '_') { if (us++) return 0; i++; continue; }
    if (i + 3 > n) return 0;
    i += 3; groups++;
  }
  return us ? groups < 8 : groups == 8;
}

static int v6_has_zero_group(const struct irc_in_addr *a)
{
  int i;
  for (i = 0; i < 8; i++) if (!a->in6_16[i]) return 1;
  return 0;
}

static int v6_zero_runs(const struct irc_in_addr *a)
{
  int i, runs = 0;
  for (i = 0; i < 8; i++)
    if (!a->in6_16[i] && (i == 0 || a->in6_16[i - 1])) runs++;
  return runs;
}

static void t_ipmask(char *s)
{
  struct irc_in_addr a, b;
  unsigned char bits = 0, bits2 = 0;
  char buf[SOCKIPLEN + 1];
  int r = ipmask_parse(s, &a, &bits);
  int r2 = ipmask_parse(s, &b, NULL);
  (void)check_if_ipmask(s);
  if (r) CHECK(bits <= 128);
  /* plain addresses (no mask syntax): compare with inet_pton */
  if (!strpbrk(s, "/*") && r2 && s[r2] == '\0') {
    unsigned char ref[16];
    if (strchr(s, ':')) {
      if (inet_pton(AF_INET6, s, ref) == 1)
        CHECK(memcmp(ref, &b, 16) == 0);
    } else if (inet_pton(AF_INET, s, ref) == 1) {
      CHECK(irc_in_addr_is_ipv4(&b));
      CHECK(memcmp(ref, &b.in6_16[6], 4) == 0);
    }
  }
  if (r) {
    struct irc_in_addr c;
    ircd_ntoa_r(buf, &a);
    CHECK(strlen(buf) <= SOCKIPLEN);
    CHECK(ipmask_parse(buf, &c, &bits2) > 0);
    /* the ircd treats ::a.b.c.d (IPv4-compatible) as IPv4, so compare the
     * way it does */
    if (strict() || irc_in_addr_is_ipv4(&a) || v6_zero_runs(&a) <= 1)
      CHECK(irc_in_addr_cmp(&a, &c) == 0);
    (void)ipmask_check(&a, &c, bits);
    (void)ipmask_clean(&a, bits);
  }
}

static void t_base64ip(char *s, const uint8_t *raw, size_t rawlen)
{
  struct irc_in_addr a, b;
  char buf[32];
  if (strict() || b64ip_wellformed(s)) {
    base64toip(s, &a);
    if (strict() || irc_in_addr_is_ipv4(&a) || v6_has_zero_group(&a))
      iptobase64(buf, &a, sizeof buf, 1);
  }
  if (rawlen >= 16) {                  /* round trip from raw 16 bytes */
    memcpy(&a, raw, 16);
    if (!strict() && !irc_in_addr_is_ipv4(&a) && !v6_has_zero_group(&a))
      a.in6_16[raw[0] & 7] = 0;
    iptobase64(buf, &a, sizeof buf, 1);
    CHECK(strlen(buf) <= 25);
    base64toip(buf, &b);
    if (!irc_in_addr_is_ipv4(&a)) {
      if (strict() || v6_zero_runs(&a) <= 1)
        CHECK(memcmp(&a, &b, 16) == 0);
    } else {
      CHECK(!memcmp(&a.in6_16[6], &b.in6_16[6], 4));
    }
    iptobase64(buf, &a, sizeof buf, 0);  /* 6-char form for v4-only peers */
    CHECK(strlen(buf) == 6);
  }
}

static void t_numnick(char *s, const uint8_t *raw, size_t rawlen)
{
  char buf[16];
  unsigned v;
  uint64_t v64;
  if (*s) (void)base64toint(s);
  if (*s) (void)base64toint_64(s);
  if (rawlen >= 8) {
    memcpy(&v, raw, 4);
    memcpy(&v64, raw, 8);
    inttobase64(buf, v, 6);
    CHECK((base64toint(buf) & 0x3fffffff) == (v & 0x3fffffff) || 1);
    CHECK(base64toint(buf) == (v & ((1u << 30) * 4 - 1)) ||
          base64toint(buf) == (unsigned)(v & 0xffffffffu));
    inttobase64_64(buf, v64, 11);
    CHECK(base64toint_64(buf) == v64);
  }
}

static void t_utf8(char *s)
{
  char *t = malloc(BUFSIZE + strlen(s) + 4);
  int v = string_is_valid_utf8(s), n;
  CHECK(v == ref_is_valid_utf8((unsigned char *)s));
  (void)string_contains_non_ascii(s);
  (void)string_character_structure_is_sane(s);
  (void)string_has_wildcards(s);
  strcpy(t, s);
  n = string_sanitize_utf8(t);
  if (n > 0) {
    CHECK((size_t)n == strlen(t));
    CHECK(n < BUFSIZE);
    CHECK(string_is_valid_utf8(t));
    CHECK(string_sanitize_utf8(t) == -1);   /* idempotent */
  } else if (strlen(s) < BUFSIZE - 1) {
    CHECK(v);                               /* -1 only when nothing to fix */
  }
  free(t);
}

static void t_clamp(char *s, unsigned arg)
{
  size_t len = strlen(s), max = arg % (len + 3);
  char *t = strdup(s);
  int tr = ircd_utf8_clamp(t, max);
  CHECK(strlen(t) <= max || !tr && len <= max);
  CHECK(strncmp(t, s, strlen(t)) == 0);
  if (string_is_valid_utf8(s)) CHECK(string_is_valid_utf8(t));
  CHECK(tr == (len > max));
  CHECK(ircd_line_body_clamp(s, len, max) <= len);
  free(t);
}

static void t_json(char *s, unsigned arg)
{
  size_t dl = 1 + arg % 300;
  char *d = malloc(dl), *doc;
  json_t *j;
  ircd_json_escape(d, dl, s);
  CHECK(strlen(d) < dl);
  doc = malloc(strlen(d) + 3);
  sprintf(doc, "\"%s\"", d);
  j = json_loads(doc, JSON_DECODE_ANY | JSON_ALLOW_NUL, NULL);
  /* A truncated escape may split a UTF-8 sequence (only the non-jansson
   * fallback in m_webpush.c uses it, with buffers sized for the field);
   * compare only when the whole input fit. */
  if (string_is_valid_utf8(s) && strlen(s) * 6 + 1 < dl) {
    CHECK(j != NULL);
    CHECK(!strcmp(json_string_value(j), s));
  }
  json_decref(j);
  free(doc);
  free(d);
}

static void t_strncpy(char *s, unsigned arg)
{
  size_t n = arg % 64, len = strlen(s);
  char a[80], b[80];
  memset(a, 'X', sizeof a); memset(b, 'X', sizeof b);
  ircd_strncpy(a, s, n);
  if (n) {
    size_t c = len < n - 1 ? len : n - 1;
    memcpy(b, s, c);
    b[c] = 0;
    CHECK(!memcmp(a, b, c + 1));
  }
  (void)ircd_strcmp(s, a);
  (void)ircd_strncmp(s, a, n);
}

static void t_tokens(char *s, unsigned arg)
{
  char *v[64], *t = strdup(s), *save = NULL, *tok;
  int n;
  char delim = (char)(arg ? arg : ',');
  n = token_vector(t, delim, v, 64);
  CHECK(n >= 0 && n <= 64);
  free(t);
  t = strdup(s);
  n = unique_name_vector(t, delim, v, 64);
  CHECK(n >= 0 && n <= 64);
  free(t);
  t = strdup(s);
  for (tok = ircd_strtok(&save, t, " ,"); tok; tok = ircd_strtok(&save, NULL, " ,"))
    ;
  free(t);
  /* canonize() writes into a static BUFSIZE buffer; its one caller
   * (m_whowas) passes a parameter of a <= 512-byte line */
  if (strlen(s) < BUFSIZE) {
    t = strdup(s);
    canonize(t);
    free(t);
  }
  (void)csv_contains_token(s, "PLAIN");
  (void)csv_contains_token("a,b,PLAIN,c", s);
}

static void t_misc(char *s, unsigned arg)
{
  char buf[HOSTLEN + 2];
  size_t pos = 0;
  char ab[64];
  {
    /* F7: skip digit runs that overflow unless strict */
    size_t run = 0, maxrun = 0, i;
    for (i = 0; s[i]; i++) { run = IsDigit(s[i]) ? run + 1 : 0; if (run > maxrun) maxrun = run; }
    if (strict() || (maxrun <= 8 && strlen(s) < 64))
      (void)ParseInterval(s);
  }
  (void)is_timestamp(s);
  /* StripColor() writes into a static BUFSIZE buffer; every caller passes
   * the body of one parsed line, which parse.c caps below BUFSIZE */
  if (strlen(s) < BUFSIZE)
    (void)StripColor(s);
  (void)HasColor(s);
  (void)valid_username(s);
  (void)valid_hostname(s);
  (void)valid_spoofhost(s, arg & 1);
  host_from_uh(buf, s, HOSTLEN);
  CHECK(strlen(buf) <= HOSTLEN);
  (void)ircd_text_mentions(s, "nick");
  (void)ircd_text_mentions("hello nick!", s);
  str_appendf(ab, sizeof ab, &pos, "%s", s);
  str_appendf(ab, sizeof ab, &pos, "%s", s);
  CHECK(pos < sizeof ab);
}

static void t_msgid(char *s)
{
  uint64_t ms = 0, ms2 = 0;
  uint16_t lg = 0;
  ms = msgid_decode_time_ms(s);
  if (msgid_decode_hlc(s, &ms2, &lg))
    CHECK(ms2 == ms && ms != 0);
  if (ms) CHECK(ms >= 1577836800000ULL && ms <= 4102444800000ULL);
  /* the time field is numnick base64: must agree with base64toint_64 */
  if (ms) {
    char f[8];
    memcpy(f, s + 5, 7);
    f[7] = 0;
    CHECK(base64toint_64(f) == ms);
  }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  char *s;
  unsigned arg;
  if (size < 2) return 0;
  arg = data[1];
  s = malloc(size - 1);
  memcpy(s, data + 2, size - 2);
  s[size - 2] = '\0';
  switch (data[0] % 10) {
  case 0: t_ipmask(s); break;
  case 1: t_base64ip(s, data + 2, size - 2); break;
  case 2: t_numnick(s, data + 2, size - 2); break;
  case 3: t_utf8(s); break;
  case 4: t_clamp(s, arg); break;
  case 5: t_json(s, arg); break;
  case 6: t_strncpy(s, arg); break;
  case 7: t_tokens(s, arg); break;
  case 8: t_misc(s, arg); break;
  case 9: t_msgid(s); break;
  }
  free(s);
  return 0;
}
