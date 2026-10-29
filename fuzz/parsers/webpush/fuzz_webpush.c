/*
 * fuzz_webpush.c - libFuzzer harness for draft/webpush input handling:
 * ircd/m_webpush.c's WEBPUSH REGISTER checks (is_valid_endpoint,
 * parse_keys) and ircd/webpush.c's subscription record parser, RFC 8291
 * encryption and VAPID JWT construction.  The endpoint URL and the
 * p256dh/auth keys are client-chosen; stored records come back from
 * RocksDB.  webpush.c is #included for its statics; the rest is stubbed by
 * common/autostub.py.
 * Byte 0 selects:
 *   0  REGISTER: "endpoint\0keys" -> is_valid_endpoint, parse_keys, the
 *      stored record built exactly as m_webpush.c does, parse it back,
 *      encrypt a payload to it, build the VAPID header for it.
 *      Oracles: an endpoint the check accepts must not name a loopback /
 *      private / link-local address by any spelling inet_aton/inet_pton
 *      accept (F19); the VAPID JWT payload must be valid JSON whose "aud"
 *      is the endpoint's origin (F20).
 *   1  stored record -> webpush_parse_subscription -> encrypt
 *   2  base64url: webpush.c's decoder vs webpush_keyring.c's (two
 *      implementations of the same codec in the tree)
 */
#include "config.h"
#include "webpush.h"
#include "webpush_keyring.h"
#include "fuzz_util.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <jansson.h>

int fz_is_valid_endpoint(const char *e);
int fz_parse_keys(const char *k, char *p, size_t ps, char *a, size_t as);

#include "../../../ircd/webpush.c"

static struct wp_key *test_key;

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
  unsigned char priv[64];
  size_t pl = sizeof priv;
  char id[WEBPUSH_KEY_ID_LEN + 1];
  (void)argc; (void)argv;
  if (webpush_key_generate(priv, &pl, id, sizeof id) != 0) abort();
  if (webpush_key_load(priv, pl, id, NULL, 0) != 0) abort();
  test_key = wp_key_find(id);
  if (!test_key) abort();
  return 0;
}

/* host of an https URL per RFC 3986 (userinfo, port, path, query,
 * fragment and IPv6 brackets stripped) */
static void url_host(const char *u, char *h, size_t hs)
{
  const char *s = strstr(u, "://"), *e, *at;
  size_t n;
  h[0] = 0;
  if (!s) return;
  s += 3;
  e = s + strcspn(s, "/?#");
  at = memchr(s, '@', e - s);
  while (at) { s = at + 1; at = memchr(s, '@', e - s); }
  if (*s == '[') {
    const char *rb = memchr(s, ']', e - s);
    if (!rb) return;
    n = rb - s - 1;
    if (n >= hs) return;
    memcpy(h, s + 1, n);
    h[n] = 0;
    return;
  }
  {
    const char *c = memchr(s, ':', e - s);
    if (c) e = c;
  }
  n = e - s;
  if (n >= hs) return;
  memcpy(h, s, n);
  h[n] = 0;
}

static int host_is_internal(const char *h)
{
  struct in_addr a4;
  unsigned char a6[16];
  char lower[256];
  size_t i;
  for (i = 0; h[i] && i < sizeof lower - 1; i++) lower[i] = (char)tolower((unsigned char)h[i]);
  lower[i] = 0;
  if (!strcmp(lower, "localhost") || !strcmp(lower, "localhost.")) return 1;
  if (inet_aton(h, &a4)) {           /* every numeric IPv4 spelling */
    uint32_t v = ntohl(a4.s_addr);
    return (v >> 24) == 127 || (v >> 24) == 10 || (v >> 24) == 0 ||
           (v >> 16) == 0xC0A8 || (v >> 20) == 0xAC1 || (v >> 16) == 0xA9FE;
  }
  if (inet_pton(AF_INET6, h, a6) == 1) {
    static const unsigned char lo[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
    if (!memcmp(a6, lo, 16)) return 1;
    if (a6[0] == 0xfe && (a6[1] & 0xc0) == 0x80) return 1;
    if ((a6[0] & 0xfe) == 0xfc) return 1;
    if (!memcmp(a6, "\0\0\0\0\0\0\0\0\0\0\xff\xff", 12))
      return a6[12] == 127 || a6[12] == 10 || (a6[12] == 192 && a6[13] == 168) ||
             (a6[12] == 172 && (a6[13] & 0xf0) == 16);
  }
  return 0;
}

static void check_vapid(const char *endpoint)
{
  char hdr[2048], *jwt, *dot1, *dot2, *pl;
  unsigned char raw[1024];
  size_t rl = 0;
  json_t *j;
  if (create_vapid_header(endpoint, test_key, hdr, sizeof hdr) != 0) return;
  /* "vapid t=<jwt>, k=<key>" */
  jwt = strstr(hdr, "t=");
  if (!jwt) return;
  jwt += 2;
  dot1 = strchr(jwt, '.');
  if (!dot1) return;
  dot2 = strchr(dot1 + 1, '.');
  if (!dot2) return;
  pl = strndup(dot1 + 1, dot2 - dot1 - 1);
  CHECK(base64url_decode(pl, strlen(pl), raw, sizeof raw - 1, &rl) == 0);
  raw[rl] = 0;
  if (getenv("FUZZ_DUMP")) fprintf(stderr, "VAPID payload: %s\n", raw);
  j = json_loads((char *)raw, 0, NULL);
  int plain = 1;
  const unsigned char *q;
  for (q = (const unsigned char *)endpoint; *q; q++)
    if (*q < 0x21 || *q > 0x7e || *q == '"' || *q == '\\') plain = 0;
  if (!fuzz_strict() && !plain) {
    /* F20 (FINDINGS.md): the endpoint is pasted into the JSON unescaped */
  } else {
    const char *s = strstr(endpoint, "://"), *e;
    size_t olen;
    CHECK(j != NULL);
    e = strchr(s + 3, '/');
    olen = e ? (size_t)(e - endpoint) : strlen(endpoint);
    CHECK(json_is_string(json_object_get(j, "aud")));
    CHECK(strlen(json_string_value(json_object_get(j, "aud"))) == olen);
    CHECK(!strncmp(json_string_value(json_object_get(j, "aud")), endpoint, olen));
  }
  json_decref(j);
  free(pl);
}

static void try_encrypt(const struct webpush_subscription *sub, const uint8_t *msg, size_t ml)
{
  unsigned char out[WEBPUSH_MAX_PAYLOAD + 256];
  size_t ol = sizeof out;
  if (ml == 0 || ml > WEBPUSH_MAX_PAYLOAD) return;
  if (webpush_encrypt(sub, msg, ml, out, &ol) == 0)
    CHECK(ol == 86 + ml + 1 + 16);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  const char *p = (const char *)data + 1, *end = (const char *)data + size;
  if (size < 1) return 0;
  switch (data[0] % 3) {
  case 0: {
    char *endpoint = fuzz_field(&p, end), *keys = fuzz_field(&p, end);
    char p256dh[128], auth[64], stored[4096], host[256];
    struct webpush_subscription sub;
    if (fz_is_valid_endpoint(endpoint)) {
      url_host(endpoint, host, sizeof host);
      if (!fuzz_strict() && host_is_internal(host)) {
        /* F19 (FINDINGS.md): the denylist is substring-based */
      } else if (host_is_internal(host)) {
        fprintf(stderr, "internal endpoint accepted: %s (host %s)\n", endpoint, host);
        abort();
      }
      check_vapid(endpoint);
      if (fz_parse_keys(keys, p256dh, sizeof p256dh, auth, sizeof auth)) {
        snprintf(stored, sizeof stored, "%s|%s|%s|%lld|%s", endpoint, p256dh, auth,
                 1700000000LL, test_key->id);
        if (webpush_parse_subscription(stored, &sub) == 0) {
          if (!strchr(endpoint, '|')) CHECK(!strcmp(sub.endpoint, endpoint));
          try_encrypt(&sub, (const uint8_t *)"hello", 5);
        }
      }
    }
    free(endpoint); free(keys);
    break;
  }
  case 1: {
    char *rec = fuzz_field(&p, end);
    struct webpush_subscription sub;
    if (webpush_parse_subscription(rec, &sub) == 0) {
      CHECK(sub.p256dh_len == 65 && sub.auth_len == 16);
      try_encrypt(&sub, (const uint8_t *)p, (size_t)(end - p));
    }
    free(rec);
    break;
  }
  case 2: {
    unsigned char a[400], b[400];
    size_t al = 0, bl = 0, n = end - p;
    int ra, rb;
    if (n > 500) n = 500;
    ra = base64url_decode(p, n, a, sizeof a, &al);
    rb = webpush_b64url_decode(p, n, b, sizeof b, &bl);
    /* explicit '=' padding: webpush.c counts it as data (noted in
     * FINDINGS.md); compared on unpadded input only */
    if (ra == 0 && rb == 0 && (!memchr(p, '=', n) || fuzz_strict()))
      CHECK(al == bl && !memcmp(a, b, al));
    /* verdicts may differ on non-canonical input; report only crashes */
    break;
  }
  }
  return 0;
}
