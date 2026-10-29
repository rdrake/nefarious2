/*
 * fuzz_webpush_keyring.c - libFuzzer harness for ircd/webpush_keyring.c:
 * VAPID key records persisted in RocksDB and relayed between servers
 * (webpush_key_parse), the subscription record key-id extractor, and the
 * base64url codec the crypto layer uses on client-supplied p256dh/auth keys.
 * Byte 0 selects:
 *   0  webpush_key_parse(id, text) -> format -> parse round trip
 *   1  webpush_record_key_id on a stored subscription record
 *   2  b64url decode of client text; decode(encode(x)) == x
 *   3  ring operations from an op stream (add/remove/find/current/prune)
 */
#include "webpush_keyring.h"
#include "fuzz_util.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  const char *p = (const char *)data + 1, *end = (const char *)data + size;
  if (size < 1) return 0;
  switch (data[0] % 4) {
  case 0: {
    char *id = fuzz_field(&p, end), *text = fuzz_field(&p, end), buf[WEBPUSH_KEY_TEXT_LEN + 64];
    struct webpush_key k, k2;
    if (webpush_key_parse(id, text, &k) == 0) {
      CHECK(strlen(k.id) <= WEBPUSH_KEY_ID_LEN && strlen(k.origin) <= WEBPUSH_KEY_ORIGIN_LEN);
      if (webpush_key_format(&k, buf, sizeof buf) >= 0) {
        CHECK(strlen(buf) < sizeof buf);
        CHECK(webpush_key_parse(k.id, buf, &k2) == 0);
        CHECK(!memcmp(k.priv, k2.priv, sizeof k.priv));
        CHECK(k.generation == k2.generation && k.created == k2.created);
        CHECK(!strcmp(k.origin, k2.origin) && k.manual == k2.manual);
      }
    }
    free(id); free(text);
    break;
  }
  case 1: {
    char *rec = fuzz_field(&p, end), out[WEBPUSH_KEY_ID_LEN + 1];
    size_t osz = 1 + (size % (WEBPUSH_KEY_ID_LEN + 1));
    if (webpush_record_key_id(rec, out, osz) == 0)
      CHECK(strlen(out) < osz);
    free(rec);
    break;
  }
  case 2: {
    unsigned char dec[512], dec2[512];
    char enc[1024];
    size_t dl = 0, dl2 = 0, n = end - p;
    if (n > 600) n = 600;
    if (webpush_b64url_decode(p, n, dec, sizeof dec, &dl) == 0) {
      int el = webpush_b64url_encode(dec, dl, enc, sizeof enc);
      CHECK(el >= 0 && strlen(enc) == (size_t)el);
      CHECK(webpush_b64url_decode(enc, el, dec2, sizeof dec2, &dl2) == 0);
      CHECK(dl2 == dl && !memcmp(dec, dec2, dl));
    }
    if (n <= 300) {
      int el = webpush_b64url_encode((const unsigned char *)p, n, enc, sizeof enc);
      if (el >= 0) {
        CHECK(webpush_b64url_decode(enc, el, dec2, sizeof dec2, &dl2) == 0);
        CHECK(dl2 == n && !memcmp(dec2, p, n));
      }
    }
    break;
  }
  case 3: {
    static struct webpush_keyring ring;
    webpush_keyring_init(&ring);
    while (p + 3 <= end) {
      struct webpush_key k;
      char id[8];
      int op = p[0] % 4;
      memset(&k, 0, sizeof k);
      snprintf(id, sizeof id, "k%02x", (unsigned char)p[1]);
      strcpy(k.id, id);
      k.generation = (unsigned char)p[2];
      k.created = (unsigned char)p[2] * 1000;
      strcpy(k.origin, "srv");
      switch (op) {
      case 0: (void)webpush_keyring_add(&ring, &k); break;
      case 1: (void)webpush_keyring_remove(&ring, id); break;
      case 2: { const struct webpush_key *c = webpush_keyring_current(&ring);
                if (c) CHECK(webpush_keyring_find(&ring, c->id) != NULL); break; }
      case 3: { struct webpush_key *f = webpush_keyring_find(&ring, id);
                if (f) (void)webpush_key_prunable(&ring, f, 100000, 3600, 60); break; }
      }
      CHECK(ring.count >= 0 && ring.count <= WEBPUSH_KEYRING_MAX);
      (void)webpush_keyring_next_generation(&ring);
      p += 3;
    }
    break;
  }
  }
  return 0;
}
