/*
 * fuzz_webpush_store.c - libFuzzer harness for ircd/webpush_store.c: the
 * per-account push subscriptions and the VAPID key ring persisted in
 * RocksDB (possibly corrupt or from an older build).  Rows from the input
 * go straight into the store's CFs (common/fake_db.c); then every read
 * path runs (get, foreach, foreach_all, cfg_get, key_foreach,
 * get_vapid_key, count) and each record is handed to the consumer the
 * ircd hands it to: webpush_parse_subscription, webpush_record_key_id,
 * webpush_armed_at, webpush_key_parse.
 */
#include "config.h"
#include "webpush_store.h"
#include "webpush.h"
#include "webpush_keyring.h"
#include "webpush_expiry.h"
#include "fake_db.h"
#include "fuzz_util.h"

int webpush_parse_subscription(const char *stored, struct webpush_subscription *sub);

static int on_sub(const char *stored, void *d)
{
  struct webpush_subscription sub;
  char kid[WEBPUSH_KEY_ID_LEN + 1];
  (void)d;
  (void)webpush_parse_subscription(stored, &sub);
  (void)webpush_record_key_id(stored, kid, sizeof kid);
  (void)webpush_armed_at(stored);
  return 0;
}
static int on_any(const char *account, const char *stored, void *d)
{
  (void)account;
  return on_sub(stored, d);
}
static int on_key(const char *id, const char *text, void *d)
{
  struct webpush_key k;
  (void)d;
  (void)webpush_key_parse(id, text, &k);
  return 0;
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
  (void)argc; (void)argv;
  if (webpush_store_init("/fuzz/webpush") != 0) abort();
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  size_t off = 0;
  int ncf = fake_db_cf_count();
  char out[4096];
  size_t ol;
  unsigned char priv[64];
  size_t pl = sizeof priv;
  fake_db_clear();
  while (off + 4 <= size) {
    int cf = data[off] % ncf;
    size_t kl = data[off + 1] % 160, vl = (data[off + 2] | (data[off + 3] << 8)) % 5000;
    off += 4;
    if (off + kl + vl > size) break;
    fake_db_put(fake_db_cf_at(cf), data + off, kl, data + off + kl, vl);
    off += kl + vl;
  }
  if (webpush_store_get("alice", "https://push.example/x", out, sizeof out) == 0)
    on_sub(out, NULL);
  (void)webpush_store_foreach("alice", on_sub, NULL);
  (void)webpush_store_foreach_all(on_any, NULL);
  (void)webpush_store_count("alice");
  (void)webpush_store_cfg_get("vapid_privkey", out, sizeof out, &ol);
  (void)webpush_store_key_foreach(on_key, NULL);
  (void)webpush_store_get_vapid_key(priv, &pl);
  return 0;
}
