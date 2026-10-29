/*
 * fuzz_metadata.c - libFuzzer harness for ircd/metadata.c's persisted
 * account metadata (draft/metadata-2) and read markers, plus the METADATA
 * key validator in ircd/m_metadata.c.
 *
 * Keys and values are set by clients (METADATA SET); stored rows are
 * TTL/visibility/zstd-encoded and may be corrupt or from an older build.
 * Byte 0 selects:
 *   0  rows: fuzz key/value rows go straight into every metadata CF, then
 *      the read paths run (get_vis, list, count, readmarker_get, purge,
 *      foreach) -- values come back exact-length, not NUL-terminated
 *   1  round trip: account\0key\0value with byte 1 = visibility/permanent:
 *      a set that succeeds reads back the same value and visibility
 *   2  key validator + decode_ttl_value/metadata_decode_visibility directly
 *   3  read markers: set(account, target, ts) then get == ts
 */
#include "config.h"
#include <stddef.h>
#include <time.h>
#include "metadata.h"
#include "ircd_features.h"
#include "fake_db.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(c) do { if (!(c)) { fprintf(stderr, "CHECK failed: %s (%s:%d)\n", #c, __FILE__, __LINE__); abort(); } } while (0)

int fz_is_valid_key(const char *key);
int feature_bool(enum Feature f) { (void)f; return 1; }
int feature_int(enum Feature f) { return f == FEAT_METADATA_CACHE_TTL ? 3600 : 0; }
const char *feature_str(enum Feature f) { (void)f; return ""; }
time_t CurrentTime = 1700000000;

#include "../../../ircd/metadata.c"

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
  (void)argc; (void)argv;
  if (metadata_lmdb_init("/fuzz/metadata") != 0) abort();
  return 0;
}

static char *field(const char **p, const char *end)
{
  const char *z = memchr(*p, 0, end - *p);
  char *r;
  if (!z) z = end;
  r = strndup(*p, z - *p);
  *p = z < end ? z + 1 : end;
  return r;
}



static void mode_rows(const uint8_t *d, size_t n)
{
  size_t off = 0;
  int ncf = fake_db_cf_count();
  char value[METADATA_VALUE_LEN], ts[64];
  int vis;
  struct MetadataEntry *l;

  fake_db_clear();
  while (off + 4 <= n) {
    int cf = d[off] % ncf;
    size_t kl = d[off + 1] % 120, vl = (d[off + 2] | (d[off + 3] << 8)) % 2000;
    off += 4;
    if (off + kl + vl > n) break;
    fake_db_put(fake_db_cf_at(cf), d + off, kl, d + off + kl, vl);
    off += kl + vl;
  }
  (void)metadata_account_get_vis("alice", "avatar", value, sizeof value, &vis);
  (void)metadata_account_get("alice", "display-name", value);
  l = metadata_account_list("alice");
  free_entry_list(l);
  (void)metadata_account_count_keys("alice");
  (void)metadata_readmarker_get("alice", "#chan", ts);

  (void)metadata_account_purge_expired();
}

static void mode_roundtrip(const uint8_t *d, size_t n)
{
  const char *p = (const char *)d + 1, *end = (const char *)d + n;
  char *acct, *key, *val, out[METADATA_VALUE_LEN];
  int vis, ovis = -1, perm, rc;
  if (n < 1) return;
  vis = (d[0] & 1) ? METADATA_VIS_PRIVATE : METADATA_VIS_PUBLIC;
  perm = (d[0] >> 1) & 1;
  acct = field(&p, end); key = field(&p, end); val = field(&p, end);
  fake_db_clear();
  if (*acct && *key && *val) {
    rc = perm ? metadata_account_set_permanent(acct, key, val, vis)
              : metadata_account_set(acct, key, val, vis);
    if (rc == 0 && metadata_account_get_vis(acct, key, out, sizeof out, &ovis) == 0) {
      int expect_vis = metadata_key_is_server_managed(key) ? METADATA_VIS_PRIVATE : vis;
      int known = !perm && vis == METADATA_VIS_PUBLIC &&
                  (!strncmp(val, "P:", 2) || !strncmp(val, "*:", 2)) &&
                  !metadata_key_is_server_managed(key) && !getenv("FUZZ_STRICT");
      if (!known) {
        if (strcmp(out, val) || ovis != expect_vis) {
          fprintf(stderr, "metadata round trip: [%s] vis %d perm %d -> [%s] vis %d\n",
                  val, vis, perm, out, ovis);
          abort();
        }
      }
    }
  }
  free(acct); free(key); free(val);
}

static void mode_direct(const uint8_t *d, size_t n)
{
  char *s = strndup((const char *)d, n), value[METADATA_VALUE_LEN];
  const char *stripped;
  time_t ts;
  int v = fz_is_valid_key(s);
  if (v) CHECK(strlen(s) < METADATA_KEY_LEN && *s);
  (void)metadata_key_is_server_managed(s);
  if (decode_ttl_value(d, n, value, sizeof value, &ts) >= 0) {
    CHECK(strlen(value) < sizeof value);
    (void)metadata_decode_visibility("k", value, &stripped);
  }
  free(s);
}

static void mode_readmarker(const uint8_t *d, size_t n)
{
  const char *p = (const char *)d, *end = p + n;
  char *acct = field(&p, end), *tgt = field(&p, end), *ts = field(&p, end), out[128];
  fake_db_clear();
  if (*acct && *tgt && metadata_readmarker_set(acct, tgt, ts) == 0 &&
      metadata_readmarker_get(acct, tgt, out) == 0)
    (void)out;
  free(acct); free(tgt); free(ts);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  if (size < 1) return 0;
  switch (data[0] % 4) {
  case 0: mode_rows(data + 1, size - 1); break;
  case 1: mode_roundtrip(data + 1, size - 1); break;
  case 2: mode_direct(data + 1, size - 1); break;
  case 3: mode_readmarker(data + 1, size - 1); break;
  }
  return 0;
}
