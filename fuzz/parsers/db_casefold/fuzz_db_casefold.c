/*
 * fuzz_db_casefold.c - libFuzzer harness for ircd/db_casefold.c: the key
 * folding every name-keyed store key goes through (channel/nick/account
 * names from clients) and the one-time key rewrite at open, which reads
 * every existing row (possibly corrupt, possibly from an older build).
 * Byte 0 = component mask; then a key.  Properties: db_casefold_key
 * output equals per-component db_casefold_bytes of the components the mask
 * selects (components are NUL-separated), is idempotent, and leaves the
 * separators and the length alone.  Then the rows are loaded into the fake
 * store and db_casefold_migrate runs over them.
 */
#include "config.h"
#include "db_types.h"
#include "db_env.h"
#include "db_casefold.h"
#include "fake_db.h"
#include "ircd_chattr.h"
#include "fuzz_util.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  static struct db_env *env;
  static struct db_cf *cf;
  unsigned mask;
  char out[600], out2[600];
  size_t kl;
  int r;
  if (size < 2) return 0;
  if (!env) { db_env_open("/fuzz/cf", NULL, 4, &env); db_cf_open(env, "rows", NULL, &cf); }
  mask = data[0] == 0xff ? DB_CASEFOLD_ALL : data[0];
  kl = size - 1 > 512 ? 512 : size - 1;
  r = db_casefold_key(mask, data + 1, kl, out, sizeof out);
  if (r >= 0) {
    size_t i, comp = 0, start = 0;
    CHECK((size_t)r == kl);
    for (i = 0; i <= kl; i++) {
      if (i == kl || data[1 + i] == 0) {
        char ref[600];
        if (mask == DB_CASEFOLD_ALL || (comp < 32 && (mask & (1u << comp)))) {
          db_casefold_bytes(ref, (const char *)data + 1 + start, i - start);
          CHECK(!memcmp(out + start, ref, i - start));
        } else {
          CHECK(!memcmp(out + start, data + 1 + start, i - start));
        }
        if (i < kl) CHECK(out[i] == 0);
        comp++; start = i + 1;
      }
    }
    CHECK(db_casefold_key(mask, out, kl, out2, sizeof out2) == r);
    CHECK(!memcmp(out, out2, kl));
  }
  /* migrate over rows taken from the input */
  fake_db_clear();
  {
    size_t off = 1;
    while (off + 2 <= size) {
      size_t k = data[off] % 40, v = data[off + 1] % 40;
      off += 2;
      if (off + k + v > size) break;
      fake_db_put(cf, data + off, k, data + off + k, v);
      off += k + v;
    }
  }
  {
    struct db_casefold_cf cfs[1];
    cfs[0].cf = cf;
    cfs[0].name = "rows";
    cfs[0].mask = mask;
    (void)db_casefold_migrate(env, "fuzz", cfs, 1);
  }
  return 0;
}
