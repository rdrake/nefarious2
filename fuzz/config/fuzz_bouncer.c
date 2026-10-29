/* libFuzzer targets: persisted bouncer session records (fuzz_bouncer) and,
 * built with -DFUZZ_RECORDS, keyed records in three column families of
 * the metadata RocksDB (fuzz_records).
 *
 * Feeds arbitrary bytes as the stored value of bouncer-session records
 * (v7..v12 BounceSessionRecord layouts, include/bouncer_session.h) in the
 * metadata RocksDB "bouncer" column family, then runs the real startup
 * restore, bounce_db_restore(): version dispatch, the frozen-layout
 * migrations, ghost creation, channel re-join, alias roster and oper
 * grant.  This is what happens at boot when the DB holds a record from an
 * older/newer build or a torn write.
 *
 * fuzz_bouncer input: up to MAX_RECORDS values separated by REC_SEP, each
 * written under its own key in the bouncer CF.
 *
 * fuzz_records input: up to MAX_RECORDS chunks separated by REC_SEP, each
 *   [cf selector byte][key length byte][key][value]
 * selector % 3: 0 = bouncer_sessions, 1 = presence (presence_record, keyed
 * "<account>\0<channel>"), 2 = metadata ("<account>\0<key>" -> "T<ts>|v",
 * optionally zstd behind COMPRESS_MAGIC).  Then the boot readers run in
 * ircd.c order: presence_init() (boot-close of open intervals), then
 * bounce_db_restore(), whose ghosts load their account's metadata through
 * metadata_load_account().  The bouncer_session.c translation unit is #included so the
 * harness can reach its static session hashes and tear every restored
 * session down after each iteration; link everything except
 * bouncer_session.o.
 */
#include "bouncer_session.c"  /* from ircd/ (on the -I path) */

#include "chathistory_presence.h"
#include "db_cursor.h"
#include "db_txn.h"
#include "s_conf.h"
#include "fuzz_common.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define REC_SEP "\xff" "BSR" "\xff"
#define MAX_RECORDS 4

static const char bouncer_conf[] =
  "General { name = \"fuzz.example.net\"; description = \"fuzz\"; numeric = 1; };\n"
  "Class { name = \"Local\"; pingfreq = 1 minutes; sendq = 160000; maxlinks = 100; };\n"
  "Client { class = \"Local\"; ip = \"*\"; host = \"*\"; };\n"
  "Class { name = \"Opers\"; pingfreq = 1 minutes; sendq = 160000; maxlinks = 10; };\n"
  "Operator { name = \"fuzzoper\"; host = \"*@*\"; password = \"x\"; class = \"Opers\"; local = no; };\n"
  "Features {\n"
  "  \"BOUNCER_ENABLE\" = \"TRUE\";\n"
  "  \"BOUNCER_PERSIST\" = \"TRUE\";\n"
  "  \"CAP_draft_metadata_2\" = \"TRUE\";\n"
  "  \"CHATHISTORY_STRICT_PRESENCE\" = \"TRUE\";\n"
  "};\n";

/* RocksDB hands out values that point into a larger block buffer, so an
 * over-read past the end of one record is invisible to ASan.  Give the
 * restore code an exact-size heap copy of every value instead.  A copy
 * lives until the same iterator moves on (RocksDB's slice is invalidated
 * by db_iter_next too) or the input ends; iterators nest (ghost creation
 * reads metadata while the restore iterator's record is still in use). */
extern const void *__real_db_iter_value(const struct db_iter *it,
                                        size_t *vlen);
#define VALUE_SLOTS 16
static struct { const struct db_iter *it; void *buf; } value_copy[VALUE_SLOTS];

static void free_value_copies(void)
{
  int i;
  for (i = 0; i < VALUE_SLOTS; i++) {
    free(value_copy[i].buf);
    value_copy[i].buf = NULL;
    value_copy[i].it = NULL;
  }
}

const void *__wrap_db_iter_value(const struct db_iter *it, size_t *vlen)
{
  const void *v = __real_db_iter_value(it, vlen);
  int i, slot = -1;
  for (i = 0; i < VALUE_SLOTS; i++)
    if (value_copy[i].it == it) { slot = i; break; }
  if (slot < 0)
    for (i = 0; i < VALUE_SLOTS; i++)
      if (!value_copy[i].it) { slot = i; break; }
  if (slot < 0)
    abort();                    /* more live iterators than expected */
  free(value_copy[slot].buf);
  value_copy[slot].buf = NULL;
  value_copy[slot].it = it;
  if (!v)
    return v;
#ifdef FUZZ_UNMASK_KNOWN
  /* FUZZ_VALUE_OFFSET=n places the value n bytes into its allocation, as
   * RocksDB's block buffer does: with a KEEP_ALIGN=1 build that shows
   * FINDINGS.md F1 (struct overlays on unaligned values). */
  {
    static int off = -1;
    if (off < 0) {
      const char *e = getenv("FUZZ_VALUE_OFFSET");
      off = e ? atoi(e) & 7 : 0;
    }
    value_copy[slot].buf = malloc(*vlen + off ? *vlen + off : 1);
    memcpy((char *)value_copy[slot].buf + off, v, *vlen);
    return (char *)value_copy[slot].buf + off;
  }
#else
  /* FINDINGS.md F5: the v12 path reads the unterminated last field
   * (bsr_kc_id) past the record; one NUL after the copy masks it. */
  value_copy[slot].buf = calloc(1, *vlen + 1);
#endif
  memcpy(value_copy[slot].buf, v, *vlen);
  return value_copy[slot].buf;
}

static void wipe_cf(struct db_env *env, struct db_cf *cf)
{
  struct db_iter *it = db_iter_open(env, cf, NULL);
  struct db_writebatch *wb = db_writebatch_new(env);
  int rc;
  for (rc = db_iter_seek_first(it); rc == DB_OK && db_iter_valid(it);
       rc = db_iter_next(it)) {
    size_t klen;
    const void *k = db_iter_key(it, &klen);
    db_writebatch_del(wb, cf, k, klen);
  }
  db_iter_close(it);
  db_writebatch_commit(wb, 0);
  db_writebatch_destroy(wb);
}

/* Tear down every session the restore created, the way an expired hold
 * does (bounce_hold_expire, no-alias branch), without broadcasting. */
static void destroy_all_sessions(void)
{
  struct BouncerSession *list[1024];
  int n = 0, i;
  unsigned int b;

  for (b = 0; b < BOUNCE_ACCOUNT_HASHSIZE; b++) {
    struct AccountSessions *as;
    for (as = accountHash[b]; as; as = as->as_hnext) {
      struct BouncerSession *s;
      for (s = as->as_sessions; s && n < 1024; s = s->hs_anext)
        list[n++] = s;
    }
  }
  for (i = 0; i < n; i++) {
    struct BouncerSession *s = list[i];
    struct Client *ghost = s->hs_client;
    s->hs_state = BOUNCE_DESTROYING;
    s->hs_client = NULL;
    s->hs_alias_count = 0;
    if (ghost && IsBouncerHold(ghost)) {
#ifndef FUZZ_UNMASK_KNOWN
      /* FINDINGS.md F2: an empty bsr_nick restores a nameless ghost and
       * its exit asserts in doprintf().  Name it so the fuzzer can move
       * past the known bug (build with -DFUZZ_UNMASK_KNOWN to see it). */
      if (!*cli_name(ghost)) {
        hRemClient(ghost);
        strcpy(cli_name(ghost), "fuzzghost");
        hAddClient(ghost);
      }
#endif
      ClearBouncerHold(ghost);
      exit_client(ghost, ghost, &me, "fuzz teardown");
    }
    if (t_active(&s->hs_hold_timer)) {
      timer_del(&s->hs_hold_timer);   /* ET_DESTROY frees the session */
    } else {
      if (t_active(&s->hs_promote_timer))
        timer_del(&s->hs_promote_timer);
      token_hash_remove(s);
      account_remove_session(s);
      MyFree(s);
    }
  }
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
  (void)argc; (void)argv;
  fuzz_ircd_boot(bouncer_conf);
  if (metadata_lmdb_init("metadata.db") != 0 || !metadata_lmdb_is_available()) {
    fprintf(stderr, "fuzz: metadata db init failed\n");
    abort();
  }
  return 0;
}

#ifdef FUZZ_RECORDS
static struct db_cf *cfs[3];

static void open_cfs(struct db_env *env)
{
  static const char *const names[3] = { "bouncer_sessions", "presence",
                                        "metadata" };
  struct db_cf_opts o;
  int i;
  memset(&o, 0, sizeof(o));
  for (i = 0; i < 3; i++)
    if (!cfs[i] && db_cf_open(env, names[i], &o, &cfs[i]) != DB_OK) {
      fprintf(stderr, "fuzz: db_cf_open(%s) failed\n", names[i]);
      abort();
    }
}
#endif

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  struct db_env *env = metadata_get_env();
  struct db_cf *cf = metadata_get_bouncer_cf();
  struct db_writebatch *wb;
  const uint8_t *p = data, *end = data + size;
  int nrec = 0;

  CurrentTime = FUZZ_NOW;
#ifdef FUZZ_RECORDS
  open_cfs(env);
  wipe_cf(env, cfs[0]);
  wipe_cf(env, cfs[1]);
  wipe_cf(env, cfs[2]);
#else
  wipe_cf(env, cf);
#endif
  wb = db_writebatch_new(env);
  while (nrec < MAX_RECORDS) {
    const uint8_t *sep = memmem(p, end - p, REC_SEP, sizeof(REC_SEP) - 1);
    const uint8_t *stop = sep ? sep : end;
#ifdef FUZZ_RECORDS
    if (stop - p >= 2) {
      struct db_cf *tcf = cfs[p[0] % 3];
      size_t klen = p[1];
      if (klen > (size_t)(stop - p - 2))
        klen = stop - p - 2;
      if (klen > 0)
        db_writebatch_put(wb, tcf, p + 2, klen, p + 2 + klen,
                          stop - p - 2 - klen);
    }
#else
    char key[32];
    int klen = snprintf(key, sizeof(key), "fuzzsess%d", nrec);
    db_writebatch_put(wb, cf, key, klen, p, stop - p);
#endif
    nrec++;
    if (!sep)
      break;
    p = sep + sizeof(REC_SEP) - 1;
  }
  db_writebatch_commit(wb, 0);
  db_writebatch_destroy(wb);
#ifdef FUZZ_RECORDS
  presence_set_boot_alive_hint(0);
  presence_init();
#endif

  {
    int restored = bounce_db_restore();
    if (getenv("FUZZ_VERBOSE")) {
      struct db_iter *it = db_iter_open(env, cf, NULL);
      int left = 0, rc;
      for (rc = db_iter_seek_first(it); rc == DB_OK && db_iter_valid(it);
           rc = db_iter_next(it))
        left++;
      db_iter_close(it);
      fprintf(stderr, "fuzz_bouncer: %d record(s), restored %d, %d left in "
              "the store\n", nrec, restored, left);
    }
  }
  destroy_all_sessions();
  free_value_copies();
  fuzz_sandbox_trim();
  return 0;
}
