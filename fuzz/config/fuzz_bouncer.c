/* libFuzzer target: persisted bouncer session records.
 *
 * Feeds arbitrary bytes as the stored value of bouncer-session records
 * (v7..v12 BounceSessionRecord layouts, include/bouncer_session.h) in the
 * metadata RocksDB "bouncer" column family, then runs the real startup
 * restore, bounce_db_restore(): version dispatch, the frozen-layout
 * migrations, ghost creation, channel re-join, alias roster and oper
 * grant.  This is what happens at boot when the DB holds a record from an
 * older/newer build or a torn write.
 *
 * Input: up to MAX_RECORDS values separated by REC_SEP, each written under
 * its own key.  The bouncer_session.c translation unit is #included so the
 * harness can reach its static session hashes and tear every restored
 * session down after each iteration; link everything except
 * bouncer_session.o.
 */
#include "bouncer_session.c"  /* from ircd/ (on the -I path) */

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
  "};\n";

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

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  struct db_env *env = metadata_get_env();
  struct db_cf *cf = metadata_get_bouncer_cf();
  struct db_writebatch *wb;
  const uint8_t *p = data, *end = data + size;
  int nrec = 0;

  CurrentTime = FUZZ_NOW;
  wipe_cf(env, cf);
  wb = db_writebatch_new(env);
  while (nrec < MAX_RECORDS) {
    const uint8_t *sep = memmem(p, end - p, REC_SEP, sizeof(REC_SEP) - 1);
    const uint8_t *stop = sep ? sep : end;
    char key[32];
    int klen = snprintf(key, sizeof(key), "fuzzsess%d", nrec);
    db_writebatch_put(wb, cf, key, klen, p, stop - p);
    nrec++;
    if (!sep)
      break;
    p = sep + sizeof(REC_SEP) - 1;
  }
  db_writebatch_commit(wb, 0);
  db_writebatch_destroy(wb);

  {
    int restored = bounce_db_restore();
    if (getenv("FUZZ_VERBOSE"))
      fprintf(stderr, "fuzz_bouncer: %d record(s), restored %d\n", nrec,
              restored);
  }
  destroy_all_sessions();
  fuzz_sandbox_trim();
  return 0;
}
