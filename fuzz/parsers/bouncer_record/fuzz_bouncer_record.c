/*
 * fuzz_bouncer_record.c - libFuzzer harness for the persisted bouncer
 * session records read back at startup by bounce_db_restore()
 * (ircd/bouncer_session.c): version dispatch over BounceSessionRecord v7..
 * v12, the frozen-layout migrations, the expiry arithmetic and the ghost
 * identity copy in bounce_create_ghost().  RocksDB values may be corrupt
 * or written by an older build.
 *
 * bouncer_session.c is #included with common/autostub.py fallbacks; the
 * record rows go into the bouncer CF of common/fake_db.c.  log_write()
 * formats its message with the real ircd_vsnprintf so a string field that
 * is not NUL-terminated inside the record is read the way the ircd would
 * read it.  SetLocalNumNick() refuses (as on a full server), so each
 * record stops after bounce_create_ghost() has copied its identity: no
 * session is registered and nothing accumulates across inputs.
 *
 * Input: repeated [version byte][2-byte length][bytes]; each record is
 * laid out at exactly the size its version expects (zero-padded or
 * truncated) with the version field set, so it passes the size gate.
 */
#include "config.h"
#include "client.h"
#include "struct.h"
#include "ircd_log.h"
#include "ircd_features.h"
#include "ircd_snprintf.h"
#include "fake_db.h"
#include "fuzz_util.h"
#include <stdarg.h>

time_t CurrentTime = 1700000000;
int feature_bool(enum Feature f) { (void)f; return 1; }
int feature_int(enum Feature f) { return f == FEAT_BOUNCER_MAX_HOLD ? 86400 * 7 : 0; }
const char *feature_str(enum Feature f) { (void)f; return ""; }

void log_write(enum LogSys subsys, enum LogLevel severity, unsigned int flags,
               const char *fmt, ...)
{
  char buf[1024];
  va_list ap;
  (void)subsys; (void)severity; (void)flags;
  va_start(ap, fmt);
  ircd_vsnprintf(0, buf, sizeof buf, fmt, ap);
  va_end(ap);
}

static struct db_env *fz_env;
static struct db_cf *fz_cf;
int metadata_lmdb_is_available(void) { return 1; }
struct db_env *metadata_get_env(void) { return fz_env; }
struct db_cf *metadata_get_bouncer_cf(void) { return fz_cf; }

static struct Client ghost_cli;
static struct Connection ghost_con;
static struct User ghost_user;
struct Client *make_client(struct Client *from, int status)
{
  (void)from; (void)status;
  memset(&ghost_cli, 0, sizeof ghost_cli);
  memset(&ghost_con, 0, sizeof ghost_con);
  cli_connect(&ghost_cli) = &ghost_con;
  return &ghost_cli;
}
struct User *make_user(struct Client *c)
{
  memset(&ghost_user, 0, sizeof ghost_user);
  cli_user(c) = &ghost_user;
  return &ghost_user;
}
int SetLocalNumNick(struct Client *c) { (void)c; return 0; }

#include "../../../ircd/bouncer_session.c"

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
  (void)argc; (void)argv;
  db_env_open("/fuzz/bouncer", NULL, 8, &fz_env);
  db_cf_open(fz_env, "bouncer", NULL, &fz_cf);
  strcpy(cli_yxx(&me), "AB");
  return 0;
}

static size_t rec_size(int v)
{
  switch (v) {
  case 7: return sizeof(struct BounceSessionRecord_v7);
  case 8: return sizeof(struct BounceSessionRecord_v8);
  case 9: return sizeof(struct BounceSessionRecord_v9);
  case 10: return sizeof(struct BounceSessionRecord_v10);
  case 11: return sizeof(struct BounceSessionRecord_v11);
  default: return sizeof(struct BounceSessionRecord);
  }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  size_t off = 0;
  int n = 0;
  fake_db_clear();
  while (off + 3 <= size && n < 8) {
    uint32_t v = 7 + data[off] % 7;          /* 7..12, 13 = unknown */
    size_t len = data[off + 1] | (data[off + 2] << 8), want;
    unsigned char *rec;
    char key[16];
    off += 3;
    if (len > size - off) len = size - off;
    want = v <= 12 ? rec_size(v) : 64;
    rec = calloc(1, want);
    memcpy(rec, data + off, len < want ? len : want);
    memcpy(rec, &v, sizeof v);
    /* F21 (FINDINGS.md): an unterminated bsr_kc_id (the record's last
     * field) is scanned past the value by account_id_valid(); terminated
     * here unless FUZZ_STRICT */
    if (v == 12 && !fuzz_strict())
      ((struct BounceSessionRecord *)rec)->bsr_kc_id[ACCOUNT_ID_LEN] = '\0';
    /* F22 (FINDINGS.md): CurrentTime - disconnect_time overflows for a
     * disconnect time near INT64_MIN; clamped unless FUZZ_STRICT */
#define CLAMP_DT(T) do { T *r_ = (T *)rec; \
      if (r_->bsr_disconnect_time < -(1LL << 62)) r_->bsr_disconnect_time = 0; } while (0)
    if (!fuzz_strict()) {
      switch (v) {
      case 7: CLAMP_DT(struct BounceSessionRecord_v7); break;
      case 8: CLAMP_DT(struct BounceSessionRecord_v8); break;
      case 9: CLAMP_DT(struct BounceSessionRecord_v9); break;
      case 10: CLAMP_DT(struct BounceSessionRecord_v10); break;
      case 11: CLAMP_DT(struct BounceSessionRecord_v11); break;
      case 12: CLAMP_DT(struct BounceSessionRecord); break;
      }
    }
    snprintf(key, sizeof key, "sess%d", n);
    fake_db_put(fz_cf, key, strlen(key), rec, want);
    free(rec);
    off += len;
    n++;
  }
  (void)bounce_db_restore();
  return 0;
}
