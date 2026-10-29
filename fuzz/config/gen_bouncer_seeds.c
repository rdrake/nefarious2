/* Emit seed records for fuzz_bouncer: one plausible, unexpired record per
 * on-disk layout v7..v12 (include/bouncer_session.h), plus multi-record
 * inputs (same account twice, two accounts).  Built and run by run.sh.
 *
 *   gen_bouncer_seeds OUTDIR
 */
#include "config.h"
#include "bouncer_session.h"
#include "fuzz_common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define REC_SEP "\xff" "BSR" "\xff"

#define S(f, v) strncpy((f), (v), sizeof(f) - 1)

#define FILL_COMMON(r, ver, n)                                           \
  do {                                                                   \
    int _i;                                                              \
    memset(&(r), 0, sizeof(r));                                          \
    (r).bsr_version = (ver);                                             \
    S((r).bsr_account, (n) ? "acct2" : "acct");                          \
    S((r).bsr_sessid, (n) ? "AZbCdEfGhIjKlMnOpQrStU" : "AYbCdEfGhIjKlMnOpQrStU"); \
    S((r).bsr_token, "tok0123456789abcdef");                             \
    S((r).bsr_name, "laptop");                                           \
    S((r).bsr_origin, "AB");                                             \
    (r).bsr_created = FUZZ_NOW - 86400;                                  \
    (r).bsr_disconnect_time = FUZZ_NOW - 30;                             \
    (r).bsr_last_active = FUZZ_NOW - 60;                                 \
    (r).bsr_last_msg_time = FUZZ_NOW - 90;                               \
    (r).bsr_total_active = 3600;                                         \
    (r).bsr_attach_count = 3;                                            \
    (r).bsr_connect_count = 4;                                           \
    S((r).bsr_nick, (n) ? "ghost2" : "ghost");                           \
    S((r).bsr_username, "~user");                                        \
    S((r).bsr_realhost, "host.example.org");                             \
    S((r).bsr_host, "acct.users.example.net");                           \
    S((r).bsr_realname, "Real Name");                                    \
    S((r).bsr_account_name, (n) ? "acct2" : "acct");                     \
    (r).bsr_acc_create = FUZZ_NOW - 999999;                              \
    S((r).bsr_sock_ip, "192.0.2.7");                                     \
    S((r).bsr_sockhost, "host.example.org");                             \
    (r).bsr_listener_port = 6697;                                        \
    (r).bsr_histcount = 2;                                               \
    for (_i = 0; _i < 2; _i++) {                                         \
      S((r).bsr_history[_i].bch_ip, "192.0.2.7");                        \
      S((r).bsr_history[_i].bch_host, "host.example.org");               \
      (r).bsr_history[_i].bch_last_connect = FUZZ_NOW - 100;             \
      (r).bsr_history[_i].bch_count = 2;                                 \
    }                                                                    \
    (r).bsr_chancount = 3;                                               \
    S((r).bsr_channels[0].name, "#chan");                                \
    (r).bsr_channels[0].modes = 1;                                       \
    (r).bsr_channels[0].join_tv_sec = FUZZ_NOW - 500;                    \
    memcpy((r).bsr_channels[0].join_msgid, "0123456789abcdef", 16);      \
    S((r).bsr_channels[1].name, "#other");                               \
    S((r).bsr_channels[2].name, "&local");                               \
  } while (0)

#define FILL_ALIASES(r, cnt)                                             \
  do {                                                                   \
    (r).bsr_aliascount = (cnt);                                          \
    S((r).bsr_aliases[0].bsar_numeric, "ABAAA");                         \
    S((r).bsr_aliases[0].bsar_server, "AB");                             \
    (r).bsr_aliases[0].bsar_caps = 5;                                    \
    (r).bsr_aliases[0].bsar_last_active = FUZZ_NOW - 5;                  \
    S((r).bsr_aliases[1].bsar_numeric, "ABAAB");                         \
    S((r).bsr_aliases[1].bsar_server, "AB");                             \
  } while (0)

static const char *outdir;
static int seq;

static void emit2(const void *a, size_t alen, const void *b, size_t blen)
{
  char path[1024];
  FILE *f;
  snprintf(path, sizeof(path), "%s/seed-%03d", outdir, seq++);
  f = fopen(path, "wb");
  if (!f) { perror(path); exit(1); }
  fwrite(a, 1, alen, f);
  if (b) {
    fwrite(REC_SEP, 1, sizeof(REC_SEP) - 1, f);
    fwrite(b, 1, blen, f);
  }
  fclose(f);
}
#define EMIT(r) emit2(&(r), sizeof(r), NULL, 0)

int main(int argc, char **argv)
{
  static struct BounceSessionRecord_v7 r7;
  static struct BounceSessionRecord_v8 r8;
  static struct BounceSessionRecord_v9 r9;
  static struct BounceSessionRecord_v10 r10;
  static struct BounceSessionRecord_v11 r11;
  static struct BounceSessionRecord r12, r12b;

  if (argc != 2) { fprintf(stderr, "usage: %s OUTDIR\n", argv[0]); return 2; }
  outdir = argv[1];

  FILL_COMMON(r7, 7, 0);
  strcpy(r7.bsr_sessid, "legacy-sessid");
  EMIT(r7);

  FILL_COMMON(r8, 8, 0);  FILL_ALIASES(r8, 2);  EMIT(r8);
  FILL_COMMON(r9, 9, 0);  FILL_ALIASES(r9, 2);
  S(r9.bsr_oper_name, "fuzzoper"); r9.bsr_oper_granted_at = FUZZ_NOW - 50;
  EMIT(r9);
  FILL_COMMON(r10, 10, 0); FILL_ALIASES(r10, 2);
  S(r10.bsr_oper_name, "fuzzoper"); EMIT(r10);
  FILL_COMMON(r11, 11, 0); FILL_ALIASES(r11, 2);
  S(r11.bsr_oper_name, "fuzzoper");
  r11.bsr_snomask = 0x1234; r11.bsr_snomask_known = 1; EMIT(r11);

  FILL_COMMON(r12, BOUNCER_DB_VERSION, 0); FILL_ALIASES(r12, 2);
  S(r12.bsr_oper_name, "fuzzoper");
  r12.bsr_snomask = 0x1234; r12.bsr_snomask_known = 1;
  S(r12.bsr_kc_id, "0123456789abcdefghijkl");
  EMIT(r12);
  /* not opered, no aliases, a local (our server "AB"? we are numeric 1
   * = "AB") alias that restore must skip */
  r12b = r12;
  r12b.bsr_oper_name[0] = '\0';
  S(r12b.bsr_aliases[0].bsar_server, "AB");
  r12b.bsr_aliascount = 1;
  EMIT(r12b);
  /* expired */
  r12b = r12; r12b.bsr_disconnect_time = 0; EMIT(r12b);
  /* two sessions, same account; then two accounts */
  r12b = r12; S(r12b.bsr_sessid, "AZZZZZZZZZZZZZZZZZZZZZ"); S(r12b.bsr_nick, "ghostb");
  emit2(&r12, sizeof(r12), &r12b, sizeof(r12b));
  FILL_COMMON(r12b, BOUNCER_DB_VERSION, 1);
  emit2(&r12, sizeof(r12), &r12b, sizeof(r12b));
  /* v7 + v12 mix */
  emit2(&r7, sizeof(r7), &r12, sizeof(r12));
  /* truncated / wrong-size records */
  emit2(&r12, sizeof(r12) - 1, NULL, 0);
  emit2(&r12, 4, NULL, 0);
  fprintf(stderr, "wrote %d bouncer seeds (v12 record = %zu bytes)\n", seq,
          sizeof(r12));
  return 0;
}
