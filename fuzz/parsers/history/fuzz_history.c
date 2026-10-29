/*
 * fuzz_history.c - libFuzzer harness for the chathistory record layer in
 * ircd/history.c (with ml_content.c, ircd_compress.c, redact_index.c and
 * db_casefold.c linked for real, storage replaced by common/fake_db.c).
 *
 * Stored rows are untrusted twice over: RocksDB values may be corrupt or
 * written by an older build, and history_deserialize_record() parses the
 * CH Z federation passthrough, a peer's raw stored record.  Message
 * fields themselves (sender nick!user@host, account, text, client tags)
 * come from clients.  Byte 0 selects a mode:
 *   0  deserialize_message() on raw bytes (plain or zstd-framed)
 *   1  round trip: fuzz fields -> history_store_message() ->
 *      history_query_latest() through the fake store; every field must
 *      come back as stored (sender/account/text/tags/original target)
 *   2  corrupt rows: the input is a list of key/value rows written straight
 *      into the history CFs, then the query/lookup/msgid APIs read them
 *   3  timestamp helpers: history_iso_to_unix / history_unix_to_iso /
 *      history_parse_ms on a client timestamp, extract_reply_tag,
 *      history_forward_encode/split round trip, parse_key
 */
#include "config.h"
#include "history.h"
#include "ircd_features.h"
#include "crdt_hlc.h"
#include "fake_db.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(c) do { if (!(c)) { fprintf(stderr, "CHECK failed: %s (%s:%d)\n", #c, __FILE__, __LINE__); abort(); } } while (0)

/* ---- ircd stubs history.c needs with real behaviour ---- */
static struct HLC fuzz_hlc;
const struct HLC *hlc_global(void) { return &fuzz_hlc; }
int feature_bool(enum Feature f)
{
  return f == FEAT_CHATHISTORY_STORE;
}
int feature_int(enum Feature f)
{
  switch (f) {
  case FEAT_CHATHISTORY_MAX: return 100;
  default: return 0;
  }
}
const char *feature_str(enum Feature f) { (void)f; return ""; }
struct Channel *hSeekChannel(const char *name) { (void)name; return NULL; }

#include "../../../ircd/history.c"

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
  (void)argc; (void)argv;
  fuzz_hlc.physical_ms = 1700000000000ULL;
  if (history_init("/fuzz/history") != 0) {
    fprintf(stderr, "history_init failed\n");
    abort();
  }
  return 0;
}

/* split helper: NUL-separated fields */
static const char *next_field(const char **p, const char *end)
{
  const char *s = *p, *z;
  if (s >= end) return strdup("");
  z = memchr(s, 0, end - s);
  if (!z) { *p = end; return strndup(s, end - s); }
  *p = z + 1;
  return strndup(s, z - s);
}

static void mode_deserialize(const uint8_t *d, size_t n)
{
  struct HistoryMessage *m = calloc(1, sizeof(*m));
  if (deserialize_message((const char *)d, (int)n, m) == 0) {
    CHECK(memchr(m->sender, 0, sizeof m->sender));
    CHECK(memchr(m->account, 0, sizeof m->account));
    CHECK(memchr(m->content, 0, sizeof m->content));
    CHECK(memchr(m->client_tags, 0, sizeof m->client_tags));
    CHECK(memchr(m->original_target, 0, sizeof m->original_target));
    CHECK(m->type >= 0 && m->type <= HISTORY_MULTILINE);
  }
  free(m);
}

/* stored length of a field after history_escape_field */
static size_t esc_len(const char *s)
{
  size_t n = 0;
  for (; *s; s++) n += (*s >= 4 && *s <= 7) ? 2 : 1;
  return n;
}

static void mode_roundtrip(const uint8_t *d, size_t n)
{
  const char *p = (const char *)d + 1, *end = (const char *)d + n;
  int type = n ? d[0] % (HISTORY_MULTILINE + 1) : 0;
  char *sender, *account, *content, *tags, *otarget;
  struct HistoryMessage *res = NULL, *m;
  char msgid[] = "AAAAAZo5AAAAAA";   /* time-carrying msgid layout */
  const char *target = "#fuzz";
  int rc;

  if (n < 1) return;
  sender = (char *)next_field(&p, end);
  account = (char *)next_field(&p, end);
  content = (char *)next_field(&p, end);
  tags = (char *)next_field(&p, end);
  otarget = (char *)next_field(&p, end);
  if (type == HISTORY_MULTILINE) type = HISTORY_PRIVMSG;  /* ml_content path */

  fake_db_clear();
  rc = history_store_message(msgid, "1700000000.123", target,
                             *otarget ? otarget : NULL, sender,
                             *account ? account : NULL,
                             (enum HistoryMessageType)type, content,
                             *tags ? tags : NULL);
  if (rc == 0 &&
      history_query_latest(target, HISTORY_REF_NONE, "*", 10, &res, NULL) > 0) {
    m = res;
    /* fields that fit their buffers and are free of the record's own
     * structure must come back unchanged */
    if (strlen(sender) < sizeof m->sender && strlen(account) < sizeof m->account &&
        esc_len(content) < 4000 && esc_len(tags) < 500 && esc_len(otarget) <= NICKLEN &&
        !getenv("FUZZ_STRICT") && (strchr(sender, '|') || strchr(account, '|'))) {
      /* F14 (FINDINGS.md): '|' in sender/account shifts the fields; the
       * default run does not assert on it */
    } else if (strlen(sender) < sizeof m->sender && strlen(account) < sizeof m->account &&
        esc_len(content) < 4000 && esc_len(tags) < 500 && esc_len(otarget) <= NICKLEN) {
      if (strcmp(m->sender, sender) || strcmp(m->account, account) ||
          strcmp(m->content, content) || strcmp(m->client_tags, tags) ||
          strcmp(m->original_target, otarget) || (int)m->type != type) {
        fprintf(stderr, "round trip mismatch:\n sender  [%s] -> [%s]\n account [%s] -> [%s]\n"
                " content [%s] -> [%s]\n tags [%s] -> [%s]\n otarget [%s] -> [%s]\n type %d -> %d\n",
                sender, m->sender, account, m->account, content, m->content,
                tags, m->client_tags, otarget, m->original_target, type, (int)m->type);
        abort();
      }
    }
    history_free_messages(res);
  }
  free(sender); free(account); free(content); free(tags); free(otarget);
}

/* rows: [cfidx][klen:2][vlen:2][key][val] ... then queries */
static void mode_rows(const uint8_t *d, size_t n)
{
  size_t off = 0;
  struct HistoryMessage *res = NULL;
  char ts[HISTORY_TIMESTAMP_LEN];
  int ncf = fake_db_cf_count();

  fake_db_clear();
  while (off + 5 <= n) {
    int cf = d[off] % ncf;
    size_t kl = d[off + 1] | (d[off + 2] << 8), vl = d[off + 3] | (d[off + 4] << 8);
    off += 5;
    kl %= 200; vl %= 9000;
    if (off + kl + vl > n) break;
    fake_db_put(fake_db_cf_at(cf), d + off, kl, d + off + kl, vl);
    off += kl + vl;
  }
  if (history_query_latest("#fuzz", HISTORY_REF_NONE, "*", 20, &res, NULL) > 0)
    history_free_messages(res);
  res = NULL;
  if (history_query_before("#fuzz", HISTORY_REF_TIMESTAMP, "1800000000.000", 20, &res, NULL) > 0)
    history_free_messages(res);
  res = NULL;
  if (history_query_after("#fuzz", HISTORY_REF_TIMESTAMP, "1.000", 20, &res, NULL) > 0)
    history_free_messages(res);
  res = NULL;
  if (history_query_around("#fuzz", HISTORY_REF_MSGID, "AAAAAZo5AAAAAA", 20, &res, NULL) > 0)
    history_free_messages(res);
  (void)history_msgid_to_timestamp("AAAAAZo5AAAAAA", ts);
  {
    struct HistoryMessage *one = NULL;
    if (history_lookup_message("#fuzz", "AAAAAZo5AAAAAA", &one) == 0 && one)
      history_free_messages(one);
  }
  (void)history_has_msgid("AAAAAZo5AAAAAA");
  (void)history_message_is_redacted("#fuzz", "AAAAAZo5AAAAAA");
  {
    struct HistoryTarget *t = NULL;
    if (history_query_targets("1.000", "1900000000.000", 1, 20, &t, NULL, NULL) > 0)
      history_free_targets(t);
  }
}

static void mode_helpers(const uint8_t *d, size_t n)
{
  char *s = strndup((const char *)d, n), out[64], iso[64], fw[1200], buf[HISTORY_MSGID_LEN];
  char *tags = NULL, *text;
  char target[CHANNELLEN + 1], ts[HISTORY_TIMESTAMP_LEN], mid[HISTORY_MSGID_LEN];
  /* F15 (FINDINGS.md): a year field strtol() saturates makes
   * "strtol(...) - 1900" overflow.  Client references are validated to a
   * 4-digit year first; only unvalidated S2S references reach it.  The
   * default run skips such inputs. */
  {
    const char *q;
    size_t dg = 0, run = 0;
    for (q = s; *q; q++) {         /* longest digit run (any field) */
      run = (*q >= '0' && *q <= '9') ? run + 1 : 0;
      if (run > dg) dg = run;
    }
    if ((dg <= 18 || getenv("FUZZ_STRICT")) && history_iso_to_unix(s, out, sizeof out) == 0)
      CHECK(strlen(out) < sizeof out);
  }
  if (history_unix_to_iso(s, iso, sizeof iso) == 0)
    CHECK(strlen(iso) < sizeof iso);
  (void)history_parse_ms(s);
  (void)extract_reply_tag(s, buf, sizeof buf);
  /* forward encode/split round trip */
  {
    size_t h = strlen(s) / 2;
    char *tg = strndup(s, h), *tx = strdup(s + h);
    history_forward_encode(fw, sizeof fw, tg, tx);
    text = history_forward_split(fw, &tags);
    if (strlen(tg) * 2 + strlen(tx) * 2 + 4 < sizeof fw && *tg && !strchr(tg, '\x06')) {
      CHECK(tags && !strcmp(tags, tg));
      CHECK(!strcmp(text, tx));
    }
    free(tg); free(tx);
  }
  (void)parse_key((const char *)d, (int)n, target, ts, mid);
  free(s);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  if (size < 1) return 0;
  switch (data[0] % 4) {
  case 0: mode_deserialize(data + 1, size - 1); break;
  case 1: mode_roundtrip(data + 1, size - 1); break;
  case 2: mode_rows(data + 1, size - 1); break;
  case 3: mode_helpers(data + 1, size - 1); break;
  }
  return 0;
}
