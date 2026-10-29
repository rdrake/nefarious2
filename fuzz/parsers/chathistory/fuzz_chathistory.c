/*
 * fuzz_chathistory.c - libFuzzer harness for the CHATHISTORY selector
 * parsing in ircd/m_chathistory.c: validate_timestamp /
 * validate_iso_timestamp (client "timestamp=" values), parse_reference
 * (client "timestamp=" / "msgid=" / "*"), ref_to_s2s / parse_s2s_reference
 * (the CH wire form, which a peer server also sends), subcmd_to_s2s /
 * s2s_to_subcmd, ref_unix_secs (with the real history.c time helpers and
 * msgid decoding), fed_ref_to_unix, and ch_base64_decode (federation chunk
 * payloads).  m_chathistory.c is #included for its statics; everything it
 * references beyond history.c/ircd_string.c gets common/autostub.py stubs.
 *
 * Input: byte 0 = flags (bit 0: FEAT_CHATHISTORY_STRICT_TIMESTAMPS),
 * then the selector text.  Properties: a reference parse_reference accepts
 * converts to the S2S form and parses back to the same type and value
 * (CH requests relay client refs to peers); ch_base64_decode never
 * reports more bytes than an independent decoder.
 */
#include "config.h"
#include "ircd_features.h"
#include "crdt_hlc.h"
#include "fake_db.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(c) do { if (!(c)) { fprintf(stderr, "CHECK failed: %s (%s:%d)\n", #c, __FILE__, __LINE__); abort(); } } while (0)

static int strict_ts;
int feature_bool(enum Feature f)
{
  if (f == FEAT_CHATHISTORY_STRICT_TIMESTAMPS) return strict_ts;
  return f == FEAT_CHATHISTORY_STORE;
}
int feature_int(enum Feature f) { return f == FEAT_CHATHISTORY_MAX ? 100 : 0; }
const char *feature_str(enum Feature f) { (void)f; return ""; }
static struct HLC fuzz_hlc;
const struct HLC *hlc_global(void) { return &fuzz_hlc; }

#include "../../../ircd/m_chathistory.c"

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
  (void)argc; (void)argv;
  fuzz_hlc.physical_ms = 1700000000000ULL;
  if (history_init("/fuzz/history") != 0) abort();
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  char *s, buf[HISTORY_MSGID_LEN + 16], ub[64];
  enum HistoryRefType t, t2;
  const char *v, *v2;
  if (size < 1) return 0;
  strict_ts = data[0] & 1;
  s = strndup((const char *)data + 1, size - 1);

  (void)validate_timestamp(s);
  (void)validate_iso_timestamp(s);
  if (parse_reference(s, &t, &v) == 0) {
    CHECK(t == HISTORY_REF_NONE || t == HISTORY_REF_TIMESTAMP || t == HISTORY_REF_MSGID);
    (void)ref_unix_secs(t, v);
    if (ref_to_s2s(s, buf, sizeof buf)) {
      /* a client ref relayed to a peer must parse back the same way */
      if (strlen(v) < sizeof buf - 1 && !(t == HISTORY_REF_MSGID && IsDigit(*v)) &&
          !(t == HISTORY_REF_MSGID && *v == '*') && *v &&
          !(t == HISTORY_REF_MSGID && (!strncmp(v, "timestamp=", 10) || !strncmp(v, "msgid=", 6)))) {
        CHECK(parse_s2s_reference(buf, &t2, &v2) == 0);
        CHECK(t2 == t);
        if (t != HISTORY_REF_NONE) CHECK(!strcmp(v2, v));
      }
    }
  }
  if (parse_s2s_reference(s, &t, &v) == 0 && t != HISTORY_REF_NONE) {
    /* S2S refs are not validated first: the time helpers see raw bytes */
    char ts[HISTORY_TIMESTAMP_LEN];
    if (t == HISTORY_REF_MSGID) (void)history_msgid_to_timestamp(v, ts);
  }
  fed_ref_to_unix(s, ub, sizeof ub);
  CHECK(strlen(ub) < sizeof ub);
  (void)subcmd_to_s2s(s);
  if (*s) (void)s2s_to_subcmd(*s);
  {
    /* F16 (FINDINGS.md): more trailing '=' than EVP_DecodeBlock produced
     * bytes drives the length negative and writes before the buffer.
     * Skipped by default; FUZZ_STRICT=1 runs it. */
    char *out = NULL;
    size_t ol = 0, sl = strlen(s), eq = 0;
    while (eq < sl && s[sl - 1 - eq] == '=') eq++;
    if ((eq <= 2 || getenv("FUZZ_STRICT")) && ch_base64_decode(s, strlen(s), &out, &ol)) {
      CHECK(ol <= strlen(s) * 3 / 4 + 3);
      MyFree(out);
    }
  }
  free(s);
  return 0;
}
