/*
 * fuzz_webhook_eventlog.c - libFuzzer harness for ircd/webhook_eventlog.c:
 * the applied-webhook-events log and webhook_relay_parse(), which parses
 * the CI cache-invalidation relay a peer server sends (ms_cacheinval) and
 * the catch-up lines at end of burst.  Input: NUL-separated CI parameters
 * (parv[1..]); records parsed relays into the log, then walks catch-up.
 * Properties: a parsed relay's fields are the parameters themselves (or
 * NULL for "*"), record/seen agree, catch-up never yields more entries
 * than recorded.
 */
#include "config.h"
#include "webhook_eventlog.h"
#include "fuzz_util.h"

static unsigned walked;
static void cb(const struct WebhookEventLogEntry *e, void *d) { (void)e; (void)d; walked++; }

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  const char *p = (const char *)data + 1, *end = (const char *)data + size;
  char *parv[8];
  int parc, i;
  struct WebhookRelay r;
  if (size < 1) return 0;
  webhook_eventlog_init(4 + data[0] % 8);
  while (p < end) {
    parc = 1 + (*p % 7);
    p++;
    parv[0] = strdup("CI");
    for (i = 1; i < parc; i++) parv[i] = fuzz_field(&p, end);
    for (; i < 8; i++) parv[i] = NULL;
    if (webhook_relay_parse(parc, parv, &r)) {
      CHECK(r.event_id == parv[3]);
      CHECK(webhook_eventlog_valid_id(r.event_id));
      if (r.username) CHECK(r.username == parv[1]);
      if (!webhook_eventlog_record(r.event_id, r.kind, r.kc_id, r.username, 1000 + (data[0] & 15)))
        CHECK(webhook_eventlog_seen(r.event_id));
      (void)webhook_eventlog_set_names(r.event_id, parv[1]);
    }
    for (i = 0; i < 8; i++) free(parv[i]);
  }
  walked = 0;
  (void)webhook_eventlog_catchup(0, cb, NULL, 1000);
  CHECK(walked <= webhook_eventlog_count());
  (void)webhook_eventlog_since(500, cb, NULL, 1 + data[0] % 5);
  (void)webhook_eventlog_oldest();
  return 0;
}
