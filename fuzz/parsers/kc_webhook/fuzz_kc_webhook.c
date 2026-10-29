/*
 * fuzz_kc_webhook.c - libFuzzer harness for the Keycloak webhook listener:
 * ircd/kc/kc_webhook.c (HTTP request parsing, signature/realm/replay
 * gate, queue, JSON dispatch) + ircd/kc/kc_webhook_sig.c, with the
 * dispatched event fed to the ircd's pure decision modules exactly as
 * sasl_webhook.c's nef_webhook_handle_event does (webhook_subject_resolve,
 * webhook_relay_kind_for, webhook_eventlog_record).
 *
 * The listener is reachable by anyone who can open its TCP port: the HTTP
 * request is unauthenticated until the signature check passes.
 * kc_webhook.c is #included and driven through the real conn_readable()
 * over a socketpair, so recv(), buffer growth and the header parser run
 * unmodified.
 *
 * Byte 0 selects a mode:
 *   0  raw: the rest is the whole HTTP request (unauthenticated surface)
 *   1  signed: byte 1 = flags, the rest is a JSON body; the harness wraps it
 *      in a POST with a correct Content-Length and a valid
 *      X-Webhook-Signature, so the JSON dispatch is reached.  Oracle: such a
 *      request is answered 200 (queued, duplicate) or 403 (other realm),
 *      never 400/401.
 *   2  kc_webhook_sig_verify with a fuzz header against an OpenSSL HMAC()
 *      reference: OK iff the header is exactly t=<digits>,v1=<lower/upper
 *      hex of the reference MAC> within the window.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <jansson.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

#include <kc/kc.h>
#include <kc/kc_event.h>

/* ---- event ops: record the socket removal and the queue timer ---- */
static int sock_removed;
static void (*pending_timer)(void *);
static int fz_socket_add(int fd, int ev, void (*cb)(int, int, void *), void *d)
{ (void)fd; (void)ev; (void)cb; (void)d; return 0; }
static int fz_socket_update(int fd, int ev) { (void)fd; (void)ev; return 0; }
static void fz_socket_remove(int fd) { (void)fd; sock_removed = 1; }
static void *fz_timer_add(unsigned long ms, void (*cb)(void *), void *d)
{ (void)ms; (void)d; pending_timer = cb; return (void *)1; }
static void fz_timer_cancel(void *h) { (void)h; }
static unsigned long fz_now(void) { return (unsigned long)time(NULL); }
static void fz_poll_hint(long ms) { (void)ms; }
static const struct kc_event_ops fz_ops = {
  fz_socket_add, fz_socket_update, fz_socket_remove,
  fz_timer_add, fz_timer_cancel, fz_now, fz_poll_hint
};
const struct kc_event_ops *kc_get_event_ops(void);
const struct kc_event_ops *kc_get_event_ops(void) { return &fz_ops; }

#include "../../../ircd/kc/kc_webhook.c"

#include "webhook_subject.h"
#include "webhook_eventlog.h"

static const char SECRET[] = "fuzz-webhook-secret";
static const char REALM[] = "fuzzrealm";

/* What nef_webhook_handle_event does with an event, minus the client-list
 * walks: the pure subject decision and the applied-events log. */
static void fz_event_cb(const struct kc_webhook_event *ev, void *data)
{
  struct WebhookSubject s;
  (void)data;
  if (ev->resource_type == KC_WH_RESOURCE_USER) {
    if (webhook_subject_resolve(ev, &s)) {
      char kind = webhook_relay_kind_for(s.kind);
      if (s.username && strlen(s.username) > 32) abort();
      if (strlen(s.kc_id) > ACCOUNT_ID_LEN) abort();
      (void)webhook_subject_kind_name(s.kind);
      if (kind && webhook_subject_kind_for_relay(kind) != s.kind) abort();
      if (kind && ev->id)
        (void)webhook_eventlog_record(ev->id, kind, s.kc_id, s.username, time(NULL));
    }
  } else if (ev->resource_type == KC_WH_RESOURCE_CREDENTIAL && ev->username && ev->id) {
    (void)webhook_eventlog_record(ev->id, 'P', NULL, ev->username, time(NULL));
  }
  if (ev->representation) {
    json_t *t = json_object_get(ev->representation, "type");
    if (t && json_is_string(t)) (void)strcmp(json_string_value(t), "x509");
  }
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
  (void)argc; (void)argv;
  cfg_secret = strdup(SECRET);
  cfg_realm_name = strdup(REALM);
  cfg_max_request_size = DEFAULT_MAX_REQUEST_SIZE;
  cfg_queue_max = 4;
  cfg_batch_size = 2;
  event_callback = fz_event_cb;
  kc_replay_ring_init(&replay_ring);
  webhook_eventlog_init(64);
  return 0;
}

static char last_resp[600];

/* Push one request through conn_readable() and return the HTTP status. */
static int run_request(const char *req, size_t len)
{
  int sv[2], status = 0;
  struct wh_conn *conn;
  size_t off = 0;
  ssize_t r;

  if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) abort();
  conn = calloc(1, sizeof(*conn));
  conn->fd = sv[0];
  snprintf(conn->peer, sizeof(conn->peer), "fuzz");
  conn->buf_size = 4096;
  conn->buffer = malloc(conn->buf_size);
  sock_removed = 0;
  last_resp[0] = '\0';
  active_connections++;
  /* conn_readable reads 4096 at a time; feed it that way */
  while (!sock_removed) {
    size_t n = len - off > 4096 ? 4096 : len - off;
    if (n == 0) {
      shutdown(sv[1], SHUT_WR);   /* EOF: recv() returns 0 -> close */
    } else if (write(sv[1], req + off, n) != (ssize_t)n) {
      abort();
    }
    off += n;
    conn_readable(sv[0], 0, conn);
  }
  r = read(sv[1], last_resp, sizeof(last_resp) - 1);
  if (r > 0) {
    last_resp[r] = '\0';
    if (sscanf(last_resp, "HTTP/1.1 %d", &status) != 1) status = -1;
  }
  close(sv[1]);
  /* drain the event queue */
  while (pending_timer) {
    void (*cb)(void *) = pending_timer;
    pending_timer = NULL;
    cb(NULL);
  }
  return status;
}

static void hexmac(const char *body, size_t blen, long long t, char out[65], int upper)
{
  unsigned char mac[32];
  unsigned int ml = 0;
  char tb[32];
  size_t tl = (size_t)snprintf(tb, sizeof tb, "%lld.", t);
  unsigned char *msg = malloc(tl + blen + 1);
  int i;
  memcpy(msg, tb, tl);
  memcpy(msg + tl, body, blen);
  HMAC(EVP_sha256(), SECRET, (int)strlen(SECRET), msg, tl + blen, mac, &ml);
  free(msg);
  for (i = 0; i < 32; i++)
    sprintf(out + 2 * i, upper ? "%02X" : "%02x", mac[i]);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  if (size < 2 || size > 70000) return 0;
  switch (data[0] % 3) {
  case 0:
    (void)run_request((const char *)data + 1, size - 1);
    break;
  case 1: {
    const char *body = (const char *)data + 2;
    size_t blen = size - 2;
    unsigned flags = data[1];
    long long t = (long long)time(NULL) - (flags & 0x0f);
    char mac[65], *req;
    int st, n;
    hexmac(body, blen, t, mac, flags & 0x10);
    req = malloc(blen + 512);
    n = sprintf(req, "POST %s HTTP/1.1\r\nHost: x\r\nContent-Length: %zu\r\n"
                "X-Webhook-Signature: t=%lld,v1=%s\r\n\r\n",
                (flags & 0x20) ? "/webhook" : "/keycloak-webhook", blen, t, mac);
    memcpy(req + n, body, blen);
    st = run_request(req, n + blen);
    /* Known bug F3 (FINDINGS.md): a request whose first recv() fills the
     * initial 4096-byte buffer is answered 400 before its headers are
     * read.  Tolerated by default; FUZZ_WH_STRICT=1 makes it fatal. */
    if (st == 400 && (n + blen < 4096 || getenv("FUZZ_WH_STRICT")))
      abort();                    /* well-formed signed request refused */
    free(req);
    break;
  }
  case 2: {
    /* header \0 body */
    const char *hdr = (const char *)data + 1;
    size_t hl = strnlen(hdr, size - 1);
    const char *body = hl + 1 < size - 1 ? hdr + hl + 1 : "";
    size_t blen = hl + 1 < size - 1 ? size - 2 - hl : 0;
    char *h = strndup(hdr, hl), mac[65];
    long long now = 1700000000LL, tt = 0;
    enum kc_sig_result r = kc_webhook_sig_verify(SECRET, h, body, blen, now, 300, &tt);
    int expect_ok = 0;
    if (!strncmp(h, "t=", 2)) {
      const char *p = h + 2, *v;
      size_t tl = 0;
      while (isdigit((unsigned char)p[tl])) tl++;
      if (tl > 0 && tl < 23 && p[tl] == ',' && !strncmp(p + tl + 1, "v1=", 3)) {
        long long t = strtoll(p, NULL, 10);
        v = p + tl + 4;
        hexmac(body, blen, t, mac, 0);
        if (strlen(v) == 64 && !strcasecmp(v, mac) &&
            !(now - t > 300 || t - now > 300))
          expect_ok = 1;
      }
    }
    if ((r == KC_SIG_OK) != expect_ok) abort();
    if (r == KC_SIG_OK && tt != strtoll(h + 2, NULL, 10)) abort();
    (void)kc_sig_result_name(r);
    free(h);
    break;
  }
  }
  return 0;
}
