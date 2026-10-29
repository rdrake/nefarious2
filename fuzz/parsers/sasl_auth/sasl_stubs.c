/*
 * sasl_stubs.c - the ircd and libkc symbols ircd/sasl_auth.c links
 * against, stubbed for a standalone build.  Asynchronous Keycloak calls
 * park their callback; the harness completes it with a canned result.
 */
#include "config.h"
#include "client.h"
#include "ircd.h"
#include "ircd_features.h"
#include "ircd_events.h"
#include "s_auth.h"
#include "bouncer_session.h"
#include "send.h"
#include <kc/kc_keycloak.h>
#include <kc/kc_jwt.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include "sasl_stubs.h"

time_t CurrentTime = 1700000000;
struct Client *LocalClientArray[MAXCONNECTIONS];

struct pending_kc pending;

/* features: FEAT_SASL_LOCAL on, every mechanism advertised */
int feature_bool(enum Feature feat) { (void)feat; return 1; }
int feature_int(enum Feature feat) { (void)feat; return 30; }
const char *feature_str(enum Feature feat)
{
  if (feat == FEAT_SASL_LOCAL_MECHANISMS)
    return "PLAIN,EXTERNAL,OAUTHBEARER,SCRAM-SHA-256,ECDSA-NIST256P-CHALLENGE";
  if (feat == FEAT_SASL_TRUSTED_AUTHZID)
    return "admin,services";
  if (feat == FEAT_KEYCLOAK_URL)
    return "http://kc.invalid";
  if (feat == FEAT_KEYCLOAK_CLIENT_ID || feat == FEAT_KEYCLOAK_CLIENT_SECRET ||
      feat == FEAT_KEYCLOAK_REALM)
    return "fuzz";
  return "";
}

struct Timer *timer_init(struct Timer *t) { memset(t, 0, sizeof(*t)); return t; }
void timer_add(struct Timer *t, EventCallBack call, void *data,
               enum TimerType type, time_t value)
{ (void)call; (void)data; (void)type; (void)value; t->t_header.gh_flags |= GEN_ACTIVE; }
void timer_del(struct Timer *t) { t->t_header.gh_flags &= ~GEN_ACTIVE; }

unsigned int fuzz_rand_state = 12345;
unsigned int ircrandom(void) { fuzz_rand_state = fuzz_rand_state * 1103515245u + 12345u; return fuzz_rand_state; }

/* Output: format into a scratch buffer so the arguments are exercised. */
static char outbuf[2048];
size_t out_count;
int send_reply(struct Client *to, int reply, ...) { (void)to; (void)reply; out_count++; return 0; }
void sendrawto_one(struct Client *to, const char *pattern, ...)
{
  va_list ap; (void)to;
  va_start(ap, pattern);
  vsnprintf(outbuf, sizeof(outbuf), pattern, ap);
  va_end(ap);
  out_count++;
}
void send_fail(struct Client *to, const char *command, const char *code,
               const char *context, const char *description)
{ (void)to; (void)command; (void)code; (void)context; (void)description; }
void send_cap_notify(const char *capname, int available, const char *value)
{ (void)capname; (void)available; (void)value; }
void sendcmdto_serv_butone(struct Client *from, const char *cmd, const char *tok,
                           struct Client *one, const char *pattern, ...)
{ (void)from; (void)cmd; (void)tok; (void)one; (void)pattern; }
void sendcmdto_common_channels_capab_butone(struct Client *from, const char *cmd,
                                            const char *tok, struct Client *one,
                                            int withcap, int skipcap,
                                            const char *pattern, ...)
{ (void)from; (void)cmd; (void)tok; (void)one; (void)withcap; (void)skipcap; (void)pattern; }

int auth_sasl_done(struct AuthRequest *auth) { (void)auth; return 0; }
void auth_sasl_start(struct AuthRequest *auth) { (void)auth; }
int auth_set_account(struct AuthRequest *auth, const char *account) { (void)auth; (void)account; return 0; }

int bounce_account_kc_conflict(const char *a, const char *k) { (void)a; (void)k; return 0; }
void bounce_emit_alias_update(struct Client *p, const char *f, const char *v) { (void)p; (void)f; (void)v; }
struct BouncerSession *bounce_get_session(struct Client *c) { (void)c; return NULL; }
int bounce_rebind_kc_conflict(const char *g, const char *i) { (void)g; (void)i; return 0; }
void bounce_session_adopt_kc_id(struct BouncerSession *s, const char *id) { (void)s; (void)id; }
const char *bounce_session_kc_id(struct BouncerSession *s) { (void)s; return ""; }
void bounce_sync_alias_identity(struct Client *p) { (void)p; }
void channel_account_adjust(struct Client *c, int d) { (void)c; (void)d; }
void free_connection(struct Connection *con) { (void)con; }
int hide_hostmask(struct Client *c) { (void)c; return 0; }
void metadata_load_account(struct Client *c, const char *a) { (void)c; (void)a; }
void presence_anchor_transfer(struct Client *c, const char *oa, int os,
                              const char *na, int ns)
{ (void)c; (void)oa; (void)os; (void)na; (void)ns; }

/* ---- libkc ---- */
int kc_token_ensure(kc_token_cb cb, void *data) { (void)cb; (void)data; return 0; }
int kc_user_get(const char *username, kc_user_cb cb, void *data)
{ (void)username; pending.kind = PK_USER; pending.user_cb = cb; pending.data = data; return 0; }
int kc_user_search(const char *query, bool exact, kc_users_cb cb, void *data)
{ (void)query; (void)exact; pending.kind = PK_SEARCH; pending.users_cb = cb; pending.data = data; return 0; }
int kc_user_verify_password(const char *username, const char *password,
                            kc_token_cb cb, void *data)
{ (void)username; (void)password; pending.kind = PK_TOKEN; pending.token_cb = cb; pending.data = data; return 0; }
int kc_token_introspect(const char *token, kc_introspect_cb cb, void *data)
{ (void)token; pending.kind = PK_INTROSPECT; pending.introspect_cb = cb; pending.data = data; return 0; }

int jwt_local_result;
int kc_jwt_validate_local(struct kc_realm realm, const char *token,
                          struct kc_token_info **info_out)
{
  (void)realm; (void)token;
  *info_out = NULL;
  if (jwt_local_result == KC_SUCCESS) {
    struct kc_token_info *i = calloc(1, sizeof(*i));
    i->active = true;
    i->username = strdup("alice");
    i->sub = strdup("f81d4fae-7dec-11d0-a765-00a0c91e6bf6");
    i->exp = CurrentTime + 100;
    *info_out = i;
  }
  return jwt_local_result;
}
void kc_jwt_token_info_free(struct kc_token_info *info)
{
  if (!info) return;
  free(info->username); free(info->email); free(info->sub);
  free(info->iss); free(info->azp); free(info);
}
int kc_jwt_prime_cache(struct kc_realm realm) { (void)realm; return 0; }
int kc_jwt_extract_sub(const char *token, char *out, size_t out_size)
{
  (void)token;
  if (out_size < 37) { if (out_size) out[0] = 0; return 0; }
  strcpy(out, "f81d4fae-7dec-11d0-a765-00a0c91e6bf6");
  return 1;
}
