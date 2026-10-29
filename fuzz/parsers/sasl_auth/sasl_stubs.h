#ifndef FUZZ_SASL_STUBS_H
#define FUZZ_SASL_STUBS_H
#include <kc/kc_keycloak.h>
enum pk_kind { PK_NONE, PK_USER, PK_SEARCH, PK_TOKEN, PK_INTROSPECT };
struct pending_kc {
  enum pk_kind kind;
  kc_user_cb user_cb;
  kc_users_cb users_cb;
  kc_token_cb token_cb;
  kc_introspect_cb introspect_cb;
  void *data;
};
extern struct pending_kc pending;
extern int jwt_local_result;
extern size_t out_count;
#endif
