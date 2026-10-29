/*
 * fuzz_kc_url.c - libFuzzer harness for ircd/kc/kc_url.c, the Keycloak
 * REST URL builders.  Their inputs are the configured realm and ids /
 * escaped names (usernames from AUTHENTICATE and /REGISTER are escaped by
 * the caller; kc_url_group_by_path escapes itself).  Input: base\0realm\0
 * arg1\0arg2.  Properties: every builder returns a NUL-terminated string
 * that starts with the base URL and contains each argument verbatim (or,
 * for group_by_path, its curl escape).
 */
#include <kc/kc.h>
#include <kc/kc_url.h>
#include <kc/kc_realm.h>
#include <curl/curl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(c) do { if (!(c)) { fprintf(stderr, "CHECK failed: %s (%s:%d)\n", #c, __FILE__, __LINE__); abort(); } } while (0)

static char *field(const char **p, const char *end)
{
  const char *z = memchr(*p, 0, end - *p);
  char *r;
  if (!z) z = end;
  r = strndup(*p, z - *p);
  *p = z < end ? z + 1 : end;
  return r;
}

static void ck(char *u, const char *base, const char *arg)
{
  if (!u) return;
  CHECK(!strncmp(u, base, strlen(base)));
  if (arg) CHECK(strstr(u, arg));
  free(u);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  const char *p = (const char *)data, *end = p + size;
  char *base = field(&p, end), *realm = field(&p, end);
  char *a = field(&p, end), *b = field(&p, end);
  struct kc_realm r = { base, realm };
  ck(kc_url_token(r), base, realm);
  ck(kc_url_introspect(r), base, realm);
  ck(kc_url_jwks(r), base, realm);
  ck(kc_url_users(r), base, realm);
  ck(kc_url_user(r, a), base, a);
  ck(kc_url_user_by_username(r, a, 1), base, a);
  ck(kc_url_user_by_username(r, a, 0), base, a);
  ck(kc_url_user_groups(r, a), base, a);
  ck(kc_url_user_group(r, a, b), base, b);
  ck(kc_url_user_reset_password(r, a), base, a);
  ck(kc_url_user_send_verify_email(r, a), base, a);
  ck(kc_url_groups(r), base, realm);
  ck(kc_url_group(r, a), base, a);
  ck(kc_url_group_members(r, a), base, a);
  ck(kc_url_group_children(r, a), base, a);
  ck(kc_url_group_by_path(r, a), base, NULL);
  ck(kc_url_group_search(r, a), base, a);
  ck(kc_url_fingerprint_search(r, a), base, a);
  free(base); free(realm); free(a); free(b);
  return 0;
}
