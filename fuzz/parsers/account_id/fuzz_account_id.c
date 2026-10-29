/*
 * fuzz_account_id.c - libFuzzer harness for ircd/account_id.c: the compact
 * Keycloak user id (22-char base64url of the 16-byte UUID) built from a
 * webhook resourcePath / JWT sub and carried in P10 (AC, +r account:ts:id,
 * CI).  Properties: account_id_from_uuid accepts exactly the canonical
 * hex digits (hyphens anywhere are ignored by design) and its output is always
 * account_id_valid; account_id_valid on arbitrary text never reads past it.
 */
#include "account_id.h"
#include "fuzz_util.h"
#include <ctype.h>

/* the codec's documented contract: hyphens are ignored wherever they
 * sit, exactly 32 hex digits of either case */
static int ref_uuid(const char *s)
{
  int n = 0;
  for (; *s; s++) {
    if (*s == '-') continue;
    if (!isxdigit((unsigned char)*s)) return 0;
    n++;
  }
  return n == 32;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  char *s = strndup((const char *)data, size), out[ACCOUNT_ID_LEN + 1];
  int ok;
  memset(out, 'Z', sizeof out);
  ok = account_id_from_uuid(s, out);
  if (ok) {
    CHECK(strlen(out) == ACCOUNT_ID_LEN);
    CHECK(account_id_valid(out));
  }
  if (!fuzz_strict()) { if (ok != ref_uuid(s)) { fprintf(stderr, "uuid verdict %d vs ref %d for [%s]\n", ok, ref_uuid(s), s); abort(); } }
  (void)account_id_valid(s);
  free(s);
  return 0;
}
