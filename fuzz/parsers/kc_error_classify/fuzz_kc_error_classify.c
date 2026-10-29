/*
 * fuzz_kc_error_classify.c - libFuzzer harness for
 * ircd/kc/kc_error_classify.c: the ROPC 400/401 error body (Keycloak's
 * JSON) -> KC_UNVERIFIED / KC_FORBIDDEN.  The body is parsed with
 * jansson exactly as kc_keycloak.c does and handed over; NULL too.
 */
#include <kc/kc.h>
#include <kc/kc_error_classify.h>
#include <jansson.h>
#include <stdint.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  json_t *j = json_loadb((const char *)data, size, JSON_DECODE_ANY, NULL);
  (void)kc_classify_grant_error(j);
  json_decref(j);
  if (!size) (void)kc_classify_grant_error(NULL);
  return 0;
}
