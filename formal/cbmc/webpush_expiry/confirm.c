/* Concrete reproduction of the CBMC counterexamples against the REAL
 * ircd/webpush_expiry.c, built with -fsanitize=address,undefined. */
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include "webpush_expiry.h"

int main(void)
{
  /* E3: the record shape m_webpush.c writes ("%s|%s|%s|%lld|%s") with an
   * 87-byte key id (base64url of a 65-byte P-256 public key). */
  char keyid[88], rec[512];
  memset(keyid, 'A', 87); keyid[87] = '\0';
  snprintf(rec, sizeof rec, "https://push.example/x|BP256dh|authsecret|%lld|%s",
           1800000000LL, keyid);
  printf("E3 keyed record (87-byte keyid): armed_at = %lld (want 1800000000)\n",
         webpush_armed_at(rec));
  snprintf(rec, sizeof rec, "e|p|a|1800000000|%.13s", keyid);
  printf("E3 keyed record (13-byte keyid): armed_at = %lld\n", webpush_armed_at(rec));
  snprintf(rec, sizeof rec, "e|p|a|1800000000|%.12s", keyid);
  printf("E3 keyed record (12-byte keyid): armed_at = %lld\n", webpush_armed_at(rec));
  /* E2: negative results despite the leading-'-' guard */
  printf("E2 \"e|p|a| -5\" -> %lld ; \"e|p|a|18446744073709551615\" -> %lld\n",
         webpush_armed_at("e|p|a| -5"), webpush_armed_at("e|p|a|18446744073709551615"));
  /* E4: signed overflow in armed + max_age (UBSan reports it) */
  printf("E4 expired(LLONG_MAX-1, now=0, 7776000) = %d\n",
         webpush_expired(LLONG_MAX - 1, 0, 7776000));
  return 0;
}
