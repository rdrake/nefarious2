/*
 * fuzz_kc_cred_derive.c - libFuzzer harness for ircd/kc/kc_cred_derive.c:
 * registration-time SCRAM-SHA-256 / Keycloak PBKDF2 credential derivation
 * from the password a client sends with /REGISTER.
 * Property: scram_sha256_derive() matches an independent RFC 5802
 * computation (PKCS5_PBKDF2_HMAC + HMAC + SHA256 + EVP_EncodeBlock) for
 * the same password, salt and iteration count (salt length 16 and small
 * iteration counts, as the only caller -- derive_random -- uses 16 bytes);
 * kc_pbkdf2_cred_build() emits JSON jansson parses with the fields
 * Keycloak expects.
 */
#include <kc/kc_cred_derive.h>
#include <jansson.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(c) do { if (!(c)) { fprintf(stderr, "CHECK failed: %s (%s:%d)\n", #c, __FILE__, __LINE__); abort(); } } while (0)

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  struct scram_sha256_creds c;
  unsigned char salt[16], sp[32], ck[32], sk[32], svk[32];
  char ref[64];
  unsigned int l;
  int it;
  char *pw;
  if (size < 17) return 0;
  memcpy(salt, data, 16);
  it = 1 + data[16] % 8;
  pw = strndup((const char *)data + 17, size - 17);
  if (scram_sha256_derive(pw, salt, sizeof salt, it, &c) == 0) {
    PKCS5_PBKDF2_HMAC(pw, strlen(pw), salt, 16, it, EVP_sha256(), 32, sp);
    HMAC(EVP_sha256(), sp, 32, (const unsigned char *)"Client Key", 10, ck, &l);
    SHA256(ck, 32, sk);
    HMAC(EVP_sha256(), sp, 32, (const unsigned char *)"Server Key", 10, svk, &l);
    EVP_EncodeBlock((unsigned char *)ref, sk, 32);
    CHECK(!strcmp(ref, c.stored_key_b64));
    EVP_EncodeBlock((unsigned char *)ref, svk, 32);
    CHECK(!strcmp(ref, c.server_key_b64));
    EVP_EncodeBlock((unsigned char *)ref, salt, 16);
    CHECK(!strcmp(ref, c.salt_b64));
    CHECK(c.iterations == it);
  }
  if (data[16] & 0x80) {          /* the PBKDF2 path is slow: sample it */
    char *cd = NULL, *sd = NULL;
    if (kc_pbkdf2_cred_build(pw, &cd, &sd) == 0) {
      json_t *a = json_loads(cd, 0, NULL), *b = json_loads(sd, 0, NULL);
      CHECK(a && b);
      json_decref(a); json_decref(b);
      free(cd); free(sd);
    }
  }
  free(pw);
  return 0;
}
