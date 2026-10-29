/*
 * fuzz_kc_jwt.c - libFuzzer harness for ircd/kc/kc_jwt.c.
 *
 * The OAUTHBEARER token is client-controlled (AUTHENTICATE payload ->
 * oauthbearer_parse -> kc_jwt_validate_local), so every byte of it is
 * attacker input.  kc_jwt.c is #included (like ircd/test/kc_jwt_cmocka.c)
 * to reach its statics; the JWKS cache is seeded with a throwaway RSA key
 * so no HTTP is attempted, and kc_http_sync_perform() is stubbed to hand
 * back fuzz bytes when the JWKS parser itself is the target.
 *
 * Input byte 0 selects a mode:
 *   0  raw token -> kc_jwt_validate_local / extract_created_at / extract_sub
 *   1  "<header-json>\x00<payload-json>": the harness base64url-encodes and
 *      RS256-signs it with the seeded key, so the claim parser is reached
 *      behind a valid signature.  Oracles: a validly signed RS256/kid=k1
 *      token is never refused for its signature; the same token with one
 *      signature byte flipped is never accepted.
 *   2  JWKS document -> jwks_refresh() key parsing (n/e reconstruction)
 *   3  differential: base64url_decode_alloc vs an independent decoder
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <kc/kc.h>
#include <kc/kc_log.h>
#include <kc/kc_base64.h>
#include <kc/kc_keycloak.h>
#include <kc/kc_http_sync.h>

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

/* kc_token_info_free lives in kc_keycloak.c (whole async client); the
 * harness frees the same fields itself. */
void kc_token_info_free(struct kc_token_info *info)
{
  if (!info) return;
  free(info->username); free(info->email); free(info->sub);
  free(info->iss); free(info->azp);
}

/* JWKS fetch stub: mode 2 sets these. */
static const char *jwks_body;
static size_t jwks_body_len;

long kc_http_sync_perform(struct kc_http_sync_opts opts,
                          struct kc_http_sync_mem *chunk_out)
{
  (void)opts;
  if (!jwks_body) return 0;
  chunk_out->response = malloc(jwks_body_len + 1);
  memcpy(chunk_out->response, jwks_body, jwks_body_len);
  chunk_out->response[jwks_body_len] = '\0';
  chunk_out->size = jwks_body_len;
  return 200;
}

#include "../../../ircd/kc/kc_jwt.c"

/* Fixed throwaway test key (generated for this harness; signs nothing real)
 * so a crash input reproduces byte-for-byte outside libFuzzer. */
static const char fuzz_key_pem[] =
  "-----BEGIN PRIVATE KEY-----\n"
  "MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAMoMsLRGUNm9rtZe\n"
  "kklSumeDaxP8OmdXI5WXJ0WyUK+nPWZYDz+XkqrKcBpa6izKewxN5UxW2DQGD0lJ\n"
  "YjcZ9EQsWw4DLOg8DgVuWERs10FpXhGd6Vkd1/6H0B68tQxHc7yiOmU8M/VTXPlx\n"
  "A6jwgSnfzC7lDhoZlSq7PnNJE3IxAgMBAAECgYAlYZWrtLqunj5joNmVwT2FezXr\n"
  "W6X+ioul2HJGncf5x4o/jhk8HbHf8VYuOhXLNabwTtUWe5bCgUCAwZfvM9kSExhz\n"
  "7f/jJLrexQ9/OkX4Ik5oEPLos2suH89tEYz1gKgrIlL+vq8dlFNRz95WYK8cgUWu\n"
  "3M3M31BM92I6P5BiVQJBAP/1B78EEZN/MJu+w+en9YfNPyEJpY3VVeUQ6knb+6bn\n"
  "rpkkjO1nw4CLG9OKU/A2DgoLEvCiFNI9448teLoqam8CQQDKFVmBwE2Tws1OyHPA\n"
  "YfBZRG0SlujowKWTEbKPOUcQyvooSchPhLhesr3bSnSAe9A4Q/ebu07reQ21RzoS\n"
  "Xr1fAkBU5weRwhy+a2NJVkcPkbQtPtTg9Z035fsfB7RfmZvpKlLNM8WXfmLoQbyS\n"
  "OAFN3fBcPn4i2fDEKIlSVggE4Mr7AkBCqLw3sqlkXlO+8xxLj4Lqz0lzYlg9vp5f\n"
  "Xu0ZlXk9rtbJx1zN7ierBSbfWTYI086hYLoioqyru+irrW0YdivdAkBq75THf8rW\n"
  "aImolbeIydqxOa9/3L5ajymUZKo+zIa5lxZkkqY6Jc2Iq14+qm1gQ2sSfepSAF3d\n"
  "1bR5YKUSjgo3\n"
  "-----END PRIVATE KEY-----\n"
;
static EVP_PKEY *signing_key;
static const struct kc_realm realm = { "http://kc.invalid", "fuzz" };

static void seed_cache(void)
{
  jwks_cleanup();
  jwks_cache.keys[0].kid = strdup("k1");
  EVP_PKEY_up_ref(signing_key);
  jwks_cache.keys[0].pkey = signing_key;
  jwks_cache.key_count = 1;
  jwks_cache.fetched = time(NULL);
  jwks_cache.realm_url = build_jwks_endpoint(realm);
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
  (void)argc; (void)argv;
  {
    BIO *b = BIO_new_mem_buf(fuzz_key_pem, -1);
    signing_key = PEM_read_bio_PrivateKey(b, NULL, NULL, NULL);
    BIO_free(b);
  }
  if (!signing_key) abort();
  seed_cache();
  return 0;
}

static char *b64url(const unsigned char *in, size_t len)
{
  char *out = NULL;
  size_t n = kc_base64_encode_alloc((const char *)in, len, &out), i, j;
  if (!out) abort();
  for (i = j = 0; i < n; i++) {
    char c = out[i];
    if (c == '=') continue;
    out[j++] = c == '+' ? '-' : c == '/' ? '_' : c;
  }
  out[j] = '\0';
  return out;
}

static char *sign_token(const char *hdr, size_t hl, const char *pl, size_t pll)
{
  char *h = b64url((const unsigned char *)hdr, hl);
  char *p = b64url((const unsigned char *)pl, pll);
  size_t si_len = strlen(h) + 1 + strlen(p);
  char *signing = malloc(si_len + 1);
  unsigned char sig[512];
  size_t sig_len = sizeof(sig);
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  char *s, *tok;

  sprintf(signing, "%s.%s", h, p);
  if (EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, signing_key) != 1 ||
      EVP_DigestSign(ctx, sig, &sig_len, (unsigned char *)signing, si_len) != 1)
    abort();
  EVP_MD_CTX_free(ctx);
  s = b64url(sig, sig_len);
  tok = malloc(si_len + 1 + strlen(s) + 1);
  sprintf(tok, "%s.%s", signing, s);
  free(h); free(p); free(s); free(signing);
  return tok;
}

/* Independent base64url decoder: same contract as base64url_decode_alloc
 * (pad to a multiple of 4, accept both alphabets, '=' only as final pad). */
static int ref_val(unsigned char c)
{
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 'a' + 26;
  if (c >= '0' && c <= '9') return c - '0' + 52;
  if (c == '+' || c == '-') return 62;
  if (c == '/' || c == '_') return 63;
  return -1;
}

static int ref_decode(const char *in, unsigned char *out, size_t *olen)
{
  size_t n = strlen(in), padded, i, o = 0;
  char *b;
  if (n == 0) return 0;
  padded = n + (4 - n % 4) % 4;
  b = malloc(padded);
  memcpy(b, in, n);
  memset(b + n, '=', padded - n);
  for (i = 0; i < padded; i += 4) {
    int v0 = ref_val(b[i]), v1 = ref_val(b[i + 1]), v2, v3;
    int last = (i + 4 == padded);
    if (v0 < 0 || v1 < 0) goto bad;
    out[o++] = (unsigned char)((v0 << 2) | (v1 >> 4));
    if (b[i + 2] == '=') {
      if (!last || b[i + 3] != '=') goto bad;
      break;
    }
    if ((v2 = ref_val(b[i + 2])) < 0) goto bad;
    out[o++] = (unsigned char)(((v1 << 4) & 0xf0) | (v2 >> 2));
    if (b[i + 3] == '=') {
      if (!last) goto bad;
      break;
    }
    if ((v3 = ref_val(b[i + 3])) < 0) goto bad;
    out[o++] = (unsigned char)(((v2 << 6) & 0xc0) | v3);
  }
  free(b);
  *olen = o;
  return 1;
bad:
  free(b);
  return 0;
}

static void run_token(const char *tok)
{
  struct kc_token_info *info = NULL;
  char sub[40];
  int rc;

  rc = kc_jwt_validate_local(realm, tok, &info);
  if (rc == KC_SUCCESS) {
    if (!info || !info->active) abort();
    kc_jwt_token_info_free(info);
  } else if (info) {
    abort();                    /* failure must not hand back claims */
  }
  (void)kc_jwt_extract_created_at(tok);
  if (kc_jwt_extract_sub(tok, sub, sizeof sub) && strlen(sub) >= sizeof sub)
    abort();
  (void)kc_jwt_extract_sub(tok, sub, 1);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  char *buf;
  if (size < 1) return 0;

  jwks_cache.fetched = time(NULL);   /* keep the seeded cache fresh */
  buf = malloc(size);
  memcpy(buf, data + 1, size - 1);
  buf[size - 1] = '\0';

  switch (data[0] % 4) {
  case 0:
    run_token(buf);
    break;
  case 1: {
    size_t hl = strnlen(buf, size - 1), pl;
    const char *pay = hl < size - 1 ? buf + hl + 1 : "";
    char *tok;
    struct kc_token_info *info = NULL;
    int rc;
    pl = hl < size - 1 ? size - 2 - hl : 0;
    if (pl > 4096 || hl > 4096) break;
    tok = sign_token(buf, hl, pay, pl);
    /* Validly signed: the outcome may be anything but a signature
     * refusal, which the claim-free path can only give as FORBIDDEN after
     * jwt_verify_signature -- check it directly. */
    {
      EVP_PKEY *k = jwks_get_key("k1");
      if (!k || jwt_verify_signature(tok, k) != KC_SUCCESS) abort();
    }
    rc = kc_jwt_validate_local(realm, tok, &info);
    if (rc == KC_SUCCESS) {
      if (!info) abort();
      if (info->exp <= time(NULL)) abort();      /* expired accepted */
      kc_jwt_token_info_free(info);
      info = NULL;
    }
    run_token(tok);
    /* Flip one bit of the signature: must never validate. */
    {
      char *last = strrchr(tok, '.');
      size_t sl = strlen(last + 1);
      if (sl > 1) {
        /* not the final char: its low bits may be padding the decoder
         * ignores; 'A'(0) <-> 'g'(32) differ in the top bit */
        size_t pos = (pl + hl) % (sl - 1);
        char c = last[1 + pos];
        last[1 + pos] = (c == 'A') ? 'g' : 'A';
        if (kc_jwt_validate_local(realm, tok, &info) == KC_SUCCESS)
          abort();                                /* forged token accepted */
        if (info) kc_jwt_token_info_free(info);
      }
    }
    free(tok);
    break;
  }
  case 2:
    jwks_body = buf;
    jwks_body_len = size - 1;
    jwks_cleanup();
    (void)jwks_refresh(realm);
    jwks_body = NULL;
    seed_cache();
    break;
  case 3: {
    size_t n = strlen(buf), kl = 0, rl = 0;
    unsigned char *ref = malloc(n + 4);
    char *kc = base64url_decode_alloc(buf, &kl);
    int rok = ref_decode(buf, ref, &rl);
    if (!!kc != rok) abort();
    if (kc && (kl != rl || memcmp(kc, ref, kl))) abort();
    free(kc);
    free(ref);
    break;
  }
  }
  free(buf);
  return 0;
}
