/*
 * fuzz_kc_base64.c - libFuzzer harness for ircd/kc/kc_base64.c (gnulib
 * base64, used by JWT/JWKS decoding, SCRAM credential encoding and the
 * webhook SPI's SCRAM fields).
 * Byte 0 selects:
 *   0  decode arbitrary text: kc_base64_decode_alloc vs an independent
 *      RFC 4648 decoder (padding required, '=' only at the end, trailing
 *      bits ignored like gnulib); with FUZZ_DUMP=1 each verdict is printed
 *      for tools/crosscheck_base64.py, which re-checks it against Python's
 *      base64.b64decode(validate=True)
 *   1  encode arbitrary bytes: decode(encode(x)) == x, length ==
 *      KC_BASE64_LENGTH, alphabet only; kc_base64_encode into a short
 *      buffer never writes past it
 */
#include <kc/kc_base64.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(c) do { if (!(c)) { fprintf(stderr, "CHECK failed: %s (%s:%d)\n", #c, __FILE__, __LINE__); abort(); } } while (0)

static int val(unsigned char c)
{
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 'a' + 26;
  if (c >= '0' && c <= '9') return c - '0' + 52;
  if (c == '+') return 62;
  if (c == '/') return 63;
  return -1;
}

static int ref_decode(const unsigned char *in, size_t n, unsigned char *out, size_t *olen)
{
  size_t i, o = 0;
  if (n % 4) return 0;
  for (i = 0; i < n; i += 4) {
    int a = val(in[i]), b = val(in[i + 1]), c, d;
    int last = (i + 4 == n);
    if (a < 0 || b < 0) return 0;
    out[o++] = (unsigned char)(a << 2 | b >> 4);
    if (in[i + 2] == '=') {
      if (!last || in[i + 3] != '=') return 0;
      break;
    }
    if ((c = val(in[i + 2])) < 0) return 0;
    out[o++] = (unsigned char)((b << 4) | (c >> 2));
    if (in[i + 3] == '=') {
      if (!last) return 0;
      break;
    }
    if ((d = val(in[i + 3])) < 0) return 0;
    out[o++] = (unsigned char)((c << 6) | d);
  }
  *olen = o;
  return 1;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  const char *in = (const char *)data + 1;
  size_t n;
  if (size < 1) return 0;
  n = size - 1;
  if (data[0] & 1) {
    char *enc = NULL, *dec = NULL, small[9];
    size_t el = kc_base64_encode_alloc(in, n, &enc), dl = 0, i;
    CHECK(enc);
    CHECK(el == KC_BASE64_LENGTH(n));
    CHECK(strlen(enc) == el);
    for (i = 0; i < el; i++) CHECK(kc_isbase64(enc[i]) || enc[i] == '=');
    CHECK(kc_base64_decode_alloc(enc, el, &dec, &dl));
    CHECK(dl == n && (n == 0 || !memcmp(dec, in, n)));
    {
      size_t ol = 1 + data[0] % 8;
      char *o = malloc(ol);
      kc_base64_encode(in, n, o, ol);
      free(o);
    }
    (void)small;
    free(enc); free(dec);
  } else {
    char *dec = NULL;
    size_t dl = 0, rl = 0;
    unsigned char *ref = malloc(n + 4);
    int ok = kc_base64_decode_alloc(in, n, &dec, &dl) && dec;
    int rok = ref_decode((const unsigned char *)in, n, ref, &rl);
    if (getenv("FUZZ_DUMP")) {
      size_t i;
      printf("DUMP ");
      for (i = 0; i < n; i++) printf("%02x", (unsigned char)in[i]);
      printf(" %d ", ok);
      for (i = 0; ok && i < dl; i++) printf("%02x", (unsigned char)dec[i]);
      printf("\n");
    }
    CHECK(ok == rok);
    if (ok) CHECK(dl == rl && (dl == 0 || !memcmp(dec, ref, dl)));
    free(dec); free(ref);
  }
  return 0;
}
