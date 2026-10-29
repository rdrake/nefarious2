/*
 * account_id_harness.c - CBMC proofs for ircd/account_id.c (with the real
 * webpush_b64url_encode from ircd/webpush_keyring.c), both #included
 * unmodified.
 */
#include "../common/cbmc_util.h"
#include "../common/libc_models.h"
#include "../../../ircd/webpush_keyring.c"
#include "../../../ircd/account_id.c"

#ifndef SMAX
#define SMAX 24
#endif

static int in_alpha(int c)
{
  return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
      || (c >= '0' && c <= '9') || c == '-' || c == '_';
}

/* I1  account_id_valid: memory safe on every string of length <= SMAX and
 *     EXACTLY the header contract: strlen == 22 and every byte in the
 *     base64url alphabet (bytes >= 0x80 rejected whatever the locale). */
void harness_valid_contract(void)
{
  char s[SMAX + 1];
  size_t i, n;
  int want = 1;
  NONDET_CSTR(s, SMAX);
  n = strlen(s);
  for (i = 0; i < n; i++)
    if (!in_alpha((unsigned char)s[i]))
      want = 0;
  if (n != ACCOUNT_ID_LEN)
    want = 0;
  __CPROVER_assert(account_id_valid(s) == want, "valid <=> 22 base64url chars");
  __CPROVER_assert(account_id_valid(0) == 0, "NULL invalid");
}

/* I2  account_id_from_uuid on ARBITRARY input (length <= SMAX): memory
 *     safe; on 0 the output is untouched; on 1 the output is a valid
 *     compact id.  (SMAX < 32 can never succeed -- see I3/I4 for that.) */
void harness_from_uuid_arbitrary(void)
{
  char s[SMAX + 1], out[ACCOUNT_ID_LEN + 1], before[ACCOUNT_ID_LEN + 1];
  int r, i;
  NONDET_CSTR(s, SMAX);
  for (i = 0; i <= ACCOUNT_ID_LEN; i++)
    before[i] = out[i] = nondet_char();
  r = account_id_from_uuid(s, out);
  if (r == 0)
    __CPROVER_assert(memcmp(out, before, sizeof(out)) == 0, "out untouched on failure");
  else
    __CPROVER_assert(account_id_valid(out), "success yields a valid id");
}

static const char hexd_lo[] = "0123456789abcdef";
static const char hexd_up[] = "0123456789ABCDEF";

/* I3  correctness: for EVERY 128-bit value, written as the 36-byte
 *     canonical 8-4-4-4-12 form with per-digit arbitrary case, the result
 *     is 1, a valid id, and decodes (base64url, independent decoder
 *     below) back to exactly those 16 bytes. */
static int b64v(char c)
{
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 'a' + 26;
  if (c >= '0' && c <= '9') return c - '0' + 52;
  if (c == '-') return 62;
  if (c == '_') return 63;
  return -1;
}
void harness_from_uuid_roundtrip(void)
{
  unsigned char raw[16];
  char uuid[37], out[ACCOUNT_ID_LEN + 1];
  int i, d = 0, pos = 0;
  unsigned bits = 0, nbits = 0, k = 0;

  for (i = 0; i < 16; i++)
    raw[i] = nondet_uchar();
  for (i = 0; i < 32; i++) {
    unsigned nib = (i & 1) ? (raw[i / 2] & 15) : (raw[i / 2] >> 4);
    if (pos == 8 || pos == 13 || pos == 18 || pos == 23)
      uuid[pos++] = '-';
    uuid[pos++] = (nondet_int() & 1) ? hexd_up[nib] : hexd_lo[nib];
  }
  uuid[36] = '\0';
  __CPROVER_assert(account_id_from_uuid(uuid, out) == 1, "canonical UUID accepted");
  __CPROVER_assert(account_id_valid(out), "valid id");
  for (i = 0; i < ACCOUNT_ID_LEN; i++) {
    bits = (bits << 6) | (unsigned)b64v(out[i]);
    nbits += 6;
    if (nbits >= 8) {
      nbits -= 8;
      __CPROVER_assert(k < 16 && (unsigned char)(bits >> nbits) == raw[k],
                       "decodes back to the UUID bytes");
      k++;
      bits &= (1u << nbits) - 1;
    }
  }
  __CPROVER_assert(k == 16 && bits == 0, "16 bytes, zero pad bits (canonical)");
  (void)d;
}

/* I4  the header's accepted-forms contract: "canonical 8-4-4-4-12 form,
 *     or the 32 hex digits without hyphens".  A 36-byte input that is 32
 *     hex digits plus 4 hyphens at NON-canonical positions must be
 *     rejected.  (Expected to FAIL: hyphens are skipped anywhere.) */
void harness_from_uuid_hyphen_positions(void)
{
  char uuid[37], out[ACCOUNT_ID_LEN + 1];
  int i, hy = 0, canonical = 1;
  for (i = 0; i < 36; i++) {
    int h = nondet_int() & 1;
    uuid[i] = h ? '-' : 'a';
    hy += h;
    if (h != (i == 8 || i == 13 || i == 18 || i == 23))
      canonical = 0;
  }
  uuid[36] = '\0';
  __CPROVER_assume(hy == 4);
  if (account_id_from_uuid(uuid, out))
    __CPROVER_assert(canonical, "only canonical hyphen positions accepted");
}
