/*
 * fuzz_dns.c - libFuzzer harness for the DNS reply parser:
 * ircd/ircd_res.c proc_answer() (static; the file is #included) and the
 * name codec in ircd/ircd_reslib.c (irc_dn_expand, irc_dn_skipname,
 * irc_ns_name_*, irc_dn_comp, irc_res_mkquery).  DNS replies are network
 * input (res_readreply only checks the source address and the 16-bit id).
 *
 * With FUZZ_STRICT=1 each input is copied into a heap buffer of EXACTLY
 * its length, so a read past the received datagram is caught
 * (res_readreply receives into a larger stack buffer, which hides it).
 * Known bug F25 (FINDINGS.md): proc_answer() copies A/AAAA rdata without
 * checking that rd_length bytes were received; by default the buffer gets
 * 16 trailing zero bytes (what the real stack buffer gives, give or take
 * stale contents) so the campaign looks past it.
 * Byte 0 selects:
 *   0..2  proc_answer for a pending T_A / T_AAAA / T_PTR request (byte 1 bit
 *         0: the request is already in REQ_CNAME state); the rest is the
 *         reply, header converted to host order the way res_readreply does
 *   3     irc_dn_expand / irc_dn_skipname / irc_ns_name_skip at every offset
 *         of the message
 *   4     text name -> irc_ns_name_pton -> irc_ns_name_ntop and
 *         irc_res_mkquery (query names come from PTR answers and clients);
 *         a name that packs must round-trip through unpack/ntop
 */
#include "config.h"
#include "ircd_features.h"
#include "fuzz_util.h"

time_t CurrentTime = 1700000000;
int feature_int(enum Feature f) { (void)f; return 5; }
int feature_bool(enum Feature f) { (void)f; return 0; }
const char *feature_str(enum Feature f) { (void)f; return ""; }

#include "../../../ircd/ircd_res.c"
#include "ircd_reslib.h"

static void mode_answer(int type, unsigned flags, const uint8_t *d, size_t n)
{
  struct reslist req;
  char name[HOSTLEN + 1];
  char *buf;
  HEADER *h;
  if (n <= sizeof(HEADER)) return;           /* res_readreply's own check */
  buf = calloc(1, n + (fuzz_strict() ? 0 : 16));
  memcpy(buf, d, n);
  h = (HEADER *)buf;
  h->ancount = ntohs(h->ancount);
  h->qdcount = ntohs(h->qdcount);
  h->nscount = ntohs(h->nscount);
  h->arcount = ntohs(h->arcount);
  memset(&req, 0, sizeof req);
  req.type = type == 0 ? T_A : type == 1 ? T_AAAA : T_PTR;
  req.state = (flags & 1) ? REQ_CNAME : (type == 2 ? REQ_PTR : type == 1 ? REQ_AAAA : REQ_A);
  name[0] = 0;
  req.name = name;
  if (h->rcode == NO_ERRORS && h->ancount != 0)   /* as res_readreply */
    if (proc_answer(&req, h, buf, buf + n) && req.type == T_PTR)
      CHECK(strlen(name) <= HOSTLEN);
  free(buf);
}

static void mode_names(const uint8_t *d, size_t n)
{
  /* F27 (FINDINGS.md): labellen() reads the bit count after a bitstring
   * label type byte (0x41) without a bound, one byte past the message
   * when that byte is last.  One spare zero byte unless FUZZ_STRICT. */
  unsigned char *msg = calloc(1, (n ? n : 1) + (fuzz_strict() ? 0 : 1));
  char out[1100];
  size_t i;
  memcpy(msg, d, n);
  for (i = 0; i < n && i < 512; i++) {
    const unsigned char *p = msg + i;
    int r = irc_dn_expand(msg, msg + n, msg + i, out, sizeof out);
    if (r >= 0) CHECK(strlen(out) < sizeof out && (size_t)r <= n - i);
    (void)irc_dn_skipname(msg + i, msg + n);
    (void)irc_ns_name_skip(&p, msg + n);
  }
  free(msg);
}

static void mode_text(const uint8_t *d, size_t n)
{
  char *s = strndup((const char *)d, n), back[1100];
  /* F26 (FINDINGS.md): an RFC 2673 bitstring label (\[x...]) with more
   * than 8 hex digits overflows the int accumulator in
   * irc_encode_bitsring; skipped unless FUZZ_STRICT */
  if (!fuzz_strict() && strstr(s, "\\[")) { free(s); return; }
  unsigned char wire[300], q[600], dn[300];
  int r = irc_ns_name_pton(s, wire, sizeof wire);
  if (r >= 0) {
    if (irc_ns_name_ntop((const char *)wire, back, sizeof back) >= 0) {
      unsigned char wire2[300];
      CHECK(irc_ns_name_pton(back, wire2, sizeof wire2) >= 0);
      CHECK(!memcmp(wire, wire2, irc_dn_skipname(wire, wire + sizeof wire) > 0 ?
                    (size_t)irc_dn_skipname(wire, wire + sizeof wire) : 1));
    }
  }
  {
    unsigned char *dnptrs[8] = { dn, NULL }, **last = dnptrs + 8;
    (void)irc_dn_comp(s, dn, sizeof dn, dnptrs, last);
  }
  r = irc_res_mkquery(s, C_IN, T_PTR, q, sizeof q);
  if (r > 0) CHECK((size_t)r <= sizeof q);
  free(s);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  if (size < 2) return 0;
  switch (data[0] % 5) {
  case 0: case 1: case 2: mode_answer(data[0] % 5, data[1], data + 2, size - 2); break;
  case 3: mode_names(data + 1, size - 1); break;
  case 4: mode_text(data + 1, size - 1); break;
  }
  return 0;
}
