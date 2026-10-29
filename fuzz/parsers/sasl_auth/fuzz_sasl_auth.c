/*
 * fuzz_sasl_auth.c - libFuzzer harness for local SASL (ircd/sasl_auth.c).
 *
 * AUTHENTICATE payloads are sent by unregistered clients and decoded and
 * parsed here before any credential is checked: the 400-byte chunk
 * accumulator (sasl_continue), the base64 decoder (sasl_base64_decode),
 * and the per-mechanism parsers -- PLAIN (sasl_handle_plain), OAUTHBEARER
 * (oauthbearer_parse), SCRAM-SHA-256 client-first/client-final
 * (sasl_scram_client_first / sasl_scram_client_final), ECDSA, EXTERNAL.
 * The real sasl_auth.c is compiled with USE_LIBKC and linked against
 * sasl_stubs.c; asynchronous Keycloak calls park their callback, which the
 * harness completes with a canned reply so a SCRAM or ECDSA exchange
 * proceeds to its second client message.
 *
 * Input: byte 0 = mechanism, byte 1 = flags (callback outcomes), then the
 * AUTHENTICATE parameters, one per '\n'-terminated line, as m_authenticate
 * would pass them (at most 400 bytes, no NUL/CR/LF).  A line starting with
 * '!' is plaintext instead: the harness replaces "@N" with the server's
 * SCRAM nonce, "\\0" with a NUL byte, base64-encodes it and sends it in
 * 400-byte chunks the way a client does -- so the mechanism parsers past
 * the decoder (and the nonce check) are reachable.
 */
#include "config.h"
#include "client.h"
#include "ircd_alloc.h"
#include "sasl_auth.h"
#include <kc/kc.h>
#include <kc/kc_keycloak.h>
#include <stdint.h>
#include <openssl/evp.h>
#include <stdlib.h>
#include <string.h>
#include "sasl_stubs.h"

/* #included (not linked) so the harness can reset the module statics --
 * kc_sasl_healthy latches off after one failed callback. */
#include "../../../ircd/sasl_auth.c"

extern struct Client *LocalClientArray[];
extern unsigned int fuzz_rand_state;

static const char *mechs[] = {
  "PLAIN", "OAUTHBEARER", "SCRAM-SHA-256", "ECDSA-NIST256P-CHALLENGE",
  "EXTERNAL", "plain", "BOGUS"
};

static const char ec_pub_pem[] =
  "-----BEGIN PUBLIC KEY-----\n"
  "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE3x+wPYN09zt+fCHKPP6HLY3vgDcv\n"
  "PqmFTIkf5hMG2XkFjRDQFfpKPojzgabr2HNiG0nKW4vnINhySCBwlcAw0w==\n"
  "-----END PUBLIC KEY-----\n";

static void complete_pending(unsigned flags)
{
  struct pending_kc p = pending;
  memset(&pending, 0, sizeof pending);
  switch (p.kind) {
  case PK_USER: {
    struct kc_user u;
    memset(&u, 0, sizeof u);
    u.id = "f81d4fae-7dec-11d0-a765-00a0c91e6bf6";
    u.username = "alice";
    u.scram_salt = "W22ZaJ0SNY7soEsUEjb6gQ==";
    u.scram_iterations = (flags & 2) ? 0 : 4096;
    u.scram_stored_key = (flags & 4) ? "short" : "WG5d8oPm3OtcPnkdi4Uo7BkeZkBFzpcXkuLmtbsT4qY=";
    u.scram_server_key = "wfPLwcE6nTWhTAmQ7tl2KeoiWGPlZqQxSrmfPwDl2dU=";
    u.ecdsa_pubkey = (flags & 8) ? NULL : (char *)ec_pub_pem;
    p.user_cb((flags & 1) ? KC_NOT_FOUND : KC_SUCCESS, &u, p.data);
    break;
  }
  case PK_SEARCH: {
    struct kc_user u;
    memset(&u, 0, sizeof u);
    u.id = "f81d4fae-7dec-11d0-a765-00a0c91e6bf6";
    u.username = "alice";
    p.users_cb((flags & 1) ? KC_ERROR : KC_SUCCESS, &u, (flags & 16) ? 2 : 1, p.data);
    break;
  }
  case PK_TOKEN: {
    struct kc_access_token t;
    memset(&t, 0, sizeof t);
    t.access_token = "eyJhbGciOiJSUzI1NiJ9.e30.sig";
    t.id_token = (flags & 32) ? NULL : "eyJhbGciOiJSUzI1NiJ9.e30.sig";
    p.token_cb((flags & 1) ? KC_FORBIDDEN : KC_SUCCESS, &t, p.data);
    break;
  }
  case PK_INTROSPECT: {
    struct kc_token_info i;
    memset(&i, 0, sizeof i);
    i.active = !(flags & 1);
    i.username = (flags & 64) ? NULL : "alice";
    i.sub = "f81d4fae-7dec-11d0-a765-00a0c91e6bf6";
    i.exp = 1700000100;
    p.introspect_cb(i.active ? KC_SUCCESS : KC_FORBIDDEN, &i, p.data);
    break;
  }
  case PK_NONE:
    break;
  }
}

/* Plaintext line -> base64 -> 400-byte AUTHENTICATE chunks. */
static int send_plain(struct Client *cli, const char *src, size_t n)
{
  unsigned char plain[1200];
  char b64[1700], chunk[401];
  struct SASLSession *s = cli_saslsession(cli);
  size_t i, o = 0, bl, pos;
  for (i = 0; i < n && o < sizeof(plain) - 130; i++) {
    if (src[i] == '@' && i + 1 < n && src[i + 1] == 'N') {
      const char *nn = (s && s->scram_combined_nonce) ? s->scram_combined_nonce : "";
      size_t l = strlen(nn);
      if (l > 128) l = 128;
      memcpy(plain + o, nn, l);
      o += l;
      i++;
    } else if (src[i] == '\\' && i + 1 < n && src[i + 1] == '0') {
      plain[o++] = 0;
      i++;
    } else {
      plain[o++] = (unsigned char)src[i];
    }
  }
  bl = (size_t)EVP_EncodeBlock((unsigned char *)b64, plain, (int)o);
  if (bl == 0) return sasl_continue(cli, "+");
  for (pos = 0; pos < bl; pos += 400) {
    size_t c = bl - pos > 400 ? 400 : bl - pos;
    int rc;
    memcpy(chunk, b64 + pos, c);
    chunk[c] = '\0';
    if ((rc = sasl_continue(cli, chunk)) < 0 || !cli_saslsession(cli))
      return -1;
    if (c == 400 && pos + c == bl && sasl_continue(cli, "+") < 0)
      return -1;
  }
  return 0;
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
  (void)argc; (void)argv;
  if (sasl_local_init() != 0 || !sasl_local_available()) abort();
  memset(&pending, 0, sizeof pending);   /* the health-check token request */
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  static struct Client cli;
  static struct Connection con;
  size_t off = 2;
  unsigned flags;
  char line[402];

  if (size < 2) return 0;
  flags = data[1];
  fuzz_rand_state = 12345;           /* same nonces every run */
  kc_sasl_healthy = 1;
  memset(&cli, 0, sizeof cli);
  memset(&con, 0, sizeof con);
  cli_connect(&cli) = &con;
  cli_fd(&cli) = 5;
  cli_status(&cli) = STAT_UNKNOWN_USER;
  LocalClientArray[5] = &cli;
  memset(&pending, 0, sizeof pending);
  jwt_local_result = (flags & 128) ? KC_SUCCESS : ((flags & 64) ? KC_FORBIDDEN : KC_ERROR);
  if (data[0] & 0x80)
    strcpy(cli_sslclifp(&cli), "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");

  if (sasl_start(&cli, mechs[(data[0] & 0x7f) % 7]) != 0)
    goto done;
  while (off < size && cli_saslsession(&cli)) {
    size_t n = 0;
    while (off < size && data[off] != '\n' && n < 400) {
      if (data[off] != '\0' && data[off] != '\r')
        line[n++] = (char)data[off];
      off++;
    }
    if (off < size && data[off] == '\n') off++;
    if (n == 0) { line[0] = '+'; n = 1; }
    line[n] = '\0';
    if (line[0] == '!') {
      if (send_plain(&cli, line + 1, n - 1) < 0)
        break;
    } else if (sasl_continue(&cli, line) < 0)
      break;
    if (pending.kind != PK_NONE)
      complete_pending(flags);
  }
done:
  if (pending.kind != PK_NONE) {
    MyFree(pending.data);
    memset(&pending, 0, sizeof pending);
  }
  sasl_session_free(&cli);
  LocalClientArray[5] = NULL;
  return 0;
}
