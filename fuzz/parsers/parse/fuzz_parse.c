/*
 * fuzz_parse.c - libFuzzer harness for the IRC line parser,
 * ircd/parse.c: parse_client() (every line a client sends, IRCv3
 * message-tag region included: label, batch, multiline-concat,
 * client-only +tags, CLIENTTAGDENY) and parse_server() (P10 lines from a
 * linked server: @A/@H compact time / HLC tags, numeric prefixes).
 * parse.c is #included; the command handlers in msgtab and everything
 * else parse.c references are common/autostub.py fallbacks (handlers
 * return 0), so what runs is the parser itself: tags, prefix, command
 * lookup, parameter split.
 *
 * Input: byte 0 = mode (bit 0: server link, bit 1: registered user with
 * every CAP active, else unregistered), then one line exactly as
 * dbuf_getmsg() hands it over (cut at the first CR/LF, <= FULL_MSG_SIZE-1,
 * NUL-terminated).
 */
#include "config.h"
#include "client.h"
#include "s_misc.h"
#include "ircd_features.h"
#include "fuzz_util.h"

time_t CurrentTime = 1700000000;
static struct ServerStatistics fz_stats;
struct ServerStatistics *ServerStats = &fz_stats;
int feature_bool(enum Feature f) { (void)f; return 1; }
int feature_int(enum Feature f) { (void)f; return 0; }
const char *feature_str(enum Feature f) { (void)f; return ""; }

#include "../../../ircd/parse.c"

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
  (void)argc; (void)argv;
  initmsgtree();
  strcpy(cli_name(&me), "fuzz.server");
  strcpy(cli_yxx(&me), "AB");
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  static struct Client cli;
  static struct Connection con;
  static struct User user;
  static struct Server serv;
  /* F24 (FINDINGS.md): parse_server() reads ch[1]/ch[2] of a line that
   * is only a numeric prefix, i.e. up to two bytes past the NUL.  In the
   * ircd cli_buffer is followed by other Connection fields; by default
   * the harness gives the buffer two spare bytes, FUZZ_STRICT=1 uses an
   * exact FULL_MSG_SIZE heap buffer. */
  static char sbuf[FULL_MSG_SIZE + 2];
  char *buf = sbuf;
  size_t n = 0;
  if (size < 1) return 0;
  if (fuzz_strict()) buf = malloc(FULL_MSG_SIZE);
  while (1 + n < size && n < FULL_MSG_SIZE - 1 && data[1 + n] != '\r' && data[1 + n] != '\n')
    n++;
  memcpy(buf, data + 1, n);
  buf[n] = '\0';

  memset(&cli, 0, sizeof cli);
  memset(&con, 0, sizeof con);
  memset(&user, 0, sizeof user);
  memset(&serv, 0, sizeof serv);
  cli_connect(&cli) = &con;
  cli_fd(&cli) = -1;
  cli_from(&cli) = &cli;
  strcpy(cli_name(&cli), "fuzzer");
  /* F28 (FINDINGS.md): a 3-character server command whose first byte is
   * a digit is a numeric computed as d0*100+d1*10+d2 with only d0
   * checked; when that is 0 ("000", "0*l", ...) parse_server skips
   * do_numeric() and dereferences mptr == NULL.  Such tokens are skipped
   * unless FUZZ_STRICT. */
  if ((data[0] & 1) && !fuzz_strict()) {
    const char *z;
    for (z = buf; *z; z++) {
      if ((z == buf || z[-1] == ' ') && z[0] >= '0' && z[0] <= '9' && z[1] && z[2] &&
          z[3] == ' ' && (z[0] - '0') * 100 + (z[1] - '0') * 10 + (z[2] - '0') == 0)
        goto out;
    }
  }
  if (data[0] & 1) {
    cli_status(&cli) = STAT_SERVER;
    cli_serv(&cli) = &serv;
    cli_handler(&cli) = SERVER_HANDLER;
    strcpy(cli_yxx(&cli), "AC");
    parse_server(&cli, buf, buf + n);
  } else {
    if (data[0] & 2) {
      cli_status(&cli) = STAT_USER;
      cli_handler(&cli) = CLIENT_HANDLER;
      cli_user(&cli) = &user;
      strcpy(user.username, "fuzz");
      strcpy(user.host, "fuzz.host");
      memset(cli_active(&cli), 0xff, sizeof(*cli_active(&cli)));
      memset(cli_capab(&cli), 0xff, sizeof(*cli_capab(&cli)));
    } else {
      cli_status(&cli) = STAT_UNKNOWN;
      cli_handler(&cli) = UNREGISTERED_HANDLER;
    }
    parse_client(&cli, buf, buf + n);
  }
out:
  if (buf != sbuf) free(buf);
  return 0;
}
