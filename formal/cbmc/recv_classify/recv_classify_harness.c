/*
 * recv_classify_harness.c - CBMC proofs for ircd/recv_classify.c (#included
 * unmodified, with the real client.h so the Connection accessors and
 * IsServer/IsHandshake are the production macros).
 *
 * The caps are 4095/8191 (tags) and 512 (body); buffers that long are out
 * of reach for bit-precise BMC, so the functional harnesses prove the
 * COUNTER semantics (which the caps are then a plain comparison on) and
 * resumability; a separate harness drives the counters near the caps by
 * starting from a symbolic mid-line state.
 */
#include "../common/cbmc_util.h"
#include "../../../ircd/recv_classify.c"

#ifndef BMAX
#define BMAX 8
#endif

static struct Client cli;
static struct Connection con;

static void setup(void)
{
  cli_connect(&cli) = &con;
  cli_status(&cli) = nondet_int() & 1 ? STAT_SERVER : STAT_USER;
  con_recv_state(&con) = RECV_TAGS;
  con_recv_tag_bytes(&con) = 0;
  con_recv_msg_bytes(&con) = 0;
}

/* Reference model of the per-line accounting (the header's design):
 * a line is split on CR or LF; if it begins with '@' the tag region is
 * the '@' and everything up to (not incl.) the first SPACE, and the body
 * is everything after that SPACE; otherwise the whole line is body. */
static void ref_line(const char *b, unsigned len, unsigned *tag, unsigned *msg)
{
  unsigned i, start = 0, sp;
  for (i = 0; i < len; i++)
    if (b[i] == '\r' || b[i] == '\n')
      start = i + 1;
  *tag = *msg = 0;
  if (start >= len)
    return;
  if (b[start] != '@') {
    *msg = len - start;
    return;
  }
  for (sp = start; sp < len && b[sp] != ' '; sp++)
    ;
  *tag = sp - start;
  *msg = sp < len ? len - sp - 1 : 0;
}

/* C1  memory safety for every buffer of length <= BMAX from a fresh line,
 *     and the counters after the call equal the reference accounting of
 *     the last (unterminated) line. */
void harness_counters(void)
{
  char buf[BMAX];
  unsigned len = nondet_unsigned(), tag, msg, i;
  setup();
  for (i = 0; i < BMAX; i++)
    buf[i] = nondet_char();
  __CPROVER_assume(len <= BMAX);
  (void)recv_classify(&cli, buf, len);
  ref_line(buf, len, &tag, &msg);
  __CPROVER_assert(con_recv_tag_bytes(&con) == tag, "tag counter == reference");
  __CPROVER_assert(con_recv_msg_bytes(&con) == msg, "msg counter == reference");
}

/* C2  resumability (header: "TCP segment boundaries mid-line do not lose
 *     context"): classifying a||b in one call or as a then b gives the
 *     same final state, and the same verdict (first overrun wins). */
void harness_split(void)
{
  char buf[BMAX];
  unsigned len = nondet_unsigned(), cut = nondet_unsigned(), i;
  unsigned st1, tg1, ms1;
  int r_whole, r1, r2;
  unsigned st0 = nondet_unsigned() & 1, tg0 = nondet_unsigned(), ms0 = nondet_unsigned();

  setup();
  /* arbitrary resumable starting state near the caps */
  __CPROVER_assume(tg0 <= 8192 && ms0 <= 513);
  __CPROVER_assume(st0 == RECV_MSG || ms0 == 0);
  for (i = 0; i < BMAX; i++)
    buf[i] = nondet_char();
  __CPROVER_assume(len <= BMAX && cut <= len);

  con_recv_state(&con) = st0; con_recv_tag_bytes(&con) = tg0; con_recv_msg_bytes(&con) = ms0;
  r_whole = recv_classify(&cli, buf, len);
  st1 = con_recv_state(&con); tg1 = con_recv_tag_bytes(&con); ms1 = con_recv_msg_bytes(&con);

  con_recv_state(&con) = st0; con_recv_tag_bytes(&con) = tg0; con_recv_msg_bytes(&con) = ms0;
  r1 = recv_classify(&cli, buf, cut);
  r2 = recv_classify(&cli, buf + cut, len - cut);

  __CPROVER_assert(st1 == con_recv_state(&con) && tg1 == con_recv_tag_bytes(&con)
                   && ms1 == con_recv_msg_bytes(&con), "split == whole (state)");
  __CPROVER_assert(r_whole == (r1 ? r1 : r2), "split == whole (verdict)");
}

/* C3  cap semantics from a symbolic mid-line state: the call reports an
 *     overrun iff some prefix pushed a counter past its cap (client
 *     4095/512, server 8191/512), and the first one wins. */
void harness_caps(void)
{
  char buf[BMAX];
  unsigned len = nondet_unsigned(), i;
  unsigned tg0 = nondet_unsigned(), ms0 = nondet_unsigned(), st0 = nondet_unsigned() & 1;
  unsigned tcap, mcap = 512, tg, ms, st;
  int r, want = RECV_CLASSIFY_OK;

  setup();
  tcap = IsServer(&cli) ? 8191 : 4095;
  __CPROVER_assume(tg0 <= 8192 && ms0 <= 513);
  __CPROVER_assume(st0 == RECV_MSG || ms0 == 0);
  for (i = 0; i < BMAX; i++)
    buf[i] = nondet_char();
  __CPROVER_assume(len <= BMAX);
  con_recv_state(&con) = st = st0; con_recv_tag_bytes(&con) = tg = tg0;
  con_recv_msg_bytes(&con) = ms = ms0;
  /* independent re-statement of the state machine */
  for (i = 0; i < len; i++) {
    char c = buf[i];
    if (c == '\r' || c == '\n') { st = RECV_TAGS; tg = ms = 0; continue; }
    if (st == RECV_TAGS && tg == 0 && c == '@') { tg = 1; continue; }
    if (st == RECV_TAGS && tg != 0 && c == ' ') { st = RECV_MSG; continue; }
    if (st == RECV_TAGS && tg != 0) {
      tg++;
      if (tg > tcap && want == RECV_CLASSIFY_OK) want = RECV_CLASSIFY_TAG_OVERRUN;
      continue;
    }
    st = RECV_MSG;
    ms++;
    if (ms > mcap && want == RECV_CLASSIFY_OK) want = RECV_CLASSIFY_MSG_OVERRUN;
  }
  r = recv_classify(&cli, buf, len);
  __CPROVER_assert(r == want, "verdict == first cap crossing");
}
