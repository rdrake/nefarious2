/*
 * fuzz_p10.c - libFuzzer harness for the Nefarious P10 server-to-server
 * input path.
 *
 * The harness links every ircd object (ircd.c is rebuilt with
 * -Dmain=ircd_main so its globals stay but its main() is out of the way)
 * and replays the start-up sequence of ircd.c main() without
 * daemonising, listening or entering the event loop.
 *
 * Per input:
 *   1. a fresh TCP loopback socket pair is made; the accepted end goes
 *      through the real add_connection() on a LISTEN_SERVER listener, so
 *      the peer is a real STAT_UNKNOWN_SERVER connection with auth
 *      started exactly as on a live hub;
 *   2. optionally (input byte 0, bit 3) two local users are registered
 *      through parse_client (NICK/USER) and joined to #fuzz, so handlers
 *      that deliver to / act on MyUser clients have targets;
 *   3. the link handshake "PASS / SERVER" goes through recv_classify ->
 *      connect_dopacket -> mr_server -> server_estab, exactly like
 *      read_packet() in s_bsd.c (our own burst is written and discarded);
 *   4. optionally (byte 0, bit 0) the peer's END_OF_BURST is sent first,
 *      so the rest of the input runs post-burst instead of in-burst;
 *   5. the remaining bytes are fed, in 4 KiB reads, through
 *      recv_classify -> server_dopacket -> parse_server -> handlers,
 *      the same call sequence read_packet() uses for a server link;
 *   6. timers due within the next FUZZ_TIMER_SECS seconds are run
 *      (byte 0, bit 4), so hold/expiry/destruct callbacks armed by the
 *      input fire too;
 *   7. state is reset: the link is squit with exit_client(), the local
 *      users are exited, and the global client list must be back to
 *      just &me (checked; FUZZ_STRICT=1 aborts on a leak).
 *
 * Byte 0 flags (the rest of the input is the raw wire stream):
 *   bit 0  0x01  send "AB EB" before the input (post-burst mode)
 *   bit 1  0x02  legacy peer: no 'v' (IRCv3-aware) / 'F' in SERVER flags
 *   bit 2  0x04  link as "uhub.fuzz", which is in a UWorld block (U-lined)
 *   bit 3  0x08  register local users alice / bob in #fuzz first
 *   bit 4  0x10  run timers after the input
 *
 * FUZZ_FILTER_KNOWN=1 drops input lines matching already-confirmed bugs
 * (see known_bug_line and FINDINGS.md) so campaigns get past them; the
 * input is then fed line by line instead of in 4 KiB reads.
 *
 * Outbound data never reaches a socket: os_send_nonb / os_sendv_nonb
 * are wrapped at link time (-Wl,--wrap) to claim every byte written.
 */
#include "config.h"
#include "ircd.h"
#include "IPcheck.h"
#include "class.h"
#include "client.h"
#include "channel.h"
#include "handlers.h"
#include "crdt_hlc.h"
#include "hash.h"
#include "bouncer_session.h"
#include "chathistory_presence.h"
#include "history.h"
#include "ircd_alloc.h"
#include "ircd_compress.h"
#include "ircd_events.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "ircd_crypt.h"
#include "capab.h"
#include "thread_pool.h"
#include "list.h"
#include "motd.h"
#include "msg.h"
#include "msgq.h"
#include "numnicks.h"
#include "packet.h"
#include "parse.h"
#include "recv_classify.h"
#include "s_auth.h"
#include "dnsbl.h"
#include "s_bsd.h"
#include "s_conf.h"
#include "s_misc.h"
#include "s_stats.h"
#include "s_user.h"
#include "send.h"
#include "listener.h"
#include "metadata.h"
#include "userload.h"
#include "whowas.h"
#include "ircd_osdep.h"
#include "sys.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <unistd.h>

extern void init_counters(void);
extern struct Connection me_con;
extern char *configfile;
extern unsigned long MsgIdCounter;
extern int server_boot_complete;

#define HUB_NUMERIC "AB"
#define ME_NUMERIC  10          /* "AK" */
#define FUZZ_TIMER_SECS 7200

static char tmpdir[256];
static struct Listener server_listener;
static struct Listener user_listener;
static int tcp_listen_fd = -1;
static struct sockaddr_in tcp_listen_addr;
static int verbose;
static int strict;
static int filter_known;

/* ---------------------------------------------------------------- */
/* Outbound path: discard everything                                  */
/* ---------------------------------------------------------------- */

/* fd whose outbound "PING :<cookie>" we want (local user registration) */
static int watch_fd = -1;
static char ping_cookie[32];

static void scan_ping(int fd, const char *buf, size_t len)
{
  const char *p;
  size_t i, n;
  if (fd != watch_fd || len < 7)
    return;
  for (p = buf; p + 6 <= buf + len; p++)
    if (!memcmp(p, "PING :", 6)) {
      p += 6;
      n = buf + len - p;
      for (i = 0; i < n && i < sizeof(ping_cookie) - 1 && p[i] >= '0' && p[i] <= '9'; i++)
        ping_cookie[i] = p[i];
      ping_cookie[i] = '\0';
      return;
    }
}

IOResult __wrap_os_send_nonb(int fd, const char *buf, unsigned int length,
                             unsigned int *count_out)
{
  scan_ping(fd, buf, length);
  *count_out = length;
  return IO_SUCCESS;
}

IOResult __wrap_os_sendv_nonb(int fd, struct MsgQ *buf, unsigned int *count_in,
                              unsigned int *count_out)
{
  struct iovec iov[128];
  unsigned int i, total = 0;
  int count;

  *count_in = 0;
  count = msgq_mapiov(buf, iov, 128, count_in);
  for (i = 0; i < (unsigned int)count; i++) {
    scan_ping(fd, iov[i].iov_base, iov[i].iov_len);
    total += iov[i].iov_len;
  }
  *count_out = total;
  return IO_SUCCESS;
}

/* ---------------------------------------------------------------- */
/* Start-up                                                          */
/* ---------------------------------------------------------------- */

static const char conf_text[] =
  "General {\n"
  "  name = \"fuzz.local\";\n"
  "  description = \"fuzz hub\";\n"
  "  numeric = 10;\n"
  "};\n"
  "Admin { Location = \"fuzz\"; Contact = \"fuzz\"; };\n"
  "Class { name = \"Server\"; pingfreq = 90; connectfreq = 300; maxlinks = 10; sendq = 90000000; };\n"
  "Class { name = \"Users\"; pingfreq = 90; maxlinks = 4000; sendq = 9000000; fakelagminimum = 0; fakelagfactor = 0; };\n"
  "Client { ip = \"*\"; host = \"*\"; class = \"Users\"; };\n"
  "Connect { name = \"hub.fuzz\"; host = \"127.0.0.1\"; password = \"fuzzpass\"; port = 4400;\n"
  "  class = \"Server\"; hub = \"*\"; autoconnect = no; };\n"
  "Connect { name = \"uhub.fuzz\"; host = \"127.0.0.1\"; password = \"fuzzpass\"; port = 4401;\n"
  "  class = \"Server\"; hub = \"*\"; autoconnect = no; };\n"
  "UWorld { name = \"uhub.fuzz\"; name = \"services.fuzz\"; name = \"x3.fuzz\"; };\n"
  "Operator { name = \"oper\"; host = \"*@*\"; password = \"$PLAIN$oper\"; class = \"Users\"; local = no; };\n"
  "Features {\n"
  "  \"LOG\" = \"SYSTEM\" \"FILE\" \"/dev/stderr\";\n"
  "  \"LOG\" = \"SYSTEM\" \"LEVEL\" \"CRIT\";\n"
  "  \"HUB\" = \"TRUE\";\n"
  "  \"NODNS\" = \"TRUE\";\n"
  "  \"NOIDENT\" = \"TRUE\";\n"
  "  \"RELIABLE_CLOCK\" = \"FALSE\";\n"
  "  \"CAP_draft_chathistory\" = \"TRUE\";\n"
  "  \"CAP_draft_metadata_2\" = \"TRUE\";\n"
  "  \"CAP_draft_read_marker\" = \"TRUE\";\n"
  "  \"CAP_draft_message_redaction\" = \"TRUE\";\n"
  "  \"CAP_draft_event_playback\" = \"TRUE\";\n"
  "  \"CAP_draft_channel_rename\" = \"TRUE\";\n"
  "  \"CAP_draft_webpush\" = \"FALSE\";\n"
  "  \"CHATHISTORY_PRIVATE\" = \"TRUE\";\n"
  "  \"BOUNCER_ENABLE\" = \"TRUE\";\n"
  "  \"BOUNCER_PERSIST\" = \"TRUE\";\n"
  "  \"EXTENDED_ACCOUNTS\" = \"TRUE\";\n"
  "  \"HALFOPS\" = \"TRUE\";\n"
  "  \"EXCEPTS\" = \"TRUE\";\n"
  "  \"EXTBANS\" = \"TRUE\";\n"
  "  \"OPLEVELS\" = \"TRUE\";\n"
  "  \"THREAD_POOL_SIZE\" = \"1\";\n"
  "};\n";

static void die(const char *what)
{
  fprintf(stderr, "fuzz_p10: init failed: %s (%s)\n", what, strerror(errno));
  abort();
}

static void rm_tmpdir(void)
{
  char cmd[300];
  if (!tmpdir[0] || getenv("FUZZ_KEEP_TMP"))
    return;
  snprintf(cmd, sizeof(cmd), "rm -rf '%s'", tmpdir);
  if (system(cmd)) { /* best effort */ }
}

static void setup_tcp_listener(void)
{
  socklen_t len = sizeof(tcp_listen_addr);
  int one = 1;

  tcp_listen_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (tcp_listen_fd < 0)
    die("socket");
  setsockopt(tcp_listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
  memset(&tcp_listen_addr, 0, sizeof(tcp_listen_addr));
  tcp_listen_addr.sin_family = AF_INET;
  tcp_listen_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  tcp_listen_addr.sin_port = 0;
  if (bind(tcp_listen_fd, (struct sockaddr *)&tcp_listen_addr, sizeof(tcp_listen_addr)))
    die("bind");
  if (listen(tcp_listen_fd, 64))
    die("listen");
  if (getsockname(tcp_listen_fd, (struct sockaddr *)&tcp_listen_addr, &len))
    die("getsockname");
}

/* Make a connected loopback TCP pair; returns the accepted end and
 * stores the connecting end in *peer. */
static int tcp_pair(int *peer)
{
  int c, a;

  c = socket(AF_INET, SOCK_STREAM, 0);
  if (c < 0)
    die("socket(c)");
  if (connect(c, (struct sockaddr *)&tcp_listen_addr, sizeof(tcp_listen_addr)))
    die("connect");
  a = accept(tcp_listen_fd, NULL, NULL);
  if (a < 0)
    die("accept");
  *peer = c;
  return a;
}

static void setup_listener(struct Listener *l, int is_server, int port)
{
  memset(l, 0, sizeof(*l));
  l->fd_v4 = -1;
  l->fd_v6 = -1;
  l->ref_count = 1 << 30;      /* never released */
  l->addr.port = port;
  FlagSet(&l->flags, LISTEN_ACTIVE);
  if (is_server)
    FlagSet(&l->flags, LISTEN_SERVER);
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
  char path[300];
  FILE *f;
  const char *base = getenv("FUZZ_TMPDIR");

  (void)argc; (void)argv;
  verbose = getenv("FUZZ_VERBOSE") != NULL;
  strict = getenv("FUZZ_STRICT") != NULL;
  filter_known = getenv("FUZZ_FILTER_KNOWN") != NULL;

  snprintf(tmpdir, sizeof(tmpdir), "%s/p10fuzz.%d.XXXXXX", base ? base : "/tmp",
           (int)getpid());
  if (!mkdtemp(tmpdir))
    die("mkdtemp");
  /* Crashing processes skip atexit (and the sanitizer death callback is
   * libFuzzer's), so their stores are left behind; the directory name
   * carries the pid so run.sh / minimize.sh can sweep dead ones. */
  atexit(rm_tmpdir);

  snprintf(path, sizeof(path), "%s/ircd.conf", tmpdir);
  if (!(f = fopen(path, "w")))
    die("fopen conf");
  fputs(conf_text, f);
  /* absolute store paths: libFuzzer resolves corpus paths against the cwd,
   * so the harness never chdir()s */
  fprintf(f, "Features {\n  \"CHATHISTORY_DB\" = \"%s/history\";\n"
          "  \"METADATA_DB\" = \"%s/metadata\";\n"
          "  \"WEBPUSH_DB\" = \"%s/webpush\";\n};\n", tmpdir, tmpdir, tmpdir);
  fclose(f);
  configfile = strdup(path);

  signal(SIGPIPE, SIG_IGN);

  /* --- ircd.c main(), minus sockets / daemon / event loop --- */
  CurrentTime = time(NULL);
  umask(077);
  memset(&me, 0, sizeof(me));
  memset(&me_con, 0, sizeof(me_con));
  cli_connect(&me) = &me_con;
  cli_fd(&me) = -1;

  event_init(MAXCONNECTIONS);
  feature_init();
  thread_pool_init(1);
  init_isupport();
  log_init("ircd");
  initload();
  init_list();
  init_hash();
  init_class();
  initwhowas();
  initmsgtree();
  initstats();
  ircd_crypt_init();
  motd_init();
  if (!init_conf())
    die("init_conf");
  init_isupport();
  init_server_identity();
  stats_init();
  dnsbl_init();
  IPcheck_init();
  CurrentTime = time(NULL);

  SetMe(&me);
  cli_magic(&me) = CLIENT_MAGIC;
  cli_from(&me) = &me;
  make_server(&me);
  cli_serv(&me)->timestamp = TStime();
  cli_serv(&me)->prot      = atoi(MAJOR_PROTOCOL);
  cli_serv(&me)->up        = &me;
  cli_serv(&me)->down      = NULL;
  cli_handler(&me)         = SERVER_HANDLER;
  SetYXXCapacity(&me, MAXCLIENTS);
  cli_lasttime(&me) = cli_since(&me) = cli_firsttime(&me) = CurrentTime;
  hlc_init((uint16_t)base64toint(cli_yxx(&me)));
  MsgIdCounter = (unsigned long)hlc_wall_clock_ms();
  hAddClient(&me);
  SetIPv6(&me);
  SetIRCv3Aware(&me);
  init_counters();

#ifdef USE_ROCKSDB
  history_set_map_size((size_t)feature_int(FEAT_HISTORY_MAP_SIZE_MB));
#ifdef USE_ZSTD
  compress_init((size_t)feature_int(FEAT_COMPRESS_THRESHOLD),
                feature_int(FEAT_COMPRESS_LEVEL));
#endif
  if (history_init(feature_str(FEAT_CHATHISTORY_DB)) != 0)
    die("history_init");
  chathistory_init_callbacks();
  if (metadata_lmdb_init(feature_str(FEAT_METADATA_DB)) != 0)
    die("metadata_lmdb_init");
  presence_set_boot_alive_hint(history_newest_activity_ms());
  presence_init();
#endif

  bounce_init();
  cap_set_value(CAP_DRAFT_PERSISTENCE, "attach,detach,list,attach-cursor");
  bounce_db_restore();
  server_boot_complete = 1;

  setup_tcp_listener();
  setup_listener(&server_listener, 1, 4400);
  setup_listener(&user_listener, 0, 6667);

  if (verbose)
    fprintf(stderr, "fuzz_p10: initialised in %s, me=%s (%s)\n", tmpdir,
            cli_name(&me), cli_yxx(&me));
  return 0;
}

/* ---------------------------------------------------------------- */
/* Per-input driving                                                 */
/* ---------------------------------------------------------------- */

static struct Client *new_connection(struct Listener *l)
{
  int peer;
  int fd = tcp_pair(&peer);
  struct Client *cptr;

  add_connection(l, fd, NULL);
  close(peer);               /* we never read the far end; writes are wrapped */
  cptr = LocalClientArray[fd];
  if (!cptr)
    die("add_connection did not register the client");
  return cptr;
}

/* Feed bytes to a connection the way read_packet() does for a server or
 * a handshaking link.  Returns 0 if the client is gone. */
static int feed_server(struct Client *cptr, const char *buf, size_t len)
{
  int rc, classify;

  if (!len)
    return 1;
  if (IsServer(cptr) || IsHandshake(cptr) || IsConnecting(cptr)) {
    classify = recv_classify(cptr, buf, len);
    if (classify == RECV_CLASSIFY_TAG_OVERRUN) {
      exit_client(cptr, cptr, &me, "Excess Flood: tag region too large");
      return 0;
    }
    if (classify == RECV_CLASSIFY_MSG_OVERRUN) {
      exit_client(cptr, cptr, &me, "Excess Flood: S2S body exceeds 512");
      return 0;
    }
  }
  if (IsServer(cptr))
    rc = server_dopacket(cptr, buf, len);
  else
    rc = connect_dopacket(cptr, buf, len);
  flush_connections(0);
  return rc != CPTR_KILLED;
}

/* Client lines: the parse_client part of client_dopacket. */
static int feed_client_line(struct Client *cptr, const char *line)
{
  char buf[BUFSIZE + 1];
  size_t n = strlen(line);
  if (n > BUFSIZE)
    n = BUFSIZE;
  int rc;
  memcpy(buf, line, n);
  buf[n] = '\0';
  rc = parse_client(cptr, buf, buf + n);
  flush_connections(0);
  return rc != CPTR_KILLED;
}

#define MAX_LOCAL 2
static struct Client *locals[MAX_LOCAL];
static int local_fd[MAX_LOCAL];

static void make_local_users(void)
{
  static const char *const nicks[MAX_LOCAL] = { "alice", "bob" };
  char line[128];
  int i;

  for (i = 0; i < MAX_LOCAL; i++) {
    struct Client *c;
    ping_cookie[0] = '\0';
    watch_fd = -2;
    c = new_connection(&user_listener);
    local_fd[i] = cli_fd(c);
    watch_fd = local_fd[i];
    locals[i] = c;
    if (i == 0) {
      /* alice negotiates the IRCv3 caps that change S2S->client delivery
       * (tags, batches, multiline, echo, account/away notify); bob stays
       * a plain client */
      feed_client_line(c, "CAP LS 302");
      feed_client_line(c, "CAP REQ :message-tags server-time batch echo-message "
                       "account-tag away-notify extended-join account-notify "
                       "chghost setname userhost-in-names multi-prefix");
      feed_client_line(c, "CAP REQ :draft/multiline draft/chathistory "
                       "draft/event-playback draft/message-redaction "
                       "draft/metadata-2 draft/read-marker labeled-response");
      feed_client_line(c, "CAP END");
    }
    snprintf(line, sizeof(line), "NICK %s", nicks[i]);
    if (!feed_client_line(c, line)) { locals[i] = NULL; continue; }
    snprintf(line, sizeof(line), "USER %s 0 * :%s real", nicks[i], nicks[i]);
    if (!feed_client_line(c, line)) { locals[i] = NULL; continue; }
    if (ping_cookie[0] && LocalClientArray[local_fd[i]] == c && !IsUser(c)) {
      snprintf(line, sizeof(line), "PONG :%s", ping_cookie);
      if (!feed_client_line(c, line)) { locals[i] = NULL; continue; }
    }
    watch_fd = -1;
    if (LocalClientArray[local_fd[i]] != c || !IsUser(c)) {
      if (verbose)
        fprintf(stderr, "fuzz_p10: local user %s did not register\n", nicks[i]);
      continue;   /* reset_local_users() still exits it */
    }
    feed_client_line(c, "JOIN #fuzz");
  }
}

static void reset_local_users(void)
{
  int i;
  for (i = 0; i < MAX_LOCAL; i++) {
    if (locals[i] && LocalClientArray[local_fd[i]] == locals[i])
      exit_client(locals[i], locals[i], &me, "fuzz reset");
    locals[i] = NULL;
  }
}

static void check_clean(void)
{
  struct Client *c;
  int n = 0;
  for (c = GlobalClientList; c; c = cli_next(c))
    if (c != &me) {
      ++n;
      if (verbose)
        fprintf(stderr, "fuzz_p10: leftover client %s (%s) status %d\n",
                cli_name(c), cli_yxx(c), cli_status(c));
    }
  if (n && strict) {
    fprintf(stderr, "fuzz_p10: %d clients left after reset\n", n);
    abort();
  }
}

/* ---------------------------------------------------------------- */
/* Known-bug filter (FUZZ_FILTER_KNOWN=1)                            */
/* ---------------------------------------------------------------- */
/* Once a crash is confirmed and written up in FINDINGS.md, the lines
 * that trigger it are dropped here so a campaign can get past it.  The
 * filter only removes whole lines; it never edits one.  Each rule names
 * the finding it stands in for. */


#define FTOK_MAX 20
struct ftoks { char *t[FTOK_MAX]; int n; char *cmd; char *src; };

/* Tokenise like parse_server: optional @tags, prefix, command, then up
 * to MAXPARA params with a ':' trailing param.  Works on a copy. */
static void ftokenise(char *s, struct ftoks *ft)
{
  int i = 0;
  memset(ft, 0, sizeof(*ft));
  /* same prefix walk as parse_server: tags, then (only after tags)
   * spaces, then up to 5 prefix chars; the pointer always advances at
   * least one char and then to the next space */
  if (*s == '@') {
    char *te = strchr(s, ' ');
    if (te) { s = te; while (*s == ' ') s++; }
  }
  ft->src = s;
  if (*s == ':') {
    ft->src = s + 1;
    s = strchr(s, ' ');
    if (!s) { ft->cmd = NULL; return; }
    *s++ = '\0';
  } else {
    do { ++s; } while (*s != ' ' && *s);
    if (*s) *s++ = '\0';
  }
  while (*s == ' ') s++;
  ft->cmd = s;
  while (*s && *s != ' ') s++;
  if (*s) *s++ = '\0';
  for (;;) {
    while (*s == ' ') *s++ = '\0';
    if (!*s || i >= FTOK_MAX - 1)
      break;
    if (*s == ':') { ft->t[i++] = s + 1; break; }
    ft->t[i++] = s;
    if (i >= MAXPARA)
      break;
    while (*s && *s != ' ') s++;
  }
  ft->n = i;
}

/* Command compare the way msg_tree_parse matches: each byte is folded
 * with & 31, so "4" is "T" and "mk" is "MK". */
static int fcmd(const char *cmd, const char *tok)
{
  if (!cmd || strlen(cmd) != strlen(tok))
    return 0;
  for (; *tok; cmd++, tok++)
    if (((unsigned char)*cmd & 31) != ((unsigned char)*tok & 31) || !IsNickChar(*cmd))
      return 0;
  return 1;
}

/* the client parse_server would resolve the prefix to */
static struct Client *fsource(const char *src)
{
  char pre[6];
  int i;
  for (i = 0; i < 5 && src[i] && src[i] != ' '; i++)
    pre[i] = src[i];
  pre[i] = '\0';
  if (i == 0)
    return NULL;
  if (i <= 2 || src[1] == ' ' || src[2] == ' ')
    return FindNServer(pre);
  return findNUser(pre);
}

/* F1: would base64toip() stay inside the 8 words and the string? */
static int b64ip_safe(const char *in)
{
  size_t len = strlen(in);
  int pos = 0;
  if (len == 6)
    return 1;
  while (pos < 8) {
    if (!*in)
      return 0;
    if (*in == '_') {
      int left = ((int)25 - (int)strlen(in)) / 3 - pos;
      if (25 < (int)strlen(in) || left < 0 || pos + left > 8)
        return 0;
      pos += left;
      in++;
    } else {
      if (!in[0] || !in[1] || !in[2])
        return 0;
      in += 3;
      pos++;
    }
  }
  return 1;
}

static int is_all_digits(const char *s)
{
  if (!*s) return 0;
  for (; *s; s++) if (*s < '0' || *s > '9') return 0;
  return 1;
}

static int known_bug_line(const char *line, size_t len)
{
  char buf[FULL_MSG_SIZE + 1];
  struct ftoks ft;
  int i;

  if (len > FULL_MSG_SIZE)
    len = FULL_MSG_SIZE;
  /* F10: a NUL where the prefix should be makes parse_server step past
   * the terminator and parse what follows it */
  {
    size_t k = 0;
    if (line[0] == '@')
      while (k < len && line[k] != ' ' && line[k]) k++;
    while (k < len && line[k] == ' ') k++;
    if (k < len && line[k] == '\0')
      return 1;
  }
  memcpy(buf, line, len);
  buf[len] = '\0';
  ftokenise(buf, &ft);
  if (!ft.cmd || !*ft.cmd)
    return 0;

  /* F3: three-char numeric command that evaluates to 0 */
  if (strlen(ft.cmd) == 3 && IsDigit(ft.cmd[0]) &&
      (ft.cmd[0] - '0') * 100 + (ft.cmd[1] - '0') * 10 + (ft.cmd[2] - '0') == 0)
    return 1;

  /* F7: MARK with fewer than two params */
  if ((fcmd(ft.cmd, "MK") || fcmd(ft.cmd, "MARK")) && ft.n < 2)
    return 1;

  /* F1 / F6: server-introduced N with a bad IP or numeric field */
  if ((fcmd(ft.cmd, "N") || fcmd(ft.cmd, "NICK")) && ft.n >= 7) {
    const char *ip = ft.t[ft.n - 3], *nn = ft.t[ft.n - 2];
    if (!b64ip_safe(ip))
      return 1;
    if (strlen(nn) != 3 && strlen(nn) != 5)
      return 1;
  }
  /* F1 also via the collision path: any N whose IP slot is unsafe */
  if ((fcmd(ft.cmd, "N") || fcmd(ft.cmd, "NICK")) && ft.n >= 3 &&
      ft.n < 7 && !b64ip_safe(ft.t[ft.n >= 3 ? ft.n - 3 : 0]))
    return 1;

  if (fcmd(ft.cmd, "B") || fcmd(ft.cmd, "BURST")) {
    for (i = 2; i < ft.n; i++) {
      const char *p = ft.t[i];
      if (*p == '+') {
        int need = 0;
        for (; *p; p++) {
          if (*p == 'k' || *p == 'l') need++;          /* F2 */
          if (*p == 'b' || *p == 'e') return 1;        /* F5 */
        }
        if (i + need >= ft.n)
          return 1;
      } else if (*p != '%') {                           /* F4 */
        const char *q = p;
        if (*q == ',' || *q == ':') return 1;
        for (; *q; q++)
          if ((q[0] == ',' && (q[1] == ',' || q[1] == ':' || !q[1])))
            return 1;
      }
    }
  }

  /* F5 (MODE path) and F8 */
  if (fcmd(ft.cmd, "M") || fcmd(ft.cmd, "MODE") ||
      fcmd(ft.cmd, "OM") || fcmd(ft.cmd, "OPMODE")) {
    int minus = 0, be = 0;
    if (ft.n >= 2)
      for (const char *p = ft.t[1]; *p; p++) {
        if (*p == '-') minus = 1;
        if (*p == 'b' || *p == 'e') be = 1;
      }
    for (i = 1; i < ft.n; i++)
      if (be && i == ft.n - 1 && IsDigit(ft.t[i][0]))
        return 1;
    for (i = 2; i < ft.n; i++)                         /* F8 */
      if (minus && (strchr(ft.t[i], ':') || strlen(ft.t[i]) < 5))
        return 1;
    for (i = 2; i < ft.n; i++)                         /* F4 via MODE */
      if (!ft.t[i][0])
        return 1;
  }

  /* F11 / F12 / F13: handlers that assume a user (or server) source */
  {
    struct Client *src = fsource(ft.src);
    if (!src && (ft.src[0] == '\0' || ft.src == ft.cmd))
      src = NULL;
    if (src && IsServer(src) &&
        (((fcmd(ft.cmd, "T") || fcmd(ft.cmd, "TOPIC")) && ft.n <= 4) ||
         fcmd(ft.cmd, "RH") || fcmd(ft.cmd, "REHASH") ||
         fcmd(ft.cmd, "W") || fcmd(ft.cmd, "WHOIS")))   /* F12, F14 */
      return 1;
    if (src && !IsServer(src) && !IsMe(src) &&
        (fcmd(ft.cmd, "S") || fcmd(ft.cmd, "SERVER")))
      return 1;
    /* empty prefix -> parse_server uses the link itself */
    if (!src && ft.src[0] != ':' &&
        (((fcmd(ft.cmd, "T") || fcmd(ft.cmd, "TOPIC")) && ft.n <= 4) ||
         fcmd(ft.cmd, "RH") || fcmd(ft.cmd, "REHASH") ||
         fcmd(ft.cmd, "W") || fcmd(ft.cmd, "WHOIS")))   /* F12, F14 */
      return 1;
  }

  /* A2: KICK of a member whose bouncer aliases are in the channel */
  if ((fcmd(ft.cmd, "K") || fcmd(ft.cmd, "KICK")) && ft.n >= 2) {
    struct Channel *ch = FindChannel(ft.t[0]);
    struct Client *who = strlen(ft.t[1]) == 5 ? findNUser(ft.t[1]) : FindUser(ft.t[1]);
    struct Membership *m;
    if (ch && who)
      for (m = ch->members; m; m = m->next_member)
        if (IsMemberAlias(m) && cli_alias_primary(m->user) == who)
          return 1;
  }

  /* A1: NICK from a bouncer alias (prefix = first <=5 chars, as in
   * parse_server) */
  if ((fcmd(ft.cmd, "N") || fcmd(ft.cmd, "NICK")) &&
      strlen(ft.src) >= 5 && ft.src[2] != ' ') {
    char pre[6];
    struct Client *c;
    memcpy(pre, ft.src, 5);
    pre[5] = '\0';
    c = strchr(pre, ' ') ? NULL : findNUser(pre);
    if (c && IsBouncerAlias(c))
      return 1;
  }
  return 0;
}

/* Feed buf, dropping lines the known-bug filter rejects. */
static int feed_server_filtered(struct Client *cptr, const char *buf, size_t len)
{
  size_t start = 0, i;
  int ok = 1, fd = cli_fd(cptr);
  for (i = 0; ok && i <= len; i++) {
    if (i == len || buf[i] == '\n' || buf[i] == '\r') {
      size_t l = i - start;
      if (l && !known_bug_line(buf + start, l))
        ok = feed_server(cptr, buf + start, l + (i < len));
      else if (l && verbose)
        fprintf(stderr, "fuzz_p10: filtered: %.*s\n", (int)(l > 120 ? 120 : l), buf + start);
      start = i + 1;
      if (LocalClientArray[fd] != cptr)
        ok = 0;
    }
  }
  return ok;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  struct Client *link;
  char hs[256];
  unsigned int flags;
  int fd, ok = 1;
  const char *name;
  size_t off;

  if (size < 1)
    return 0;
  flags = data[0];
  data++; size--;

  CurrentTime = time(NULL);

  if (flags & 0x08)
    make_local_users();

  link = new_connection(&server_listener);
  fd = cli_fd(link);
  name = (flags & 0x04) ? "uhub.fuzz" : "hub.fuzz";
  snprintf(hs, sizeof(hs),
           "PASS :fuzzpass\r\nSERVER %s 1 %lu %lu J10 " HUB_NUMERIC "A]] +h6%s%s :fuzz peer\r\n",
           name, (unsigned long)(CurrentTime - 3600), (unsigned long)CurrentTime,
           (flags & 0x02) ? "" : "vF", (flags & 0x04) ? "s" : "");
  ok = feed_server(link, hs, strlen(hs));
  if (!ok || LocalClientArray[fd] != link || !IsServer(link)) {
    fprintf(stderr, "fuzz_p10: link did not establish\n");
    abort();
  }

  if (flags & 0x01) {
    static const char eb[] = HUB_NUMERIC " EB\n";
    ok = feed_server(link, eb, sizeof(eb) - 1);
  }

  if (filter_known)
    ok = feed_server_filtered(link, (const char *)data, size);
  else for (off = 0; ok && off < size; ) {
    size_t chunk = size - off;
    if (chunk > 4096)
      chunk = 4096;
    ok = feed_server(link, (const char *)data + off, chunk);
    off += chunk;
    if (LocalClientArray[fd] != link)
      ok = 0;
  }

  if (flags & 0x10) {
    /* fire whatever the input armed */
    CurrentTime += FUZZ_TIMER_SECS;
    timer_run();
  }

  if (LocalClientArray[fd] == link)
    exit_client(link, link, &me, "fuzz reset");
  reset_local_users();
  /* Reap anything a squit left for the destruct timer. */
  check_clean();
  return 0;
}
