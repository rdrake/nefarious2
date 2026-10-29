/*
 * fuzz/client/fuzz_client.c -- libFuzzer harness for the Nefarious IRCd
 * CLIENT protocol (the untrusted client-to-server surface).
 *
 * The harness links every ircd object (ircd.o with its main() renamed to
 * ircd_main by objcopy) and replicates ircd.c's startup minus daemonizing,
 * signals and listening sockets.  Clients are real local clients: each one
 * is a socketpair whose server end goes through add_connection() on a
 * harness-made Listener, so start_auth(), registration, the read path
 * (read_packet -> recv_classify -> dbuf -> client_dopacket -> parse_client),
 * fakelag, recvQ/sendQ limits and exit_client() are all the real code.
 * Bytes are delivered by writing to the peer end of the socketpair and
 * raising ET_READ on the client's socket (exactly what the epoll engine
 * would do); everything the server writes is read back from the peer end
 * and discarded.
 *
 * Network side effects are cut at link time with -Wl,--wrap:
 *   os_get_peername / os_get_sockname  -> fake TCP endpoints (the socket is
 *                                         AF_UNIX, the ircd wants inet)
 *   kc_http_request / kc_http_sync_perform -> immediate "no network"
 *   kc_user_verify_password             -> Keycloak verdict without HTTP:
 *                                         password "fuzzpass" succeeds
 *   kc_token_ensure / kc_jwt_prime_cache -> no-ops
 * Asynchronous replies are delivered from a 0-second ircd timer, i.e. on a
 * later event-loop turn, like a real HTTP completion.
 *
 * Input format (see README.md):
 *   byte 0      : mode flags (FZ_* below)
 *   bytes 1..   : lines separated by '\n'.  Each line is written to client
 *                 A's socket followed by "\r\n" unless it starts with a
 *                 control byte:
 *                   0x01 rest -> line sent by peer client B
 *                   0x02 N    -> advance the clock by N seconds, run timers
 *                   0x03      -> client A's TCP connection drops (EOF)
 *                   0x04      -> client A reconnects (new connection, prelude)
 *                   0x05 rest -> raw bytes to A's socket (no CRLF, no
 *                                WebSocket framing)
 */
#include "config.h"

#include "ircd.h"
#include "IPcheck.h"
#include "class.h"
#include "client.h"
#include "crdt_hlc.h"
#include "hash.h"
#include "bouncer_session.h"
#include "capab.h"
#include "chathistory_presence.h"
#include "history.h"
#include "ircd_alloc.h"
#include "ircd_compress.h"
#include "ircd_events.h"
#include "ircd_features.h"
#include "ircd_geoip.h"
#include "ircd_log.h"
#include "ircd_string.h"
#include "ircd_crypt.h"
#include "list.h"
#include "listener.h"
#include "motd.h"
#include "msgq.h"
#include "numnicks.h"
#include "parse.h"
#include "querycmds.h"
#include "s_auth.h"
#include "s_bsd.h"
#include "s_conf.h"
#include "s_debug.h"
#include "s_misc.h"
#include "s_stats.h"
#include "s_user.h"
#include "send.h"
#include "ssl.h"
#include "uping.h"
#include "userload.h"
#include "whowas.h"
#include "metadata.h"
#include "webpush.h"
#include "webpush_store.h"
#include "sasl_auth.h"
#include "sasl_conf.h"
#include "ircd_kc_adapter.h"
#include "dbuf.h"
#include "res.h"
#include "sys.h"
#include "handlers.h"
#include <kc/kc.h>
#include <kc/kc_keycloak.h>
#include <kc/kc_http.h>
#include <kc/kc_http_sync.h>
#include <kc/kc_jwt.h>

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <signal.h>
#include <dirent.h>

extern char *configfile;
extern struct Connection me_con;
extern int kc_transport_ready;
extern int server_boot_complete;
extern int dnsbl_init(void);
extern int webpush_setup(void);
extern void stats_init(void);
extern void initmsgtree(void);
extern void init_counters(void);

/* ---- mode flags (byte 0) ------------------------------------------- */
#define FZ_REGISTER   0x01  /* A completes registration in the prelude */
#define FZ_ALLCAPS    0x02  /* A negotiates every capability */
#define FZ_SASL       0x04  /* A logs in with SASL PLAIN (account fuzzacct) */
#define FZ_PEER       0x08  /* peer B exists: registered, logged in, on #fuzz */
#define FZ_OPER       0x10  /* A opers up (needs FZ_REGISTER) */
#define FZ_WEBSOCKET  0x20  /* A connects through a WebSocket listener */
#define FZ_PEERCHAN   0x40  /* A also joins #fuzz after registering */

#define MAX_LINES     256

/* Requested in chunks: one CAP REQ line must fit the 512-byte body. */
static const char *const ALL_CAPS[] = {
  "multi-prefix userhost-in-names extended-join away-notify account-notify "
  "sasl cap-notify server-time echo-message account-tag chghost "
  "invite-notify labeled-response batch setname standard-replies",
  "message-tags no-implicit-names draft/extended-isupport draft/pre-away "
  "draft/multiline draft/chathistory soju.im/search draft/event-playback "
  "draft/message-redaction draft/account-registration draft/read-marker",
  "draft/channel-rename evilnet/channel-relocate draft/metadata-2 "
  "draft/webpush draft/authtoken draft/bouncer draft/persistence "
  "draft/oper-tag",
  NULL
};

struct fz_conn;
static void fz_req_all_caps(struct fz_conn *c);

static int fz_verbose;
static struct Listener *fz_listener;
static struct Listener *fz_ws_listener;
static char fz_dir[256];

/* ---- fake client connections --------------------------------------- */
struct fz_conn {
  struct Client *cli;
  int fd;        /* server end */
  int peer;      /* our end */
  int ws;        /* A connected through the WebSocket listener */
};

static struct fz_conn fzA, fzB;
static unsigned int fz_port_seq;

static int fz_alive(struct fz_conn *c)
{
  return c->cli && c->fd >= 0 && c->fd < MAXCONNECTIONS &&
         LocalClientArray[c->fd] == c->cli;
}

/* ---- graveyard for freelist-patched objects (see freelist.patch) ---- */
static void **fz_grave;
static size_t fz_grave_n, fz_grave_cap;

void fuzz_defer_free(void *p)
{
  if (fz_grave_n == fz_grave_cap) {
    fz_grave_cap = fz_grave_cap ? fz_grave_cap * 2 : 256;
    fz_grave = realloc(fz_grave, fz_grave_cap * sizeof(*fz_grave));
  }
  fz_grave[fz_grave_n++] = p;
}

/* Only called from the harness top level, between events: anything
 * still pointing at a buried object now dangles for real. */
static void fz_flush(void)
{
  size_t i;
  for (i = 0; i < fz_grave_n; i++)
    MyFree(fz_grave[i]);
  fz_grave_n = 0;
}

/* ---- link-time wraps ----------------------------------------------- */
int __wrap_os_get_peername(int fd, struct irc_sockaddr *sin_out)
{
  memset(sin_out, 0, sizeof(*sin_out));
  /* A different address for B so per-IP accounting sees two hosts. */
  ircd_aton(&sin_out->addr, (fzB.fd == fd) ? "100.64.2.77" : "100.64.1.10");
  sin_out->port = (unsigned short)(40000 + (fz_port_seq++ & 0x3fff));
  return 1;
}

int __wrap_os_get_sockname(int fd, struct irc_sockaddr *sin_out)
{
  (void)fd;
  memset(sin_out, 0, sizeof(*sin_out));
  ircd_aton(&sin_out->addr, "100.64.0.1");
  sin_out->port = 6667;
  return 1;
}

/* Deferred async completions (HTTP / Keycloak) ------------------------ */
enum fz_job_kind { FZJ_HTTP, FZJ_VERIFY };
struct fz_job {
  struct fz_job *next;
  enum fz_job_kind kind;
  int ok;
  kc_http_callback http_cb;
  kc_token_cb tok_cb;
  void *data;
};
static struct fz_job *fz_jobs, **fz_jobs_tail = &fz_jobs;
static struct Timer fz_job_timer;

static void fz_run_jobs(struct Event *ev)
{
  struct fz_job *list, *j;

  (void)ev;
  if (ev && ev_type(ev) == ET_DESTROY)
    return;
  list = fz_jobs;
  fz_jobs = NULL;
  fz_jobs_tail = &fz_jobs;
  while ((j = list)) {
    list = j->next;
    if (j->kind == FZJ_HTTP) {
      struct kc_http_response resp;
      memset(&resp, 0, sizeof(resp));
      resp.status_code = 0;
      resp.error = "fuzz: no network";
      j->http_cb(&resp, j->data);
    } else {
      if (j->ok) {
        struct kc_access_token tok;
        memset(&tok, 0, sizeof(tok));
        tok.access_token = "fuzz.token";
        tok.access_token_size = 10;
        j->tok_cb(KC_SUCCESS, &tok, j->data);
      } else {
        j->tok_cb(KC_FORBIDDEN, NULL, j->data);
      }
    }
    free(j);
  }
}

static void fz_queue(struct fz_job *j)
{
  j->next = NULL;
  *fz_jobs_tail = j;
  fz_jobs_tail = &j->next;
  if (!t_active(&fz_job_timer))
    timer_add(timer_init(&fz_job_timer), fz_run_jobs, 0, TT_RELATIVE, 0);
}

int __wrap_kc_http_request(const struct kc_http_request *req,
                           kc_http_callback cb, void *data)
{
  struct fz_job *j;
  (void)req;
  if (!cb)
    return 0;
  j = calloc(1, sizeof(*j));
  j->kind = FZJ_HTTP;
  j->http_cb = cb;
  j->data = data;
  fz_queue(j);
  return 0;
}

long __wrap_kc_http_sync_perform(struct kc_http_sync_opts opts,
                                 struct kc_http_sync_mem *chunk_out)
{
  (void)opts;
  if (chunk_out) {
    chunk_out->response = NULL;
    chunk_out->size = 0;
  }
  return -1;
}

int __wrap_kc_user_verify_password(const char *username, const char *password,
                                   kc_token_cb cb, void *data)
{
  struct fz_job *j = calloc(1, sizeof(*j));
  j->kind = FZJ_VERIFY;
  /* Only the harness's accounts can log in, so end-of-input cleanup
   * knows every bouncer session that can exist. */
  j->ok = password && !strcmp(password, "fuzzpass") && username &&
          (!ircd_strcmp(username, "fuzzacct") ||
           !ircd_strcmp(username, "peeracct") ||
           !ircd_strcmp(username, "fuzzalt"));
  j->tok_cb = cb;
  j->data = data;
  fz_queue(j);
  return 0;
}

int __wrap_kc_token_ensure(kc_token_cb cb, void *data)
{
  (void)cb; (void)data;
  return 0;
}

int __wrap_kc_jwt_prime_cache(struct kc_realm realm)
{
  (void)realm;
  return -1;
}

/* ---- I/O helpers --------------------------------------------------- */
static void fz_drain(struct fz_conn *c)
{
  char buf[65536];
  ssize_t n;

  if (c->peer < 0)
    return;
  while ((n = read(c->peer, buf, sizeof(buf))) > 0) {
    if (fz_verbose)
      fwrite(buf, 1, (size_t)n, stderr);
  }
}

/* Run the event-loop work that would follow a readable socket: flush
 * sendQs (ET_WRITE), let fakelag'd recvQs drain on the client process
 * timer, deliver async completions. */
static void fz_pump(int rounds)
{
  int i;
  struct fz_conn *cs[2] = { &fzA, &fzB };

  for (i = 0; i < rounds; i++) {
    int k, busy = 0;
    for (k = 0; k < 2; k++) {
      struct fz_conn *c = cs[k];
      fz_drain(c);
      if (!fz_alive(c))
        continue;
      if (MsgQLength(&cli_sendQ(c->cli)) || cli_replay(c->cli) || cli_listing(c->cli)) {
        event_generate(ET_WRITE, &cli_socket(c->cli), 0);
        fz_flush();
        busy = 1;
      }
      if (fz_alive(c) && DBufLength(&cli_recvQ(c->cli)) && !NoNewLine(c->cli))
        busy = 1;
    }
    timer_run();
    fz_flush();
    if (!busy && !fz_jobs)
      break;
    CurrentTime += 1;
  }
  fz_drain(&fzA);
  fz_drain(&fzB);
}

static void fz_send_raw(struct fz_conn *c, const char *data, size_t len)
{
  size_t off = 0;

  if (!fz_alive(c))
    return;
  while (off < len) {
    ssize_t n = write(c->peer, data + off, len - off);
    if (n <= 0) {
      /* socket buffer full: let the server read what is there */
      if (!fz_alive(c))
        return;
      event_generate(ET_READ, &cli_socket(c->cli), 0);
      fz_flush();
      fz_pump(4);
      if (!fz_alive(c))
        return;
      continue;
    }
    off += (size_t)n;
  }
  if (!fz_alive(c))
    return;
  event_generate(ET_READ, &cli_socket(c->cli), 0);
  fz_flush();
  fz_pump(32);
}

/* Masked client->server WebSocket text frame. */
static void fz_send_ws(struct fz_conn *c, const char *data, size_t len)
{
  static unsigned char frame[16384 + 16];
  size_t hl, i;
  static const unsigned char mask[4] = { 0x12, 0x34, 0x56, 0x78 };

  if (len > 16000)
    len = 16000;
  frame[0] = 0x81;
  if (len < 126) {
    frame[1] = 0x80 | (unsigned char)len;
    hl = 2;
  } else {
    frame[1] = 0x80 | 126;
    frame[2] = (unsigned char)(len >> 8);
    frame[3] = (unsigned char)len;
    hl = 4;
  }
  memcpy(frame + hl, mask, 4);
  hl += 4;
  for (i = 0; i < len; i++)
    frame[hl + i] = (unsigned char)data[i] ^ mask[i & 3];
  fz_send_raw(c, (const char *)frame, hl + len);
}

static void fz_line(struct fz_conn *c, const char *data, size_t len)
{
  static char buf[16384];

  if (c->ws) {
    fz_send_ws(c, data, len);
    return;
  }
  if (len > sizeof(buf) - 2)
    len = sizeof(buf) - 2;
  memcpy(buf, data, len);
  buf[len] = '\r';
  buf[len + 1] = '\n';
  fz_send_raw(c, buf, len + 2);
}

static void fz_cmd(struct fz_conn *c, const char *s)
{
  fz_line(c, s, strlen(s));
}

static int fz_connect(struct fz_conn *c, int websocket)
{
  int sv[2];
  int sz = 1 << 20;

  memset(c, 0, sizeof(*c));
  c->fd = c->peer = -1;
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0)
    return 0;
  setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &sz, sizeof(sz));
  setsockopt(sv[1], SOL_SOCKET, SO_RCVBUF, &sz, sizeof(sz));
  setsockopt(sv[1], SOL_SOCKET, SO_SNDBUF, &sz, sizeof(sz));
  fcntl(sv[1], F_SETFL, O_NONBLOCK);
  c->fd = sv[0];
  c->peer = sv[1];
  c->ws = websocket;
  if (c->fd >= MAXCONNECTIONS) {
    close(sv[0]);
    close(sv[1]);
    c->fd = c->peer = -1;
    return 0;
  }
  add_connection(websocket ? fz_ws_listener : fz_listener, c->fd, NULL);
  c->cli = LocalClientArray[c->fd];
  if (!c->cli) {
    close(c->peer);
    c->peer = -1;
    return 0;
  }
  if (websocket) {
    static const char req[] =
      "GET / HTTP/1.1\r\n"
      "Host: fuzz.test.net\r\n"
      "Upgrade: websocket\r\n"
      "Connection: Upgrade\r\n"
      "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
      "Sec-WebSocket-Protocol: text.ircv3.net\r\n"
      "Sec-WebSocket-Version: 13\r\n\r\n";
    fz_send_raw(c, req, sizeof(req) - 1);
  }
  fz_pump(4);
  return fz_alive(c);
}

static void fz_disconnect(struct fz_conn *c)
{
  if (fz_alive(c)) {
    /* What a dropped TCP connection looks like to the server. */
    close(c->peer);
    c->peer = -1;
    event_generate(ET_EOF, &cli_socket(c->cli), 0);
    fz_flush();
    fz_pump(4);
  }
  if (c->peer >= 0)
    close(c->peer);
  c->peer = -1;
  c->cli = NULL;
  c->fd = -1;
}

/* End-of-iteration teardown: really remove the client, bouncer or not. */
static void fz_destroy(struct fz_conn *c)
{
  if (fz_alive(c))
    exit_client(c->cli, c->cli, &me, "fuzz iteration end");
  fz_flush();
  if (c->peer >= 0)
    close(c->peer);
  c->peer = -1;
  c->cli = NULL;
  c->fd = -1;
}

/* Bouncer sessions outlive their connections by design; drop every
 * session of the harness accounts so the next input starts clean. */
static void fz_kill_sessions(void)
{
  static const char *const accts[] = { "fuzzacct", "peeracct", "fuzzalt", NULL };
  int i, guard;

  for (i = 0; accts[i]; i++) {
    for (guard = 0; guard < 16; guard++) {
      struct BouncerSession *s = bounce_find_any_session(accts[i]);
      struct Client *prim;
      if (!s)
        break;
      prim = s->hs_client;
      bounce_kill_session(s, "fuzz iteration end");
      if (prim && cli_magic(prim) == CLIENT_MAGIC && !IsDead(prim) &&
          !HasFlag(prim, FLAG_CLOSING))
        exit_client(prim, prim, &me, "fuzz iteration end");
      fz_flush();
    }
  }
}

static void fz_sasl_plain(struct fz_conn *c, const char *acct)
{
  char raw[128], b64[256], line[300];
  size_t n, i, o = 0;
  static const char tbl[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

  n = (size_t)snprintf(raw, sizeof(raw), "%c%s%cfuzzpass", 0, acct, 0);
  for (i = 0; i < n; i += 3) {
    unsigned v = (unsigned char)raw[i] << 16;
    if (i + 1 < n) v |= (unsigned char)raw[i + 1] << 8;
    if (i + 2 < n) v |= (unsigned char)raw[i + 2];
    b64[o++] = tbl[(v >> 18) & 63];
    b64[o++] = tbl[(v >> 12) & 63];
    b64[o++] = (i + 1 < n) ? tbl[(v >> 6) & 63] : '=';
    b64[o++] = (i + 2 < n) ? tbl[v & 63] : '=';
  }
  b64[o] = 0;
  fz_cmd(c, "AUTHENTICATE PLAIN");
  snprintf(line, sizeof(line), "AUTHENTICATE %s", b64);
  fz_cmd(c, line);
}

static void fz_req_all_caps(struct fz_conn *c)
{
  char line[600];
  int i;
  for (i = 0; ALL_CAPS[i]; i++) {
    snprintf(line, sizeof(line), "CAP REQ :%s", ALL_CAPS[i]);
    fz_cmd(c, line);
  }
}

static void fz_prelude_A(unsigned flags)
{

  if (!fz_connect(&fzA, (flags & FZ_WEBSOCKET) != 0))
    return;
  if (flags & (FZ_ALLCAPS | FZ_SASL))
    fz_cmd(&fzA, "CAP LS 302");
  if (flags & FZ_ALLCAPS)
    fz_req_all_caps(&fzA);
  else if (flags & FZ_SASL)
    fz_cmd(&fzA, "CAP REQ :sasl");
  if (flags & FZ_SASL)
    fz_sasl_plain(&fzA, "fuzzacct");
  if (flags & FZ_REGISTER) {
    fz_cmd(&fzA, "NICK fuzzA");
    fz_cmd(&fzA, "USER fuzza 0 * :Fuzz A");
    if (flags & (FZ_ALLCAPS | FZ_SASL))
      fz_cmd(&fzA, "CAP END");
    if (flags & FZ_OPER)
      fz_cmd(&fzA, "OPER fuzzoper fuzzoperpass");
    if (flags & FZ_PEERCHAN)
      fz_cmd(&fzA, "JOIN #fuzz");
  }
}

static void fz_prelude_B(void)
{

  if (!fz_connect(&fzB, 0))
    return;
  fz_cmd(&fzB, "CAP LS 302");
  fz_req_all_caps(&fzB);
  fz_sasl_plain(&fzB, "peeracct");
  fz_cmd(&fzB, "NICK fuzzB");
  fz_cmd(&fzB, "USER fuzzb 0 * :Fuzz B");
  fz_cmd(&fzB, "CAP END");
  fz_cmd(&fzB, "JOIN #fuzz");
}

/* ---- init ---------------------------------------------------------- */
static void fz_write_file(const char *name, const char *content)
{
  char path[512];
  FILE *f;
  snprintf(path, sizeof(path), "%s/%s", fz_dir, name);
  f = fopen(path, "w");
  if (f) {
    fputs(content, f);
    fclose(f);
  }
}

static void fz_write_conf(const char *tmpl_path)
{
  FILE *in = fopen(tmpl_path, "r");
  char path[512];
  FILE *out;
  char line[4096];

  if (!in) {
    fprintf(stderr, "fuzz_client: cannot open config template %s\n", tmpl_path);
    exit(1);
  }
  snprintf(path, sizeof(path), "%s/ircd.conf", fz_dir);
  out = fopen(path, "w");
  while (fgets(line, sizeof(line), in)) {
    char *p, *s = line;
    while ((p = strstr(s, "@DIR@"))) {
      fwrite(s, 1, (size_t)(p - s), out);
      fputs(fz_dir, out);
      s = p + 5;
    }
    fputs(s, out);
  }
  fclose(in);
  fclose(out);
}

static void fz_rm_rf(const char *path)
{
  DIR *d = opendir(path);
  struct dirent *e;
  char sub[1024];

  if (d) {
    while ((e = readdir(d))) {
      if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, ".."))
        continue;
      snprintf(sub, sizeof(sub), "%s/%s", path, e->d_name);
      fz_rm_rf(sub);
    }
    closedir(d);
    rmdir(path);
  } else
    unlink(path);
}

/* Best effort: each (fork-mode) worker makes its own RocksDB dir. */
static void fz_cleanup(void)
{
  if (fz_dir[0] && !getenv("FUZZ_CLIENT_KEEP_TMP"))
    fz_rm_rf(fz_dir);
}

static struct Listener *fz_make_listener(int websocket)
{
  struct Listener *l = (struct Listener *)MyCalloc(1, sizeof(*l));
  l->fd_v4 = l->fd_v6 = -1;
  l->ref_count = 1;          /* never released */
  ircd_aton(&l->addr.addr, "100.64.0.1");
  l->addr.port = websocket ? 8080 : 6667;
  FlagSet(&l->flags, LISTEN_ACTIVE);
  FlagSet(&l->flags, LISTEN_IPV4);
  if (websocket)
    FlagSet(&l->flags, LISTEN_WEBSOCKET);
  return l;
}

static const char *fz_conf_template(char **argv)
{
  static char path[1024];
  const char *env = getenv("FUZZ_CLIENT_CONF");
  char *slash;

  if (env)
    return env;
  /* default: fuzz.conf.in next to the binary */
  snprintf(path, sizeof(path), "%s", argv[0]);
  slash = strrchr(path, '/');
  if (slash)
    slash[1] = 0;
  else
    strcpy(path, "./");
  strncat(path, "fuzz.conf.in", sizeof(path) - strlen(path) - 1);
  return path;
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
  const char *tmpl = fz_conf_template(*argv);
  char tmpl_abs[1024];
  const char *base = getenv("FUZZ_CLIENT_TMP");

  fz_verbose = getenv("FUZZ_CLIENT_VERBOSE") != NULL;
  if (!realpath(tmpl, tmpl_abs)) {
    fprintf(stderr, "fuzz_client: config template %s not found "
            "(set FUZZ_CLIENT_CONF)\n", tmpl);
    exit(1);
  }
  snprintf(fz_dir, sizeof(fz_dir), "%s/nefuzz.XXXXXX", base ? base : "/tmp");
  if (!mkdtemp(fz_dir)) {
    perror("mkdtemp");
    exit(1);
  }
  atexit(fz_cleanup);
  fz_write_conf(tmpl_abs);
  fz_write_file("ircd.motd", "Welcome to the fuzz net\nline two\n");
  fz_write_file("remote.motd", "remote motd\n");
  {
    static char confpath[600];
    snprintf(confpath, sizeof(confpath), "%s/ircd.conf", fz_dir);
    configfile = confpath;
  }

  signal(SIGPIPE, SIG_IGN);   /* as setup_signals() does */
  CurrentTime = time(NULL);
  umask(077);
  memset(&me, 0, sizeof(me));
  memset(&me_con, 0, sizeof(me_con));
  cli_connect(&me) = &me_con;
  cli_fd(&me) = -1;

  init_connection_limits();
  event_init(MAXCONNECTIONS);
  feature_init();
  init_isupport();
  log_init("fuzz_client");
  initload();
  /* init_list() only pre-fills the (fuzz-disabled) freelists; skip it. */
  init_hash();
  init_class();
  initwhowas();
  initmsgtree();
  initstats();
  ircd_crypt_init();
  motd_init();
  if (!init_conf()) {
    fprintf(stderr, "fuzz_client: init_conf failed (%s)\n", configfile);
    exit(1);
  }
  init_isupport();
  init_server_identity();
  if (ssl_init())
    fprintf(stderr, "fuzz_client: ssl_init failed (continuing)\n");
  uping_init();
  stats_init();
  dnsbl_init();
  IPcheck_init();

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
  geoip_init();

  history_set_map_size((size_t)feature_int(FEAT_HISTORY_MAP_SIZE_MB));
#ifdef USE_ZSTD
  compress_init((size_t)feature_int(FEAT_COMPRESS_THRESHOLD),
                feature_int(FEAT_COMPRESS_LEVEL));
#endif
  if (history_init(feature_str(FEAT_CHATHISTORY_DB)) == 0)
    chathistory_init_callbacks();
  else
    fprintf(stderr, "fuzz_client: history_init failed\n");
  if (metadata_lmdb_init(feature_str(FEAT_METADATA_DB)) != 0)
    fprintf(stderr, "fuzz_client: metadata init failed\n");
  if (webpush_store_init(feature_str(FEAT_WEBPUSH_DB)) != 0)
    fprintf(stderr, "fuzz_client: webpush store init failed\n");
  presence_set_boot_alive_hint(history_newest_activity_ms());
  presence_init();

  bounce_init();
  cap_set_value(CAP_DRAFT_PERSISTENCE, "attach,detach,list,attach-cursor");
  bounce_db_restore();

  ircd_kc_adapter_init();
  if (kc_init(ircd_kc_get_event_ops(), ircd_kc_get_log_ops()) == 0) {
    kc_transport_ready = 1;
    sasl_conf_boot_apply();
    /* No Keycloak{} block: arm local SASL from the features, as the
     * deprecated-feature fallback does on a real boot. */
    sasl_local_init();
  }
  if (feature_bool(FEAT_CAP_draft_webpush))
    webpush_setup();

  server_boot_complete = 1;
  fz_listener = fz_make_listener(0);
  fz_ws_listener = fz_make_listener(1);
  fzA.fd = fzA.peer = fzB.fd = fzB.peer = -1;
  timer_run();
  (void)argc;
  return 0;
}

/* ---- one input ----------------------------------------------------- */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  unsigned flags;
  size_t pos, nlines = 0;

  if (size < 1)
    return 0;
  flags = data[0];
  CurrentTime += 2;

  if (flags & FZ_PEER)
    fz_prelude_B();
  fz_prelude_A(flags);

  pos = 1;
  while (pos < size && nlines < MAX_LINES) {
    const uint8_t *nl = memchr(data + pos, '\n', size - pos);
    size_t end = nl ? (size_t)(nl - data) : size;
    const char *line = (const char *)data + pos;
    size_t len = end - pos;

    pos = end + 1;
    nlines++;
    if (len == 0)
      continue;
    switch ((unsigned char)line[0]) {
    case 0x01:
      fz_line(&fzB, line + 1, len - 1);
      break;
    case 0x02:
      CurrentTime += (len > 1) ? (unsigned char)line[1] : 1;
      fz_pump(8);
      break;
    case 0x03:
      fz_disconnect(&fzA);
      break;
    case 0x04:
      fz_disconnect(&fzA);
      fz_prelude_A(flags);
      break;
    case 0x05:
      fz_send_raw(&fzA, line + 1, len - 1);
      break;
    default:
      fz_line(&fzA, line, len);
      break;
    }
  }

  fz_kill_sessions();
  fz_destroy(&fzA);
  fz_destroy(&fzB);
  fz_kill_sessions();
  /* Let held bouncer sessions, deferred destroys and async completions
   * settle so the next input starts from a quiet server. */
  fz_pump(4);
  return 0;
}
