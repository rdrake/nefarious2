#define _GNU_SOURCE 1
/* Shared boot code for the Nefarious config / persisted-record fuzzers.
 *
 * Replicates ircd.c:main() up to init_conf() and make_server(&me), minus
 * daemonizing, signals, the pid file, sockets that would listen, and the
 * timers that drive the event loop (the fuzzers never enter it).
 */
#include "config.h"
#include "ircd.h"
#include "IPcheck.h"
#include "class.h"
#include "client.h"
#include "crdt_hlc.h"
#include "hash.h"
#include "bouncer_session.h"
#include "ircd_alloc.h"
#include "ircd_events.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_string.h"
#include "ircd_crypt.h"
#include "list.h"
#include "motd.h"
#include "msg.h"
#include "numnicks.h"
#include "parse.h"
#include "s_bsd.h"
#include "s_conf.h"
#include "s_misc.h"
#include "s_stats.h"
#include "s_user.h"
#include "struct.h"
#include "sys.h"
#include "userload.h"
#include "whowas.h"
#include "fileio.h"
#include "dnsbl.h"
#include "fuzz_common.h"

#include <dirent.h>
#include <dlfcn.h>
#include <ftw.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

extern struct Connection me_con;
extern char *configfile;
extern void init_isupport(void);

static char conf_path[512];
static char sandbox[512];

const char fuzz_baseline_conf[] =
  "General {\n"
  "  name = \"fuzz.example.net\";\n"
  "  description = \"fuzz\";\n"
  "  numeric = 1;\n"
  "};\n"
  "Class { name = \"Server\"; pingfreq = 1 minutes; connectfreq = 5 minutes; maxlinks = 1; sendq = 9000000; };\n"
  "Class { name = \"Local\"; pingfreq = 1 minutes; sendq = 160000; maxlinks = 100; };\n"
  "Client { class = \"Local\"; ip = \"*\"; host = \"*\"; };\n";

const char *fuzz_conf_path(void) { return conf_path; }

void fuzz_write_conf(const char *buf, size_t len)
{
  int fd = open(conf_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
  if (fd < 0) { perror("open conf"); abort(); }
  while (len > 0) {
    ssize_t n = write(fd, buf, len);
    if (n <= 0) { perror("write conf"); abort(); }
    buf += n; len -= (size_t)n;
  }
  close(fd);
}

/* ---- harness sandboxing --------------------------------------------- */

/* Listener / Connect / Webhook blocks bind sockets while the conf is read.
 * Nothing in the fuzzers ever accepts, so make bind(2) a no-op: it keeps
 * parallel jobs from colliding on ports and from binding real ports. */
int bind(int fd, const struct sockaddr *addr, socklen_t len)
{
  (void)fd; (void)addr; (void)len;
  return 0;
}
int listen(int fd, int backlog) { (void)fd; (void)backlog; return 0; }

/* IAuth { program = ...; }; forks and execs whatever the conf names, and
 * gitsync forks too.  Never let fuzzed input run a program: the child
 * exits before it can exec.  With FUZZ_UNMASK_KNOWN fork() fails instead,
 * which reaches FINDINGS.md F4 (auth_spawn's fork-failure path leaves
 * deleted sockets behind for the next REHASH to delete again). */
#ifdef FUZZ_UNMASK_KNOWN
pid_t fork(void) { errno = EAGAIN; return -1; }
#else
pid_t fork(void)
{
  static pid_t (*real_fork)(void);
  pid_t pid;
  if (!real_fork)
    real_fork = (pid_t (*)(void))dlsym(RTLD_NEXT, "fork");
  pid = real_fork();
  if (pid == 0)
    _exit(127);
  return pid;
}
#endif
pid_t vfork(void) { errno = EAGAIN; return -1; }

/* Keep `include "...";` from blocking on devices (/dev/stdin, fifos). */
extern FBFILE *__real_fbopen(const char *filename, const char *mode);
FBFILE *__wrap_fbopen(const char *filename, const char *mode)
{
  struct stat st;
  if (filename && stat(filename, &st) == 0 && !S_ISREG(st.st_mode)) {
    errno = EACCES;
    return NULL;
  }
  return __real_fbopen(filename, mode);
}

#ifndef FUZZ_UNMASK_KNOWN
/* FINDINGS.md F3: dnsbl_parse_index() never advances past a character
 * that is not a digit, space or comma, so `host = "127.0.0.2";` in a DNSBL
 * block hangs the parser.  Drop such characters before the real call so
 * the fuzzer is not stuck in timeouts on the known bug (build with
 * -DFUZZ_UNMASK_KNOWN to see it). */
extern struct DNSBLServer *__real_dnsbl_add_server(const char *, const char *,
    unsigned int, enum DNSBLAction, const char *, int);
struct DNSBLServer *__wrap_dnsbl_add_server(const char *domain,
    const char *index, unsigned int bitmask, enum DNSBLAction action,
    const char *mark, int score)
{
  char clean[512];
  size_t i, j = 0;
  if (index) {
    for (i = 0; index[i] && j < sizeof(clean) - 1; i++)
      if ((index[i] >= '0' && index[i] <= '9') || index[i] == ',' ||
          index[i] == ' ' || index[i] == '\t')
        clean[j++] = index[i];
    clean[j] = '\0';
    index = clean;
  }
  return __real_dnsbl_add_server(domain, index, bitmask, action, mark, score);
}
#else
extern struct DNSBLServer *__real_dnsbl_add_server(const char *, const char *,
    unsigned int, enum DNSBLAction, const char *, int);
struct DNSBLServer *__wrap_dnsbl_add_server(const char *domain,
    const char *index, unsigned int bitmask, enum DNSBLAction action,
    const char *mark, int score)
{
  return __real_dnsbl_add_server(domain, index, bitmask, action, mark, score);
}
#endif

/* Fuzzed confs can point log files (Features "LOG" ... "FILE") at the
 * sandbox and turn logging up to DEBUG; truncate everything but the conf
 * after each input so the disk does not fill.  Directories (RocksDB) are
 * left alone. */
void fuzz_sandbox_trim(void)
{
  DIR *d = opendir(sandbox);
  struct dirent *de;
  while (waitpid(-1, NULL, WNOHANG) > 0)
    ;                           /* stub IAuth children (see fork()) */
  if (!d)
    return;
  while ((de = readdir(d)) != NULL) {
    struct stat st;
    char path[1024];
    if (!strcmp(de->d_name, "ircd.conf"))
      continue;
    snprintf(path, sizeof(path), "%s/%s", sandbox, de->d_name);
    if (lstat(path, &st) == 0 && S_ISREG(st.st_mode) && st.st_size > 0)
      truncate(path, 0);
  }
  closedir(d);
}

static int rm_entry(const char *path, const struct stat *st, int flag,
                    struct FTW *ftw)
{
  (void)st; (void)flag; (void)ftw;
  remove(path);
  return 0;
}

static void remove_sandbox(void)
{
  nftw(sandbox, rm_entry, 16, FTW_DEPTH | FTW_PHYS);
}

void fuzz_ircd_boot(const char *conf_text)
{
  const char *base = getenv("FUZZ_SANDBOX");
  CurrentTime = FUZZ_NOW;

  snprintf(sandbox, sizeof(sandbox), "%s/nefuzz.%d",
           base ? base : "/tmp", (int)getpid());
  mkdir(sandbox, 0700);
  atexit(remove_sandbox);
  if (chdir(sandbox)) { perror("chdir sandbox"); abort(); }
  snprintf(conf_path, sizeof(conf_path), "%s/ircd.conf", sandbox);
  configfile = conf_path;
  fuzz_write_conf(conf_text, strlen(conf_text));

  umask(077);
  memset(&me, 0, sizeof(me));
  memset(&me_con, 0, sizeof(me_con));
  cli_connect(&me) = &me_con;
  cli_fd(&me) = -1;

  init_connection_limits();
  event_init(MAXCONNECTIONS);
  feature_init();
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

  if (!init_conf()) {
    fprintf(stderr, "fuzz: baseline conf rejected\n");
    abort();
  }
  init_isupport();
  init_server_identity();

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
  hAddClient(&me);
  SetIPv6(&me);
  SetIRCv3Aware(&me);
  bounce_init();
  /* Not SIGCHLD: Initialize also runs in the -fork=N parent, which waits
   * for its jobs.  Stub IAuth children are reaped in fuzz_sandbox_trim(). */
  signal(SIGPIPE, SIG_IGN);
}
