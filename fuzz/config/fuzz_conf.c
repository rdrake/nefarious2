/* libFuzzer target: ircd.conf parser (ircd_lexer.l / ircd_parser.y /
 * s_conf.c) driven through the real REHASH path.
 *
 * Input: one or more conf texts separated by REHASH_SEP.  Each piece is
 * written to the conf file and loaded with rehash(&me, 2) -- exactly what
 * /REHASH, SIGHUP and a gitsync-triggered reload do -- so the second and
 * later pieces exercise freeing and re-creating the previous piece's
 * classes, connect/oper/client blocks, features, listeners, SASL/webhook,
 * webpush and bouncer settings.  After the input the baseline conf is
 * loaded again so every iteration starts from the same state.
 *
 * Between the first and second piece a socketless local client takes
 * references the way connected clients do -- attach_conf() on Client,
 * Connect, Operator and UWorld items (which also pins their classes) and
 * a listener reference -- and drops them only after the later pieces are
 * loaded.  That drives the "still in use" side of REHASH: CONF_ILLEGAL
 * items freed on the last detach, classes kept past class_delete_marked(),
 * listeners kept open past close_listeners().
 */
#include "config.h"
#include "ircd.h"
#include "client.h"
#include "s_conf.h"
#include "list.h"
#include "listener.h"
#include "fuzz_common.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define REHASH_SEP "\n#@REHASH@\n"
#define MAX_PIECES 3

/* Hold references like a connected client would; see the header. */
static struct Client *take_refs(void)
{
  struct Client *holder = make_client(NULL, STAT_UNKNOWN);
  struct ConfItem *aconf;
  int n = 0;

  for (aconf = GlobalConfList; aconf && n < 16; aconf = aconf->next) {
    if (aconf->status & (CONF_CLIENT | CONF_SERVER | CONF_OPERATOR |
                         CONF_UWORLD)) {
      attach_conf(holder, aconf);
      n++;
    }
  }
  if (ListenerPollList) {
    cli_listener(holder) = ListenerPollList;
    ListenerPollList->ref_count++;
  }
  return holder;
}

static void drop_refs(struct Client *holder)
{
  det_confs_butmask(holder, 0);
  if (cli_listener(holder)) {
    release_listener(cli_listener(holder));
    cli_listener(holder) = NULL;
  }
  free_client(holder);
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
  (void)argc; (void)argv;
  fuzz_ircd_boot(fuzz_baseline_conf);
  return 0;
}

#ifndef FUZZ_UNMASK_KNOWN
/* FINDINGS.md F6: `expr '/' expr` in ircd_parser.y divides with no zero
 * check (SIGFPE).  Turn every '/' outside quoted strings and comments into
 * '+' so the fuzzer is not stopped by the known bug.  (Signed overflow in
 * the same rules is silenced by building y.tab.c without that check.) */
static void mask_division(char *buf, size_t len)
{
  size_t i;
  int quoted = 0, comment = 0;
  for (i = 0; i < len; i++) {
    char c = buf[i];
    if (comment) {
      if (c == '\n')
        comment = 0;
    } else if (quoted) {
      if (c == '"' || c == '\n')
        quoted = 0;
    } else if (c == '"') {
      quoted = 1;
    } else if (c == '#') {
      comment = 1;
    } else if (c == '/') {
      buf[i] = '+';
    }
  }
}
#endif

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  char *copy = malloc(size + 1);
  const char *p = copy;
  const char *end = p + size;
  int pieces = 0;
  struct Client *holder = NULL;

  memcpy(copy, data, size);
#ifndef FUZZ_UNMASK_KNOWN
  mask_division(copy, size);
#endif

  CurrentTime = FUZZ_NOW;
  while (p <= end && pieces < MAX_PIECES) {
    const char *sep = memmem(p, end - p, REHASH_SEP, sizeof(REHASH_SEP) - 1);
    const char *stop = sep ? sep : end;
    fuzz_write_conf(p, stop - p);
    rehash(&me, 2);
    if (getenv("FUZZ_VERBOSE"))
      fprintf(stderr, "fuzz_conf: piece %d: %s\n", pieces,
              conf_get_error_flag() ? "parse errors" : "clean");
    if (!holder)
      holder = take_refs();
    pieces++;
    if (!sep)
      break;
    p = sep + sizeof(REHASH_SEP) - 1;
  }

  drop_refs(holder);
  fuzz_write_conf(fuzz_baseline_conf, strlen(fuzz_baseline_conf));
  rehash(&me, 2);
  free(copy);
  fuzz_sandbox_trim();
  return 0;
}
