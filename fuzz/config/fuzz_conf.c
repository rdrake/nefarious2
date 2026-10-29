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
 */
#include "config.h"
#include "ircd.h"
#include "client.h"
#include "s_conf.h"
#include "fuzz_common.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define REHASH_SEP "\n#@REHASH@\n"
#define MAX_PIECES 3

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
    pieces++;
    if (!sep)
      break;
    p = sep + sizeof(REHASH_SEP) - 1;
  }

  fuzz_write_conf(fuzz_baseline_conf, strlen(fuzz_baseline_conf));
  rehash(&me, 2);
  free(copy);
  fuzz_sandbox_trim();
  return 0;
}
