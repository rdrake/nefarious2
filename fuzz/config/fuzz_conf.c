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

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  const char *p = (const char *)data;
  const char *end = p + size;
  int pieces = 0;

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
  fuzz_sandbox_trim();
  return 0;
}
