/*
 * fuzz_exit_reason.c - libFuzzer harness for ircd/exit_reason.c, which
 * classifies a QUIT/exit info string (client QUIT messages and peer SQUIT
 * reasons reach it).  Pure; memory safety only.
 */
#include "exit_reason.h"
#include "fuzz_util.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  char *s = strndup((const char *)data, size);
  (void)exit_reason_is_clobbered_info(s);
  free(s);
  return 0;
}
