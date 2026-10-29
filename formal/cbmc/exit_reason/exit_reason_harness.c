/*
 * exit_reason_harness.c - CBMC proof for ircd/exit_reason.c (#included
 * unmodified).
 */
#include "../common/cbmc_util.h"
#include "../../../ircd/exit_reason.c"

#ifndef SMAX
#define SMAX 24
#endif

/* X1  memory safety on every string of length <= SMAX, and the header
 *     contract stated independently: 1 exactly when info is
 *     "Write error: " followed by at least one byte, or is exactly
 *     "Max sendQ exceeded" / "Buffer allocation error". */
void harness_contract(void)
{
  static const char we[] = "Write error: ";
  char s[SMAX + 1];
  size_t n, i;
  int prefix = 1, want;
  NONDET_CSTR(s, SMAX);
  n = strlen(s);
  for (i = 0; i < sizeof(we) - 1; i++)
    if (i >= n || s[i] != we[i])
      prefix = 0;
  want = (prefix && n > sizeof(we) - 1)
      || (n == 18 && memcmp(s, "Max sendQ exceeded", 18) == 0)
      || (n == 23 && memcmp(s, "Buffer allocation error", 23) == 0);
  __CPROVER_assert(exit_reason_is_clobbered_info(s) == want, "contract");
  __CPROVER_assert(exit_reason_is_clobbered_info(0) == 0, "NULL");
}
