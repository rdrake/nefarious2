/* libc bodies CBMC 5.95 does not ship (an absent body returns nondet,
 * which would make proofs meaningless).  Straightforward reference
 * implementations, same contracts as C11. */
#ifndef CBMC_LIBC_MODELS_H
#define CBMC_LIBC_MODELS_H
#include <stddef.h>
#ifdef __CPROVER__
void *memchr(const void *s, int c, size_t n)
{
  const unsigned char *p = (const unsigned char *)s;
  size_t i;
  for (i = 0; i < n; i++)
    if (p[i] == (unsigned char)c)
      return (void *)(p + i);
  return 0;
}
#endif
#endif
