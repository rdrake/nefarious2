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

size_t strnlen(const char *s, size_t maxlen)
{
  size_t i;
  for (i = 0; i < maxlen && s[i]; i++)
    ;
  return i;
}

char *strstr(const char *h, const char *n)
{
  size_t i, j;
  if (!n[0])
    return (char *)h;
  for (i = 0; h[i]; i++) {
    for (j = 0; n[j] && h[i + j] == n[j]; j++)
      ;
    if (!n[j])
      return (char *)(h + i);
  }
  return 0;
}
#endif
#endif
