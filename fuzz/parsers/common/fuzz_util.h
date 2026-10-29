/* fuzz_util.h - small helpers shared by the harnesses */
#ifndef FUZZ_UTIL_H
#define FUZZ_UTIL_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define CHECK(c) do { if (!(c)) { fprintf(stderr, "CHECK failed: %s (%s:%d)\n", #c, __FILE__, __LINE__); abort(); } } while (0)

/* FUZZ_STRICT=1: also run the inputs a harness steps around for a known
 * (already reported) bug */
static inline int fuzz_strict(void)
{
  static int s = -1;
  if (s < 0) s = getenv("FUZZ_STRICT") != NULL;
  return s;
}

/* next NUL-separated field of [*p, end) as a fresh string */
static inline char *fuzz_field(const char **p, const char *end)
{
  const char *z;
  char *r;
  if (*p >= end) return strdup("");
  z = memchr(*p, 0, end - *p);
  if (!z) z = end;
  r = strndup(*p, z - *p);
  *p = z < end ? z + 1 : end;
  return r;
}
#endif
