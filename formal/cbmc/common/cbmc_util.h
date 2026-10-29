/* Shared helpers for the nefarious pure-module CBMC harnesses. */
#ifndef CBMC_UTIL_H
#define CBMC_UTIL_H
#include <stddef.h>
#include <string.h>

/* Bodiless declarations: CBMC treats each call as a fresh nondet value. */
char nondet_char(void);
int nondet_int(void);
long nondet_long(void);
long long nondet_ll(void);
unsigned nondet_unsigned(void);
size_t nondet_size_t(void);
unsigned short nondet_ushort(void);
unsigned char nondet_uchar(void);

/* A nondeterministic NUL-terminated string in a caller buffer of n+1
 * bytes: every byte is arbitrary (an embedded NUL shortens it) and the
 * last is forced to NUL, so its strlen is anything in [0, n]. */
#define NONDET_CSTR(buf, n) do {                      \
    size_t _i;                                         \
    for (_i = 0; _i < (size_t)(n); _i++)               \
      (buf)[_i] = nondet_char();                       \
    (buf)[(n)] = '\0';                                 \
  } while (0)
#endif
