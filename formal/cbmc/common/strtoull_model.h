/* strtoull_model.h - a faithful, loop-bounded model of glibc strtoull()
 * for base 10, used because CBMC ships no body for strtoull (an absent
 * body would make the result AND *endptr nondeterministic, hiding real
 * behaviour).  Semantics modelled (C11 7.22.1.4 + glibc):
 *   - leading isspace() bytes skipped (' ', \t \n \v \f \r)
 *   - optional '+' or '-'
 *   - decimal digits; none => return 0, *endptr = nptr
 *   - magnitude overflow => ULLONG_MAX (errno not modelled)
 *   - '-' => the unsigned negation of the magnitude (when no overflow)
 * The model is validated against glibc by common/strtoull_model_check.c
 * (run by every run.sh). */
#ifndef CBMC_STRTOULL_MODEL_H
#define CBMC_STRTOULL_MODEL_H
#include <limits.h>
#include <stddef.h>

static unsigned long long cbmc_strtoull10(const char *nptr, char **endptr)
{
  const char *s = nptr;
  unsigned long long acc = 0;
  int neg = 0, any = 0, ovf = 0;

  while (*s == ' ' || (*s >= '\t' && *s <= '\r'))
    s++;
  if (*s == '+' || *s == '-') {
    neg = (*s == '-');
    s++;
  }
  for (; *s >= '0' && *s <= '9'; s++) {
    unsigned d = (unsigned)(*s - '0');
    any = 1;
    if (acc > (ULLONG_MAX - d) / 10ULL)
      ovf = 1;
    else
      acc = acc * 10ULL + d;
  }
  if (endptr)
    *endptr = (char *)(any ? s : nptr);
  if (!any)
    return 0;
  if (ovf)
    return ULLONG_MAX;
  return neg ? (0ULL - acc) : acc;
}
#endif

#ifdef __CPROVER__
/* Give CBMC a body for the real symbol so the module under proof links
 * against the model, unmodified.  Only base 10 is modelled. */
unsigned long long strtoull(const char *nptr, char **endptr, int base)
{
  __CPROVER_assert(base == 10, "strtoull model: only base 10 is modelled");
  return cbmc_strtoull10(nptr, endptr);
}
#endif
