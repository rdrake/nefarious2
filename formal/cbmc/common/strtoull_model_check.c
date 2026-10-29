/* Differential check: cbmc_strtoull10 vs glibc strtoull on edge inputs. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "strtoull_model.h"

int main(void)
{
  static const char *v[] = {
    "", " ", "0", "-0", "+0", "5", "-5", " -5", "\t+7x", "abc", "-", "+",
    "18446744073709551615", "18446744073709551616", "-18446744073709551615",
    "-18446744073709551616", "99999999999999999999999", "9223372036854775808",
    "00000000000000000000001", "1 2", "\v\f\r\n9", "--1", "+-1", "12abc", 0 };
  int i, bad = 0;
  for (i = 0; v[i]; i++) {
    char *e1, *e2;
    unsigned long long a = strtoull(v[i], &e1, 10);
    unsigned long long b = cbmc_strtoull10(v[i], &e2);
    if (a != b || e1 != e2) {
      printf("MISMATCH %d '%s': glibc %llu/%ld model %llu/%ld\n", i, v[i],
             a, (long)(e1 - v[i]), b, (long)(e2 - v[i]));
      bad = 1;
    }
  }
  printf(bad ? "strtoull model: MISMATCH\n" : "strtoull model: agrees with glibc on %d inputs\n", i);
  return bad;
}
