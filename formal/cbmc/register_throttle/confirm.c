/* Concrete reproductions against the REAL ircd/register_throttle.c at the
 * production geometry (64 buckets x 4), -fsanitize=address,undefined.
 *  1. LRU-eviction bypass: 5 /64s whose first 64 bits XOR to the same
 *     bucket, round-robin, limit 3 / 3600 s, global cap off.
 *  2. Backward clock step pins the global window. */
#include <stdio.h>
#include <string.h>
#include "register_throttle.h"
#include "res.h"

int main(void)
{
  struct irc_in_addr a[5];
  int i, k, ok = 0, tries = 0;
  time_t t = 1800000000;

  memset(a, 0, sizeof a);
  for (i = 0; i < 5; i++) {
    a[i].in6_16[0] = 0x2001; a[i].in6_16[1] = 0x0db8;
    a[i].in6_16[3] = (unsigned short)((i + 1) << 6);   /* same bucket */
  }
  reg_throttle_clear();
  for (k = 0; k < 20; k++)
    for (i = 0; i < 5; i++, tries++, t++)
      ok += reg_throttle_check(&a[i], t, 3, 3600, 0) == REG_THROTTLE_OK;
  printf("eviction: %d of %d REGISTERs from 5 /64s allowed within %ld s "
         "(intended cap 5*3 = 15)\n", ok, tries, (long)(t - 1800000000));

  reg_throttle_clear();
  reg_throttle_check(0, 1800003600, 0, 60, 1);       /* clock 1h fast */
  printf("clock step back: global check 1 period after the step: %s\n",
         reg_throttle_check(0, 1800000060, 0, 60, 1) == REG_THROTTLE_OK
         ? "OK" : "still REFUSED (window pinned until clock catches up)");
  return 0;
}
