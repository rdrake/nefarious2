/* Concrete reproductions against the REAL ircd/chathistory_presence.c
 * (#included; static interval core called directly), built with
 * -fsanitize=address,undefined.  Unreached ircd symbols are left
 * unresolved at link time (-Wl,--unresolved-symbols=ignore-all). */
#include <stdio.h>
#include <stdlib.h>
#include "../../../ircd/chathistory_presence.c"

int feature_int(enum Feature f) { (void)f; return 2; }   /* cap = 2 */

static void show(const char *tag, const struct presence_record *r)
{
  int i;
  printf("%s count=%u open=%lld:", tag, r->count, (long long)r->open_since);
  for (i = 0; i < r->count; i++)
    printf(" [%lld,%lld]", (long long)r->intervals[i].start, (long long)r->intervals[i].end);
  printf("\n");
}

int main(void)
{
  static struct presence_record r;
  int64_t ms2026 = 1790000000000LL, start, end;

  /* F1: PN ingest exactly as m_markread.c does it. */
  start = presence_norm_time((int64_t)strtoull("-1", NULL, 10));
  end   = presence_norm_time((int64_t)strtoull("117309440000000000", NULL, 10));
  memset(&r, 0, sizeof r);
  record_union_close(&r, start, end);
  show("F1 PN start=\"-1\":", &r);
  printf("F1 visible at 1990-01-01 (packed)? %d\n",
         record_was_present(&r, PRESENCE_TIME_FROM_MS(631152000000LL)));

  /* F2: magnitude-normalisation overflow (UBSan: left shift of ... ) */
  printf("F2 presence_norm_time(200000000000000) = %lld\n",
         (long long)presence_norm_time(200000000000000LL));

  /* F3: at the cap, an older-starting window that also spans the retained
   * ones is dropped whole -- losing instants NEWER than retained windows. */
  memset(&r, 0, sizeof r);
  record_union_close(&r, PRESENCE_TIME_FROM_MS(ms2026 + 3600000), PRESENCE_TIME_FROM_MS(ms2026 + 3660000));
  record_union_close(&r, PRESENCE_TIME_FROM_MS(ms2026 + 7200000), PRESENCE_TIME_FROM_MS(ms2026 + 7260000));
  show("F3 before:", &r);
  r.open_since = PRESENCE_TIME_FROM_MS(ms2026);       /* joined before both */
  record_apply_part(&r, PRESENCE_TIME_FROM_MS(ms2026 + 9000000));
  show("F3 after part:", &r);
  printf("F3 visible mid-session (t0+5000s)? %d  (member was present the whole time)\n",
         record_was_present(&r, PRESENCE_TIME_FROM_MS(ms2026 + 5000000)));
  return 0;
}
