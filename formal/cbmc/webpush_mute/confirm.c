/* Concrete reproductions against the REAL ircd/webpush_mute.c,
 * -fsanitize=address,undefined. */
#include <stdio.h>
#include <string.h>
#include "webpush_mute.h"

int main(void)
{
  time_t now = 1800000000;
  char out[64];
  int r;
  /* M1: a far-future until (> LLONG_MAX) wraps negative and is read as
   * already expired, though `-N` (explicit sign) is read as indefinite. */
  printf("M1 '#c:99999999999999999999' muted? %d   '#c:-1' muted? %d   '#c:9223372036854775807' muted? %d\n",
         webpush_mute_check("#c:99999999999999999999", "#c", now),
         webpush_mute_check("#c:-1", "#c", now),
         webpush_mute_check("#c:9223372036854775807", "#c", now));
  /* M2: leading whitespace defeats the '-' detection */
  printf("M2 '#c:-5' muted? %d   '#c: -5' muted? %d\n",
         webpush_mute_check("#c:-5", "#c", now), webpush_mute_check("#c: -5", "#c", now));
  /* M3: prune drops malformed entries yet reports "unchanged" */
  r = webpush_mute_prune("#a:0;junk;#b:0", NULL, now, out, sizeof out);
  printf("M3 prune('#a:0;junk;#b:0') = %d, out='%s'\n", r, out);
  return 0;
}
