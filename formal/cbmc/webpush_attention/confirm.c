/* Concrete reproduction against the REAL ircd/webpush_attention.c,
 * -fsanitize=address,undefined: last_msg (replicated from peers via
 * BX U la=) + idle overflows for an absurd last_msg. */
#include <stdio.h>
#include <limits.h>
#include "webpush_attention.h"
int main(void)
{
  struct webpush_conn_state c = { 0, 0, LLONG_MAX - 10 };
  printf("attending(last_msg=LLONG_MAX-10, idle=900) = %d\n",
         webpush_conn_attending(&c, 1800000000LL, 900));
  return 0;
}
