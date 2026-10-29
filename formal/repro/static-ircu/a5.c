#include <stdlib.h>
#include <stdio.h>
/* s_auth.c iauth_parse: for a has_cli command (e.g. 'L') sent with NO params,
   parc==0 so params[0]==NULL, and strtol(params[0]) runs BEFORE 'if (parc<3)'. */
int main(void){
  char *params[2]; int parc = 0;
  params[parc] = NULL;              /* params[0] == NULL */
  char *endptr; 
  long id = strtol(params[0], &endptr, 10);   /* s_auth.c:3305 */
  if (parc < 3) { printf("would send E Missing\n"); }
  printf("id=%ld\n", id);
  return 0;
}
