#include <stdio.h>
#include <string.h>
#include <stdlib.h>
/* Mirrors ircd/s_auth.c iauth_read line-splitter (~3381-3391). */
static void iauth_read_mirror(char *readbuf){
  char *sol, *eol;
  for (sol = readbuf; (eol = strchr(sol, '\n')) != NULL; sol = eol + 1) {
    *eol = '\0';
    if (*(eol - 1) == '\r')   /* <-- s_auth.c:3383 : eol can == readbuf */
      *(eol - 1) = '\0';
    printf("line: \"%s\"\n", sol);
  }
}
int main(void){
  /* IAuth read that begins with '\n' (fresh buffer, i_count==0) */
  char *buf = malloc(8);
  strcpy(buf, "\nL");     /* first byte is '\n' */
  iauth_read_mirror(buf);
  free(buf);
  return 0;
}
