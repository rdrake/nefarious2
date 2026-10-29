#include <stdio.h>
extern const char* geoip_continent_name_by_code(const char* cc);
int main(int argc,char**argv){
  const char* cc = argc>1?argv[1]:"ZZ";
  const char* r = geoip_continent_name_by_code(cc);
  /* force a read through the returned pointer, as ircd_strncpy would */
  volatile char sink=0; for(const char*p=r;*p;p++) sink^=*p;
  printf("code=%s -> name=%s (sink=%d)\n", cc, r, sink);
  return 0;
}
