#include <string.h>
#include <stdlib.h>
int feature_bool(int f){(void)f;return 0;}
int feature_conf_loading(void){return 0;}
const char* feature_str(int f){(void)f;return NULL;}
/* real strlcpy-style copy: reads from src (the suspect pointer) */
char* ircd_strncpy(char*d,const char*s,size_t n){
  size_t i=0; if(n){ for(;i<n-1 && s[i];i++) d[i]=s[i]; d[i]=0;} return d;
}
