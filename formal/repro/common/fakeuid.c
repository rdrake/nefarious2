#include <sys/types.h>
uid_t getuid(void){return 1000;} uid_t geteuid(void){return 1000;}
gid_t getgid(void){return 1000;} gid_t getegid(void){return 1000;}
#define _GNU_SOURCE
#include <dlfcn.h>
#include <string.h>
int access(const char *p, int m){ static int (*r)(const char*,int); if(!strcmp(p,"/root/bin/ircd")) return 0; if(!r) r=dlsym(RTLD_NEXT,"access"); return r(p,m);}
