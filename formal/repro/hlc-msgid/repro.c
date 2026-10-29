#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "crdt_hlc.h"
static int nwarn;
void log_write(int a,int b,unsigned c,const char*f,...){(void)a;(void)b;(void)c;(void)f;nwarn++;}
static const char convert2y[] = {
  'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P',
  'Q','R','S','T','U','V','W','X','Y','Z','a','b','c','d','e','f',
  'g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v',
  'w','x','y','z','0','1','2','3','4','5','6','7','8','9','[',']'};
static const char* inttobase64_64(char* buf, uint64_t v, unsigned int count){
  buf[count]='\0'; while(count>0){buf[--count]=convert2y[v&63]; v>>=6;} return buf;}
static unsigned long MsgIdCounter;
static struct HLC prev; static int havep, mono_breaks; static long first_break=-1;
static char *gen(char *buf, size_t n, long i){
  struct HLC hlc = hlc_global_event();
  if (havep && hlc_compare(&hlc,&prev) <= 0){ mono_breaks++; if(first_break<0){first_break=i;
     printf("  monotonicity break at call %ld: prev=(%llu,%u) new=(%llu,%u)\n",i,
     (unsigned long long)prev.physical_ms,prev.logical,(unsigned long long)hlc.physical_ms,hlc.logical);}}
  prev=hlc; havep=1;
  char l[4],t[8],c[3];
  inttobase64_64(l,hlc.logical,3); inttobase64_64(t,hlc.physical_ms,7);
  inttobase64_64(c,(++MsgIdCounter)&0xFFF,2);
  snprintf(buf,n,"AB%s%s%s",l,t,c); return buf;
}
/* simple open-addressing set of 14-char ids */
#define HS (1u<<22)
static char (*tab)[15];
static long *idx;
static long insert(const char*s,long i){ uint64_t h=1469598103934665603ULL; for(const char*p=s;*p;p++){h^=(unsigned char)*p;h*=1099511628211ULL;}
  for(uint64_t k=h&(HS-1);;k=(k+1)&(HS-1)){ if(!tab[k][0]){strcpy(tab[k],s);idx[k]=i;return -1;} if(!strcmp(tab[k],s)) return idx[k];}}
int main(int argc,char**argv){
  long N = argc>1? atol(argv[1]) : 200000;
  int mix = argc>2? atoi(argv[2]) : 0; /* every mix-th event also do a non-msgid HLC event (forwarded_label/receive) */
  tab=calloc(HS,15); idx=calloc(HS,sizeof(long));
  hlc_init(1);
  MsgIdCounter = (unsigned long)hlc_wall_clock_ms();
  /* adopt a peer stamp 30 s ahead (within default 60000 bound) */
  struct HLC remote = { hlc_wall_clock_ms() + 30000, 5, 2 };
  int rej = hlc_global_receive(&remote, 60000, NULL);
  printf("peer 30s ahead adopted (rejected=%d): pt=%llu logical=%u\n", rej,
    (unsigned long long)hlc_global()->physical_ms, hlc_global()->logical);
  uint64_t pt0 = hlc_global()->physical_ms;
  char buf[32]; long dups=0;
  for(long i=1;i<=N;i++){
    gen(buf,sizeof buf,i);
    if (strlen(buf)!=14){printf("bad len %s\n",buf);}
    long j=insert(buf,i);
    if(j>=0){ if(!dups) printf("  FIRST DUPLICATE msgid %s at call %ld (same as call %ld, gap %ld)\n",buf,i,j,i-j); dups++; }
    if(mix && i%mix==0){ struct HLC r={pt0-1000,0,3}; if(i%(2*mix)==0) hlc_global_event(); else hlc_global_receive(&r,60000,NULL);} 
  }
  printf("calls=%ld dups=%ld mono_breaks=%d overflow_warnings=%d final pt-delta=%lld ms logical=%u wall-ahead=%lld ms\n",
    N,dups,mono_breaks,nwarn,(long long)(hlc_global()->physical_ms-pt0),hlc_global()->logical,
    (long long)(hlc_global()->physical_ms-hlc_wall_clock_ms()));
  return 0;
}
