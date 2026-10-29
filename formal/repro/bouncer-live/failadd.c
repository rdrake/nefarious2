#define _GNU_SOURCE
#include <dlfcn.h>
#include <sys/epoll.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
static int (*real)(int,int,int,struct epoll_event*);
int epoll_ctl(int epfd,int op,int fd,struct epoll_event*ev){
  if(!real) real=dlsym(RTLD_NEXT,"epoll_ctl");
  if(op==EPOLL_CTL_ADD && access("/tmp/claude-0/bncval/failadd",F_OK)==0){
    unlink("/tmp/claude-0/bncval/failadd");
    fprintf(stderr,"FAILADD: failing epoll_ctl ADD fd=%d\n",fd);
    errno=ENOSPC; return -1;
  }
  return real(epfd,op,fd,ev);
}
