#!/bin/bash
# usage: start.sh HOLDSECS
R=/tmp/claude-0/bncval/run
[ -f $R/ircd.pid ] && kill $(cat $R/ircd.pid) 2>/dev/null; sleep 0.5
rm -rf $R/history $R/asan.* $R/ircd.log; 
sed "s/HOLDSECS/${1:-60}/" $R/ircd.conf > $R/live.conf
cd $R
ASAN_OPTIONS=log_path=$R/asan:detect_leaks=0:abort_on_error=0 UBSAN_OPTIONS=print_stacktrace=1:suppressions=/tmp/claude-0/sendval/ubsan.supp:log_path=$R/asan \
LD_PRELOAD=/usr/lib/gcc/x86_64-linux-gnu/13/libasan.so:/tmp/claude-0/sendval/shim/fakeuid.so:$LDP nohup ${BIN:-/tmp/claude-0/bncval/src/ircd/ircd} -n -x 9 -d $R -f $R/live.conf > $R/ircd.out 2>&1 &
sleep 2; (netstat -ltn 2>/dev/null || cat /proc/net/tcp) | head -3; tail -5 $R/ircd.out
