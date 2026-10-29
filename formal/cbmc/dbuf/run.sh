#!/bin/sh
# CBMC proofs for ircd/dbuf.c.  See README.md.
# One run per filler size K: the bytes under test then start 0..3 bytes
# before the end of the first 2048-byte DBufBuffer (K = 2048 puts them at
# the start of the second buffer).
cd "$(dirname "$0")"
fail=0
for K in 2045 2046 2047 2048; do
  mkdir -p logs
  NOCONV=1 ../common/run_harness.sh dbuf_harness.c harness_getmsg 12 \
    -DAMAX=3 -DLMAX=8 -DKFIX=$K || fail=1
  [ -f logs/harness_getmsg.log ] && mv logs/harness_getmsg.log logs/harness_getmsg_K$K.log
done
exit $fail
