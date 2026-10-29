#!/bin/sh
# CBMC proofs for ircd/recv_classify.c.  See README.md.
cd "$(dirname "$0")"
R=../common/run_harness.sh
H=recv_classify_harness.c
fail=0
NOCONV=1 $R $H harness_counters 10 -DBMAX=8 || fail=1
NOCONV=1 $R $H harness_split 10 -DBMAX=8 || fail=1
NOCONV=1 $R $H harness_caps 10 -DBMAX=8 || fail=1
exit $fail
