#!/bin/sh
# CBMC proofs for ircd/webpush_mute.c.  See README.md.
cd "$(dirname "$0")"
R=../common/run_harness.sh
H=webpush_mute_harness.c
fail=0
# value strings up to 8 bytes: every loop is bounded by strlen+2.
# H1 carries --conversion-check (it reports the known (long long) cast);
# the functional harnesses run without it so their verdict is their own.
$R $H harness_check_safe 12 -DVALUE_MAX=8 -DTARGET_MAX=2 || fail=1
for fn in harness_check_monotone harness_check_boundary; do
  NOCONV=1 $R $H $fn 12 -DVALUE_MAX=8 -DTARGET_MAX=2 || fail=1
done
# prune harnesses call check() several times: 6-byte values
for fn in harness_prune_preserves harness_prune_drop; do
  NOCONV=1 $R $H $fn 10 -DVALUE_MAX=6 -DTARGET_MAX=2 || fail=1
done
# 22-byte single-entry value with a 20-digit until token
NOCONV=1 $R $H harness_check_large_until 26 || fail=1
exit $fail
