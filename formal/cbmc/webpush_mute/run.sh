#!/bin/sh
# CBMC proofs for ircd/webpush_mute.c.  See README.md.
cd "$(dirname "$0")"
R=../common/run_harness.sh
H=webpush_mute_harness.c
fail=0
# value strings up to 8 bytes: every loop is bounded by strlen+2
for fn in harness_check_safe harness_check_monotone harness_check_boundary \
          harness_prune_preserves harness_prune_drop; do
  $R $H $fn 12 -DVALUE_MAX=8 -DTARGET_MAX=2 || fail=1
done
# 22-byte single-entry value with a 20-digit until token
$R $H harness_check_large_until 26 || fail=1
exit $fail
