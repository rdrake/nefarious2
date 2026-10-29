#!/bin/sh
# CBMC proofs for ircd/register_throttle.c.  See README.md.
cd "$(dirname "$0")"
R=../common/run_harness.sh
H=register_throttle_harness.c
SMALL="-DREG_THROTTLE_TABLE_BITS=0 -DREG_THROTTLE_BUCKET_DEPTH=2"
fail=0
$R $H harness_safety 70 || fail=1                       # production 64x4
$R $H harness_safety_any_time 70 || fail=1
$R $H harness_refusal_records_nothing 5 $SMALL || fail=1
$R $H harness_per_ip_bound 6 $SMALL -DRT_CALLS=4 || fail=1
$R $H harness_per_ip_bound_with_neighbours 6 $SMALL -DRT_CALLS=4 || fail=1
$R $H harness_global_bound 6 $SMALL -DRT_CALLS=5 || fail=1
$R $H harness_global_clock_step_back 5 $SMALL || fail=1
exit $fail
