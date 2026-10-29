#!/bin/sh
# CBMC proofs for ircd/register_throttle.c.  See README.md.
cd "$(dirname "$0")"
R=../common/run_harness.sh
H=register_throttle_harness.c
SMALL="-DREG_THROTTLE_TABLE_BITS=0 -DREG_THROTTLE_BUCKET_DEPTH=2"
fail=0
$R $H harness_safety 18 -DREG_THROTTLE_TABLE_BITS=2 -DREG_THROTTLE_BUCKET_DEPTH=4 || fail=1
$R $H harness_safety_any_time 18 $SMALL || fail=1
$R $H harness_refusal_records_nothing 18 $SMALL || fail=1
$R $H harness_per_ip_bound 18 $SMALL -DRT_CALLS=4 || fail=1
$R $H harness_per_ip_bound_with_neighbours 18 $SMALL -DRT_CALLS=4 || fail=1
$R $H harness_global_bound 18 $SMALL -DRT_CALLS=5 || fail=1
$R $H harness_global_clock_step_back 18 $SMALL || fail=1
exit $fail
