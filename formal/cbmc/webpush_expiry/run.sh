#!/bin/sh
# CBMC proofs for ircd/webpush_expiry.c.  See README.md.
cd "$(dirname "$0")"
R=../common/run_harness.sh
H=webpush_expiry_harness.c
fail=0
$R $H harness_armed_at_safe 30 -DREC_MAX=26 || fail=1
$R $H harness_armed_at_nonneg 30 -DREC_MAX=26 || fail=1
$R $H harness_armed_at_keyed_record 40 -DKEYID_MAX=16 || fail=1
$R $H harness_expired_total 2 || fail=1
$R $H harness_expired_props 2 || fail=1
exit $fail
