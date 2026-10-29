#!/bin/sh
# CBMC proofs for ircd/account_id.c.  See README.md.
cd "$(dirname "$0")"
R=../common/run_harness.sh
H=account_id_harness.c
fail=0
NOCONV=1 $R $H harness_valid_contract 26 -DSMAX=24 || fail=1
NOCONV=1 $R $H harness_from_uuid_arbitrary 42 -DSMAX=40 || fail=1
NOCONV=1 $R $H harness_from_uuid_roundtrip 40 || fail=1
NOCONV=1 $R $H harness_from_uuid_hyphen_positions 40 || fail=1
exit $fail
