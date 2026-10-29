#!/bin/sh
# CBMC proofs for ircd/webpush_attention.c.  See README.md.
cd "$(dirname "$0")"
R=../common/run_harness.sh
H=webpush_attention_harness.c
fail=0
$R $H harness_attending_total 2 || fail=1
$R $H harness_attention_contract 5 -DNCONN=2 || fail=1
../common/run_confirm.sh confirm.c ../../../ircd/webpush_attention.c
exit $fail
