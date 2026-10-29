#!/bin/sh
# CBMC proofs for the interval core of ircd/chathistory_presence.c.
# See README.md.  CAP = per-record interval cap fed to the module through
# the feature_int() stub.
cd "$(dirname "$0")"
R=../common/run_harness.sh
H=chathistory_presence_harness.c
fail=0
for fn in harness_union_wf harness_union_sound harness_union_complete_below_cap \
          harness_union_cap_drops_oldest harness_union_idem_comm \
          harness_join_part harness_next_visible; do
  NOCONV=1 $R $H $fn 8 -DCAP=3 || fail=1
done
NOCONV=1 $R $H harness_norm_time_any 2 || fail=1
NOCONV=1 $R $H harness_pn_ingest_any 8 -DCAP=3 || fail=1
NOCONV=1 $R $H harness_union_any_time 8 -DCAP=3 || fail=1
NOCONV=1 $R $H harness_norm_record_any 257 || fail=1
exit $fail
