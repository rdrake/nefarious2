#!/bin/sh
# Run the bouncer decision-module CBMC proofs.  Exit non-zero on failure.
cd "$(dirname "$0")" || exit 1
rc=0
for f in harness_converge_agreement harness_converge_empty_ids \
         harness_rebind_auth harness_kc_join harness_deauth harness_fields; do
  printf '%-28s ' "$f"
  if cbmc -I../../../include bouncer_decisions_harness.c --function "$f" \
       --bounds-check --pointer-check --signed-overflow-check \
       --unwind 12 --unwinding-assertions >"$f.log" 2>&1; then
    echo OK
  else
    echo FAIL; grep FAILURE "$f.log"; rc=1
  fi
done
exit $rc
