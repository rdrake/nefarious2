#!/bin/sh
# CBMC proofs for the interval core of ircd/chathistory_presence.c.
# See README.md.  CAP = per-record interval cap fed to the module through
# the feature_int() stub.
cd "$(dirname "$0")"
R=../common/run_harness.sh
H=chathistory_presence_harness.c
SRC=../../../ircd/chathistory_presence.c
mkdir -p build
# The one textual reduction (see the harness): array dimension 256 -> 8.
n=$(grep -c '^#define PRESENCE_MAX_INTERVALS 256$' $SRC)
[ "$n" = 1 ] || { echo "reduction anchor not found exactly once in $SRC" >&2; exit 2; }
sed 's/^#define PRESENCE_MAX_INTERVALS 256$/#define PRESENCE_MAX_INTERVALS 8/' \
  $SRC > build/chathistory_presence_small.c
fail=0
for fn in harness_union_wf harness_union_sound harness_union_complete_below_cap \
          harness_union_cap_drops_oldest harness_union_idempotent \
          harness_union_commutative \
          harness_join_part harness_next_visible; do
  NOCONV=1 $R $H $fn 8 -DCAP=3 -DPRESENCE_SMALL || fail=1
done
NOCONV=1 $R $H harness_pn_ingest_any 8 -DCAP=3 -DPRESENCE_SMALL || fail=1
NOCONV=1 $R $H harness_union_any_time 8 -DCAP=3 -DPRESENCE_SMALL || fail=1
NOCONV=1 $R $H harness_norm_time_any 2 -DPRESENCE_SMALL || fail=1
NOCONV=1 $R $H harness_cap_clamp 2 -DFEATURE_ANY || fail=1
../common/run_confirm.sh confirm.c -Wl,--unresolved-symbols=ignore-all
exit $fail
