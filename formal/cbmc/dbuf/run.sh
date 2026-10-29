#!/bin/sh
# dbuf.c: bounded-exhaustive concrete check across the 2048-byte block
# boundary (real dbuf.c, ASan+UBSan).  The CBMC harness (dbuf_harness.c)
# is kept for reference but does not scale with CBMC 5.95 on this
# machine -- see README.md; run it with:  RUN_CBMC=1 ./run.sh
cd "$(dirname "$0")"
fail=0
if [ -n "${RUN_CBMC:-}" ]; then
  NOCONV=1 ../common/run_harness.sh dbuf_harness.c harness_getmsg 12 \
    -DAMAX=4 -DLMAX=10 -DKFIX=0 || fail=1
fi
../common/run_confirm.sh exhaustive_boundary.c || fail=1
exit $fail
