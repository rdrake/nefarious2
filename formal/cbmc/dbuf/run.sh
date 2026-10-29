#!/bin/sh
# dbuf.c: CBMC proof inside one DBufBuffer (KFIX=0), plus a bounded-
# exhaustive concrete check across the 2048-byte block boundary (CBMC ran
# out of memory on the 2 KB blocks -- see README.md).
cd "$(dirname "$0")"
fail=0
NOCONV=1 ../common/run_harness.sh dbuf_harness.c harness_getmsg 12 \
  -DAMAX=4 -DLMAX=10 -DKFIX=0 || fail=1
../common/run_confirm.sh exhaustive_boundary.c || fail=1
exit $fail
