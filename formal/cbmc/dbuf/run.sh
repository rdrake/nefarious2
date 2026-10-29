#!/bin/sh
# CBMC proofs for ircd/dbuf.c.  See README.md.
cd "$(dirname "$0")"
NOCONV=1 ../common/run_harness.sh dbuf_harness.c harness_getmsg 12 -DAMAX=4 -DLMAX=10
