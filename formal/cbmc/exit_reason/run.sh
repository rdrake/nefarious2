#!/bin/sh
# CBMC proof for ircd/exit_reason.c.  See README.md.
cd "$(dirname "$0")"
../common/run_harness.sh exit_reason_harness.c harness_contract 26 -DSMAX=24
