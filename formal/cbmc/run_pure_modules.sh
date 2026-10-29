#!/bin/sh
# Runs every pure-module CBMC suite in this directory (not crdt_hlc, which
# has its own owner).  Each suite's run.sh prints one verdict line per
# harness; logs land in <module>/logs/.  Expected failures (documented
# findings) make the overall exit status nonzero -- see each README.md.
cd "$(dirname "$0")"
command -v cbmc >/dev/null || { echo "cbmc not found" >&2; exit 2; }
"$PWD/common/strtoull_model_check.sh" || exit 2
rc=0
for m in webpush_mute webpush_expiry webpush_attention register_throttle \
         account_id recv_classify exit_reason chathistory_presence \
         websocket dbuf; do
  echo "=== $m"
  ./$m/run.sh || rc=1
done
exit $rc
