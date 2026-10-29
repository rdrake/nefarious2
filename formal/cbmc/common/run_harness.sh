#!/bin/sh
# run_harness.sh <harness.c> <entry-function> <unwind> [extra cbmc args...]
# Runs one CBMC proof with the standard checks, writes the full log to
# logs/<entry>.log next to the harness, prints a one-line verdict plus
# any failed properties.  Exit status: 0 = verified, 1 = failed.
#
# NOCONV=1 drops --conversion-check: used for the functional harnesses
# whose module has a KNOWN implementation-defined unsigned->signed
# conversion that a sibling safety harness already reports, so the
# functional verdict is not drowned by it.
set -u
src=$1; fn=$2; unwind=$3; shift 3
dir=$(dirname "$src")
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
conv=--conversion-check
[ -n "${NOCONV:-}" ] && conv=
mkdir -p "$dir/logs"
log="$dir/logs/$fn.log"
start=$(date +%s)
cbmc "$src" -I "$root/include" -I "$here" \
  --function "$fn" \
  --bounds-check --pointer-check --pointer-overflow-check \
  --signed-overflow-check $conv \
  --unwind "$unwind" --unwinding-assertions \
  --sat-solver cadical --trace "$@" > "$log" 2>&1
rc=$?
secs=$(( $(date +%s) - start ))
if grep -q "VERIFICATION SUCCESSFUL" "$log"; then
  printf '%-34s VERIFIED   (%ss)\n' "$fn" "$secs"
  exit 0
fi
printf '%-34s FAILED     (%ss, cbmc rc=%s)\n' "$fn" "$secs" "$rc"
grep -E '^\[.*\] .*: FAILURE' "$log" | sed 's/^/    /' | head -20
grep -qE 'FAILURE|SUCCESS' "$log" || tail -5 "$log" | sed 's/^/    /'
exit 1
