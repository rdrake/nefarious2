#!/bin/bash
# Dedupe crash artifacts by sanitizer summary + top in-ircd frames,
# replaying each in the plain ASan build (bin/repro_p10).
#
#   fuzz/p10/triage.sh <artifact-dir> [outdir]
#
# Writes <outdir>/<n>.txt (full report of the smallest reproducer per
# signature) and prints "count  signature  smallest-file".
HERE="$(cd "$(dirname "$0")" && pwd)"
ART="${1:?artifact dir}"
OUT="${2:-$ART/../triage}"
mkdir -p "$OUT"
export FUZZ_TMPDIR="${FUZZ_TMPDIR:-/dev/shm/p10fuzz-store}"
mkdir -p "$FUZZ_TMPDIR"
export ASAN_OPTIONS="detect_leaks=0:abort_on_error=0:symbolize=1:detect_stack_use_after_return=1"
export UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=1"
TMP=$(mktemp -d)
for f in "$ART"/crash-* "$ART"/timeout-* ; do
  [ -f "$f" ] || continue
  log="$TMP/$(basename "$f").log"
  timeout 60 "$HERE/bin/repro_p10" "$f" >"$log" 2>&1
  rc=$?
  kind=$(grep -m1 -oE "runtime error: [a-z -]*|ERROR: AddressSanitizer: [a-z-]*|Assertion failure at [^:]*:[0-9]*|ERROR: LeakSanitizer|SEGV" "$log" | head -1)
  [ -z "$kind" ] && { [ $rc = 0 ] && kind="NO-REPRO" || kind="rc=$rc"; }
  frames=$(grep -E "^ +#[0-9]+ " "$log" | grep -vE "libc|__sanitizer|asan_|ubsan|abort|raise|__assert|log_write|libFuzzer|fuzzer::|LLVMFuzzer|standalone.c|run_file|fuzz_p10.c|_start" \
           | head -3 | sed -E 's/.* in ([^ ]+) .*\/([^/]+:[0-9]+).*/\1@\2/' | tr '\n' ' ')
  loc=$(grep -m1 -oE "^[a-z_A-Z0-9]+\.c:[0-9]+:[0-9]+: runtime error" "$log" | cut -d: -f1,2)
  echo "$kind|$loc|$frames|$(stat -c %s "$f")|$f"
done | sort -t'|' -k1,3 -k4n | awk -F'|' -v out="$OUT" -v tmp="$TMP" '
  { sig=$1"|"$2"|"$3; cnt[sig]++; if (!(sig in best)) { best[sig]=$5; order[++n]=sig } }
  END { for (i=1;i<=n;i++) { s=order[i]; printf "%4d  %s  %s\n", cnt[s], s, best[s];
        split(best[s], p, "/"); cmd="cp " tmp "/" p[length(p)] ".log " out "/" i ".txt"; system(cmd);
        print best[s] > (out "/" i ".input") } }'
rm -rf "$TMP"
"$HERE/sweep.sh" "$FUZZ_TMPDIR"
