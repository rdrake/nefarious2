#!/bin/bash
# Minimize crash reproducers with libFuzzer's -minimize_crash.
#   fuzz/p10/minimize.sh <out-dir> <crash-file>...
# Each <crash-file> becomes <out-dir>/<basename>.min (runs up to 4 in parallel).
HERE="$(cd "$(dirname "$0")" && pwd)"
OUTD="${1:?out dir}"; shift
mkdir -p "$OUTD"
export FUZZ_TMPDIR="${FUZZ_TMPDIR:-/dev/shm/p10fuzz-store}"
mkdir -p "$FUZZ_TMPDIR"
"$HERE/sweep.sh" "$FUZZ_TMPDIR" 2 & SWEEP=$!
trap 'kill $SWEEP 2>/dev/null; "$HERE/sweep.sh" "$FUZZ_TMPDIR"' EXIT
export ASAN_OPTIONS="detect_leaks=0:symbolize=0"
export UBSAN_OPTIONS="halt_on_error=1"
for f in "$@"; do
  b=$(basename "$f")
  ( mkdir -p "$OUTD/$b.art"
    "$HERE/bin/fuzz_p10" -minimize_crash=1 -artifact_prefix="$OUTD/$b.art/" -max_total_time="${MINTIME:-120}" -detect_leaks=0 \
      -exact_artifact_path="$OUTD/$b.min" "$f" >"$OUTD/$b.minlog" 2>&1
    rm -rf "$OUTD/$b.art"
    [ -f "$OUTD/$b.min" ] || cp "$f" "$OUTD/$b.min"
    echo "$b: $(stat -c %s "$f") -> $(stat -c %s "$OUTD/$b.min")" ) &
  while [ "$(jobs -r | wc -l)" -ge "${JOBS:-4}" ]; do wait -n; done
done
wait
