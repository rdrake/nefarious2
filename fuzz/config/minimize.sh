#!/bin/bash
# Merge-minimize the live corpora (run.sh's $WORK) and the seeds into the
# committed corpora, fuzz/config/corpus/TARGET.  Only inputs that add
# coverage are kept (libFuzzer -merge=1), so re-running is incremental.
#
#   fuzz/config/minimize.sh [TARGET...] [BUILD_DIR via $BUILD_DIR]
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
BUILD=${BUILD_DIR:-$HOME/fz}
WORK=${WORK:-/srv/nefuzz}
TARGETS=${*:-conf feature bouncer records}
SB=$(mktemp -d)
trap 'rm -rf "$SB"' EXIT
for t in $TARGETS; do
  out=$HERE/corpus/$t
  mkdir -p "$out"
  opts=detect_leaks=0
  [ "$t" = conf ] && opts=$opts:malloc_fill_byte=0     # F7, as in run.sh
  srcs=()
  for d in "$WORK/corpus/$t" "$WORK/seeds/$t"; do [ -d "$d" ] && srcs+=("$d"); done
  FUZZ_SANDBOX=$SB ASAN_OPTIONS=$opts nice -n 10 "$BUILD/out-fuzz/fuzz_$t" \
    -merge=1 -timeout=10 -rss_limit_mb=4096 "$out" "${srcs[@]}" \
    > "$SB/merge-$t.log" 2>&1 || { tail -5 "$SB/merge-$t.log"; exit 1; }
  echo "$t: $(ls "$out" | wc -l) files, $(du -sh "$out" | cut -f1)"
done
