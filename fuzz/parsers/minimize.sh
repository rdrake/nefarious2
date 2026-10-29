#!/bin/bash
# minimize.sh - merge the campaign's working corpus back into the
# committed <target>/corpus with libFuzzer's set-cover merge (keeps one
# input per feature), dropping inputs over $MAXB bytes (default 64 KiB).
#   ./minimize.sh [target...]
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
WORK=${FUZZ_WORK:-/tmp/nefarious-fuzz}
MAXB=${MAXB:-65536}
if [ $# -gt 0 ]; then targets="$*"; else targets=$(ls "$WORK/corpus"); fi
for t in $targets; do
  bin=$HERE/out/fuzz_$t
  [ -x "$bin" ] || continue
  new=$HERE/$t/corpus.new
  rm -rf "$new"; mkdir -p "$new"
  srcs=()
  for d in "$HERE/$t/corpus" "$HERE/$t/seeds" "$WORK/corpus/$t"; do [ -d "$d" ] && srcs+=("$d"); done
  opts=()
  [ -f "$HERE/$t/options" ] && read -r -a opts < "$HERE/$t/options"
  env -u FUZZ_WS_KNOWN_HANG -u FUZZ_STRICT "$bin" -merge=1 -timeout=10 -rss_limit_mb=2560 "${opts[@]}" "$new" "${srcs[@]}" > "$HERE/out/merge_$t.log" 2>&1 || true
  find "$new" -type f -size +"${MAXB}"c -delete
  rm -rf "$HERE/$t/corpus"; mv "$new" "$HERE/$t/corpus"
  echo "$t: $(ls "$HERE/$t/corpus" | wc -l) inputs, $(du -sk "$HERE/$t/corpus" | cut -f1) KiB"
done
