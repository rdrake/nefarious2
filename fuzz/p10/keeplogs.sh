#!/bin/bash
# Fork mode overwrites each child's job log; keep the ones holding a
# sanitizer report or assertion (with the full stack) for triage.
#   fuzz/p10/keeplogs.sh <out-dir>
OUT="${1:?out dir}"; mkdir -p "$OUT"
while sleep 1; do
  for f in /tmp/libFuzzerTemp.FuzzWithFork*.dir/*.log; do
    [ -f "$f" ] || continue
    if grep -qE "ERROR: AddressSanitizer|Assertion failure|runtime error: (member|null|load|index)" "$f" 2>/dev/null; then
      h=$(md5sum "$f" | cut -c1-12)
      [ -f "$OUT/$h.log" ] || cp "$f" "$OUT/$h.log"
    fi
  done
done
