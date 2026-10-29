#!/usr/bin/env bash
# Report only NEW crash signatures (top frame) not already known.
cd "$(dirname "$0")/work"
export ASAN_OPTIONS=detect_leaks=0 FUZZ_CLIENT_TMP="$PWD/tmp"
KNOWN="m_trace.c:186|parse.c:1744|m_markread.c:108"
seen=/tmp/claude-0/seen_sigs; : > "$seen"
end=$(( $(date +%s) + 8400 ))
while [ "$(date +%s)" -lt "$end" ]; do
  if ! kill -0 6113 2>/dev/null; then echo "CAMPAIGN_DONE"; break; fi
  for f in artifacts/crash-* artifacts/oom-* artifacts/timeout-*; do
    [ -f "$f" ] || continue
    grep -qxF "$f" "$seen" && continue
    echo "$f" >> "$seen"
    sig=$(timeout 40 ../out/fuzz_client "$f" 2>&1 | grep -oE "[a-z_]+\.c:[0-9]+" | grep -vE "fuzz_client|ircd_events|packet\.c|s_bsd\.c|parse\.c:1742" | head -1)
    [ -z "$sig" ] && continue
    if echo "$sig" | grep -qE "$KNOWN"; then continue; fi
    echo "NEW_SIG $sig  ($f)"
  done
  sleep 45
done
