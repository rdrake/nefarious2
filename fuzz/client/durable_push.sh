#!/usr/bin/env bash
# Periodic durability: while the campaign (pid in $1) runs, every ~20 min
# refresh the committed corpus and snapshot any raw crash inputs, then
# commit+push. Safe: only touches fuzz/client/{corpus,crashes/incoming}.
set -u
CAMP_PID="${1:-}"
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
export ASAN_OPTIONS=detect_leaks=0 FUZZ_CLIENT_TMP="$HERE/work/tmp"
cd "$REPO"
while :; do
  sleep 1200
  # snapshot raw crash inputs (durability of reproducers, pre-triage)
  mkdir -p "$HERE/crashes/incoming"
  cp -n "$HERE"/work/artifacts/* "$HERE/crashes/incoming/" 2>/dev/null || true
  # refresh coverage-minimized corpus
  tmp="$HERE/work/corpus_merge"; rm -rf "$tmp"; mkdir -p "$tmp"
  timeout 420 "$HERE/out/fuzz_client" -merge=1 "$tmp" "$HERE"/work/corpus "$HERE"/work/seeds >/dev/null 2>&1
  if [ -n "$(ls -A "$tmp" 2>/dev/null)" ]; then
    rm -rf "$HERE/corpus"; mv "$tmp" "$HERE/corpus"
  fi
  git add "$HERE/corpus" "$HERE/crashes" >/dev/null 2>&1
  if ! git diff --cached --quiet; then
    git commit -q -m "fuzz/client: periodic corpus/crash snapshot (campaign in progress)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01PARbFsSxrdoHWbzcxxTWrn"
    for i in 1 2 3 4; do git push -q origin fuzz/client-protocol && break; sleep $((2**i)); done
  fi
  [ -n "$CAMP_PID" ] && ! kill -0 "$CAMP_PID" 2>/dev/null && break
done
