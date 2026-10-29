#!/usr/bin/env bash
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
W="$HERE/work"; SECS="${1:-9000}"
export FUZZ_CLIENT_TMP="$W/tmp" FUZZ_CLIENT_CONF="$HERE/fuzz.conf.in"
export ASAN_OPTIONS="detect_leaks=0:abort_on_error=1:handle_abort=1:allocator_may_return_null=1"
export UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=1"
python3 "$HERE/gen_seeds.py" "$W/seeds" >/dev/null
# Reaper: crashed -fork workers can't run their atexit cleanup, so their
# per-process RocksDB temp dirs leak and fill the disk over a long run.
# Delete nefuzz.* dirs untouched for >3 min (a live worker keeps opening
# files under its dir, so its mtime stays fresh).
( while kill -0 $$ 2>/dev/null; do
    find "$W/tmp" -maxdepth 1 -name 'nefuzz.*' -mmin +3 -exec rm -rf {} + 2>/dev/null || true
    sleep 120
  done ) &
REAPER=$!
trap 'kill $REAPER 2>/dev/null' EXIT
cd "$W"
exec "$HERE/out/fuzz_client" -fork="$(nproc)" -ignore_crashes=1 -ignore_timeouts=1 \
  -ignore_ooms=1 -fork_corpus_groups=1 -max_len=8192 -dict="$HERE/client.dict" \
  -timeout=25 -rss_limit_mb=4096 -max_total_time="$SECS" -detect_leaks=0 \
  -print_final_stats=1 -artifact_prefix="$W/artifacts/" \
  "$W/corpus" "$HERE/corpus" "$W/seeds"
