#!/usr/bin/env bash
# fuzz/client/run.sh -- run a fuzzing campaign with the client harness.
#
#   fuzz/client/run.sh [seconds] [variant]      (default: 3600 s, fuzz)
#
# Uses every core (-fork=$(nproc)), the dictionary, the committed corpus
# plus the generated seeds.  New corpus entries go to work/corpus, crashes
# to work/artifacts, logs to work/<variant>-<date>.log.  Extra libFuzzer
# flags can be passed in FUZZ_FLAGS.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SECS="${1:-3600}"
VARIANT="${2:-fuzz}"
case "$VARIANT" in
  fuzz)  BIN="$HERE/out/fuzz_client" ;;
  ubsan) BIN="$HERE/out/fuzz_client_ubsan" ;;
  *) echo "variant must be fuzz or ubsan" >&2; exit 1 ;;
esac
[ -x "$BIN" ] || "$HERE/build.sh" "$VARIANT"

W="$HERE/work"
mkdir -p "$W/corpus" "$W/artifacts" "$W/tmp" "$W/seeds"
python3 "$HERE/gen_seeds.py" "$W/seeds" >/dev/null
# stale per-worker RocksDB dirs from killed workers
find "$W/tmp" -maxdepth 1 -name 'nefuzz.*' -mmin +30 -exec rm -rf {} + 2>/dev/null || true

export FUZZ_CLIENT_TMP="$W/tmp"
export FUZZ_CLIENT_CONF="$HERE/fuzz.conf.in"
# Leaks are triaged separately (see FINDINGS.md); RocksDB init leaks 3 bytes.
export ASAN_OPTIONS="detect_leaks=0:abort_on_error=1:symbolize=1:allocator_may_return_null=1"
export UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=1"

( while kill -0 $$ 2>/dev/null; do
    find "$W/tmp" -maxdepth 1 -name 'nefuzz.*' -mmin +3 -exec rm -rf {} + 2>/dev/null || true
    sleep 120
  done ) &  # reaper for leaked crashed-worker temp dirs
trap 'kill %1 2>/dev/null' EXIT
LOG="$W/$VARIANT-$(date +%Y%m%d-%H%M%S).log"
echo "logging to $LOG"
cd "$W"
"$BIN" -fork="$(nproc)" -ignore_crashes=1 -ignore_timeouts=1 -ignore_ooms=1 \
  -max_len=8192 -dict="$HERE/client.dict" -timeout=25 -rss_limit_mb=4096 \
  -max_total_time="$SECS" -detect_leaks=0 -print_final_stats=1 \
  -artifact_prefix="$W/artifacts/" ${FUZZ_FLAGS:-} \
  "$W/corpus" "$HERE/corpus" "$W/seeds" 2>&1 | tee "$LOG" | grep -E "^#|crash|ERROR|DONE" || true
