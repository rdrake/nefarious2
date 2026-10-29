#!/bin/bash
# Run the P10 fuzzer in libFuzzer fork mode on all cores.
#
#   fuzz/p10/run.sh [seconds]        (default 3600; 0 = forever)
#
# WORK (default /home/user/fuzzwork) holds:
#   corpus/      the growing corpus (seeded from fuzz/p10/seeds)
#   artifacts/   crash-*, timeout-*, oom-* reproducers
# $STORE (tmpfs) holds the per-process rocksdb stores (one per harness
# process, removed at exit; dirs of crashed children are swept by pid).
#   fuzz.log     libFuzzer output
#
# Fork mode: each child process runs one LLVMFuzzerInitialize (rocksdb,
# conf, bouncer init) and then many inputs in-process; per-input state is
# reset by squitting the link (see fuzz_p10.c).  -ignore_crashes keeps the
# campaign going after a crash so all distinct crashes are collected.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="${WORK:-/home/user/fuzzwork}"
# RocksDB preallocates ~150 MB per harness process (3 stores); keep them on
# tmpfs so crashing children do not exhaust the disk.
STORE="${STORE:-/dev/shm/p10fuzz-store}"
SECS="${1:-3600}"
JOBS="${JOBS:-$(nproc)}"

mkdir -p "$WORK/corpus" "$WORK/artifacts" "$STORE"
export FUZZ_TMPDIR="$STORE"
export ASAN_OPTIONS="detect_leaks=0:abort_on_error=1:symbolize=1:allocator_may_return_null=1"
export UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=0:report_error_type=1"

# sweep store dirs left by children that died
"$HERE/sweep.sh" "$STORE" 5 &
SWEEP=$!
trap 'kill $SWEEP 2>/dev/null || true' EXIT

ARGS=(-fork="$JOBS" -max_len=16384 -dict="$HERE/p10.dict"
      -detect_leaks=0 -ignore_crashes=1 -ignore_ooms=1 -ignore_timeouts=1
      -timeout=30 -rss_limit_mb=4096 -print_final_stats=1
      -artifact_prefix="$WORK/artifacts/")
[ "$SECS" != 0 ] && ARGS+=(-max_total_time="$SECS")

"$HERE/bin/fuzz_p10" "${ARGS[@]}" "$WORK/corpus" "$HERE/seeds" ${EXTRA_CORPUS:-} \
  >>"$WORK/fuzz.log" 2>&1
