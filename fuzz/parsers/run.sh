#!/bin/bash
# run.sh - run the parser fuzzers.
#
#   ./run.sh one <target> <seconds> [libFuzzer args...]
#       Fuzz one target (fork mode, keeps going past crashes/timeouts).
#   ./run.sh campaign <jobs> <schedule-file>
#       Run "target seconds" lines from the schedule, <jobs> at a time
#       (one fuzzer per core), e.g. ./run.sh campaign $(nproc) schedule.txt
#
# Working state goes to $FUZZ_WORK (default /tmp/nefarious-fuzz):
#   corpus/<t>/    growing corpus (seeded from <t>/seeds and <t>/corpus)
#   artifacts/<t>/ crash-/timeout-/oom- inputs
#   logs/<t>.<n>.log
# Minimize the working corpus back into <t>/corpus with ./minimize.sh.
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
WORK=${FUZZ_WORK:-/tmp/nefarious-fuzz}

one() {
  local t=$1 secs=$2; shift 2
  local bin=$HERE/out/fuzz_$t opts=() n
  [ -x "$bin" ] || { echo "no $bin; run ./build.sh $t" >&2; return 1; }
  mkdir -p "$WORK/corpus/$t" "$WORK/artifacts/$t" "$WORK/logs"
  [ -f "$HERE/$t/$t.dict" ] && opts+=("-dict=$HERE/$t/$t.dict")
  [ -f "$HERE/$t/options" ] && read -r -a extra < "$HERE/$t/options" && opts+=("${extra[@]}")
  local seeds=()
  for d in "$HERE/$t/seeds" "$HERE/$t/corpus"; do [ -d "$d" ] && seeds+=("$d"); done
  n=$(ls "$WORK/logs" | grep -c "^$t\." || true)
  echo "[run] $t for ${secs}s -> $WORK/logs/$t.$n.log"
  "$bin" -fork=1 -ignore_crashes=1 -ignore_timeouts=1 -ignore_ooms=1 \
    -timeout=10 -rss_limit_mb=2560 -max_total_time="$secs" \
    -artifact_prefix="$WORK/artifacts/$t/" -print_final_stats=1 \
    "${opts[@]}" "$@" "$WORK/corpus/$t" "${seeds[@]}" \
    > "$WORK/logs/$t.$n.log" 2>&1 || true
}

campaign() {
  local jobs=$1 sched=$2
  grep -v '^\s*#' "$sched" | grep -v '^\s*$' | \
    xargs -P "$jobs" -L 1 "$0" one
}

cmd=$1; shift
case $cmd in
  one) one "$@" ;;
  campaign) campaign "$@" ;;
  *) echo "usage: $0 one <target> <secs> | campaign <jobs> <schedule>" >&2; exit 1 ;;
esac
