#!/bin/bash
# Run one of the config / persisted-record fuzzers.
#
#   fuzz/config/run.sh TARGET [JOBS] [SECONDS] [BUILD_DIR]
#
#   TARGET   conf | feature | bouncer | records
#   JOBS     libFuzzer -fork workers (default: nproc)
#   SECONDS  -max_total_time (default 3600)
#
# The fuzzed confs can name files to write (Features "LOG" ... "FILE"),
# programs to run (IAuth -- the harness stubs fork()) and arbitrary
# include paths, so when started as root this drops to an unprivileged
# `nefuzz` user that can only write its work dir.  Work dir: $WORK
# (default /srv/nefuzz); crashes land in $WORK/artifacts/TARGET/.
set -euo pipefail

T=${1:?usage: $0 conf|feature|bouncer|records [JOBS] [SECONDS] [BUILD_DIR]}
JOBS=${2:-$(nproc)}
SECS=${3:-3600}
HERE=$(cd "$(dirname "$0")" && pwd)
BUILD=${4:-${BUILD_DIR:-$HOME/fz}}
WORK=${WORK:-/srv/nefuzz}
BIN=$BUILD/out-fuzz/fuzz_$T

[ -x "$BIN" ] || { echo "build first: $HERE/build.sh fuzz" >&2; exit 1; }

mkdir -p "$WORK"/{bin,corpus/$T,seeds,artifacts/$T,sandbox,logs}
cp "$BIN" "$WORK/bin/"
cp "$HERE"/*.dict "$WORK/bin/"
# Seeds: generated (conf, feature, bouncer) + the committed minimized corpus.
if [ ! -d "$WORK/seeds/conf" ] || [ ! -d "$WORK/seeds/feature" ]; then
  python3 -I "$HERE/gen_seeds.py" "$WORK/seeds"
fi
if [ ! -d "$WORK/seeds/bouncer" ] || [ ! -d "$WORK/seeds/records" ]; then
  mkdir -p "$WORK/seeds/bouncer" "$WORK/seeds/records"
  "$BUILD/out-fuzz/gen_bouncer_seeds" "$WORK/seeds/bouncer" "$WORK/seeds/records"
fi
if [ -d "$HERE/corpus/$T" ]; then
  cp -n "$HERE/corpus/$T"/* "$WORK/corpus/$T/" 2>/dev/null || true
fi

DICT=
case $T in
  conf)    DICT=-dict=$WORK/bin/conf.dict; MAXLEN=-max_len=16384 ;;
  feature) DICT=-dict=$WORK/bin/feature.dict; MAXLEN=-max_len=4096 ;;
  bouncer|records) MAXLEN=-max_len=65536 ;;
esac

RUNAS=()
if [ "$(id -u)" = 0 ]; then
  id nefuzz >/dev/null 2>&1 || useradd -r -M -d "$WORK" -s /usr/sbin/nologin nefuzz
  chown -R nefuzz: "$WORK"
  RUNAS=(setpriv --reuid=nefuzz --regid=nefuzz --init-groups --)
fi

cd "$WORK"
export FUZZ_SANDBOX=$WORK/sandbox
export ASAN_OPTIONS=detect_leaks=0:abort_on_error=1:symbolize=1:allocator_may_return_null=1
export UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1
# FINDINGS.md F7: crule_parse frees an uninitialised child pointer on some
# syntax errors.  ASan's default 0xbe malloc fill turns that into a SEGV on
# nearly every mutated CRule; zero-fill new allocations for the conf
# target so the campaign is not stuck on it.
[ "$T" = conf ] && ASAN_OPTIONS=$ASAN_OPTIONS:malloc_fill_byte=0

exec "${RUNAS[@]}" "$WORK/bin/fuzz_$T" -fork="$JOBS" -ignore_crashes=1 \
  -ignore_timeouts=1 -ignore_ooms=1 -timeout=10 -rss_limit_mb=4096 \
  -max_total_time="$SECS" $DICT $MAXLEN \
  -artifact_prefix="$WORK/artifacts/$T/" \
  "$WORK/corpus/$T" "$WORK/seeds/$T"
