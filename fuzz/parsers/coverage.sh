#!/bin/bash
# coverage.sh - source-based line coverage of each harness over its corpus.
#   ./coverage.sh [target...]     (default: every target in build.sh)
# Builds out/cov_<t> (-fprofile-instr-generate -fcoverage-mapping, no
# sanitizers, common/standalone_main.c), replays <t>/corpus (+ seeds),
# and prints llvm-cov's per-file summary for the ircd sources the target
# links.  Reports land in out/coverage/<t>.txt; the summary table on
# stdout is what FINDINGS.md quotes.
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
OUT=$HERE/out
mkdir -p "$OUT/coverage"
CC=${CC:-clang}
I=$ROOT/ircd; C=$HERE/common
# reuse the target table from build.sh without building anything
eval "$(sed -n '/^declare -A T/,/^# per-target extra compiler flags/p' "$HERE/build.sh" | grep -v '^mkdir\|^printf')"
mkdir -p "$OUT/gen"
printf '#define REG_THROTTLE_TABLE_BITS 0\n#define REG_THROTTLE_BUCKET_DEPTH 4\n#include "%s/register_throttle.c"\n' "$I" > "$OUT/gen/register_throttle_small.c"
CF="-g -O0 -w -I$ROOT/include -I$ROOT -I$ROOT/ircd -I$HERE/sasl_auth -I$HERE/common -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fprofile-instr-generate -fcoverage-mapping"
# the source file each harness is about (others it links are in the report)
declare -A M=( [kc_jwt]=kc/kc_jwt.c [kc_webhook]=kc/kc_webhook.c [websocket]=websocket.c
  [sasl_auth]=sasl_auth.c [ircd_string]=ircd_string.c [match]=match.c [history]=history.c
  [chathistory]=m_chathistory.c [metadata]=metadata.c [webpush]=webpush.c
  [webpush_store]=webpush_store.c [webpush_line]=webpush_line.c [webpush_mute]=webpush_mute.c
  [webpush_expiry]=webpush_expiry.c [webpush_keyring]=webpush_keyring.c [account_id]=account_id.c
  [recv_classify]=recv_classify.c [exit_reason]=exit_reason.c [register_throttle]=register_throttle.c
  [webhook_eventlog]=webhook_eventlog.c [bouncer_record]=bouncer_session.c
  [paste_listener]=paste_listener.c [ircd_compress]=ircd_compress.c [dbuf]=dbuf.c
  [db_casefold]=db_casefold.c [crule]=crule.c [ircd_snprintf]=ircd_snprintf.c
  [kc_base64]=kc/kc_base64.c [kc_url]=kc/kc_url.c [kc_error_classify]=kc/kc_error_classify.c
  [kc_cache]=kc/kc_cache.c [kc_cred_derive]=kc/kc_cred_derive.c )
if [ $# -gt 0 ]; then targets="$*"; else targets=$(printf '%s\n' "${!T[@]}" | sort); fi
printf '%-20s %10s %8s  %s\n' target lines covered "main source"
for t in $targets; do
  spec=${T[$t]}; srcs=${spec%%|*}; libs=${spec#*|}
  od=$OUT/obj/$t/cov; mkdir -p "$od"; objs=(); i=0; ircdsrc=()
  for s in $srcs; do
    case $s in /*) ;; *) s=$HERE/$s;; esac
    case $s in $I/*) ircdsrc+=("$s");; esac
    o=$od/$i.o; $CC $CF -c "$s" -o "$o"; objs+=("$o"); i=$((i+1))
  done
  $CC $CF -c "$C/standalone_main.c" -o "$od/main.o"; objs+=("$od/main.o")
  if [ -n "${A[$t]}" ]; then
    python3 "$C/autostub.py" "${objs[@]}" > "$od/autostub.c"
    $CC -g -O0 -w -c "$od/autostub.c" -o "$od/autostub.o"; objs+=("$od/autostub.o")
  fi
  $CC -fprofile-instr-generate "${objs[@]}" -o "$OUT/cov_$t" $libs
  rm -f "$od"/*.profraw
  dirs=(); for d in "$HERE/$t/corpus" "$HERE/$t/seeds"; do [ -d "$d" ] && dirs+=("$d"); done
  LLVM_PROFILE_FILE="$od/%p.profraw" FUZZ_WS_KNOWN_HANG= timeout 600 "$OUT/cov_$t" "${dirs[@]}" >/dev/null 2>&1 || true
  llvm-profdata merge -sparse "$od"/*.profraw -o "$od/cov.profdata" 2>/dev/null
  # the harness may #include the ircd source: report on the harness's
  # files and every ircd file it links
  llvm-cov report "$OUT/cov_$t" -instr-profile="$od/cov.profdata" > "$OUT/coverage/$t.txt" 2>/dev/null || true
  main=ircd/${M[$t]}
  line=$(grep -E "(^|/)$main " "$OUT/coverage/$t.txt" | head -1)
  # columns: Filename Regions Missed Cover Functions Missed Executed Lines Missed Cover
  printf '%-20s %10s %8s  %s\n' "$t" "$(echo "$line" | awk '{print $8}')" "$(echo "$line" | awk '{print $10}')" "$main"
done
