#!/bin/bash
# build.sh - build every parser fuzz harness twice:
#   out/fuzz_<t>   libFuzzer + ASan + UBSan (the fuzzing binary)
#   out/repro_<t>  plain ASan + UBSan with common/standalone_main.c (triage)
#
# Needs a configured tree (config.h at the repo root); runs ./configure
# with the CLAUDE.md options when it is missing.  No ircd source is
# modified; harnesses #include or link the real ircd/*.c files.
#
#   ./build.sh            build all targets
#   ./build.sh kc_jwt ... build the named targets only
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
OUT=$HERE/out
mkdir -p "$OUT"
CC=${CC:-clang}

if [ ! -f "$ROOT/config.h" ]; then
  (cd "$ROOT" && ./configure --enable-debug --with-maxcon=4096 \
     --with-rocksdb=/usr --with-zstd=/usr --enable-keycloak >/dev/null)
fi

SAN="-fsanitize=address,undefined -fno-sanitize-recover=undefined -fno-omit-frame-pointer"
CFLAGS_COMMON="-g -O1 -w -I$ROOT/include -I$ROOT -I$ROOT/ircd -I$HERE/sasl_auth -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION"
I=$ROOT/ircd
C=$HERE/common

# target -> "harness.c [extra sources...] | libs"
declare -A T
T[websocket]="websocket/fuzz_websocket.c $I/ircd_alloc.c $I/ircd_string.c $C/ircd_stubs.c | -lssl -lcrypto"
T[kc_webhook]="kc_webhook/fuzz_kc_webhook.c $I/kc/kc_webhook_sig.c $I/webhook_subject.c $I/webhook_eventlog.c $I/account_id.c $I/webpush_keyring.c $C/kc_log_stub.c | -ljansson -lcrypto"
T[sasl_auth]="sasl_auth/fuzz_sasl_auth.c sasl_auth/sasl_stubs.c $I/ircd_alloc.c $I/ircd_string.c $I/account_id.c $I/webpush_keyring.c $C/ircd_stubs.c | -lssl -lcrypto -ljansson"
T[ircd_string]="ircd_string/fuzz_ircd_string.c $I/ircd_string.c $I/numnicks.c $I/match.c $I/ircd_alloc.c $C/ircd_stubs.c | -ljansson"
T[match]="match/fuzz_match.c $I/match.c $I/ircd_string.c $C/ircd_stubs.c |"
T[kc_jwt]="kc_jwt/fuzz_kc_jwt.c $I/kc/kc_base64.c $C/kc_log_stub.c | -ljansson -lcrypto"

# per-target extra compiler flags
declare -A F
# F8 (FINDINGS.md): iptobase64() shifts a promoted uint16 into the sign
# bit for every IPv4 address >= 128.0.0.0; left on, UBSan stops the
# campaign at the first such address.  repro_ builds keep the check.
F[ircd_string]="-fno-sanitize=shift-base"

build_one() {
  local name=$1 spec=${T[$1]}
  local srcs=${spec%%|*} libs=${spec#*|} abs=()
  for s in $srcs; do case $s in /*) abs+=("$s");; *) abs+=("$HERE/$s");; esac; done
  echo "[build] $name"
  $CC $CFLAGS_COMMON $SAN ${F[$name]} -fsanitize=fuzzer "${abs[@]}" -o "$OUT/fuzz_$name" $libs
  $CC $CFLAGS_COMMON $SAN "${abs[@]}" "$C/standalone_main.c" -o "$OUT/repro_$name" $libs
}

if [ $# -gt 0 ]; then targets="$*"; else targets=$(printf '%s\n' "${!T[@]}" | sort); fi
for t in $targets; do build_one "$t"; done
