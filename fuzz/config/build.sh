#!/bin/bash
# Build the Nefarious config / persisted-record fuzzers.
#
#   fuzz/config/build.sh [fuzz|asan] [BUILD_DIR]
#
#   fuzz  (default) clang + libFuzzer + ASan + UBSan, -O1
#   (alignment checks are off by default: finding F1 fires on every
#   restored record; KEEP_ALIGN=1 turns them back on)
#   asan  plain ASan + UBSan, -O0, with repro_main.c as the driver (no
#         libFuzzer) -- used to confirm findings outside the fuzzer;
#         known-finding masks are off (FUZZ_UNMASK_KNOWN)
#   cov   clang source-based coverage, repro_main.c driver, masks on --
#         replay a corpus and llvm-cov report (see FINDINGS.md)
#
# The tree is exported with `git archive HEAD` into BUILD_DIR/src-<variant>
# (so the checkout stays clean), configured like CLAUDE.md says and built;
# then every ircd object except ircd.o is linked with fuzz_common.c and one
# harness each.  ircd.c is recompiled with -Dmain=ircd_main so its globals
# (me, me_con, configfile, ...) are available.  fuzz_bouncer #includes
# bouncer_session.c, so bouncer_session.o is left out of its link.
#
# Needs: clang (18 tested), libclang-rt-18-dev, flex, bison, autoconf,
# automake, librocksdb-dev libzstd-dev libcurl4-openssl-dev libjansson-dev
# libssl-dev libgit2-dev libmaxminddb-dev libgeoip-dev.
set -euo pipefail

VARIANT=${1:-fuzz}
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
BUILD=${2:-${BUILD_DIR:-$HOME/fz}}
SRC=$BUILD/src-$VARIANT
OUT=$BUILD/out-$VARIANT
JOBS=$(nproc)
# FUZZ_DEFS=-DFUZZ_UNMASK_KNOWN removes the harness masks for known findings
# (asan variant: always unmasked, it is the one that confirms them).
FUZZ_DEFS=${FUZZ_DEFS:-}
[ "$VARIANT" = asan ] && FUZZ_DEFS=-DFUZZ_UNMASK_KNOWN
# The cov build runs masked (like fuzz) so a corpus replays to the end.

NOALIGN=-fno-sanitize=alignment
[ -n "${KEEP_ALIGN:-}" ] && NOALIGN=
case $VARIANT in
  fuzz)
    SAN="-fsanitize=address,undefined -fno-sanitize-recover=undefined -fno-sanitize=function $NOALIGN"
    CFLAGS="-g -O1 -fsanitize=fuzzer-no-link $SAN -fno-omit-frame-pointer"
    DRIVER="-fsanitize=fuzzer"
    ;;
  asan)
    SAN="-fsanitize=address,undefined -fno-sanitize-recover=undefined -fno-sanitize=function $NOALIGN"
    CFLAGS="-g -O0 $SAN -fno-omit-frame-pointer"
    DRIVER="$HERE/repro_main.c"
    ;;
  cov)
    SAN=""
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping"
    DRIVER="$HERE/repro_main.c -fprofile-instr-generate"
    ;;
  *) echo "usage: $0 [fuzz|asan|cov] [BUILD_DIR]" >&2; exit 2 ;;
esac

if [ ! -x "$SRC/ircd/ircd" ] || [ -n "${REBUILD:-}" ]; then
  rm -rf "$SRC"; mkdir -p "$SRC"
  (cd "$REPO" && git archive HEAD) | tar -x -C "$SRC"
  cd "$SRC"
  autoreconf -fi >/dev/null 2>&1
  CC=clang CFLAGS="$CFLAGS" LDFLAGS="$SAN" ./configure --enable-debug \
    --with-maxcon=4096 --with-rocksdb=/usr --with-zstd=/usr \
    --enable-keycloak > configure.log 2>&1
  # Only the daemon: the in-tree cmocka/test helpers do not link with
  # sanitizer CFLAGS and are not needed here.
  make -C ircd -j"$JOBS" ircd > make.log 2>&1 || { tail -30 make.log; exit 1; }
fi

cd "$SRC/ircd"
OBJS=$(make -s -f Makefile -f - print-objs <<'MK'
print-objs: ; @echo $(OBJS) version.o
MK
)
LIBS=$(make -s -f Makefile -f - print-libs <<'MK'
print-libs: ; @echo $(LIBS)
MK
)
if [ "$VARIANT" = fuzz ] && [ -z "${FUZZ_DEFS:-}" ]; then
  # Rebuild objects holding known UB findings without that one check so the
  # fuzzer gets past them (FINDINGS.md):
  #   F6   conf expr rules overflow int          (y.tab.c)
  #   F11  presence_norm_time shift overflow     (chathistory_presence.c)
  for ov in y.tab:signed-integer-overflow chathistory_presence:shift; do
    o=${ov%%:*}; chk=${ov##*:}
    clang $CFLAGS -fno-sanitize=$chk -I. -I$SRC -I$SRC/include \
      -c $o.c -o "$OUT/$o.o"
    OBJS=$(echo "$OBJS" | tr ' ' '\n' | sed "s|^$o\.o\$|$OUT/$o.o|" | tr '\n' ' ')
  done
fi
OBJS_NOMAIN=$(echo "$OBJS" | tr ' ' '\n' | grep -v '^ircd\.o$' | tr '\n' ' ')
OBJS_NOBOUNCE=$(echo "$OBJS_NOMAIN" | tr ' ' '\n' | grep -v '^bouncer_session\.o$' | tr '\n' ' ')

mkdir -p "$OUT"
INC="-I$SRC -I$SRC/include -I$SRC/ircd -I$HERE -DHAVE_CONFIG_H"
mkdir -p "$OUT"
clang $CFLAGS $INC -Dmain=ircd_main -c ircd.c -o "$OUT/ircd_nomain.o"
clang $CFLAGS $INC $FUZZ_DEFS -c "$HERE/fuzz_common.c" -o "$OUT/fuzz_common.o"

WRAP="-Wl,--wrap=fbopen -Wl,--wrap=dnsbl_add_server -Wl,--wrap=init_lexer_file -Wl,--wrap=yyerror -Wl,--wrap=add_listener"
for h in conf feature bouncer records; do
  objs=$OBJS_NOMAIN
  hwrap=
  src=$HERE/fuzz_$h.c
  defs=$FUZZ_DEFS
  case $h in
    bouncer) objs=$OBJS_NOBOUNCE; hwrap=-Wl,--wrap=db_iter_value ;;
    records) objs=$OBJS_NOBOUNCE; hwrap=-Wl,--wrap=db_iter_value
             src=$HERE/fuzz_bouncer.c; defs="$defs -DFUZZ_RECORDS" ;;
  esac
  clang $CFLAGS $INC $defs -c "$src" -o "$OUT/fuzz_$h.o"
  clang $CFLAGS $DRIVER $WRAP $hwrap -o "$OUT/fuzz_$h" "$OUT/fuzz_$h.o" \
    "$OUT/fuzz_common.o" "$OUT/ircd_nomain.o" $objs $LIBS -lstdc++
  echo "built $OUT/fuzz_$h"
done

clang -g $INC "$HERE/gen_bouncer_seeds.c" -o "$OUT/gen_bouncer_seeds" -lzstd
echo "built $OUT/gen_bouncer_seeds"
