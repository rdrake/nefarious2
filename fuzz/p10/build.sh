#!/bin/bash
# Build the P10 server-input fuzzer.
#
#   fuzz/p10/build.sh [fuzz|asan|all]     (default: all)
#
#   fuzz  -> $OUT/fuzz_p10        libFuzzer + ASan + UBSan (coverage-instrumented)
#   ubsan -> $OUT/repro_ubsan_p10 ASan + UBSan (all fatal), standalone driver
#   asan  -> $OUT/repro_p10       plain ASan build (no UBSan), no fuzzer
#                                 instrumentation, standalone driver
#                                 (repro_p10 file...) for confirming crashes
#   cov   -> $OUT/cov_p10         clang source-based coverage build
#                                 (-fprofile-instr-generate -fcoverage-mapping)
#
# The ircd sources are exported from the checkout (HEAD + working-tree
# changes under ircd/ include/) into $BUILD/<mode>/src, configured with the
# fork's normal options (rocksdb, zstd, keycloak, debug => asserts ON),
# and every ircd object except main is linked into the harness.  ircd.c
# is recompiled with -Dmain=ircd_main; no ircd source is modified.
#
# Env: BUILD (default /home/user/fuzzbuild-p10 or $PWD/fuzz/p10/build),
#      OUT (default fuzz/p10/bin), JOBS (default nproc), CC (default clang).
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
BUILD="${BUILD:-$HERE/build}"
OUT="${OUT:-$HERE/bin}"
JOBS="${JOBS:-$(nproc)}"
CC="${CC:-clang}"
MODES="${1:-all}"
[ "$MODES" = all ] && MODES="fuzz asan"

mkdir -p "$OUT"

configure_tree() { # <mode> <cflags> <ldflags>
  local mode="$1" cflags="$2" ldflags="$3"
  local src="$BUILD/$mode/src"
  if [ ! -f "$src/.configured" ] || [ "$(cat "$src/.configured")" != "$cflags" ]; then
    rm -rf "$src"; mkdir -p "$src"
    # Snapshot the tree as it is now (tracked files, incl. uncommitted edits).
    (cd "$REPO" && git ls-files -z | grep -zv '^fuzz/' | xargs -0 tar -cf -) | tar -xf - -C "$src"
    (cd "$src" && autoreconf -fi >autoreconf.log 2>&1)
    (cd "$src" && CC="$CC" CFLAGS="$cflags" LDFLAGS="$ldflags" ./configure \
        --enable-debug --with-maxcon=4096 \
        --with-rocksdb=/usr --with-zstd=/usr --enable-keycloak >configure.log 2>&1) \
      || { echo "configure failed, see $src/configure.log"; exit 1; }
    grep -q '#define USE_ROCKSDB' "$src/config.h" || { echo "USE_ROCKSDB not defined"; exit 1; }
    echo "$cflags" >"$src/.configured"
  else
    # refresh changed sources
    (cd "$REPO" && git ls-files -z ircd include | xargs -0 tar -cf -) | tar -xf - -C "$src"
  fi
  # Build all objects (the ircd target links the real binary too, which is
  # a useful check that the object set is complete).
  make -C "$src/ircd" -j"$JOBS" ircd >"$src/make.log" 2>&1 \
    || { tail -30 "$src/make.log"; echo "make failed, see $src/make.log"; exit 1; }
}

objs_and_libs() { # <src>  -> sets OBJS LIBS
  local src="$1"
  printf 'print-objs:\n\t@echo $(OBJS)\nprint-libs:\n\t@echo $(LIBS)\n' >"$src/ircd/.print.mk"
  OBJS=$(cd "$src/ircd" && make -s -f Makefile -f .print.mk print-objs)
  LIBS=$(cd "$src/ircd" && make -s -f Makefile -f .print.mk print-libs)
  OBJS=$(for o in $OBJS; do [ "$o" = ircd.o ] || echo "$src/ircd/$o"; done)
  OBJS="$OBJS $src/ircd/version.o"
}

link_harness() { # <mode> <cflags> <harness-ldflags> <out> [extra sources]
  local mode="$1" cflags="$2" hld="$3" out="$4"; shift 4
  local src="$BUILD/$mode/src"
  objs_and_libs "$src"
  # ircd.c without its main()
  $CC $cflags -Dmain=ircd_main -I"$src" -I"$src/include" -I"$src/ircd" \
      -c "$src/ircd/ircd.c" -o "$src/ircd/ircd_nomain.o"
  $CC $cflags -I"$src" -I"$src/include" -I"$src/ircd" \
      -c "$HERE/fuzz_p10.c" -o "$src/ircd/fuzz_p10.o"
  local extra_o=""
  for s in "$@"; do
    $CC $cflags -c "$s" -o "$src/ircd/$(basename "$s" .c).o"
    extra_o="$extra_o $src/ircd/$(basename "$s" .c).o"
  done
  # shellcheck disable=SC2086
  $CC $cflags $hld "$src/ircd/fuzz_p10.o" $extra_o "$src/ircd/ircd_nomain.o" $OBJS \
      -Wl,--wrap=os_send_nonb -Wl,--wrap=os_sendv_nonb \
      $LIBS -lstdc++ -o "$out"
  echo "built $out"
}

for m in $MODES; do
  case "$m" in
    fuzz)
      # signed shift / overflow UB is logged but not fatal in the fuzz build so
      # it does not mask deeper bugs (repro_p10 keeps it fatal)
      CF="-g -O1 -fsanitize=fuzzer-no-link,address,undefined -fno-sanitize-recover=undefined -fsanitize-recover=shift,signed-integer-overflow -fno-omit-frame-pointer"
      configure_tree fuzz "$CF" "-fsanitize=address,undefined"
      link_harness fuzz "$CF" "-fsanitize=fuzzer,address,undefined" "$OUT/fuzz_p10"
      ;;
    asan)
      # plain ASan only: shows what a production-like build does (a NULL
      # deref is a SEGV, not a UBSan report); asserts stay on (--enable-debug)
      CF="-g -O1 -fsanitize=address -fno-omit-frame-pointer"
      configure_tree asan "$CF" "-fsanitize=address"
      link_harness asan "$CF" "-fsanitize=address" "$OUT/repro_p10" "$HERE/standalone.c"
      ;;
    ubsan)
      # ASan+UBSan, everything fatal, no fuzzer instrumentation
      CF="-g -O1 -fsanitize=address,undefined -fno-sanitize-recover=undefined -fno-omit-frame-pointer"
      configure_tree ubsan "$CF" "-fsanitize=address,undefined"
      link_harness ubsan "$CF" "-fsanitize=address,undefined" "$OUT/repro_ubsan_p10" "$HERE/standalone.c"
      ;;
    cov)
      CF="-g -O0 -fprofile-instr-generate -fcoverage-mapping"
      configure_tree cov "$CF" "-fprofile-instr-generate"
      link_harness cov "$CF" "-fprofile-instr-generate" "$OUT/cov_p10" "$HERE/standalone.c"
      ;;
    *) echo "unknown mode $m"; exit 1;;
  esac
done
