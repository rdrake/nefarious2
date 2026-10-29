#!/usr/bin/env bash
# fuzz/client/build.sh -- build the client-protocol fuzz harness.
#
#   fuzz/client/build.sh [fuzz|ubsan|plain|cov] ...   (default: fuzz)
#
# Variants (each in its own copy of the source tree under $OUT/<variant>):
#   fuzz   libFuzzer + ASan + UBSan (no recover)          -> out/fuzz_client
#   ubsan  libFuzzer + UBSan + -fsanitize=integer (minus
#          unsigned-integer-overflow), no ASan             -> out/fuzz_client_ubsan
#   plain  ASan only, NO libFuzzer, NO freelist patch, the
#          replay_main.c driver: confirms a crash outside
#          the fuzz configuration                         -> out/fuzz_client_plain
#   cov    libFuzzer + -fprofile-instr-generate
#          -fcoverage-mapping for llvm-cov reports         -> out/fuzz_client_cov
#
# The ircd sources are never modified in place: the tree is copied (git
# archive of HEAD plus any uncommitted ircd/include changes), the fuzz-only
# freelist patch is applied to the copy (fuzz/ubsan/cov variants), and
# ircd.o's main() is renamed with objcopy so libFuzzer's main can link.
#
# Requirements (Debian/Ubuntu): clang-18 libclang-rt-18-dev librocksdb-dev
#   libzstd-dev libcurl4-openssl-dev libjansson-dev libssl-dev libgit2-dev
#   libmaxminddb-dev flex bison autoconf automake
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$(cd "$HERE/../.." && pwd)"
OUT="${OUT:-$HERE/out}"
CC="${CC:-clang}"
JOBS="${JOBS:-$(nproc)}"
mkdir -p "$OUT"

WRAPS="-Wl,--wrap=os_get_peername -Wl,--wrap=os_get_sockname \
-Wl,--wrap=kc_http_request -Wl,--wrap=kc_http_sync_perform \
-Wl,--wrap=kc_user_verify_password -Wl,--wrap=kc_token_ensure \
-Wl,--wrap=kc_jwt_prime_cache"

build_variant() {
  local v="$1" cflags ldflags patch=1 driver="" bin
  case "$v" in
    fuzz)
      cflags="-g -O1 -fsanitize=fuzzer-no-link,address,undefined -fno-sanitize-recover=undefined -fno-sanitize=function -fno-omit-frame-pointer"
      ldflags="-fsanitize=fuzzer,address,undefined"
      bin=fuzz_client ;;
    ubsan)
      cflags="-g -O1 -fsanitize=fuzzer-no-link,undefined,integer -fno-sanitize=unsigned-integer-overflow,unsigned-shift-base,implicit-conversion,function -fno-sanitize-recover=all -fno-omit-frame-pointer"
      ldflags="-fsanitize=fuzzer,undefined,integer"
      bin=fuzz_client_ubsan ;;
    plain)
      cflags="-g -O1 -fsanitize=address -fno-omit-frame-pointer"
      ldflags="-fsanitize=address"
      patch=0
      driver="$HERE/replay_main.c"
      bin=fuzz_client_plain ;;
    cov)
      cflags="-g -O1 -fsanitize=fuzzer-no-link -fprofile-instr-generate -fcoverage-mapping"
      ldflags="-fsanitize=fuzzer,fuzzer-no-link -fprofile-instr-generate -fcoverage-mapping"
      bin=fuzz_client_cov ;;
    *) echo "unknown variant $v" >&2; exit 1 ;;
  esac

  local B="$OUT/build-$v"
  if [ "${FAST:-0}" = 1 ] && [ -f "$B/ircd/Makefile" ]; then
    echo "=== [$v] FAST=1: reusing $B (harness relink only)"
  else
  echo "=== [$v] preparing source tree in $B"
  rm -rf "$B"
  mkdir -p "$B"
  (cd "$SRC" && git archive HEAD | tar -x -C "$B")
  # carry uncommitted ircd/include edits too (fuzzing a working tree)
  (cd "$SRC" && git diff HEAD -- ircd include configure.in) | (cd "$B" && patch -p1 -s) || true
  if [ "$patch" = 1 ]; then
    (cd "$B" && patch -p1 -s < "$HERE/freelist.patch")
  fi

  echo "=== [$v] configure"
  (cd "$B" && autoreconf -fi >autoreconf.log 2>&1 &&
   CC="$CC" CFLAGS="$cflags" LDFLAGS="$(echo "$ldflags" | sed 's/fuzzer,//')" ./configure \
     --enable-debug --with-maxcon=4096 --with-rocksdb=/usr --with-zstd=/usr \
     --enable-keycloak --prefix="$B/inst" >configure.log 2>&1)
  fi

  echo "=== [$v] make (objects)"
  # Objects only: the stock ircd link needs a main() that libFuzzer replaces.
  local objs
  objs=$(make -s -C "$B/ircd" --no-print-directory \
           --eval='fz-print-objs: ; @echo $(OBJS)' fz-print-objs)
  (cd "$B/ircd" && make -j"$JOBS" $objs version.o >make.log 2>&1) || {
    tail -40 "$B/ircd/make.log"; exit 1; }

  echo "=== [$v] link"
  local libs
  libs=$(make -s -C "$B/ircd" --no-print-directory \
           --eval='fz-print-libs: ; @echo $(LIBS)' fz-print-libs)
  (cd "$B/ircd" &&
   objcopy --redefine-sym main=ircd_main ircd.o ircd_fuzz.o &&
   local_objs=$(echo $objs version.o | sed 's/\bircd\.o\b/ircd_fuzz.o/') &&
   $CC $cflags -I. -I.. -I../include -c "$HERE/fuzz_client.c" -o fuzz_client.o &&
   if [ -n "$driver" ]; then $CC $cflags -c "$driver" -o replay_main.o; fi &&
   $CC $ldflags $WRAPS -o "$OUT/$bin" fuzz_client.o \
     $( [ -n "$driver" ] && echo replay_main.o ) $local_objs $libs -lstdc++)
  cp "$HERE/fuzz.conf.in" "$OUT/fuzz.conf.in"
  echo "=== [$v] built $OUT/$bin"
}

variants=("$@")
[ ${#variants[@]} -eq 0 ] && variants=(fuzz)
for v in "${variants[@]}"; do
  build_variant "$v"
done
