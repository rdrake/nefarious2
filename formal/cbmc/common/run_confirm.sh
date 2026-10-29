#!/bin/sh
# run_confirm.sh <confirm.c> [extra gcc args...]
# Builds a concrete reproduction against the REAL ircd sources with
# -fsanitize=address,undefined and runs it (UBSan reports go to stderr).
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
src=$1; shift
out=${TMPDIR:-/tmp}/cbmc_confirm.$$
echo "--- concrete reproduction: $src"
gcc -g -fsanitize=address,undefined -I "$here" -I "$root/include" "$src" "$@" -o "$out" \
  || { echo "    (build failed)"; exit 1; }
"$out" 2>&1 | sed 's/^/    /'
rm -f "$out"
