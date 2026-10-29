#!/bin/sh
# Differential check of the strtoull model against glibc (gcc required).
cd "$(dirname "$0")"
out=${TMPDIR:-/tmp}/strtoull_model_check.$$
gcc -Wall -o "$out" strtoull_model_check.c && "$out"; rc=$?
rm -f "$out"
exit $rc
