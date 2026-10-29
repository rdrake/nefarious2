#!/bin/bash
# Remove harness store dirs (p10fuzz.<pid>.XXXXXX) whose process is gone.
#   fuzz/p10/sweep.sh <dir> [interval]   (interval > 0: loop forever)
DIR="${1:?dir}"; INT="${2:-0}"
while :; do
  for d in "$DIR"/p10fuzz.*.*; do
    [ -d "$d" ] || continue
    pid=$(basename "$d" | cut -d. -f2)
    [ -d "/proc/$pid" ] || rm -rf "$d"
  done
  [ "$INT" -gt 0 ] || exit 0
  sleep "$INT"
done
