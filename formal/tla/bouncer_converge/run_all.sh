#!/bin/sh
# Run every config under clean/ and repro/; print one result line per config.
cd "$(dirname "$0")"
for c in clean/*.cfg repro/*.cfg; do
  out=$(java -XX:+UseParallelGC -cp /opt/tla/tla2tools.jar tlc2.TLC -workers 4 \
        -deadlock -noGenerateSpecTE -config "$c" BouncerConverge 2>&1)
  res=$(echo "$out" | grep -oE "Invariant [A-Za-z]+ is violated|Temporal properties were violated|No error has been found" | head -1)
  st=$(echo "$out" | grep -oE "[0-9,]+ distinct states found" | tail -1)
  dp=$(echo "$out" | grep -oE "depth of the complete state graph search is [0-9]+" | grep -oE "[0-9]+$")
  printf '%-40s %-40s %s, depth %s\n' "$c" "$res" "$st" "$dp"
done
