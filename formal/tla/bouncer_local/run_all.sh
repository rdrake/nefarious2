#!/bin/sh
# Run every configuration in this directory and summarise the outcome.
# Usage: ./run_all.sh [cfg ...]     (default: all *.cfg)
cd "$(dirname "$0")"
JAR=${TLA_JAR:-/opt/tla/tla2tools.jar}
for cfg in ${@:-*.cfg}; do
  printf '%-26s ' "$cfg"
  java -XX:+UseParallelGC -cp "$JAR" tlc2.TLC -workers 4 -deadlock \
       -noGenerateSpecTE -config "$cfg" BouncerLocal.tla > "${cfg%.cfg}.out" 2>&1
  grep -hE 'is violated|were violated|was violated|No error has been found' "${cfg%.cfg}.out" | head -1 | tr '\n' ' '
  grep -hE 'distinct states found' "${cfg%.cfg}.out" | tail -1 | sed 's/.*generated, //'
done
rm -rf states
