#!/bin/sh
# usage: run.sh <cfg> [trace.json]  -- runs TLC on BouncerConverge with <cfg>
cfg=$1; shift
out=${1:-/dev/null}
java -XX:+UseParallelGC -cp /opt/tla/tla2tools.jar tlc2.TLC -workers 4 -deadlock -noGenerateSpecTE \
  -config "$cfg" -dumpTrace json "$out" BouncerConverge 2>&1 | grep -v JAVA_TOOL
