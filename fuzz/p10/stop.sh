#!/bin/bash
# Stop a running campaign started by run.sh (fuzzer, its children, sweeper).
for p in $(pgrep -x fuzz_p10) $(pgrep -f 'sweep\.sh /dev/shm'); do
  [ "$p" != "$$" ] && kill "$p" 2>/dev/null
done
exit 0
