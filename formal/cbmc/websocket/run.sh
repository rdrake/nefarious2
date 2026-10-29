#!/bin/sh
# CBMC proofs for the pure parsers in ircd/websocket.c.  See README.md.
# Also builds and runs the concrete hang reproduction (needs gcc + libssl).
cd "$(dirname "$0")"
R=../common/run_harness.sh
H=websocket_harness.c
fail=0
$R $H harness_decode_frame 14 -DFMAX=12 -DPMAX=8 || fail=1
$R $H harness_decode_control_fin 14 -DFMAX=8 -DPMAX=4 || fail=1
$R $H harness_decode_len64 16 || fail=1
$R $H harness_encode_bounds 12 -DPMAX=8 || fail=1
# string-library loops over a ~50-byte request need a larger bound
$R $H harness_handshake_terminates 70 -DHVAL=3 || fail=1
out=${TMPDIR:-/tmp}/ws_hang_repro.$$
if gcc -g -fsanitize=address,undefined -I ../common -I ../../../include \
     confirm_subproto_hang.c -lssl -lcrypto -o "$out" 2>/dev/null; then
  for p in text.ircv3.net chat; do "$out" "$p"; done
  rm -f "$out"
fi
exit $fail
