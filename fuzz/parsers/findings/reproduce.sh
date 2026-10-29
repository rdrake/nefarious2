#!/bin/bash
# reproduce.sh - replay every reproducer in this directory through the
# plain ASan/UBSan build (out/repro_<target>, no libFuzzer) with the
# known-bug guards switched off, and check each still shows its signature.
#   ./findings/reproduce.sh            all
#   ./findings/reproduce.sh F14        one (prefix match)
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=$HERE/../out
export FUZZ_STRICT=1 FUZZ_WS_KNOWN_HANG=1 FUZZ_WS_STRICT_FRAG=1 FUZZ_WH_STRICT=1
export ASAN_OPTIONS=detect_leaks=0 UBSAN_OPTIONS=print_stacktrace=1
pass=0 fail=0
# file | target | expected substring in the output ("TIMEOUT" = must hang)
#      [| nostrict: replay with the guards on, so only this bug fires]
while IFS='|' read -r f t sig mode; do
  [ -z "$f" ] && continue
  case "$f" in \#*) continue;; esac
  [ -n "$1" ] && case "$f" in "$1"*) ;; *) continue;; esac
  if [ "$mode" = nostrict ]; then
    out=$(env -u FUZZ_STRICT timeout 10 "$OUT/repro_$t" "$HERE/$f" 2>&1); rc=$?
  else
    out=$(timeout 10 "$OUT/repro_$t" "$HERE/$f" 2>&1); rc=$?
  fi
  if [ "$sig" = TIMEOUT ]; then
    [ $rc -eq 124 ] && ok=1 || ok=0
  else
    case "$out" in *"$sig"*) ok=1;; *) ok=0;; esac
  fi
  if [ $ok = 1 ]; then pass=$((pass+1)); echo "ok    $f"; else fail=$((fail+1)); echo "FAIL  $f (rc $rc)"; echo "$out" | tail -5; fi
done <<'LIST'
F01-websocket-subprotocol-hang.bin|websocket|TIMEOUT
F02-websocket-frag-nul-overflow.bin|websocket|heap-buffer-overflow
F03-webhook-4096-byte-request.bin|kc_webhook|harness oracle
F04a-base64toip-overwrite.bin|ircd_string|stack-buffer-overflow
F04b-base64toip-overread.bin|ircd_string|heap-buffer-overflow
F05-iptobase64-index8.bin|ircd_string|stack-buffer-overflow
F06-iptobase64-wrong-address.bin|ircd_string|CHECK failed: memcmp(&a, &b, 16) == 0
F07-parseinterval-overflow.bin|ircd_string|signed integer overflow
F08-iptobase64-shift-ub.bin|ircd_string|left shift of|nostrict
F09-ircd_ntoa_r-wrong-address.bin|ircd_string|CHECK failed: irc_in_addr_cmp(&a, &c) == 0
F10-matchexec-underread.bin|match|heap-buffer-overflow
F11-mmatch-empty-mask.bin|match|heap-buffer-overflow
F12-match-trailing-backslash.bin|match|heap-buffer-overflow
F13-mmatch-backslash-unsound.bin|match|CHECK failed: match(A, ib) == 0
F14-history-pipe-nick-field-shift.bin|history|round trip mismatch
F15-history-iso-to-unix-overflow.bin|history|signed integer overflow
F16-ch_base64_decode-underflow.bin|chathistory|heap-buffer-overflow
F17-webpush-expired-overflow.bin|webpush_expiry|signed integer overflow
F18a-webpush-ssrf-hex-ip.bin|webpush|internal endpoint accepted
F18b-webpush-ssrf-userinfo.bin|webpush|internal endpoint accepted
F19-webpush-vapid-json-injection.bin|webpush|CHECK failed
F20-bouncer-record-kcid-overread.bin|bouncer_record|heap-buffer-overflow
F21-bouncer-record-time-overflow.bin|bouncer_record|signed integer overflow
F22-crule-arglist-overflow.bin|crule|heap-buffer-overflow
F23-crule-empty-operand.bin|crule|null pointer
F24-parse_server-prefix-only-overread.bin|parse|heap-buffer-overflow
F25a-dns-truncated-A-rdata.bin|dns|heap-buffer-overflow
F25b-dns-truncated-AAAA-rdata.bin|dns|heap-buffer-overflow
F26-reslib-bitstring-shift.bin|dns|left shift of
F27-reslib-labellen-overread.bin|dns|heap-buffer-overflow
F28-parse_server-numeric-000.bin|parse|null pointer
LIST
echo "$pass reproduced, $fail failed"
[ $fail -eq 0 ]
