MARKREAD with a target byte >= 0x80 on the in-memory session path:
sm_hash() does ToLower((unsigned char)*p), overreading the 256-entry
ToLowerTab_8859_1 (ToLower expects a plain signed char). Documented audit
class (skill: 80c93e2) -- this session-path site was missed.
base64: M01BUktSRUFEIP8=
printable: mode byte 0x33, line 'MARKREAD \xff'
