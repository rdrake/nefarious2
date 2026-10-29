# CBMC: ircd/account_id.c

Real `account_id.c` and the real `webpush_b64url_encode`
(`ircd/webpush_keyring.c`) `#include`d unmodified. Run `./run.sh`.

| Harness | Property | Bound | Result |
|---|---|---|---|
| `harness_valid_contract` | `account_id_valid(s)` == (strlen 22 and every byte in `[A-Za-z0-9_-]`), any byte values incl. >= 0x80; NULL -> 0 | len <= 24 | VERIFIED |
| `harness_from_uuid_arbitrary` | memory safety on arbitrary input; on 0 `out` untouched; on 1 `out` is a valid id | len <= 40 (covers the 32/36-char success paths) | VERIFIED |
| `harness_from_uuid_roundtrip` | for EVERY 128-bit value in canonical 8-4-4-4-12 form with per-digit arbitrary case: returns 1, valid id, and an independent base64url decoder recovers exactly the 16 bytes with zero pad bits (so the map is injective and canonical) | all 2^128 values | VERIFIED |
| `harness_from_uuid_hyphen_positions` | header: only canonical or hyphen-free forms accepted | 36-char inputs, 4 hyphens anywhere | **FAILS** (informational) |

`--conversion-check` is off for the functional harnesses: it only flags
the idiomatic `(unsigned char)*p`.

## Finding (informational, confirmed)

Hyphens are skipped anywhere (account_id.c:37-38), so e.g.
`"----aaaaaaaa...(32 hex)"` or `"a-a-a-..."` is accepted, contrary to the
header's "canonical 8-4-4-4-12 form, or the 32 hex digits without
hyphens". Because hyphens carry no bits the compact id is still the
correct 128-bit value (round-trip harness), so no two distinct UUIDs
collide; the only effect is lax input validation on Keycloak `sub` /
user ids (sasl_auth.c:926, :1149, :1350, :1464, :1689, :2021;
webhook_subject.c:64). Fix if strictness is wanted: accept hyphens only
at offsets 8/13/18/23 when the length is 36.
