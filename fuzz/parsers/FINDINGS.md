# Parser fuzzing campaign — findings

Branch `fuzz/parsers`, base `ircv3.2-upgrade` @ `ca213aa`.  Every harness,
stub and script is under `fuzz/parsers/`; no ircd source was modified.

* Build: `./build.sh` (clang 18, `-g -O1 -fsanitize=fuzzer,address,undefined
  -fno-sanitize-recover=undefined`); each target also gets a plain
  ASan/UBSan `out/repro_<t>` binary (no libFuzzer) for triage.
* Run: `./run.sh campaign 4 schedule.txt` (one fuzzer per core, fork mode,
  rotates through the schedule); `./minimize.sh` merges the working corpus
  back into `<t>/corpus`; `./coverage.sh` gives source line coverage.
* Reproduce: `./findings/reproduce.sh` replays every reproducer below
  through the plain ASan build with the known-bug guards off and checks its
  signature (25/25 at the time of writing).

Each harness steps around the bugs already reported here so the campaign
could keep looking past them; `FUZZ_STRICT=1` (and, for the WebSocket and
webhook harnesses, `FUZZ_WS_KNOWN_HANG=1`, `FUZZ_WS_STRICT_FRAG=1`,
`FUZZ_WH_STRICT=1`) turns the guards off.  The guards are listed in each
harness's header comment.

Severity is for this codebase as deployed (single-threaded ircd, P10 peers
trusted-but-not-blindly, config operator-controlled).

| ID | Severity | Where | What | Who controls the input |
|----|----------|-------|------|------------------------|
| F01 | **High** | `ircd/websocket.c:188` | infinite loop in `parse_ws_handshake` | any client on a WebSocket port, before registration |
| F14 | **High** | `ircd/history.c:399` / `:462` | `|` in a nick shifts the stored history fields: account spoofing on replay | any client (nick change) |
| F03 | Medium | `ircd/kc/kc_webhook.c:563` | webhook requests whose first read fills 4096 bytes are refused 400 | Keycloak (large events are lost) |
| F16 | Medium | `ircd/m_chathistory.c:4356-4360` | `ch_base64_decode` length goes negative, NUL written before the buffer | a linked server (CH Z / CH B / CH WB) |
| F18 | Medium | `ircd/m_webpush.c:123` | push endpoint SSRF check is a substring denylist | any logged-in client (WEBPUSH REGISTER) |
| F19 | Medium | `ircd/webpush.c:825` | push endpoint pasted unescaped into the VAPID JWT the server signs | any logged-in client |
| F04 | Medium (inherited) | `ircd/numnicks.c:547-555` | `base64toip` reads past / writes far past the address | a linked server (NICK IP) |
| F06 | Low-Medium (inherited) | `ircd/numnicks.c:502` | `iptobase64` encodes some IPv6 addresses as a different address | the client's own address |
| F09 | Low-Medium (inherited) | `ircd/ircd_string.c:893` | `ircd_ntoa_r` prints some IPv6 addresses as a different address | the client's own address |
| F02 | Low | `ircd/s_bsd.c:1461` | WebSocket reassembly writes one byte past `con_ws_frag_buf` | any WebSocket client |
| F10 | Low (inherited) | `ircd/match.c:513` | `matchexec` reads before the subject string | WHO masks, G-lines |
| F11 | Low (inherited) | `ircd/match.c:91-93` | `mmatch` reads `old_mask[-1]` for an empty mask | ban / silence / gline masks |
| F12 | Low (inherited) | `ircd/match.c:210` | `match` steps past both NULs on a dangling `\` | any wildcard mask |
| F13 | Low (inherited) | `ircd/match.c:67-170` | `mmatch` says A covers B when it does not (escapes) | chanop ban masks |
| F05 | Low (inherited) | `ircd/numnicks.c:494` | `iptobase64` reads `in6_16[8]` | the client's own address |
| F08 | Low (inherited) | `ircd/numnicks.c:479,484,486` | signed shift overflow for every IPv4 >= 128.0.0.0 | every client |
| F07 | Low (inherited) | `ircd/ircd_string.c:1183,1185` | `ParseInterval` signed overflow | opers (GLINE/SHUN/ZLINE/JUPE) |
| F15 | Low | `ircd/history.c:951,955` | `history_iso_to_unix` signed overflow | linked server / X3 (CH refs) |
| F17 | Low | `ircd/webpush_expiry.c:56` | `armed + max_age` overflow | corrupt stored record |
| F20 | Low | `ircd/bouncer_session.c:3114,3591` | unterminated `bsr_kc_id` read past the record | corrupt stored record |
| F21 | Low | `ircd/bouncer_session.c:3529` | `CurrentTime - disconnect_time` overflow | corrupt stored record |
| F22 | Low (inherited) | `ircd/crule.c:742` | CRULE argument list overflows `arg[3]` (heap write) | ircd.conf / linesync |
| F23 | Low (inherited) | `ircd/crule.c:767` / `:548-569` | CRULE `&&` with a missing operand: NULL / uninitialized child freed | ircd.conf / linesync |
| F24 | Low (inherited) | `ircd/parse.c:2103` | `parse_server` reads up to 2 bytes past a prefix-only line | a linked server |

"Inherited" = the same code is in upstream ircu; it is reachable here all
the same.  Informational notes (behaviour differences, latent hazards,
discarded harness artifacts) follow the findings.

---

## F01 — WebSocket handshake: infinite loop on an unsupported subprotocol (High)

**Reproducer** `findings/F01-websocket-subprotocol-hang.bin` (target
`websocket`, mode 0 = handshake, run with `FUZZ_WS_KNOWN_HANG=1`):

```
b64: AEAAR0VUIC8gSFRUUC8xLjENClVwZ3JhZGU6IHdlYnNvY2tldA0KQ29ubmVjdGlvbjogVXBncmFkZQ0KU2VjLVdlYlNvY2tldC1LZXk6IGRHaGxJSE5oYlhCc1pTQnViMjVqWlE9PQ0KU2VjLVdlYlNvY2tldC1WZXJzaW9uOiAxMw0KU2VjLVdlYlNvY2tldC1Qcm90b2NvbDogY2hhdA0KDQo=
txt: \x00@\x00GET / HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: chat\r\n\r\n
```

The HTTP request alone (without the 3-byte harness header) is the attack:
any upgrade request whose first `Sec-WebSocket-Protocol:` line offers no
`text.ircv3.net` / `binary.ircv3.net` token.

**Stack** (sampled while spinning):
```
#0 parse_ws_handshake        ircd/websocket.c:191
#1 websocket_handshake       ircd/websocket.c:374
#2 websocket_handshake_feed  ircd/websocket.c:542
   (read_packet, ircd/s_bsd.c:1303)
```

**Root cause** `ircd/websocket.c:188-207`: the token scan's inner loop stops
at `'\r'` (`*e != '\r'`), but the outer loop only skips spaces, tabs and
commas and only ends on NUL or a match.  Once `p` reaches the line's `\r`
with no supported token seen, `e == p`, `n == 0`, `p = e` — forever.

**Reachability** `read_packet()` feeds every byte from a WebSocket listener
(and from a `paste = yes; websocket = yes` port via
`paste_promote_to_client`) to `websocket_handshake_feed` before the client
has registered, authenticated or passed any check but the listener's.  One
TCP connection with one request hangs the single-threaded ircd: all
clients and server links time out.  Any client library that offers its own
subprotocol name (`Sec-WebSocket-Protocol: irc`, `chat`, …) triggers it by
accident.

**Fix** stop the scan at the end of the header line, e.g.
`while (p < end && *p != '\r' && *subproto == WS_SUBPROTO_NONE)`, or
advance `p` past the delimiter when `n == 0` (`if (e == p) break;`).  A
regression test: the cmocka `build_request` with
`Sec-WebSocket-Protocol: chat`.

## F14 — chathistory: `|` in a nick shifts the stored fields (High)

**Reproducer** `findings/F14-history-pipe-nick-field-shift.bin` (target
`history`, mode 1 = store then query):

```
b64: AQBhfGFkbWlufGIhdXNlckBob3N0AHJlYWxhY2N0AHNwb29mPwAA
txt: \x01\x00a|admin|b!user@host\x00realacct\x00spoof?\x00\x00
```
i.e. `history_store_message(..., sender="a|admin|b!user@host",
account="realacct", content="spoof?")` followed by `history_query_latest`
returns

```
 sender  [a|admin|b!user@host] -> [a]
 account [realacct] -> [admin]
 content [spoof?] -> [b!user@host|realacct|spoof?]
```

**Root cause** `serialize_message()` (`ircd/history.c:399`) writes
`"%d|%s|%s|..."` with the sender and account unescaped;
`deserialize_message()` (`ircd/history.c:462-484`) splits on the first two
`|`.  `history_escape_field` escapes only 0x04-0x07.  `|` is a valid nick
character (`table_gen.c:77` marks `{|}~` as lowercase letters, so
`NTL_IRCNK` includes it), and nicks like `foo|away` are common.

**Reachability** every PRIVMSG/NOTICE/TAGMSG/JOIN/... stored by
`ircd_relay.c:268-277`, `ircd_relay.c:431-438`, `channel.c:166` builds the
sender as `nick!user@host` from the live client.  An unauthenticated user
picks the nick `a|admin|b` (length 9 < NICKLEN 30), speaks in a channel,
and every CHATHISTORY replay shows the line from `a` with
`account=admin` (`m_chathistory.c:761` emits `account=%s` from
`msg->account`) and the real account glued into the text.  Clients that
display account names (or trust `account-tag` for identity, as many
IRCv3 clients do) show the message as coming from the `admin` account.
Every row stored by a `|`-nick is also mangled (sender and text) — data
loss for ordinary users, and the record is also what CH Z federation
ships to peers.

**Fix** escape `|` in the sender and account fields (e.g. extend
`history_field_needs_escape` to the header fields, or length-prefix them),
or split from the right for the account (accounts cannot contain `|`) and
validate that the sender has the `nick!user@host` shape.  Existing rows
written by `|`-nicks can be recognized (sender without `!`) and dropped.

## F03 — webhook listener refuses any request whose first read fills its buffer (Medium)

**Reproducer** `findings/F03-webhook-4096-byte-request.bin` (target
`kc_webhook`, mode 1 = correctly signed POST, run with `FUZZ_WH_STRICT=1`):
a valid, correctly signed `POST /keycloak-webhook` whose total size is
4329 bytes is answered `HTTP/1.1 400 Bad Request`.  (The file is the
harness input: mode byte, flag byte, then the JSON body; the harness adds
the request line, `Content-Length` and a valid `X-Webhook-Signature`.)

**Root cause** `parse_http_headers()` (`ircd/kc/kc_webhook.c:563`) returns
-1 (`400`) when `buf_used >= buf_size`, before looking for the end of the
headers.  `conn_readable()` grows the buffer only when the new bytes would
*exceed* it (`buf_used + nbytes > buf_size`), so a `recv()` that fills the
initial 4096-byte buffer exactly leaves no room for the NUL the parser
wants and is refused — even though the headers are complete.  `recv()`
returns the full 4096 whenever that much of the request is already
buffered, which is the normal case for a request of 4096 bytes or more on
a local or fast link (the harness drives the real `conn_readable()` over a
socketpair).

**Reachability** the listener is the Keycloak SPI's delivery endpoint.
Admin events that carry a full user representation (attributes, required
actions, credentials metadata) easily exceed 4 KB.  Every such delivery is
refused and the SPI's retries are refused the same way, so a `DELETE` /
disable / credential-removal event never deauths the user or purges the
SASL caches (`sasl_webhook.c` never sees it).  This is a revocation
failure, not a crash.

**Fix** grow the buffer when `buf_used + nbytes >= buf_size` (room for the
NUL), or keep the buffer one byte larger than the reads it accepts.

## F16 — `ch_base64_decode`: negative length, NUL written before the buffer (Medium)

**Reproducer** `findings/F16-ch_base64_decode-underflow.bin` (target
`chathistory`): `b64: AD09PT09PT09PT09PT09PT0=`, `txt: \x00================`
(16 `=`).

```
==ERROR: AddressSanitizer: heap-buffer-overflow  WRITE of size 1
#0 ch_base64_decode ircd/m_chathistory.c:4360
```

**Root cause** `ircd/m_chathistory.c:4341-4364`: `EVP_DecodeBlock` returns
3 bytes per 4-character block (padding included); the loop then subtracts
one per trailing `=` — four per `====` block — so `decoded_len` goes
negative (−k for k blocks) and `decoded[decoded_len] = '\0'` writes k
bytes before the allocation; `*outlen` becomes `(size_t)-k` and the caller
(`history_deserialize_record`, `add_fed_message`) is handed a huge length.

**Reachability** S2S only: the payloads of `CH Z` (`m_chathistory.c:6850`),
`CH B` and `CH WB` chunk reassembly (`:6947`, `:7315`) from a linked
server answering a federated chathistory request.  A compromised or buggy
peer can corrupt the heap of every server that federates with it.

**Fix** count padding only in the last block and at most two, and reject
`decoded_len < 0`; or decode with `EVP_DecodeUpdate`/`EVP_DecodeFinal`,
which report the exact length.

## F18 — WebPush endpoint SSRF check is a substring denylist (Medium)

**Reproducers** `findings/F18a-webpush-ssrf-hex-ip.bin`,
`findings/F18b-webpush-ssrf-userinfo.bin` (target `webpush`, mode 0 =
WEBPUSH REGISTER):

```
F18a b64: AGh0dHBzOi8vMHg3ZjAwMDAwMS94AHAyNTZkaD1CQUVDQXdRRkJnY0lDUW9MREEwT0R4QVJFaE1VRlJZWEdCa2FHeHdkSGg4Z0lTSWpKQ1VtSnlncEtpc3NMUzR2TURFeU16UTFOamM0T1RvN1BEMC1QMEE7YXV0aD1BQUFBQUFBQUFBQUFBQUFBQUFBQUFB
     txt: \x00https://0x7f000001/x\x00p256dh=<65-byte key>;auth=AAAAAAAAAAAAAAAAAAAAAA
F18b txt: \x00https://user@127.0.0.1/\x00p256dh=a;auth=b
```
`internal endpoint accepted: https://0x7f000001/x (host 0x7f000001)` /
`... https://user@127.0.0.1/ (host 127.0.0.1)`.

**Root cause** `is_valid_endpoint()` (`ircd/m_webpush.c:123-152`) rejects
private addresses with `strstr(endpoint, "://127.")` etc.  Any other
spelling of the same address passes: userinfo (`https://x@127.0.0.1/`),
numeric forms curl accepts (`https://2130706433/`, `https://0x7f000001/`,
`https://0177.0.0.1/`), upper case (`https://LOCALHOST/`), IPv4-mapped
IPv6 (`https://[::ffff:127.0.0.1]/`), `169.254.169.254` (cloud metadata)
and `100.64/10` are not listed at all, and any DNS name resolving to an
internal address passes by construction.  (`"://172.2"` also blocks public
addresses like 172.200.x.)

**Reachability** a logged-in client registers the endpoint with `WEBPUSH
REGISTER`; the ircd then POSTs an encrypted push there through libkc/curl
(`webpush_send_async`) on every highlight/PM.  Blind SSRF from the ircd's
network position (internal HTTP services, metadata endpoints).

**Fix** check the address curl actually connects to, not the URL text:
`CURLOPT_OPENSOCKETFUNCTION` / `CURLOPT_PREREQFUNCTION` (curl >= 7.80) to
refuse loopback, private, link-local, CGNAT and metadata ranges after
resolution; or resolve first and pin with `CURLOPT_RESOLVE`.  Optionally
restrict endpoints to an allow-list of push-service domains.

## F19 — VAPID JWT: endpoint text injected into the signed claims (Medium)

**Reproducer** `findings/F19-webpush-vapid-json-injection.bin` (target
`webpush`, mode 0):

```
b64: AGh0dHBzOi8vZXZpbC5leGFtcGxlPyIsImF1ZCI6Imh0dHBzOlx1MDAyZlx1MDAyZmZjbS5nb29nbGVhcGlzLmNvbQBwMjU2ZGg9YTthdXRoPWI=
txt: \x00https://evil.example?","aud":"https:\\u002f\\u002ffcm.googleapis.com\x00p256dh=a;auth=b
```
The ircd signs (ES256, its VAPID key):
```
{"aud":"https://evil.example?","aud":"https://fcm.googleapis.com","exp":...,"sub":"mailto:noreply@afternet.org"}
```

**Root cause** `create_vapid_header()` (`ircd/webpush.c:794-826`) takes the
"origin" as everything up to the first `/` after `://` and formats it into
the payload with `"{\"aud\":\"%s\",...}"` — no JSON escaping and no URL
validation (`is_valid_endpoint` only checks the `https://` prefix).
Quotes and backslashes in the endpoint become JSON structure; `/`
keeps `/` out of the text the origin scan sees.

**Reachability** any logged-in client (WEBPUSH REGISTER), and the push is
delivered to the attacker's own host, which receives the signed JWT in the
`Authorization: vapid t=...` header.  With duplicate-key "last wins" JSON
parsers (jansson, Python's `json`), the token's audience is a push service
the attacker chose, signed with this server's VAPID key, valid 24 h.
Additional claims can be injected the same way.  Impact is bounded by what
a push service lets a VAPID token do (it still needs a subscription
endpoint bound to this key), but the server should never sign
attacker-shaped claims.

**Fix** parse the endpoint with a URL parser, require a plain
`https://host[:port]/` with host characters `[A-Za-z0-9.-]` (or a bracketed
IPv6 literal), and build the payload with `json_object_set_new` +
`json_dumps` (jansson is already linked) instead of `snprintf`.

## F04 — `base64toip`: over-read for short tokens, far over-write for long ones (Medium, inherited)

**Reproducers** (target `ircd_string`, mode 1):
`F04a-base64toip-overwrite.bin` — `txt: \x01\x00_` + 38×`A`
(`b64: AQBfQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE=`),
`F04b-base64toip-overread.bin` — `txt: \x01\x00AB` (`b64: AQBBQg==`).

```
F04a  stack-buffer-overflow WRITE  #0 base64toip ircd/numnicks.c:550
F04b  heap-buffer-overflow  READ   #0 base64toip ircd/numnicks.c:547
```

**Root cause** `base64toip()` (`ircd/numnicks.c:533-560`):
`left = (25 - strlen(input)) / 3 - pos` is computed in `size_t`; for a
token longer than 25 characters containing `_` it wraps to a huge count
and the loop writes zeros far past `addr->in6_16[8]`.  Tokens that are
neither 6 characters nor whole 3-character groups make the decoder read
past the NUL (each non-`_` step consumes three characters unconditionally).

**Reachability** the IP field of a server-introduced `NICK`
(`m_nick.c:524`, `m_nick.c:730`, `s_user.c:1218`), i.e. any linked server
(or a services link).  `irc_in_addr` is on the stack in `m_nick.c` and
inside `struct Client` in `s_user.c`: a malformed NICK from a peer
corrupts memory on every server it reaches.

**Fix** validate the token first: exactly 6 chars, or only base64 groups
of 3 plus at most one `_`, total <= 24, and the zero run computed from the
remaining group count (`left = 8 - pos - remaining_groups`), never from
`strlen`.

## F06 — `iptobase64` encodes some IPv6 addresses as a different address (Low-Medium, inherited)

**Reproducer** `findings/F06-iptobase64-wrong-address.bin` (target
`ircd_string`, mode 1 round trip of a raw address):
`b64: AQAAAAAjAAARHwAAAEFCQ0Ff`, address `0:23:0:111f:0:41:4243:415f`
decodes back as `0:23:0:0:0:41:4243:415f`.

**Root cause** `ircd/numnicks.c:499-506`: the longest-zero-run search only
resets `curr_zeros` when the current run beats the best one, so separate
runs accumulate; `max_start = ii - curr_zeros` then points into non-zero
groups, and the `_` compression swallows them.

**Reachability** every local IPv6 client's address is sent to peers in its
P10 `NICK` with this encoding.  Any address with two or more zero runs —
the client picks its own interface identifier — appears on every other
server as a different address (remote WHOIS/CHECK, IP-based G-lines and
clone counting on peers, and the cloak computed there).

**Fix** reset `curr_zeros = 0` on every non-zero group (move the reset
out of the `if`).

## F09 — `ircd_ntoa_r` prints some IPv6 addresses as a different address (Low-Medium, inherited)

**Reproducer** `findings/F09-ircd_ntoa_r-wrong-address.bin` (target
`ircd_string`, mode 0): `txt: \x00\x00f:0:a:f:0:a:0:a`
(`b64: AABmOjA6YTpmOjA6YTowOmE=`).  `ircd_ntoa_r` renders it as
`f:0:a:f:0::a`, which parses back as `f:0:a:f:0:0:0:a`.

**Root cause** `ircd/ircd_string.c:889-897`, the same zero-run bug as F06.

**Reachability** `cli_sock_ip` is `ircd_ntoa_r(cli_ip)` (`s_bsd.c:240`,
`s_bsd.c:1004`).  Non-CIDR G-line host masks are matched against that
string (`gline.c:1083-1084`), and it is what opers see, what goes to
IAuth/DNSBL/WEBIRC handling and to logs.  A client chooses an address
whose text form is another address's (or matches no G-line meant for it).
(`ipmask_parse` also accepts `:::`, e.g. `f:0:a:f:0:a:::a`.)

**Fix** as F06: reset `curr_zeros` on each non-zero group.

## F02 — WebSocket fragment reassembly writes one byte past `con_ws_frag_buf` (Low)

**Reproducer** `findings/F02-websocket-frag-nul-overflow.bin` (target
`websocket`, mode 1 = frame stream, `FUZZ_WS_STRICT_FRAG=1`): a masked
non-FIN TEXT frame of 16000 bytes followed by a FIN continuation of 384
bytes (16384 in total).

```
heap-buffer-overflow WRITE of size 1   ws_read_model fuzz_websocket.c:198
(= ircd/s_bsd.c:1461  frag_data[frag_len] = '\0')
```

**Root cause** `ircd/s_bsd.c:1447-1462`: continuation frames are accepted
while `frag_len + ws_len <= 16384`, the size of `con_ws_frag_buf`
(`include/client.h:510`); the TEXT branch then NUL-terminates at
`frag_data[16384]`, one past the array.  The harness reproduces the
`read_packet()` WebSocket branch verbatim with each per-connection buffer
allocated separately (documented in the harness), because the real buffer
is an array inside `struct Connection` where ASan cannot see the overrun.

**Reachability** any WebSocket client after the handshake.  In the real
struct the byte lands in the low byte of `con_ws_frag_len` (the next
field), which is reset to 0 right after, so the effect today is benign —
but it is an out-of-bounds write by a client.

**Fix** accept fragments while `frag_len + ws_len < sizeof(frag_buf)` (or
make the buffer 16385 bytes).

## F10 — `matchexec` reads before the subject string (Low, inherited)

**Reproducer** `findings/F10-matchexec-underread.bin` (target `match`,
`FUZZ_STRICT=1`): `txt: *a\x00a` — `matchexec("a", matchcomp("*a"))`.

`heap-buffer-overflow READ  #0 matchexec ircd/match.c:513`

**Root cause** the `trytail` loop (`ircd/match.c:513-514`) does up to four
`*--s` per condition before re-checking; when the compiled tail matches
back to the first character it reads `string[-1]`.

**Reachability** `WHO <mask>` (`m_who.c:387`, every client) and G-line
matching (`gline.c:420,445`) run `matchexec` against nick/user/host
strings.  Those strings are arrays inside `struct Client`, so the stray
byte is the previous field: no crash, possibly a wrong result.

**Fix** stop the tail walk at `string` (`s > string` before each
decrement).

## F11 — `mmatch` reads `old_mask[-1]` for an empty mask (Low, inherited)

**Reproducer** `findings/F11-mmatch-empty-mask.bin` (target `match`):
`txt: \x00\\?cab?abc` — `mmatch("", "\\?cab?abc")`.
`heap-buffer-overflow READ  #0 mmatch ircd/match.c:93`.

**Root cause** `ircd/match.c:91-93`: on an exhausted old mask the code
does `m--` and then reads `*m` even when `m` started at `old_mask` (the
`m > old_mask` guard is only in the loop).

**Reachability** `mmatch` compares ban/except/invex masks, SILENCE
masks and G-line masks; callers normally pretty-print masks first, so an
empty old mask is unusual.  One byte before a heap string.

**Fix** `if (m > old_mask) m--;` before the backward scan, and test
`(m >= old_mask && *m == '*')`.

## F12 — `match` steps past both NULs on a dangling backslash (Low, inherited)

**Reproducer** `findings/F12-match-trailing-backslash.bin` (target
`match`, `FUZZ_STRICT=1`): `txt: #a\\\x00#a` — `match("#a\\", "#a")`.
`heap-buffer-overflow READ  #0 match ircd/match.c:195`.

**Root cause** `ircd/match.c:208-212`: for `\` the code advances the mask
and compares `*m++ != *n++`; when both are at their NUL they compare equal
and both pointers move past the terminators, and the loop keeps reading.
The same happens when a `\` is consumed as a literal after a wildcard
(`?\\` at the end).

**Reachability** any wildcard mask ending in `\` (channel bans after
pretty-printing rarely end that way; LIST/WHOWAS/SILENCE/server masks can).
Over-read of a few bytes past the mask and name; a wrong match is
possible.

**Fix** `case '\\': m++; if (!*m) goto backtrack /* or: return *n != 0 */;`
— never compare two NULs as a match inside the escape.

## F13 — `mmatch` claims a superset it is not, with escapes (Low, inherited)

**Reproducer** `findings/F13-mmatch-backslash-unsound.bin` (target
`match`, `FUZZ_STRICT=1`): `mmatch("??*?\\**", B) == 0` ("A covers B") for
`B = "a(?*?\xb9*?O\xce\\?**?*\\\\**"`, yet the literal instance of B that B
matches is not matched by A.

**Root cause** `mmatch` and `match` disagree on escapes: `match` treats
`\X` as a literal `X` for any X, `mmatch` (and `matchcomp`) only for `\?`
and `\*`, and `mmatch`'s wildcard/escape pairing (`ircd/match.c:111-151`)
is not sound for mixed escapes.

**Reachability** chanops setting bans: `mmatch` decides which existing
bans a new one makes redundant (and removes them) and whether a new ban is
already covered.  A crafted mask can make the ircd drop a ban that still
had work to do.

**Fix** give the three matchers one escape grammar (`\` escapes only `*`
and `?`, or any character, but the same everywhere) and re-derive mmatch
against it; the harness's soundness check is a ready regression oracle.

## F05 — `iptobase64` reads `in6_16[8]` (Low, inherited)

**Reproducer** `findings/F05-iptobase64-index8.bin` (target `ircd_string`):
`txt: \x01\x00AABAACAADAAEAAFAAGAAHAAI` (an IPv6 address with no zero
group).  `stack-buffer-overflow READ of size 2  #0 iptobase64
ircd/numnicks.c:494`.

**Root cause** `for (ii = 0; (addr->in6_16[ii]) && (ii < 8); ++ii)` tests
the element before the index.

**Reachability** every local client whose IPv6 address has no zero group
(common for SLAAC addresses), at every NICK burst.  Two bytes past the
address inside `struct Client`; the loop ends anyway, so only UB.

**Fix** swap the operands: `(ii < 8) && addr->in6_16[ii]`.

## F08 — `iptobase64`: signed shift overflow for IPv4 >= 128.0.0.0 (Low, inherited)

**Reproducer** `findings/F08-iptobase64-shift-ub.bin` (target
`ircd_string`, default guards; the fuzz build disables `shift-base` for
this target so the campaign is not stopped by it, the repro build keeps
it): `::ffff:192.168.1.1`.

`ircd/numnicks.c:479:46: runtime error: left shift of 49320 by 16 places
cannot be represented in type 'int'` (also lines 484, 486).

**Root cause** `ntohs(...)` promotes to `int`; `<< 16` overflows for
values >= 0x8000.

**Reachability** every IPv4 client in the upper half of the address space.
Compilers produce the intended bits today; it is UB nonetheless.

**Fix** `((unsigned int)ntohs(...) << 16)`.

## F07 — `ParseInterval` signed overflow (Low, inherited)

**Reproducer** `findings/F07-parseinterval-overflow.bin`:
`txt: \x08\x009999999999999999d`.
`ircd/ircd_string.c:1183:30: runtime error: signed integer overflow:
999999999 * 10 cannot be represented in type 'int'` (and `:1185` for the
`long` product).

**Reachability** opers: duration arguments of GLINE/SHUN/ZLINE
(`m_gline.c:435,475`, `m_shun.c:431,471`, `m_zline.c:435,475`) and JUPE
(`m_jupe.c:216,224`).  A wrapped duration gives a line that expires
immediately or effectively never.

**Fix** accumulate in `unsigned long` with an overflow check and clamp
(and reject absurd durations).

## F15 — `history_iso_to_unix` signed overflow (Low)

**Reproducer** `findings/F15-history-iso-to-unix-overflow.bin` (target
`history`, mode 3, `FUZZ_STRICT=1`):
`txt: \x03-9999999999999999999-01-01T00:00:00Z`.
`ircd/history.c:951:41: runtime error: signed integer overflow:
-9223372036854775808 - 1900` (and `:955` for the month).

**Root cause** `strtol(...) - 1900` / `- 1` on a saturated `strtol`.

**Reachability** client references are validated first
(`validate_timestamp` requires a 4-digit year), but S2S references are not:
`parse_s2s_reference` (`m_chathistory.c:451`) accepts `timestamp=<any>` (X3
sends that form) and the query functions convert it
(`history.c:2008,2049,2094,2332,2494,2508`).  Linked servers / services
only.

**Fix** parse the fields with bounded digit counts (or `sscanf("%4d-%2d-
%2dT%2d:%2d:%2d")`) and range-check before arithmetic.

## F17 — `webpush_expired`: `armed + max_age` overflow (Low)

**Reproducer** `findings/F17-webpush-expired-overflow.bin` (target
`webpush_expiry`, `FUZZ_STRICT=1`): a stored record armed at
`9223372036854775807`.  `ircd/webpush_expiry.c:56:16: runtime error:
signed integer overflow`.

**Reachability** stored subscription records (RocksDB), written by the
server with its own clock; a corrupt or foreign record only.

**Fix** `return armed <= (long long)now - max_age;` (no overflow for
`armed`, `now`, `max_age` > 0).

## F20 — bouncer restore: unterminated `bsr_kc_id` read past the record (Low)

**Reproducer** `findings/F20-bouncer-record-kcid-overread.bin` (target
`bouncer_record`, `FUZZ_STRICT=1`): a v12 record of exactly
`sizeof(struct BounceSessionRecord)` (14680) bytes, all `A`.  Generator:
`python3 -c "import struct,sys;b=b'A'*14680;sys.stdout.buffer.write(bytes([5])+struct.pack('<H',len(b))+b)"`.

```
heap-buffer-overflow READ  #0 account_id_valid ircd/account_id.c:64
                           #1 bounce_create_ghost ircd/bouncer_session.c:3114
                           #2 bounce_db_restore   ircd/bouncer_session.c:3536
```

**Root cause** `bsr_kc_id` is the last field of a v12 record; the restore
path calls `account_id_valid(rec->bsr_kc_id)` (`bouncer_session.c:3114`,
`:3591`), which scans for a NUL, on bytes that come straight from the
RocksDB value (`rec = (struct BounceSessionRecord *)vbuf`, `:3320`).  The
other string fields are copied with bounded `ircd_strncpy`; this check is
the unbounded read.
The cast of `vbuf` also assumes RocksDB returns suitably aligned memory.

**Reachability** a corrupt record or one written by a build whose layout
differs (the size check only catches size changes).  Startup only.

**Fix** memcpy the value into a local `struct BounceSessionRecord` (fixes
alignment too) and force-terminate every char array before use
(`rec.bsr_kc_id[sizeof rec.bsr_kc_id - 1] = 0`, etc.).

## F21 — bouncer restore: `CurrentTime - disconnect_time` overflow (Low)

**Reproducer** `findings/F21-bouncer-record-time-overflow.bin` (v12 record
with `bsr_disconnect_time = INT64_MIN`).
`ircd/bouncer_session.c:3529:27: runtime error: signed integer overflow:
1700000000 - -9223372036854775808`.

**Fix** reject records whose times are negative or in the future before
subtracting.

## F22 — CRULE argument list overflows `CRuleNode.arg[]` (Low, inherited)

**Reproducer** `findings/F22-crule-arglist-overflow.bin` (target `crule`,
`FUZZ_STRICT=1`): `connected(a,b,c,d,e,f,g,h)`.

```
heap-buffer-overflow WRITE of size 8
#0 crule_parsearglist  ircd/crule.c:742
#1 crule_parsefunction ircd/crule.c:680
#2 crule_parseprimary  ircd/crule.c:632
```

**Root cause** `argrootp->arg[argrootp->numargs++] = argelemp` has no
bound; `arg[]` holds `CR_MAXARGS` (3).  The arity check against the
function table runs only after the list is parsed.

**Reachability** `crule_parse` is called only from the config parser
(`ircd_parser.y` Connect block `rule`, `y.tab.c:4970,4976`): ircd.conf,
REHASH, and configuration pulled by `tools/linesync`.  A bad rule
corrupts the heap at load time.

**Fix** `if (argrootp->numargs >= CR_MAXARGS) return CR_ARGMISMAT;` before
storing.

## F23 — CRULE `&&` with a missing operand frees a NULL / uninitialized child (Low, inherited)

**Reproducer** `findings/F23-crule-empty-operand.bin`: `&&` (also
`\t\t&\t&`, `connected(a) && <junk>`).

```
ircd/crule.c:767:18: runtime error: member access within null pointer of type 'struct CRuleNode'
#0 crule_free  ircd/crule.c:767
#1 crule_free  ircd/crule.c:775
#2 crule_parse ircd/crule.c:454
```

**Root cause** `crule_parseandexpr` (`ircd/crule.c:536-569`) builds an and
node when the first primary parsed to NULL (`andptr->arg[0] = primary`),
and leaves `arg[1]` uninitialized until the next operand parses (the same
shape in `crule_parseorexpr`, `:480-505`).  On the error path
`crule_free` recurses into those children without a NULL check (its own
comment says not to call it on NULL).

**Reachability** as F22 (config).  A typo in a Connect rule crashes the
server at boot or REHASH.

**Fix** reject a missing operand before allocating the node, initialize
`arg[1] = NULL`, and make `crule_free` NULL-safe.

## F24 — `parse_server`: prefix-only line read past its NUL (Low, inherited)

**Reproducer** `findings/F24-parse_server-prefix-only-overread.bin`
(target `parse`, mode 1 = server link, `FUZZ_STRICT=1`): the line `A`×8702
(an unknown numeric prefix filling `cli_buffer`).  Generator:
`python3 -c "import sys;sys.stdout.buffer.write(b'\x01'+b'A'*8702)"`.

```
heap-buffer-overflow READ of size 1
#0 parse_server ircd/parse.c:2103
```

**Root cause** for a prefix whose numeric is unknown (`from == NULL`,
`ircd/parse.c:2084-2108`) the code skips spaces and then tests `ch[1]` and
`ch[2]` without checking that `*ch` is not the terminator.  A line that is
nothing but a prefix leaves `ch` on the NUL, so `ch[1]`/`ch[2]` are read
past it — past `cli_buffer` itself when the line is `FULL_MSG_SIZE - 1`
bytes (the next `struct Connection` fields in the real layout).

**Reachability** P10 input from a directly linked server (any line can
carry a numeric prefix the receiver does not know, e.g. during a netsplit
race).  Over-read of two bytes; the result only selects whether the line
is dropped.

**Fix** `if (!*ch) return 0;` after skipping the spaces (and test `ch[1]`
before `ch[2]`).

---

## Informational notes (no finding filed)

* **WebSocket TEXT sanitizing truncates.** `string_sanitize_utf8`
  (`ircd_string.c:177`) works in a `BUFSIZE` buffer: a TEXT frame longer
  than ~508 bytes with an invalid byte early is cut to 508 bytes in
  `s_bsd.c:1503-1509` (the rest of the frame — possibly several IRC lines —
  is dropped), and one whose first invalid byte is past 508 passes
  unsanitized (documented in the function's comment).
* **`match` vs `matchcomp`/`matchexec` disagree on escapes** (`\X` for a
  plain X).  Code paths that use one or the other (WHO and G-lines use the
  compiled form, most others `match`) can disagree on a mask containing
  backslashes.  Root of F13.
* **Metadata TTL rows**: a public TTL value that begins with `P:` or `*:`
  reads back with its prefix stripped and private visibility
  (`metadata.c:376-393`).  Today only `last_present` (digits) takes that
  path; client values go through `metadata_account_set_permanent`, which
  always prefixes.  Latent.
* **Compressed-value marker**: an uncompressed value whose first byte is
  `COMPRESS_MAGIC` (0x1F) is decoded as zstd (`ircd_compress.c:38`).  No
  store writes such a value today (history rows start with the type digit,
  multiline with the sender, metadata with `T`/`P:`/`*:`).  The non-zstd
  `decompress_data` macro (`ircd_compress.h:96`) ignores the output size;
  all callers are inside `#ifdef USE_ZSTD`.
* **webpush.c's base64url decoder counts explicit `=` padding as data**
  (`"iih="` decodes to 3 bytes where `webpush_keyring.c`'s decoder gives
  2), so padded p256dh/auth keys are rejected as the wrong length.
* **`ircd_snprintf` vs C**: `%#x`/`%#o` of 0 print `0x0`/`00` (C: `0`),
  and `%05d` of a negative number pads five digits after the sign
  (C counts the sign in the width).  `%#x` is used by `RPL_SNOMASK`.
* **kc_cache userid cache** keys compare with `strcasecmp` and are
  truncated at 63 bytes; it has no caller in the ircd today.
* **`account_id_from_uuid`** ignores hyphens anywhere and accepts either
  case (by design; noted because the harness's first oracle assumed the
  canonical 8-4-4-4-12 form).

### Discarded harness artifacts

Each was a harness calling a function outside its callers' contract; the
harness now honours the precondition (noted in the code):

* `canonize()` and `StripColor()` write into a static `BUFSIZE` buffer;
  their callers pass one parameter / the body of one parsed line, which
  `parse.c` keeps below `BUFSIZE`.
* `ircd_json_escape()` truncated into a tiny buffer can split a UTF-8
  sequence; its only caller (the non-jansson fallback in `m_webpush.c`)
  sizes the buffer for the field.
* `kc_user_repr_cache_get()` returns a borrowed reference (documented);
  the first harness decref'd it.
* Fields that cannot contain CR/LF in the ircd (they come from a parsed
  line) were fed with CR/LF to `webpush_line_message`.
* `scram_sha256_derive()` with a salt longer than 23 bytes would leave the
  base64 salt unterminated; its only caller uses 16 bytes.
* JWT: flipping the last base64url character of a signature can change
  only the unused padding bits — the first oracle's "forged token
  accepted" was that, not a verification bypass.

---

## Targets, executions and coverage

`execs` is the sum over every libFuzzer job of the final campaign
(`schedule.txt`, 4 cores) plus the earlier shakedown runs; `cov`/`ft` are
the last values libFuzzer reported (edges / features).  `lines` is source
line coverage of the target's main file by its committed corpus
(`./coverage.sh`).  Untrusted-network targets got the longest slots.

STATS_TABLE_PLACEHOLDER

Coverage gaps worth knowing (checked where a target plateaued):

COVERAGE_NOTES_PLACEHOLDER
