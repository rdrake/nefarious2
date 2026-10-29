# P10 server-input fuzzing — findings

Target: `rdrake/nefarious2` `ircv3.2-upgrade` @ `ca213aa` (branch `fuzz/p10-server`
adds only `fuzz/p10/`). Harness: `fuzz/p10/fuzz_p10.c` (see its header comment;
`README` section at the end of this file).

**Threat model.** A directly linked peer (hub, leaf, buggy/legacy server, or a
compromised leaf) sends bytes on an established, authenticated server link.
Every finding below needs nothing more than that: the hub has accepted the
peer's PASS/SERVER, and the peer sends the listed lines. No finding depends on
harness-only state. Where a finding needs the link to still be in burst, it
says so; that is the normal state for the first seconds of every link.

All reproducers are in `fuzz/p10/repro/` (20 files, one crash each; the standalone driver stops at the first crash, so run them one at a time). **Byte 0 of each file is a harness
flag byte** (0x01 = send `AB EB` first, i.e. post-burst; 0x00 = in burst), the
rest is the wire stream from peer `hub.fuzz` (numeric `AB`) to our server
`fuzz.local` (`AK`). Run one with

```
FUZZ_TMPDIR=/dev/shm/x fuzz/p10/bin/repro_p10 fuzz/p10/repro/<file>
```

`repro_p10` is a plain ASan build (no UBSan, no fuzzer instrumentation,
`--enable-debug`, so asserts are on, as in the shipped Docker image). Stacks
below come from it.

## Summary

| # | Severity | Where | What a peer sends | Effect |
|---|----------|-------|-------------------|--------|
| F1 | **Critical** | `numnicks.c:549-550` `base64toip` | `N` with an IP field longer than 25 chars containing `_` | heap/stack buffer overflow (WRITE, unbounded) |
| F6 | **Critical** | `numnicks.c:358-382` `SetRemoteNumNick` + `numnicks.c:259` `RemoveYXXClient` | `N` whose numeric field is 1 char | dangling `client_list` slot, use-after-free of a pooled `Client` |
| F5 | **High** | `channel.c:4197` (`mode_parse_ban`) + early returns in `mode_parse` (`channel.c:5271`, `5298-5301`) | `M #c +b mask <newer-ts>` during burst, or a second `B` with a newer TS and `+b` | stack `struct Ban` left linked in `chptr->banlist` (stack-use-after-return, later `free()` of a stack address) |
| A1 | **High** | `s_user.c:1469-1472`, `s_misc.c:348-396`, `m_nick.c:403` | `BX C` alias, primary `Q`, then the alias numeric sends `N` | alias put in nick hash, never removed: **assert `list.c:334` abort**; with NDEBUG a dangling hash entry (UAF), and a hash self-loop **hang** |
| A2 | **High** | `channel.c:967-974` `remove_user_from_channel` + `bouncer_session.c:6936` `bounce_sync_alias_part` | `KICK` of a bouncer primary whose alias is in the channel and nobody else is | heap-use-after-free WRITE on the freed `Channel`/`Membership` |
| F4 | High | `numnicks.c:136-143` `base64toint` via `findNUser` (`m_burst.c:595`, `channel.c:4587`) | `B #c <ts> ABAAA,:vvvvvvvv` (empty member before `:`), or `ABAAA M #c -o :` (empty client-mode param) | out-of-bounds read of `server_list[]` → wild pointer → SEGV |
| F2 | Medium | `m_burst.c:125` `netride_modes` | `B #new <ts> +k` (no key argument) | `strcmp(key, NULL)` → SEGV |
| F3 | Medium | `parse.c:2247` `parse_server` | any line whose command is a numeric evaluating to 0: `AB 000 x`, `AB 0/: x` | `mptr == NULL` → SEGV |
| F7 | Medium | `m_mark.c:112` `ms_mark` | `AB MK x` (fewer than 2 params) | `strcmp(NULL, ...)` → SEGV |
| F8 | Medium | `channel.c:2870` `modebuf_flush_int` | `AB M #c -o ABAAA:1` (deop carrying an op-level) | `strptro_i == NULL` write → SEGV |
| F11 | Medium | `m_topic.c:149` `do_settopic` (via `ms_topic m_topic.c:383`) | server-sourced `AB T #c :topic` (no setter field) | `cli_user(server)->username` → SEGV (default `HOST_IN_TOPIC`) |
| F12 | Medium | `m_rehash.c:210` `ms_rehash` | `AB RH` (server-sourced REHASH) | `cli_user(server)` NULL → SEGV |
| F13 | Medium | `m_server.c:751` `ms_server` | `SERVER` line whose prefix is a **user** numeric (`ABAAA S leaf ...`) | `cli_serv(user)` NULL → SEGV in `add_dlink` |
| F14 | Medium | `m_whois.c:353-355` `do_whois` (via `ms_whois m_whois.c:617`) | server-sourced `AB W :<nick>` where the target is an oper with `+W` | `cli_user(server)->username` → SEGV |
| F10 | Low | `parse.c:2042-2070` `parse_server` | a line starting with NUL | prefix scan steps past the terminator, so the bytes after the NUL are parsed as a server-sourced command (memory-safe: stays in the 8 KiB line buffer; it is how F6 was reached with an "empty" line) |
| U1 | Low (UB) | `m_burst.c:577` | op-level digits `ABAAA:99999999999` in a `B` | signed overflow; the wrapped negative op-level passes the `> MAXOPLEVEL` clamp |
| U2 | Low (UB) | `numnicks.c:479` `iptobase64` | any IPv4 address >= 128.0.0.0 | `uint16 << 16` signed-int overflow (benign on two's-complement) |

Every Critical/High/Medium entry kills the hub process (SEGV or assert abort).
Each one is reachable by **any** linked server with one or a few syntactically
plausible lines. Nothing found needed protocol-impossible, harness-only state
(category (b)). See "Discarded" at the end.

---

## F1 — `base64toip` unbounded write (N introduction)

**Reproducer** `repro/b64ip_underscores`
```
\x01AB N x 2 1760000000 u h +i ____________________________ ABAAA :r
```
base64: `AUFCIE4geCAyIDE3NjAwMDAwMDAgdSBoICtpIF9fX19fX19fX19fX19fX19fX19fX19fX19fX18gQUJBQUEgOnIK`

**Stack**
```
ERROR: AddressSanitizer: heap-buffer-overflow ... WRITE of size 2
  #0 base64toip        numnicks.c:550
  #1 set_nick_name     s_user.c:1218
  #2 ms_nick           m_nick.c:438
  #3 parse_server      parse.c:2249
```
The same function is called on a stack `struct irc_in_addr` on the nick-collision path
(`m_nick.c:524`, `m_nick.c:730`), which gives a stack-buffer-overflow instead.

**Root cause.** `numnicks.c:546`:
`for (left = (25 - strlen(input)) / 3 - pos; left; left--) addr->in6_16[pos++] = 0;`
`left` is `unsigned`. For `strlen(input) > 25`, or `pos` past the computed count, it
wraps to ~4e9 and the loop zero-fills far past the 16-byte `irc_in_addr`. Non-`_`
groups also read 3 bytes without checking for the terminator (`numnicks.c:553-555`),
which over-reads for short/odd-length fields.

**Reachability.** Any linked server, one `N` line; `parv[parc-3]` is passed
unvalidated from `ms_nick` → `set_nick_name`. Corrupts the heap (the new
`Client` and whatever follows it) or the stack.

**Fix.** Validate the IP field before decoding: length 6 (IPv4), or
<= 24 chars of `[A-Za-z0-9\[\]_]` with at most one `_`, and compute `left` signed,
rejecting `left < 0 || pos + left > 8`. Stop at NUL in the 3-char groups.
Reject the `N` (protocol_violation + KILL toward the link) on a bad field.

## F6 — 1-character numeric in `N` leaves a dangling `client_list` slot (UAF)

**Reproducers** `repro/nick_short_numeric_uaf`, `repro/nick_short_numeric_squit`
```
\x01AB N x 2 1000 u h +i B]AAAB A :r
AB N x 2 1000 u h +i B]AAAC ABAAB :r
ABAAA P #x :hi
```
base64: `AUFCIE4geCAyIDEwMDAgdSBoICtpIEJdQUFBQiBBIDpyCkFCIE4geCAyIDEwMDAgdSBoICtpIEJdQUFBQyBBQkFBQiA6cgpBQkFBQSBQICN4IDpoaQo=`

**Stack** (third line; the squit variant crashes in `exit_one_client s_misc.c:469`)
```
ERROR: AddressSanitizer: SEGV on unknown address 0x000000000018
  #0 parse_server   parse.c:2113        cli_from(from) on a freed Client
  #1 server_dopacket packet.c:107
```
The fuzzer reached the same dangling slot through `ms_burst m_burst.c:595`,
`ms_account m_account.c:225/234`, `exit_one_client s_misc.c:380/469`,
`exit_client s_misc.c:837` (from `SetRemoteNumNick`'s ghost exit) and the
`list.c:334` assert.

**Root cause.** `SetRemoteNumNick` (`numnicks.c:363-367`) handles a numeric whose
length is not 5 by reading `yxx[1]` and `yxx[2]`. For a 1-char numeric, `yxx[1]`
is the NUL, so `cli_yxx` becomes `""`, and `yxx[2]` reads past the end of the
parameter. The slot index comes from `base64toint("")`, which also reads past the
NUL (see F4). The client is stored in `client_list[idx]`. When it exits,
`RemoveYXXClient` (`numnicks.c:259`) skips it because `if (*yxx)` is false. The
slot keeps pointing at the freed `Client`, which `free_client` returns to the
client freelist (so ASan reports a NULL `cli_connect` rather than a
use-after-free). The next `findNUser` that maps to that slot (any message from
that numeric, a BURST member, an AC, or the squit of that server) dereferences
it. Once the struct is reused for another client, the stale slot misattributes
traffic.

The collision in line 2 (same nick, equal TS → both killed) is just one way to
exit the bad client. A `KILL` or the server's squit has the same effect.

**Reachability.** Any linked server, two lines. **Fix.** In `ms_nick`, require
`strlen(parv[parc-2])` to be 3 (with a 1-char server) or 5, all base64 chars,
with the server part equal to the introducing server. Make `SetRemoteNumNick`
assert or reject otherwise, and make `RemoveYXXClient` compute the same index
`SetRemoteNumNick` used (or store the slot index in the Client).

## F5 — stack `struct Ban` left linked into `chptr->banlist`

**Reproducers** `repro/mode_ts_stackban` (MODE path, in burst), `repro/burst_stackban_use` (BURST path)
```
\x00AB N n 2 1000 u h +i B]AAAB ABAAA :r
AB B #c 1000 ABAAA:o
ABAAA M #c +b *!*@x 1500
```
base64: `AEFCIE4gbiAyIDEwMDAgdSBoICtpIEJdQUFBQiBBQkFBQSA6cgpBQiBCICNjIDEwMDAgQUJBQUE6bwpBQkFBQSBNICNjICtiICohKkB4IDE1MDAK`

```
\x00AB N n 2 1000 u h +i B]AAAB ABAAA :r
AB B #c 1000 ABAAA
AB B #c 2000 +b *!*@x
AB N m 2 1000 u h +i B]AAAC ABAAB :r
AB B #c 1000 ABAAB
```
base64: `AEFCIE4gbiAyIDEwMDAgdSBoICtpIEJdQUFBQiBBQkFBQSA6cgpBQiBCICNjIDEwMDAgQUJBQUEKQUIgQiAjYyAyMDAwICtiICohKkB4CkFCIE4gbSAyIDEwMDAgdSBoICtpIEJdQUFBQyBBQkFBQiA6cgpBQiBCICNjIDEwMDAgQUJBQUIK`

**Stacks**
```
ERROR: AddressSanitizer: stack-use-after-return
  #0 sub1_from_channel          channel.c:416   (free_ban of the stack Ban)
  #1 remove_user_from_channel   channel.c:974
  #2 remove_user_from_all_channels channel.c:1006
  #3 exit_one_client            s_misc.c:542
--
ERROR: AddressSanitizer: stack-use-after-return
  #0 ms_burst  m_burst.c:742   (ban list walk on the next BURST)
```

**Root cause.** `mode_parse_ban` (`channel.c:4197`) puts a temporary `Ban`, an element
of `state->banlist[]` (the `ParseState` on `mode_parse`'s stack), onto the live
`chptr->banlist` via `apply_ban`. `mode_process_bans` is the only code that
unlinks those temporaries, and `mode_parse` returns early without calling it in
two cases:
* the "source server still in burst and the MODE carries a newer TS" branch
  (`channel.c:5271`, `return state.args_used;` after zeroing the modebuf);
* `!state.mbuf` (`channel.c:5298-5301`). `ms_burst` calls `mode_parse` with a NULL
  modebuf when the incoming channel TS is newer than ours (the modes are
  ignored), but `b`/`e` in the mode string still reach `mode_parse_ban` /
  `mode_parse_except`.

After return, `chptr->banlist` points into a dead stack frame. Every ban check
on the channel reads garbage, and the next ban-list cleanup calls `free()` on a
stack address (glibc aborts with "free(): invalid pointer"). Exceptions
(`+e`, `mode_parse_except`) have the same pattern.

**Reachability.** Any linked server. The MODE variant needs the source server
still in burst, which is the normal state for the whole of a netjoin. This
looks inherited from upstream ircu (same structure in 2.10.12), and the fork's
`+e` handling copies it. **Fix.** Never link temporaries into the live list.
Keep them on a list local to `ParseState` and merge them in
`mode_process_bans` / `mode_process_excepts`. At minimum, run the
unlink/cleanup on every return path of `mode_parse` once `DONE_BANCLEAN` is
set (and skip `b`/`e` entirely when `!state->mbuf`).

## A1 — orphan bouncer alias renamed into the nick hash (assert abort / UAF / hang)

**Reproducer** `repro/bx_q_nick_then_lookup` (also `repro/bx_alias_nick_after_primary_quit`, which aborts at the squit)
```
\x01AB N Bnc 2 1760000000 bnc h +ixr bnc B]AAAB ABAAL :Bnc
AB BX C ABAAL ABAAM bnc 0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b :#x
ABAAL Q :bye
ABAAM N NewNick 1793289405
AB N NewNick 2 1760000001 x h +i B]AAAC ABAAN :x
```
base64: `AUFCIE4gQm5jIDIgMTc2MDAwMDAwMCBibmMgaCAraXhyIGJuYyBCXUFBQUIgQUJBQUwgOkJuYwpBQiBCWCBDIEFCQUFMIEFCQUFNIGJuYyAwMTkwYTFiMi1jM2Q0LTdlNWYtOGE5Yi0wYzFkMmUzZjRhNWIgOiN4CkFCQUFMIFEgOmJ5ZQpBQkFBTSBOIE5ld05pY2sgMTc5MzI4OTQwNQpBQiBOIE5ld05pY2sgMiAxNzYwMDAwMDAxIHggaCAraSBCXUFBQUMgQUJBQU4gOngKQUJBQU4gUCBOZXdOaWNrIDpoaQo=`

**Stack**
```
SYSTEM [CRIT]: Assertion failure at list.c:334: "cli_hnext(cptr) == cptr"
  free_client      list.c:334
  exit_one_client  s_misc.c
  exit_client      s_misc.c:1089
  exit_client_msg  s_misc.c:1136
  ms_nick          m_nick.c:918   (nick collision on "NewNick")
```

**Root cause** (traced with the `bouncer-analyst` agent).
1. With no `BS C` for the session, `bounce_alias_create` (`bouncer_session.c:9050-9144`)
   builds ABAAM (`SetBouncerAlias`, `alias_primary` = ABAAL, not hashed by
   design) without filing it in any session.
2. `ABAAL Q` → `exit_one_client` finds no session, so nothing is promoted.
   `bounce_null_alias_primary_pointing_at` (`s_misc.c:724`) then sets ABAAM's
   `alias_primary` to NULL. The result is an orphan alias.
3. `ABAAM N NewNick`: the alias→primary redirect at `m_nick.c:403` only runs
   while `alias_primary` is set, so `set_nick_name` renames the alias itself.
   At `s_user.c:1470-1472`, `hRemClient` fails quietly and `hAddClient` hashes
   the alias under "NewNick".
4. Every exit of an `IsBouncerAlias` client takes the alias branch
   (`s_misc.c:348-396`), which returns at `:396` without `hRemClient`, so
   `free_client` asserts. `BX X` (`bounce_alias_destroy` →
   `remove_client_from_list`) hits the same assert.

**Consequences.**
* asserts on (the shipped image): the hub aborts → remote DoS.
* NDEBUG: the freed `Client` stays in the nick hash, so
  `FindClient("NewNick")` is a use-after-free. Reusing the struct resets
  `hnext` and cuts the bucket chain.
* `bounce_promote_alias` calls `hAddClient` with no "already hashed" check
  (`bouncer_session.c:5044`). An alias already hashed this way gets inserted a
  second time, which creates a self-loop in the bucket. During campaign 1,
  three libFuzzer children spun for more than 25 minutes in `hSeekClient` (from
  `ms_nick`, `m_nick.c:436`, looking up the alias's nick) after inputs of this
  family. That is the hang, a remote CPU-lock DoS. The single input dumped from
  a stuck child did not hang on its own, because the state was built up across
  inputs in the same process, so treat the hang as a consequence of A1 rather
  than a separately confirmed issue.

**Reachability.** Real-world reachable. A fork peer sends NICK sourced from the
alias numeric by design (`m_nick.c:219-224`). If that crosses an in-flight
primary `Q` (hold disabled or failed) or the primary's server SQUITs, an
intermediate hub sees exactly `Q` then `alias N`. A legacy/buggy peer sending
`N` for an alias numeric hits it directly. The fuzzer also reached it through
prefix forms like `ABAAM\tAB N ...` (parse_server takes the first 5 prefix chars).

**Fix.** In `ms_nick`/`m_nick`, refuse NICK from an `IsBouncerAlias` source
with no `alias_primary` (protocol_violation), or redirect it to the session's
current primary. In `set_nick_name`, never `hAddClient` an `IsBouncerAlias`
client; renaming an alias only updates `cli_name`. Belt and braces:
`hRemClient` in the alias exit branch before `s_misc.c:396`, and remove before
add in `bounce_promote_alias` (`:5044`). Also decide whether an orphan alias
should be reaped when its primary exits.

## A2 — KICK of a bouncer primary: channel freed under `remove_user_from_channel`

**Reproducer** `repro/kick_primary_with_alias`
```
\x01AB N Bnc 2 1760000000 bnc h +ixr bnc B]AAAB ABAAL :Bnc
AB B #c 1760000000 ABAAL
AB BX C ABAAL ABAAM bnc 0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b +ix :#c
AB K #c ABAAL :bye
```
base64: `AUFCIE4gQm5jIDIgMTc2MDAwMDAwMCBibmMgaCAraXhyIGJuYyBCXUFBQUIgQUJBQUwgOkJuYwpBQiBCICNjIDE3NjAwMDAwMDAgQUJBQUwKQUIgQlggQyBBQkFBTCBBQkFBTSBibmMgMDE5MGExYjItYzNkNC03ZTVmLThhOWItMGMxZDJlM2Y0YTViICtpeCA6I2MKQUIgSyAjYyBBQkFBTCA6YnllCg==`
```
ERROR: AddressSanitizer: heap-use-after-free ... WRITE of size 8
  #0 remove_member_from_channel   channel.c
  #1 remove_user_from_channel     channel.c:974
  #2 make_zombie                  channel.c:2371
  #3 ms_kick                      m_kick.c:456
freed by thread T0 here:
  #1 destruct_channel             channel.c:501
  #2 sub1_from_channel            channel.c:440
  #3 remove_user_from_channel     channel.c:987   (all-zombies sweep)
  #4 bounce_sync_alias_part       bouncer_session.c:6936
  #5 remove_user_from_channel     channel.c:967
  #6 make_zombie                  channel.c:2371
```
**Root cause.** `make_zombie` marks the kicked primary as a zombie, then calls
`remove_user_from_channel(primary)`. Before removing the primary's own
membership, that first calls `bounce_sync_alias_part` (`channel.c:967`), which
removes each alias with a recursive `remove_user_from_channel`. In the inner
call, after the alias's membership goes, the only member left is the zombie
primary, so the `channel_all_zombies` sweep (`channel.c:980-987`) removes it too
and `sub1_from_channel` destroys the channel. Back in the outer call,
`remove_member_from_channel(member)` (`channel.c:974`) writes through the freed
`Membership`/`Channel`.

**Reachability.** Any KICK of a bouncer primary (by services, a chanop, or a
server) in a channel where the session's own connections are the only members.
That is the normal state of a user idling in their own channel or a
just-created one. Here the KICK came from the link the user is behind
(`make_zombie` case d). The local-primary branch (`MyUser(who)`) calls the same
`remove_user_from_channel` after `SetZombie`, so it should behave the same way
(not separately reproduced). Found in campaign 5 as a state-dependent crash, then rebuilt as the
4-line reproducer above. **Fix.** In `remove_user_from_channel`, remove the
member itself first and part the aliases afterwards, or make
`bounce_sync_alias_part` skip the all-zombies sweep (e.g. remove alias
memberships with `remove_member_from_channel` directly and let the outer call do
the sweep). Re-look up `find_member_link(chptr, cptr)` after the alias pass, and
hold a reference on `chptr` across it.

## F4 — empty BURST member: `base64toint("")` over-read

**Reproducer** `repro/burst_empty_member`
```
\x01AB B #x 1760000000 ABAAA,:vvvvvvvv
```
base64: `AUFCIEIgI3ggMTc2MDAwMDAwMCBBQkFBQSw6dnZ2dnZ2dnYK`
```
ERROR: AddressSanitizer: SEGV on unknown address 0x55e40e48b5b8
  #0 FindNServer  numnicks.c:218
  #1 findNUser    numnicks.c:243
  #2 ms_burst     m_burst.c:595
```
Second call site, `repro/mode_empty_client_param` (any chanop user on the peer):
```
\x01AB N n 2 1760000000 u h +i B]AAAB ABAAA :n
ABAAA C #c 1760000000
ABAAA M #c -o :
```
base64 `AUFCIE4gbiAyIDE3NjAwMDAwMDAgdSBoICtpIEJdQUFBQiBBQkFBQSA6bgpBQkFBQSBDICNjIDE3NjAwMDAwMDAKQUJBQUEgTSAjYyAtbyA6Cg==`.
The stack is `FindNServer numnicks.c:218 ← findNUser numnicks.c:243 ← mode_parse_client channel.c:4587`.
For remote sources, `mode_parse_client` passes the raw parameter to `findNUser`,
and an empty trailing parameter is `""`.

A third call site showed up during the campaigns (job log, ASan
stack-buffer-overflow READ in `base64toint numnicks.c:139 ← findNUser
numnicks.c:244 ← parse_server parse.c:2064`). The prefix of a line that is a
single character with no following space (e.g. `B`) is looked up with
`findNUser("B")`, which resolves server AB and then calls
`base64toint("B" + 1)`, reading past the end of the 6-byte `numeric_prefix`
stack buffer. Whether it runs off the buffer depends on uninitialised stack
bytes and on what the reused line buffer holds after the NUL (a leftover space
at `ch[2]` takes the safe `FindNServer` path), so it did not reproduce
standalone. The root cause and the fix are the same.

**Root cause.** In the member `:vvvvvvvv`, `ms_burst` (`m_burst.c:513-514`) cuts
the nick at `:`, leaving `nick = ""`. `findNUser("")` → `FindNServer("")` →
`base64toint("")`. `base64toint` (`numnicks.c:138`) consumes `*s++` before it
tests for NUL, so it walks into the following bytes (`vvvvvvvv`). The resulting
index runs far past `server_list[4096]`, and the wild pointer read from there
is dereferenced. **Fix.** In `base64toint`, return 0 for an empty string (test
`*s` before consuming). In `findNUser` / `FindNServer`, reject lengths other
than 1–2 / 3 / 5. In `ms_burst`, skip empty nicks.

## F2 — `netride_modes` `strcmp(key, NULL)`

**Reproducer** `repro/burst_k_noarg` — `\x01AB B #x 1760000000 +k`
(base64 `AUFCIEIgI3ggMTc2MDAwMDAwMCArawo=`)
```
ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000
  #0 strcmp
  #1 netride_modes  m_burst.c:125
  #2 ms_burst       m_burst.c:312
```
**Root cause.** `netride_modes` ignores its `parc` and does `strcmp(curr_key, *++parv)`.
For `+k` as the last parameter, `parv[parc]` is NULL. This runs for any channel
we don't have yet (`!chptr->creationtime`) or have with a newer TS. `+l` also
advances `parv` unchecked. **Fix.** Bounds-check against `parc` (`if (--parc <= 0) break;`).

## F3 — numeric command `000` → NULL `mptr`

**Reproducer** `repro/numeric_000` — `\x01AB 000 AKAAA :x` (base64 `AUFCIDAwMCBBS0FBQSA6eAo=`); also `repro/numeric_0slash` (`AB 0/: ...`)
```
ERROR: AddressSanitizer: SEGV on unknown address 0x000000000010
  #0 parse_server  parse.c:2247   (mptr->count++)
```
**Root cause.** `parse_server` sets `numeric = d0*100 + d1*10 + d2` (only the
first char is checked with `IsDigit`), and `mptr = NULL`. It then dispatches
with `if (numeric) return do_numeric(...)`, so a numeric that evaluates to 0
falls through to `mptr->count++`. Inherited from ircu. **Fix.** Track
"is numeric" with a separate flag. Require all three chars to be digits and the
value to be in 1..999, otherwise drop the line.

## F7 — `ms_mark` reads `parv[2]` without a parc check

**Reproducer** `repro/mark_noargs` — `\x01AB MK x` (base64 `AUFCIE1LIHgK`)
```
ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000
  #0 strcmp
  #1 ms_mark   m_mark.c:112
```
**Fix.** `if (parc < 3) return need_more_params(sptr, "MARK");` before line 112.

## F8 — deop carrying an op-level → `modebuf_flush_int` NULL write

**Reproducer** `repro/mode_deop_oplevel`
```
\x01AB N n 2 1760000000 u h +i B]AAAB ABAAA :n
AB B #c 1760000000 ABAAA:o
AB M #c -o ABAAA:1
```
base64: `AUFCIE4gbiAyIDE3NjAwMDAwMDAgdSBoICtpIEJdQUFBQiBBQkFBQSA6bgpBQiBCICNjIDE3NjAwMDAwMDAgQUJBQUE6bwpBQiBNICNjIC1vIEFCQUFBOjEK`
```
ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000
  #0 addc / doprintf / ircd_snprintf  ircd_snprintf.c
  #3 modebuf_flush_int   channel.c:2870
  #4 modebuf_flush       channel.c:3193
  #5 ms_mode             m_mode.c:338
```
A second form, `repro/mode_deop_short_param` (`ABAAA M #c -o+v ABAA :notice`),
reaches the same NULL write by another route. `mode_parse_client` tests
`t_str[5] == ':'` without checking the parameter's length, so for the 4-char
`ABAA` it reads one byte past its terminator: the `:` that still opens the next
parameter. It then takes `atoi("notice")` = 0 as an op-level.
base64 `AUFCIE4gbiAyIDE3NjAwMDAwMDAgdSBoICtpIEJdQUFBQiBBQkFBQSA6bgpBQkFBQSBDICNjIDE3NjAwMDAwMDAKQUJBQUEgTSAjYyAtbyt2IEFCQUEgOm5vdGljZQo=`.

**Root cause.** For remote sources, `mode_parse_client` (`channel.c:4583-4586`) takes
`XXXXX:<n>` as an op-level in either direction. `modebuf_flush_int` sets
`strptro = strptro_i = NULL` for `MODE_DEL` (`channel.c:2856-2859`), but then
writes through `strptro_i` in the "chanop with known oplevel" branch
(`channel.c:2864-2871`), which doesn't check the direction. A chanop user on a
remote server can also send it (`-o` of another member). **Fix.** Guard the
second `ircd_snprintf` with `if (strptro)`, and ignore the `:level` suffix on
`MODE_DEL` for remote sources as is already done for local ones.

## F11 — server-sourced TOPIC without a setter field

**Reproducer** `repro/topic_from_server`
```
\x01AB N n 2 1760000000 u h +i B]AAAB ABAAA :n
AB B #c 1760000000 ABAAA
AB T #c :new topic
```
base64: `AUFCIE4gbiAyIDE3NjAwMDAwMDAgdSBoICtpIEJdQUFBQiBBQkFBQSA6bgpBQiBCICNjIDE3NjAwMDAwMDAgQUJBQUEKQUIgVCAjYyA6bmV3IHRvcGljCg==`
```
ERROR: AddressSanitizer: SEGV on unknown address 0x000000000058
  #0 my_strnlen / doprintf / ircd_snprintf   ircd_snprintf.c:1510
  #3 do_settopic   m_topic.c:149
  #4 ms_topic      m_topic.c:383
```
**Root cause.** `ms_topic` only takes a setter from `parv[parc-4]` when `parc > 5`.
Otherwise `do_settopic(sptr, ...)` builds `nick!user@host` from
`cli_user(from)` (`m_topic.c:148-149`, `FEAT_HOST_IN_TOPIC` defaults to TRUE).
For a server source that is NULL. Any linked server, one line, on any existing
channel. The fuzzer also reached it as `AB 4 #fuzz ...`, because the command
trie folds each byte with `& 31`, so `4` is `T` (`parse.c:1347`). Filtering
commands by their literal string does not catch such aliases. **Fix.** In
`do_settopic`, use `cli_name(from)` when `!cli_user(from)` (or require a setter
field from servers).

## F12 — server-sourced REHASH

**Reproducer** `repro/rehash_from_server` — `\x01AB RH` (base64 `AUFCIFJICg==`)
```
ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000
  #0 ms_rehash   m_rehash.c:210
```
**Root cause.** `ms_rehash` (`m_rehash.c:165-213`) assumes `sptr` is a user:
`cli_name(cli_user(sptr)->server)` at `:208` and `:210`. Nothing rejects a
server source. Note that once that is fixed, any remote source still triggers a
real `rehash()` of this server when `NETWORK_REHASH` is on (the default), with
no `IsOper` check on this side. That is a trust question for the operators,
not a crash. **Fix.** `if (!IsUser(sptr)) return protocol_violation(...)` at the
top. Consider requiring `IsOper(sptr)`.

## F13 — SERVER introduced by a user

**Reproducer** `repro/server_from_user`
```
\x01AB N n 2 1760000000 u h +i B]AAAB ABAAA :n
ABAAA S leaf.fuzz 2 1760000000 1793289405 J10 ACA]] +h6 :leaf
```
base64: `AUFCIE4gbiAyIDE3NjAwMDAwMDAgdSBoICtpIEJdQUFBQiBBQkFBQSA6bgpBQkFBQSBTIGxlYWYuZnV6eiAyIDE3NjAwMDAwMDAgMTc5MzI4OTQwNSBKMTAgQUNBXV0gK2g2IDpsZWFmCg==`
```
ERROR: AddressSanitizer: SEGV on unknown address 0x000000000008
  #0 add_dlink   list.c:713
  #1 ms_server   m_server.c:751   add_dlink(&(cli_serv(sptr))->down, acptr)
```
**Root cause.** `ms_server` never checks that `sptr` is a server, so
`cli_serv(sptr)` is NULL for a user prefix. The fuzzer hit it with a
5-byte prefix `ABAA\x11` that `findNUser` resolves to user ABAAA. **Fix.**
`if (!IsServer(sptr)) return protocol_violation(...)` (and squit the link).

## F14 — server-sourced WHOIS on a `+W` oper

**Reproducer** `repro/whois_from_server`
```
\x01AB N n 2 1760000000 u h +i B]AAAB ABAAA :n
ABAAA M n +oW
AB W :n
```
base64: `AUFCIE4gbiAyIDE3NjAwMDAwMDAgdSBoICtpIEJdQUFBQiBBQkFBQSA6bgpBQkFBQSBNIG4gK29XCkFCIFcgOm4K`
```
ERROR: AddressSanitizer: SEGV on unknown address 0x000000000058
  #0 my_strnlen / doprintf          ircd_snprintf.c:1510
  #4 msgq_vmake                     msgq.c:345
  #6 sendcmdto_one                  send.c
  #7 do_whois                       m_whois.c:353
  #8 ms_whois                       m_whois.c:617
```
**Root cause.** `ms_whois` accepts any source. `do_whois` tells a `+W` oper
target who asked, formatting `cli_user(sptr)->username/host`
(`m_whois.c:352-355`), and `cli_user(server)` is NULL. Other `send_reply(sptr, ...)`
calls in `do_whois` also assume a user asker. Opers commonly set `+W`, and the
target can be local or remote. **Fix.** In `ms_whois`, drop or reject
non-user sources: `if (!IsUser(sptr)) return 0;`.

## F10 — NUL in the prefix position

`parse_server` (`parse.c:2042-2070`) copies the prefix until space/NUL. With an
empty prefix it reports "Missing Prefix", uses `from = cptr`, and then
`do { ++ch; } while (*ch != ' ' && *ch);` steps *over* the NUL and keeps
parsing the bytes that follow. A line `\0AB N nick1 ...` is therefore handled as
a server-sourced `N`. This is memory-safe (the read stays inside `con_buffer`),
but it parses data past the string terminator and lets content hide behind a
NUL. **Fix.** `if (!*ch) return -1;` after the empty-prefix protocol_violation.

## U1 / U2 — undefined behaviour (no crash in production builds)

* `m_burst.c:577`: `level_increment = 10 * level_increment + ...` overflows `int`
  for long op-level digit runs (`ABAAA:99999999999`). The wrapped negative value
  skips the `oplevel > MAXOPLEVEL` clamp at `:581`, so a member can be given a
  negative op-level. Use `unsigned`, and clamp per digit.
* `numnicks.c:479`: `ntohs(...) << 16` is a signed-int overflow for every IPv4
  address >= 128.0.0.0. Cast to `unsigned int` first.

These were made non-fatal in the fuzz build (`-fsanitize-recover=shift,signed-integer-overflow`)
so they would not mask deeper bugs. `repro_ubsan_p10` (`build.sh ubsan`) keeps them fatal.

## Discarded / not reported

* No crash needed harness-only state. Every case above was re-derived as a
  short, clean, well-formed line sequence from the linked peer.
* Crash classes found only in the libFuzzer build and not reproducible in
  `repro_p10` were, on inspection, either the UBSan-only U1/U2 or state carried
  between inputs in one fork child (A1's hang). None is listed as a separate
  finding.

---

## Campaign statistics

4 cores, libFuzzer `-fork=4 -max_len=16384 -dict=p10.dict`, ASan+UBSan fuzz build.

| Campaign | Wall time (UTC) | Execs | Final cov (counters) | Corpus | Notes |
|---|---|---|---|---|---|
| 1 | 16:25–16:56 (31 min) | 154,769 | 26,710 | 3,551 | no filter; 310 crash artifacts; 3 of 4 children hung in `hSeekClient` (A1) for most of it |
| 2 | 16:57–17:17 (20 min) | 314,348 | 36,321 | 5,079 | known-bug filter on |
| 3 | 17:18–17:34 (16 min) | 417,580 | 44,574 | 5,935 | filter v2; found F11–F13 |
| 4 | 17:35–18:11 (36 min) | 805,524 | 48,998 | 7,059 | filter v3; found F14, F4/F8 variants |
| 5a | 18:23–18:34 (11 min) | 241,721 | 53,798 | 7,009 | harness: alice negotiates IRCv3 caps; found A2 |
| 5b | 18:34–19:09 (35 min) | 702,501 | 55,266 | 7,765 | stopped early (parent session: out of credits) |
| **Total** | **~149 min wall** | **~2.64 M** | **55,266 peak** | 7,291 after merge | |

**Shorter than asked.** The request was at least 3 hours of fuzzing. The
campaign was stopped at about 2 h 29 min when the parent session reported it
was out of cloud credits.

Throughput: 60–200 exec/s for the whole 4-core run (about 15–50 per core).
Each input does a real TCP accept, the PASS/SERVER handshake, our own outbound
burst, optional registration of two local users (MOTD, 005, CAP), RocksDB
history writes, and a full squit at reset. The figures sank as the corpus grew
toward longer bursts. Without local users a minimal input runs in about 0.4 ms
per core.

Corpus: `fuzz/p10/corpus.tar.xz` (7,291 files, 42 MB unpacked, 0.8 MB
compressed). This is `-merge=1` of the final corpus with the filter on. Unpack
with `mkdir corpus && tar -xJf fuzz/p10/corpus.tar.xz -C corpus`.

### Coverage (clang source coverage, `build.sh cov`, corpus after campaign 2)

A coverage report was only generated after campaign 2 (`llvm-cov report`).
Campaigns 3–5 added about 19k more counters (36k → 55k), mostly from local-user
delivery with caps, bouncer and mode paths, so the figures below understate the
final corpus.

Whole binary: 26.9% of lines (most of the ircd is client-facing). S2S handler
entry points, by function region coverage:

* well covered (>75%): `ms_burst` (file 97% lines), `ms_svsnick`, `ms_metadata` 91%,
  `ms_markread` 100%, `ms_redact` 89%, `ms_multiline` 84%, `ms_rename` 81%,
  `bounce_handle_bs` 80%, `bounce_handle_bt` 100%, BX `C`/`P`/`N`/`U`/`V`
  subhandlers 86–100%, `m_endburst.c` 86%, `parse.c` 68% lines
* partly covered: `ms_cacheinval` 70%, `ms_presencesync` 68%, `ms_quit` 56%,
  `bounce_alias_destroy` (BX X) 54%, `bounce_alias_echo` (BX E) 50%,
  `ms_batch` 49%, `bounce_alias_snomask` (BX K) 41%,
  `bounce_alias_multiline_echo` (BX M) 39%
* **weak / uncovered S2S paths:** `ms_tagmsg` 15% (needs a local recipient
  with `message-tags`; added in campaign 5 via alice's caps), `ms_svsjoin` 20%,
  `bounce_rebind_ghost_to_remote_primary` 0% (needs a local held ghost from
  BOUNCER_PERSIST restore), `m_webpush.c` 5% (webpush disabled: no libkc
  transport in the harness), `sasl_webhook.c` 9% (CI relay only; the Keycloak
  webhook listener is not started), `m_chathistory.c` 3% (client command; its
  S2S query path is small)

Seeds added for the weak spots: `batch_netjoin`, `tagmsg_locals`,
`svsjoin_part`, `multiline_locals` (run in campaign 5).

### Aside (not a P10 finding)

`m_cap.c:869`: `bsearch(..., subcmd_search)` passes a comparator whose type
does not match `int (*)(const void *, const void *)`. UBSan `-fsanitize=function`
reports it on every CAP line. It is harmless on x86-64 and only on the client
path; the check is off in the fuzz build.


## Harness / how to run

```
fuzz/p10/build.sh            # fuzz + asan builds (also: ubsan, cov)
fuzz/p10/run.sh 3600         # fork mode on all cores, dict, -max_len=16384
fuzz/p10/stop.sh             # stop a campaign
fuzz/p10/triage.sh <artifact-dir> [out]   # dedupe by sanitizer kind + top ircd frames
fuzz/p10/ddmin.py <input> <signature-regex>   # signature-preserving line minimizer
fuzz/p10/minimize.sh <out> <crash>...      # libFuzzer -minimize_crash (may drift class)
python3 fuzz/p10/gen_seeds.py fuzz/p10/seeds
```

* `fuzz_p10.c` links every ircd object; `ircd.c` is recompiled with
  `-Dmain=ircd_main`. No ircd source is modified. `os_send_nonb` /
  `os_sendv_nonb` are wrapped with `-Wl,--wrap` to discard output (and to read
  the registration PING cookie for local users).
* Per input: a real loopback TCP connection goes through `add_connection` on a
  `LISTEN_SERVER` listener, then `PASS`/`SERVER` through
  `recv_classify` → `connect_dopacket` → `mr_server` → `server_estab` (our
  burst is written and discarded). The input is then fed through `recv_classify`
  → `server_dopacket` → `parse_server`, as `read_packet` does. Byte 0 of the
  input selects post-burst (send `AB EB` first), a legacy peer (no `v`/`F`
  flags), a U-lined peer (`uhub.fuzz`), two registered local users (alice/bob in
  `#fuzz`), and running timers after the input.
* Reset: the link is squit with `exit_client`, local users are exited, and the
  client list is checked to be back to `&me` (`FUZZ_STRICT=1` aborts on a leak).
* RocksDB (history/metadata) runs for real in a per-process store on tmpfs
  (`/dev/shm/p10fuzz-store`, ~150 MB per process because of preallocation).
  Stores of crashed children are swept by pid (`sweep.sh`).
* `FUZZ_FILTER_KNOWN=1` (default in `run.sh`) drops input lines that match a
  confirmed finding above (`known_bug_line`), so later campaigns get past them.
  Turn it off (`FUZZ_FILTER_KNOWN=`) to rediscover them.
