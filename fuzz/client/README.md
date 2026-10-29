# Client-protocol fuzz harness

A libFuzzer harness for the Nefarious IRCd **client** protocol — the untrusted
client→server surface: the read path (`read_packet` → `recv_classify` →
dbuf → `client_dopacket`/`connect_dopacket` → `parse_client`), message-tag
parsing, flood/fakelag and length limits, CAP/SASL/registration, and every
`m_*` client command including the IRCv3 fork features (CHATHISTORY, BATCH /
draft/multiline, METADATA, MARKREAD, REDACT, TAGMSG, WEBPUSH, BOUNCER,
PERSISTENCE, MONITOR/WATCH/SILENCE, WHO/WHOX, RENAME/RELOCATE, …).

No ircd source is modified to "fix" anything, and nothing is pushed to
`ircv3.2-upgrade`. Everything lives under `fuzz/client/`. The ircd objects are
built from a throwaway copy of the tree; `ircd.c`'s `main()` is renamed with
`objcopy` so libFuzzer's `main` can link; the network and Keycloak side effects
are cut at **link time** with `-Wl,--wrap`; and a fuzz-only source patch
(`freelist.patch`, applied only to the build copy) turns the custom object
freelists into real `malloc`/`free` so AddressSanitizer can see
use-after-free. The in-tree sources stay untouched.

## Files

| file | purpose |
|------|---------|
| `fuzz_client.c`   | the harness: startup replicated from `ircd.c`, fake local clients over socketpairs, the `--wrap` stubs, and `LLVMFuzzerTestOneInput` |
| `replay_main.c`   | `main()` for the non-libFuzzer `plain` build (replays crash files) |
| `fuzz.conf.in`    | fuzz `ircd.conf` (`@DIR@` is replaced with a temp dir at init) |
| `build.sh`        | builds the variants (see below) |
| `run.sh`          | runs a campaign (default 1 h) |
| `campaign.sh`     | minimal long-campaign launcher used for the committed corpus |
| `freelist.patch`  | fuzz-only: disable object freelists so ASan sees UAF |
| `client.dict` / `gen_dict.py` | libFuzzer dictionary + its generator |
| `gen_seeds.py`    | seed-corpus generator (one file per command family) |
| `lsan.supp`       | suppress the one-time RocksDB `DB::Open` allocation |
| `corpus/`         | committed, merged minimal corpus |
| `crashes/`        | confirmed reproducers (see `FINDINGS.md`) |
| `FINDINGS.md`     | confirmed issues + campaign stats |

## Build

Requirements (Debian/Ubuntu, clang 18):
```
apt-get install -y librocksdb-dev libzstd-dev libcmocka-dev libcurl4-openssl-dev \
  libjansson-dev libssl-dev libgit2-dev libmaxminddb-dev libgeoip-dev \
  flex bison autoconf automake libclang-rt-18-dev
```
```
./build.sh              # the main fuzz variant (ASan + UBSan + libFuzzer)
./build.sh fuzz ubsan plain cov
```
Variants:
* **fuzz** — ASan + UBSan (`-fno-sanitize-recover=undefined`) + libFuzzer, the
  freelist patch applied. The campaign driver. → `out/fuzz_client`
* **ubsan** — UBSan + `-fsanitize=integer` (minus unsigned-overflow/shift/
  implicit-conversion) without ASan, for low-noise integer-overflow signal.
  → `out/fuzz_client_ubsan`
* **plain** — ASan only, **no** libFuzzer and **no** freelist patch; links
  `replay_main.c`. Used to confirm a crash reproduces outside the fuzz
  configuration. → `out/fuzz_client_plain crash1 [crash2 …]`
* **cov** — libFuzzer + source-based coverage (`-fprofile-instr-generate
  -fcoverage-mapping`) for `llvm-cov` reports. → `out/fuzz_client_cov`

All variants are built with `-fno-sanitize=function` — see `FINDINGS.md` K-1
(a pre-existing `m_cap.c` function-pointer-cast issue, triaged elsewhere, that
would otherwise mask real findings).

`FAST=1 ./build.sh <variant>` relinks the harness against an already-built tree
(skips reconfigure/rebuild) — use it while iterating on `fuzz_client.c`.

## Run

```
./run.sh [seconds] [fuzz|ubsan]      # default 3600 s, variant fuzz
```
Uses `-fork=$(nproc)`, the dictionary, and `corpus/` + generated seeds; new
corpus entries go to `work/corpus`, crashes to `work/artifacts`.

## Input format

Byte 0 is a **mode** bitmask that sets up the client(s) before the scripted
lines run:

| bit | meaning |
|-----|---------|
| `0x01` | client A completes registration (NICK/USER, CAP END) |
| `0x02` | A negotiates every capability (`CAP REQ`) |
| `0x04` | A logs in with SASL PLAIN as `fuzzacct` |
| `0x08` | peer B exists: registered, logged in as `peeracct`, joined `#fuzz` |
| `0x10` | A opers up (`OPER fuzzoper …`) |
| `0x20` | A connects through a WebSocket listener (lines are WS-framed) |
| `0x40` | A also joins `#fuzz` after registering |

Bytes 1.. are `\n`-separated lines. A leading control byte redirects a line:

| byte | effect |
|------|--------|
| `0x01` rest | line sent by peer **B** |
| `0x02` N    | advance the clock by `N` seconds and run timers |
| `0x03`      | A's TCP connection drops (EOF) |
| `0x04`      | A reconnects (fresh connection + prelude) |
| `0x05` rest | raw bytes to A's socket (no CRLF, no WebSocket framing) |
| `0x06`      | B's TCP connection drops (EOF) |

Any other line is sent as-is from A, with `\r\n` appended (WS-framed when A is
a WebSocket client).

### How network / Keycloak are cut

`-Wl,--wrap` replaces, at link time:
* `os_get_peername` / `os_get_sockname` → fake inet endpoints (the socket is
  AF_UNIX; A and B get distinct IPs so per-IP accounting sees two hosts);
* `kc_http_request` / `kc_http_sync_perform` → immediate "no network";
* `kc_user_verify_password` → a Keycloak verdict without HTTP: password
  `fuzzpass` for accounts `fuzzacct` / `peeracct` / `fuzzalt` succeeds,
  everything else fails. Async verdicts are delivered from a 0-second ircd
  timer, i.e. on a later event-loop turn like a real HTTP completion.
* `kc_token_ensure` / `kc_jwt_prime_cache` → no-ops.

Outbound server writes go to the socketpair peer end and are drained/discarded
(verbose mode, `FUZZ_CLIENT_VERBOSE=1`, prints them to stderr).

### Env vars
* `FUZZ_CLIENT_CONF`    — path to `fuzz.conf.in` (default: next to the binary).
* `FUZZ_CLIENT_TMP`     — parent dir for each process's RocksDB/motd/pid dir.
* `FUZZ_CLIENT_VERBOSE` — echo server output to stderr.
* `FUZZ_CLIENT_KEEP_TMP`— don't delete the temp dir at exit.
* `FUZZ_CLIENT_NOSWEEP` — don't clear held bouncer ghosts between inputs
  (needed to reproduce the cross-connection state in F-1).
* `FUZZ_CLIENT_DUMP`    — print leftover `GlobalClientList` entries at the end
  of each input (debugging state leakage).
