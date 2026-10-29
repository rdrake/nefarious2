# Live reproductions

These harnesses reproduced each finding against a sanitizer build of
`ircv3.2-upgrade`, and then showed the fix on its branch. They are the
evidence behind the fix PRs; see `../FINDINGS.md` for the ledger.

Some files still carry the absolute `/tmp/claude-0/...` paths of the
original runs (config `CHATHISTORY_DB`, SSL cert, run directory). Adjust
those before reuse.

## Common setup

- **Build.**
  ```
  git archive <branch> | tar -x -C <dir>
  autoreconf -fi
  CC=gcc CFLAGS="-g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer" \
    LDFLAGS="-fsanitize=address,undefined" ./configure --enable-debug \
    --with-maxcon=4096 --with-rocksdb=/usr --with-zstd=/usr --enable-keycloak
  make
  ```
  clang works too, but clang's `-fsanitize=function` aborts on the `m_cap.c`
  comparators until PR #3 is merged.
- **Run as root in a container.** ircd refuses to run as root, so
  `common/fakeuid.c` is an LD_PRELOAD shim that fakes the uid. Build it with
  `gcc -shared -fPIC -o fakeuid.so fakeuid.c`.
  - With gcc ASan, preload the ASan runtime first:
    `LD_PRELOAD="$(gcc -print-file-name=libasan.so) ./fakeuid.so"`.
  - Run the ircd in the foreground: `ircd -n -x 9 -d <rundir> -f <rundir>/ircd.conf`.
- **Config.** `common/ircd.conf.example` is a minimal config: one client
  port, `MSGID`, `NODNS`, `NOIDENT`, `CHATHISTORY_DB` and an SSL cert. The
  server-link reproductions append a `Class "Server"`, a `Connect` block and
  a `Port { server = yes; }`.

## Per finding

| Directory | Finding | PR | How it was driven |
|---|---|---|---|
| `hlc-msgid/` | HLC logical wrap mints duplicate msgids | #1 | `repro.c` links `crdt_hlc.c` (original or fixed) with `logstub.c`, pins `physical_ms` ahead of the wall clock and counts duplicate msgids |
| `send-tags-msgid/` | Own JOIN/PART/NICK echo carries the wrong msgid | #2 | `two_clients.py <port>`: two clients, labeled and +D JOIN/PART/NICK; compare the msgids each side sees |
| `m-cap-ubsan/` | CAP comparators called through the wrong type (clang UBSan abort) | #3 | `cap.py <port>` against a clang ASan+UBSan build |
| `multiline-null/` | `@batch=r PRIVMSG #c` with no text crashes the server | #6 | `multiline_null.py <port>`: a sender plus a watching client |
| `p10-numeric-000/` | A linked server's `000` line crashes the peer | #7 | Add Connect/Port blocks with password `pw`, then `fake_server.py <server-port> "AB 000 x"` |
| `rehash-handshake-uaf/` | A rehash during an outbound handshake causes a use-after-free | #8 | Connect block with `autoconnect = yes` to the port `stalling_peer.py <port> <go-file>` listens on; once it is connected, `kill -HUP` the ircd, then `touch <go-file>` |
| `geoip-continent/` | Unknown continent code reads past the table | #5 | `harness.c` + `stubs.c` link the real `ircd_geoip.o`; `fake.py` is a MARK-path driver |
| `static-ircu/` | IAuth `strtol(NULL)` and the `eol[-1]` read | #7 | ASan mirror harnesses of the two s_auth.c functions |
| `bouncer-live/` | Bouncer F1, F2, F6, plus the refused-resume duplicate nick | #9, #10 | `h.py` is a fake P10 services server (SASL relay and `AC R`) plus client helpers. Start the ircd with `start2.sh <holdsecs>` (`BIN=<ircd binary>`; `LDP=failadd.so` for F6), then run `f2.py` (BOUNCER RESUME use-after-free), `f1.py trigger <secs>` (+Z plaintext login) or `f6.py inject <secs>` (socket_add fault injection; `failadd.c` is the LD_PRELOAD shim) |

The CBMC, TLA+ and Z3 models have their own `run.sh` / `run_all.sh` under
`../cbmc`, `../tla` and `../z3`.
