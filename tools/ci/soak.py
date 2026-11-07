#!/usr/bin/env python3
"""Soak two linked servers with ordinary traffic and bad actors.

    tools/ci/soak.py path/to/bindir SECONDS [WORKDIR]

Starts a hub and a leaf from BINDIR/ircd and links them.  For SECONDS it
keeps three kinds of traffic going:

 - Ordinary clients (40) on both servers: joins, parts, channel and
   private messages, notices, TAGMSG, topics, modes, nick changes, away,
   WHO/WHOIS/LIST, CHATHISTORY, SETNAME, quits and reconnects.  An oper on
   the hub SQUITs the leaf every few minutes and the leaf links back, so
   bursts and netjoins happen too.
 - Bad clients, each reconnecting after the server throws it out:
   flooders, slowloris connections that never finish a line, clients
   that never read (their sendq fills), byte fuzzers that send mutated
   and random lines, and capability abusers (CAP, AUTHENTICATE, BATCH,
   multiline, CHATHISTORY and tag edge cases).
 - A rogue server that links to the hub with the right password,
   introduces a few users and then sends a mix of real and mangled P10.
   The hub may drop it; it links again.

Every minute it prints each server's RSS and the traffic counters, and
how often the servers threw out each kind of bad actor.  It fails if a
server exits or stops answering, if a server does not stop on SIGTERM,
or if a sanitizer reports anything.  Sanitizer reports go to
WORKDIR/sanitizer.* (the servers close stderr once they are up).
"""
import json
import os
import random
import re
import select
import signal
import socket
import subprocess
import sys
import tempfile
import time

SEED = int(os.environ.get("SOAK_SEED", "1"))
rng = random.Random(SEED)
BASE_PORT = int(os.environ.get("SOAK_PORT", "16700"))

SERVERS = {
    "hub": dict(name="hub.soak", numeric=1, port=BASE_PORT + 1, sport=BASE_PORT + 11),
    "leaf": dict(name="leaf.soak", numeric=2, port=BASE_PORT + 2, sport=BASE_PORT + 12),
}
ROGUE = dict(name="rogue.soak", numeric="AD", password="roguepw")

CONF = """General {{ name = "{name}"; description = "soak"; numeric = {numeric}; }};
Admin {{ Location = "soak"; Contact = "soak"; }};
Class {{ name = "Users"; pingfreq = 90 seconds; sendq = 200000; recvq = 4000; maxlinks = 1000; }};
Class {{ name = "Server"; pingfreq = 30 seconds; connectfreq = 10 seconds; maxlinks = 5; sendq = 20000000; }};
Client {{ ip = "*"; class = "Users"; }};
Port {{ vhost = "127.0.0.1"; port = {port}; }};
Port {{ vhost = "127.0.0.1"; port = {sport}; server = yes; }};
Connect {{ name = "{peer}"; host = "127.0.0.1"; password = "soakpw"; port = {peer_sport};
          class = "Server"; hub; autoconnect = {autoconnect}; }};
{rogue_connect}
Operator {{ host = "*@*"; password = "$PLAIN$soakoper"; name = "soakoper"; class = "Users"; local = no; }};
Features {{
  "HUB" = "TRUE";
  "PPATH" = "{dir}/ircd.pid";
  "SSL_CERTFILE" = "{dir}/ircd.pem";
  "SSL_KEYFILE" = "{dir}/ircd.pem";
  "LOG" = "SYSTEM" "FILE" "{dir}/ircd.log";
  "LOG" = "SYSTEM" "LEVEL" "INFO";
  "NICKDELAY" = "0";
  "IPCHECK_CLONE_LIMIT" = "100000";
  "IPCHECK_CLONE_PERIOD" = "1";
  "TARGET_LIMITING" = "FALSE";
  "NOIDENT" = "TRUE";
  "MSGID" = "TRUE";
  "CAP_server_time" = "TRUE";
  "CAP_echo_message" = "TRUE";
  "CAP_batch" = "TRUE";
  "CAP_labeled_response" = "TRUE";
  "CAP_message_tags" = "TRUE";
  "CAP_away_notify" = "TRUE";
  "CAP_extended_join" = "TRUE";
  "CAP_setname" = "TRUE";
  "CAP_sasl" = "TRUE";
  "CAP_draft_chathistory" = "TRUE";
  "CAP_draft_message_redaction" = "TRUE";
  "CAP_draft_multiline" = "TRUE";
  "CAP_draft_read_marker" = "TRUE";
  "CAP_draft_metadata_2" = "TRUE";
  "CHATHISTORY_DB" = "{dir}/history";
  "CHATHISTORY_STORE" = "TRUE";
  "CHATHISTORY_PRIVATE" = "TRUE";
}};
"""
ROGUE_CONNECT = """Connect {{ name = "{name}"; host = "127.0.0.1"; password = "{password}"; port = 1;
          class = "Server"; leaf; autoconnect = no; }};"""

CHANNELS = ["#soak%d" % i for i in range(10)]
CAPS = ("message-tags server-time echo-message batch labeled-response away-notify "
        "extended-join setname draft/chathistory draft/message-redaction draft/multiline")
SANITIZER = re.compile(r"ERROR: (Address|Leak|Memory|Thread)Sanitizer|runtime error:")

stats = {"actions": 0, "reconnects": 0, "squits": 0, "bad_lines": 0, "rogue_links": 0,
         "rogue_lines": 0, "lines_in": 0}
kicked = {}  # why a server closed a bad actor -> count


def b64(n, width):
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789[]"
    out = ""
    for _ in range(width):
        out = alphabet[n & 63] + out
        n >>= 6
    return out


def reason(error):
    """The why of an ERROR, SQUIT or KILL line, without numbers or names."""
    if not error:
        return "closed without a reason"
    found = re.findall(r"\(([^()]*)\)", error)
    why = found[-1] if found else error.split(" :", 1)[-1]
    return re.sub(r"\d+", "N", why).strip()[:50]


def word():
    return rng.choice(["hello", "ünïcödé", "日本語", "\x02bold\x02", "\x0304red", "😀" * 3,
                       "x" * rng.randrange(1, 400)])


def mutate(line):
    """Flip, drop, duplicate or insert a few bytes of a line."""
    b = bytearray(line)
    for _ in range(rng.randrange(1, 6)):
        op = rng.random()
        i = rng.randrange(len(b) + 1)
        if op < 0.3 and b:
            b[min(i, len(b) - 1)] = rng.randrange(256)
        elif op < 0.5 and b:
            del b[min(i, len(b) - 1)]
        elif op < 0.7:
            b[i:i] = bytes([rng.choice(b" :@;=\\\x00\r\x01\xff\xc3")])
        elif op < 0.85:
            j = rng.randrange(len(b) + 1)
            b[i:i] = b[min(i, j):max(i, j)][:2000]
        else:
            b = b[:i]
    return bytes(b).replace(b"\n", b"")


class Conn:
    """A non-blocking line connection with PING handling."""

    def __init__(self, port, rcvbuf=None):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if rcvbuf:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, rcvbuf)
        s.settimeout(5)
        s.connect(("127.0.0.1", port))
        s.setblocking(False)
        self.sock = s
        self.buf = b""
        self.closed = False
        self.last_error = None

    def send(self, data):
        if self.closed:
            return
        try:
            self.sock.sendall(data)
        except (BlockingIOError, OSError):
            self.close()

    def line(self, text):
        self.send(text.encode("utf-8") + b"\r\n")

    def read(self):
        """Return complete lines; mark the connection closed at EOF."""
        try:
            data = self.sock.recv(262144)
        except BlockingIOError:
            return []
        except OSError:
            data = b""
        if not data:
            self.close()
            return []
        self.buf += data
        out = []
        while b"\n" in self.buf:
            raw, self.buf = self.buf.split(b"\n", 1)
            stats["lines_in"] += 1
            text = raw.rstrip(b"\r").decode("utf-8", "replace")
            if text.startswith("@"):
                text = text.split(" ", 1)[-1]
            parts = text.split(" ", 3)
            if text.startswith("ERROR ") or (len(parts) > 2 and parts[1] in ("SQ", "D")):
                self.last_error = text
            out.append(text)
        return out

    def close(self):
        if not self.closed:
            self.closed = True
            try:
                self.sock.close()
            except OSError:
                pass


class Client:
    """An ordinary user."""

    def __init__(self, idx):
        self.idx = idx
        self.conn = None
        self.next_at = 0.0
        self.start()

    def start(self):
        if self.conn:
            self.conn.close()
        self.server = rng.choice(["hub", "leaf"])
        self.nick = "s%d_%d" % (self.idx, rng.randrange(100000))
        self.registered = False
        self.chans = set()
        self.caps = rng.random() < 0.7
        try:
            self.conn = Conn(SERVERS[self.server]["port"])
        except OSError:
            self.conn = None
            self.next_at = time.monotonic() + 5
            return
        if self.caps:
            self.conn.line("CAP LS 302")
            self.conn.line("CAP REQ :" + CAPS)
        self.conn.line("NICK " + self.nick)
        self.conn.line("USER s 0 * :soak client")
        if self.caps:
            self.conn.line("CAP END")
        self.next_at = time.monotonic() + rng.uniform(3, 6)

    def restart(self):
        stats["reconnects"] += 1
        self.start()

    def fileno(self):
        return self.conn.sock

    def on_readable(self):
        for text in self.conn.read():
            if text.startswith("PING "):
                self.conn.line("PONG " + text[5:])
            elif re.match(r"^:\S+ 001 ", text):
                self.registered = True
            elif re.match(r"^:\S+ 43[23] ", text):
                self.nick = "s%d_%d" % (self.idx, rng.randrange(100000))
                self.conn.line("NICK " + self.nick)
        if self.conn.closed:
            self.restart()

    def tick(self, now):
        if self.conn is None or self.conn.closed:
            if now >= self.next_at:
                self.restart()
            return
        if now < self.next_at or not self.registered:
            return
        # One command every two to four seconds stays under fake lag.
        self.next_at = now + rng.uniform(2, 4)
        stats["actions"] += 1
        send = self.conn.line
        r = rng.random()
        ch = rng.choice(CHANNELS)
        mine = sorted(self.chans)
        if r < 0.10 or not mine:
            send("JOIN " + ch)
            self.chans.add(ch)
        elif r < 0.40:
            tag = "@+draft/reply=abc;+typing=done " if self.caps and rng.random() < 0.3 else ""
            send("%sPRIVMSG %s :%s %d" % (tag, rng.choice(mine), word(), stats["actions"]))
        elif r < 0.47:
            send("PRIVMSG s%d_%d :%s" % (rng.randrange(40), rng.randrange(100000), word()))
        elif r < 0.50:
            send("NOTICE %s :%s" % (rng.choice(mine), word()))
        elif r < 0.54 and self.caps:
            send("@+typing=active TAGMSG " + rng.choice(mine))
        elif r < 0.58:
            c = rng.choice(mine)
            send("PART %s :bye" % c)
            self.chans.discard(c)
        elif r < 0.62:
            send("TOPIC %s :%s" % (rng.choice(mine), word()))
        elif r < 0.66:
            send("MODE %s %s" % (rng.choice(mine), rng.choice([
                "+nt", "-t", "+b *!*@bad%d" % rng.randrange(50), "-b *!*@bad%d" % rng.randrange(50),
                "+l 100", "-l", "+k key", "-k key", "+e *!*@ok", "+v " + self.nick])))
        elif r < 0.70:
            self.nick = "s%d_%d" % (self.idx, rng.randrange(100000))
            send("NICK " + self.nick)
        elif r < 0.73:
            send(rng.choice(["AWAY :gone", "AWAY"]))
        elif r < 0.76:
            send(rng.choice(["WHO " + ch, "WHO s1*", "WHOIS s%d_*" % rng.randrange(40), "LIST",
                             "NAMES " + ch, "LUSERS", "MAP", "LINKS"]))
        elif r < 0.84 and self.caps:
            send(rng.choice([
                "CHATHISTORY LATEST %s * 50" % ch,
                "CHATHISTORY BEFORE %s timestamp=2030-01-01T00:00:00.000Z 20" % ch,
                "CHATHISTORY AFTER %s timestamp=2020-01-01T00:00:00.000Z 20" % ch,
                "CHATHISTORY TARGETS timestamp=2020-01-01T00:00:00.000Z timestamp=2030-01-01T00:00:00.000Z 10",
            ]))
        elif r < 0.87 and self.caps:
            send("SETNAME :soak %d" % rng.randrange(1000))
        elif r < 0.91:
            send("QUIT :cycling")
            self.conn.close()
        else:
            send("PING :soak%d" % stats["actions"])


VALID_CLIENT_LINES = [
    b"PRIVMSG #soak0 :hello there", b"JOIN #soak1,#soak2 key", b"MODE #soak0 +bl *!*@x 5",
    b"@+draft/reply=x;label=1 PRIVMSG #soak0 :x", b"TOPIC #soak0 :topic", b"WHO #soak0 %tcnf,42",
    b"CHATHISTORY LATEST #soak0 * 50", b"CHATHISTORY AROUND #soak0 msgid=abc 10",
    b"CHATHISTORY BETWEEN #soak0 timestamp=2020-01-01T00:00:00Z timestamp=2030-01-01T00:00:00Z 10",
    b"BATCH +a draft/multiline #soak0", b"@batch=a PRIVMSG #soak0 :line", b"BATCH -a",
    b"CAP REQ :draft/multiline batch", b"AUTHENTICATE PLAIN", b"AUTHENTICATE " + b"A" * 400,
    b"METADATA * SET avatar :x", b"MARKREAD #soak0 timestamp=2026-01-01T00:00:00.000Z",
    b"REDACT #soak0 msgid :why", b"MONITOR + a,b,c,d", b"SETNAME :x", b"TAGMSG #soak0",
    b"KICK #soak0 someone :bye", b"INVITE s1_1 #soak0", b"USERHOST a b c d e", b"ISON a b c",
]


class BadActor:
    """A client that misbehaves in one fixed way and reconnects when thrown out."""

    KINDS = ["flooder", "slowloris", "nonreader", "fuzzer", "capabuser", "churner"]

    def __init__(self, kind, idx):
        self.kind = kind
        self.idx = idx
        self.conn = None
        self.next_at = time.monotonic() + rng.uniform(5, 15)
        self.registered = False

    def fileno(self):
        return self.conn.sock

    def start(self):
        self.registered = False
        port = SERVERS[rng.choice(["hub", "leaf"])]["port"]
        try:
            self.conn = Conn(port, rcvbuf=4096 if self.kind == "nonreader" else None)
        except OSError:
            self.conn = None
            return
        nick = "%s%d_%d" % (self.kind[:4], self.idx, rng.randrange(1000))
        if self.kind == "slowloris":
            # Start registering and never finish a line.
            self.conn.send(b"NICK " + nick.encode())
            return
        if self.kind == "churner":
            if rng.random() < 0.5:
                self.conn.send(b"NICK " + nick.encode() + b"\r\nUSER")
            self.conn.close()
            return
        if self.kind == "capabuser":
            self.conn.line("CAP LS " + rng.choice(["302", "999999999999", "-1", "", "abc"]))
            self.conn.line("CAP REQ :" + " ".join(rng.choice(CAPS.split() + ["-batch", "bogus", "=", ""])
                                                  for _ in range(rng.randrange(1, 60))))
        self.conn.line("NICK " + nick)
        self.conn.line("USER b 0 * :bad actor")
        if self.kind == "capabuser":
            self.conn.line("CAP END")

    def on_readable(self):
        if self.kind == "nonreader" and self.registered:
            return  # never read again: the server's sendq for us fills up
        for text in self.conn.read():
            if text.startswith("PING "):
                self.conn.line("PONG " + text[5:])
            elif re.match(r"^:\S+ 001 ", text):
                self.registered = True
                if self.kind == "nonreader":
                    self.conn.line("JOIN " + ",".join(CHANNELS))
                    self.conn.line("LIST")
                    self.conn.line("WHO *")

    def tick(self, now):
        if self.conn is not None and self.conn.closed:
            why = "%s: %s" % (self.kind, reason(self.conn.last_error))
            kicked[why] = kicked.get(why, 0) + 1
            self.conn = None
            self.next_at = now + rng.uniform(1, 8)
        if self.conn is None:
            if now >= self.next_at:
                self.start()
            return
        if now < self.next_at:
            return
        c = self.conn
        if self.kind == "flooder":
            self.next_at = now + rng.uniform(5, 20)
            if self.registered:
                c.send(b"".join(b"PRIVMSG #soak%d :flood %d\r\n" % (rng.randrange(10), i)
                                for i in range(rng.randrange(20, 400))))
                stats["bad_lines"] += 1
        elif self.kind == "slowloris":
            self.next_at = now + rng.uniform(5, 30)
            c.send(bytes([rng.choice(b"abcdefgh ")]))
        elif self.kind == "nonreader":
            self.next_at = now + rng.uniform(1, 3)
            if self.registered:
                c.line("NAMES " + ",".join(CHANNELS))
        elif self.kind == "fuzzer":
            self.next_at = now + rng.uniform(0.5, 2)
            if rng.random() < 0.2:
                data = bytes(rng.randrange(256) for _ in range(rng.randrange(1, 600)))
            else:
                data = mutate(rng.choice(VALID_CLIENT_LINES))
            c.send(data.replace(b"\n", b"") + rng.choice([b"\r\n", b"\n", b"\r", b""]))
            stats["bad_lines"] += 1
        elif self.kind == "capabuser":
            self.next_at = now + rng.uniform(1, 3)
            bid = rng.choice(["a", "b", "x" * 300, "", "-"])
            c.send(rng.choice([
                b"BATCH +%s draft/multiline #soak%d\r\n" % (bid.encode(), rng.randrange(10)),
                b"@batch=%s;draft/multiline-concat PRIVMSG #soak0 :%s\r\n" % (bid.encode(), b"y" * rng.randrange(600)),
                b"@batch=%s PRIVMSG #soak0 :\r\n" % bid.encode(),
                b"BATCH -%s\r\n" % bid.encode(),
                b"BATCH +n draft/multiline #soak0\r\nBATCH +m draft/multiline #soak0\r\n",
                b"AUTHENTICATE " + rng.choice([b"PLAIN", b"EXTERNAL", b"*", b"+", b"=" * 400, b"A" * 401]) + b"\r\n",
                b"CHATHISTORY " + rng.choice([b"LATEST", b"BEFORE", b"AFTER", b"AROUND", b"BETWEEN", b"TARGETS", b"X"])
                + b" #soak0 " + rng.choice([b"*", b"msgid=", b"msgid=" + b"=" * 40, b"timestamp=",
                                             b"timestamp=99999-99-99T99:99:99.999Z", b"timestamp=-1"])
                + b" " + rng.choice([b"0", b"-1", b"999999999999999999999", b"10"]) + b"\r\n",
                b"@" + b";".join(b"+k%d=%s" % (i, b"\\" * rng.randrange(20)) for i in range(rng.randrange(1, 200))) + b" TAGMSG #soak0\r\n",
                b"METADATA * SET " + b"k" * rng.randrange(400) + b" :" + b"v" * rng.randrange(2000) + b"\r\n",
                b"MARKREAD #soak0 timestamp=" + rng.choice([b"", b"x", b"2026-13-40T25:61:61Z"]) + b"\r\n",
                b"REDACT #soak0 " + rng.choice([b"", b"*", b"x" * 300]) + b" :reason\r\n",
                b"MONITOR + " + b",".join(b"m%d" % i for i in range(300)) + b"\r\n",
                b"CAP REQ :" + b"draft/multiline " * 60 + b"\r\n",
            ]))
            stats["bad_lines"] += 1


class RogueServer:
    """A linked server that sends mangled P10 among real P10."""

    def __init__(self, hub_numeric):
        self.hub = hub_numeric
        self.conn = None
        self.next_at = time.monotonic() + 20
        self.linked = False
        self.users = []

    def fileno(self):
        return self.conn.sock

    def start(self):
        try:
            self.conn = Conn(SERVERS["hub"]["sport"])
        except OSError:
            self.conn = None
            return
        now = int(time.time())
        me = ROGUE["numeric"]
        self.users = ["%sAA%s" % (me, b64(i, 1)) for i in range(4)]
        out = ["PASS :" + ROGUE["password"],
               "SERVER %s 1 %d %d J10 %s]]] +h6 :rogue soak server" % (ROGUE["name"], now, now, me)]
        for i, num in enumerate(self.users):
            out.append("%s N rogue%d 1 %d r rogue.host +i B]AAAB %s :rogue" % (me, i, now - 100, num))
        out.append("%s B #soak%d %d +nt %s:o" % (me, rng.randrange(10), now - 1000, self.users[0]))
        out.append("%s EB" % me)
        for l in out:
            self.conn.line(l)
        stats["rogue_links"] += 1
        self.linked = True

    def p10_line(self):
        me = ROGUE["numeric"]
        u = rng.choice(self.users)
        ch = rng.choice(CHANNELS)
        now = int(time.time())
        valid = [
            "%s P %s :rogue says %s" % (u, ch, word()),
            "%s J %s %d" % (u, ch, now),
            "%s L %s :bye" % (u, ch),
            "%s M %s +o %s" % (me, ch, u),
            "%s O s1_1 :notice" % u,
            "%s TM %s" % (u, ch),
            "@time=2026-01-01T00:00:00.000Z;msgid=abc %s P %s :tagged" % (u, ch),
            "%s T %s %d %d :rogue topic" % (u, ch, now, now),
            "%s N rogue%d %d" % (u, rng.randrange(1000), now),
            "%s A :away" % u,
            "%s G !%d.%d %s" % (me, now, 0, self.hub),
            "%s CH Z %s 1 :%s" % (me, self.hub, "=" * rng.randrange(1, 40)),
            "%s CH B %s 1 :%s" % (me, self.hub, "QUJD" * rng.randrange(1, 40)),
        ]
        line = rng.choice(valid).encode()
        r = rng.random()
        if r < 0.4:
            return line
        if r < 0.8:
            return mutate(line)
        if r < 0.803:  # rare: the hub drops a link for this, and the rogue has to relink
            return b"@" + b"x" * 9000 + b" AD G :a"
        return rng.choice([b"@a=b", b"@a=b ", b"@a=b :AD", b":", b"AD", b"AD ", b"ADAAA",
                           b"ZZ P #soak0 :unknown source",
                           b"AD D s1_1 :rogue kill", b"\x00\x01\x02",
                           bytes(rng.randrange(256) for _ in range(rng.randrange(1, 500)))])

    def on_readable(self):
        me = ROGUE["numeric"]
        for text in self.conn.read():
            parts = text.split()
            if len(parts) >= 3 and parts[1] == "G":  # ping from the hub
                self.conn.line("%s Z %s %s" % (me, parts[0], " ".join(parts[2:])))
            elif parts and parts[0] == "PING":
                self.conn.line("%s Z %s" % (me, " ".join(parts[1:])))

    def tick(self, now):
        if self.conn is not None and self.conn.closed:
            why = "rogue server: " + reason(self.conn.last_error)
            kicked[why] = kicked.get(why, 0) + 1
            self.conn = None
            self.next_at = now + rng.uniform(10, 30)
        if self.conn is None:
            if now >= self.next_at:
                self.start()
            return
        if now >= self.next_at:
            self.next_at = now + rng.uniform(0.2, 1.5)
            self.conn.send(self.p10_line().replace(b"\n", b"") + b"\r\n")
            stats["rogue_lines"] += 1


class Oper:
    """An oper on the hub who splits the leaf off now and then."""

    def __init__(self):
        self.conn = Conn(SERVERS["hub"]["port"])
        self.conn.line("NICK soakoper")
        self.conn.line("USER o 0 * :oper")
        self.next_squit = time.monotonic() + 240
        self.alive_token = None
        self.alive_sent = 0.0
        self.last_alive = time.monotonic()

    def fileno(self):
        return self.conn.sock

    def on_readable(self):
        for text in self.conn.read():
            if text.startswith("PING "):
                self.conn.line("PONG " + text[5:])
            elif re.match(r"^:\S+ 001 ", text):
                self.conn.line("OPER soakoper soakoper")
            elif self.alive_token and self.alive_token in text and " PONG " in " " + text:
                self.last_alive = time.monotonic()
                self.alive_token = None

    def tick(self, now):
        if self.conn.closed:
            raise RuntimeError("the oper's connection to the hub closed")
        if now >= self.next_squit:
            self.conn.line("SQUIT leaf.soak :soak netsplit")
            stats["squits"] += 1
            self.next_squit = now + rng.uniform(180, 360)
        if self.alive_token is None and now - self.alive_sent > 15:
            self.alive_token = "alive%d" % int(now)
            self.alive_sent = now
            self.conn.line("PING :" + self.alive_token)
        if now - self.last_alive > 120:
            raise RuntimeError("the hub has not answered a PING for two minutes")


def rss(pid):
    try:
        with open("/proc/%d/status" % pid) as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1])
    except OSError:
        return None


def start_servers(bindir, work):
    procs = {}
    env = dict(os.environ)
    for var in ("ASAN_OPTIONS", "UBSAN_OPTIONS"):
        opts = [o for o in env.get(var, "").split(":") if o and not o.startswith("log_path=")]
        env[var] = ":".join(opts + ["log_path=" + os.path.join(work, "sanitizer")])
    for key, s in SERVERS.items():
        d = os.path.join(work, key)
        os.makedirs(d, exist_ok=True)
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
                        "-subj", "/CN=" + s["name"], "-keyout", d + "/ircd.pem", "-out", d + "/cert.pem"],
                       check=True, capture_output=True)
        with open(d + "/ircd.pem", "a") as out, open(d + "/cert.pem") as cert:
            out.write(cert.read())
        peer = SERVERS["leaf" if key == "hub" else "hub"]
        with open(d + "/ircd.conf", "w") as f:
            f.write(CONF.format(dir=d, peer=peer["name"], peer_sport=peer["sport"],
                                autoconnect="yes" if key == "leaf" else "no",
                                rogue_connect=ROGUE_CONNECT.format(**ROGUE) if key == "hub" else "",
                                **s))
        log = open(d + "/output.log", "w")
        procs[key] = subprocess.Popen([os.path.join(bindir, "ircd"), "-n", "-d", d, "-f", d + "/ircd.conf"],
                                      stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, env=env)
    deadline = time.monotonic() + 30
    for s in SERVERS.values():
        while True:
            try:
                socket.create_connection(("127.0.0.1", s["port"]), 0.5).close()
                break
            except OSError:
                if time.monotonic() > deadline:
                    raise RuntimeError("%s did not open its port" % s["name"])
                time.sleep(0.2)
    return procs


def run(bindir, seconds, work):
    procs = start_servers(bindir, work)
    actors = []
    failure = None
    start = time.monotonic()
    next_sample = start
    samples = []
    oper = None
    try:
        while time.monotonic() - start < seconds:
            now = time.monotonic()
            for key, p in procs.items():
                if p.poll() is not None:
                    raise RuntimeError("%s exited with %s after %ds" % (key, p.returncode, now - start))
            elapsed = now - start
            normal = sum(1 for a in actors if isinstance(a, Client))
            if normal < 40 and elapsed > normal * 0.5:
                actors.append(Client(normal))
            elif normal >= 40 and not any(isinstance(a, BadActor) for a in actors):
                for i, kind in enumerate(BadActor.KINDS * 2):
                    actors.append(BadActor(kind, i))
                actors.append(RogueServer(b64(SERVERS["hub"]["numeric"], 2)))
            if oper is None and elapsed > 5:
                oper = Oper()
                actors.append(oper)
            live = [a for a in actors if a.conn is not None and not a.conn.closed]
            # A registered nonreader never drains its socket on purpose, so
            # its fd stays readable; keeping it in the select() set would
            # make select return at once on every pass and spin the loop.
            watch = [a.fileno() for a in live
                     if not (isinstance(a, BadActor) and a.kind == "nonreader" and a.registered)]
            if watch:
                readable, _, _ = select.select(watch, [], [], 0.05)
            else:
                time.sleep(0.05)
                readable = []
            ready = set(readable)
            for a in live:
                if a.fileno() in ready:
                    a.on_readable()
            for a in actors:
                a.tick(now)
            if now >= next_sample:
                sample = {"t": int(elapsed), **{k + "_rss_kb": rss(p.pid) for k, p in procs.items()},
                          "clients": sum(1 for a in actors if isinstance(a, Client) and a.registered
                                         and a.conn and not a.conn.closed),
                          **stats}
                samples.append(sample)
                print(json.dumps(sample), flush=True)
                next_sample += 60
    except Exception as e:
        failure = str(e)
    for a in actors:
        if a.conn is not None:
            a.conn.close()
    for key, p in procs.items():
        if p.poll() is None:
            p.send_signal(signal.SIGTERM)
    for key, p in procs.items():
        try:
            p.wait(60)
        except subprocess.TimeoutExpired:
            p.kill()
            failure = failure or "%s did not stop on SIGTERM" % key
    reports = ""
    for name in sorted(os.listdir(work)):
        if name.startswith("sanitizer."):
            reports += open(os.path.join(work, name), errors="replace").read()
    if SANITIZER.search(reports):
        sys.stdout.write(reports[-20000:])
        failure = failure or "sanitizer report from a server"
    with open(os.path.join(work, "samples.json"), "w") as f:
        json.dump(samples, f)
    print("thrown out:", json.dumps(dict(sorted(kicked.items(), key=lambda kv: -kv[1])), indent=1))
    print("soak:", "FAIL: " + failure if failure else "ok", json.dumps(stats))
    return 1 if failure else 0


def main():
    if len(sys.argv) not in (3, 4):
        sys.exit(__doc__)
    bindir, seconds = os.path.abspath(sys.argv[1]), int(sys.argv[2])
    if len(sys.argv) == 4:
        work = os.path.abspath(sys.argv[3])
        os.makedirs(work, exist_ok=True)
        return run(bindir, seconds, work)
    with tempfile.TemporaryDirectory(prefix="ircd-soak-") as work:
        return run(bindir, seconds, work)


if __name__ == "__main__":
    sys.exit(main())
