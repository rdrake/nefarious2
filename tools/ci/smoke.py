#!/usr/bin/env python3
"""Boot a built ircd, drive a few clients through it, and stop it.

    tools/ci/smoke.py path/to/ircd

Fails when the server does not start, a client step times out, the
server stops answering after a batch of malformed lines, or the
server's output carries a sanitizer report.  Meant for CI on top of the
unit tests: it is the only check that runs the real event loop, the
parser and the channel code together, which matters most for the
sanitizer and hardened builds.
"""
import os
import re
import select
import signal
import socket
import subprocess
import sys
import tempfile
import time

PORT = int(os.environ.get("SMOKE_PORT", "16667"))
TIMEOUT = float(os.environ.get("SMOKE_TIMEOUT", "20"))

CONF = """General {{ name = "smoke.test"; description = "smoke"; numeric = 1; }};
Admin {{ Location = "ci"; Contact = "ci"; }};
Class {{ name = "Users"; pingfreq = 3 minutes; sendq = 160000; maxlinks = 100; }};
Client {{ ip = "*"; class = "Users"; }};
Operator {{ host = "*@*"; password = "$PLAIN$smokepass"; name = "smokeoper"; class = "Users"; local = no; }};
Port {{ vhost = "127.0.0.1"; port = {port}; }};
Features {{
  "PPATH" = "{dir}/ircd.pid";
  "SSL_CERTFILE" = "{dir}/ircd.pem";
  "SSL_KEYFILE" = "{dir}/ircd.pem";
  "CHATHISTORY_STORE" = "FALSE";
  "LOG" = "SYSTEM" "FILE" "{dir}/ircd.log";
  "LOG" = "SYSTEM" "LEVEL" "INFO";
}};
"""

SANITIZER = re.compile(r"ERROR: (Address|Leak|Memory|Thread)Sanitizer|runtime error:")


class ServerClosed(RuntimeError):
    pass


class Client:
    def __init__(self, nick, caps=()):
        self.nick = nick
        self.sock = socket.create_connection(("127.0.0.1", PORT), 5)
        self.sock.setblocking(False)
        self.buf = b""
        self.queue = []  # lines read but not yet consumed by expect()
        if caps:
            self.send("CAP LS 302")
            self.send("CAP REQ :" + " ".join(caps))
        self.send("NICK " + nick)
        self.send("USER %s 0 * :smoke test" % nick)
        if caps:
            self.send("CAP END")
        self.expect(r"^:\S+ 001 ")

    def send(self, line):
        self.sock.sendall(line.encode("utf-8", "surrogateescape") + b"\r\n")

    def send_raw(self, data):
        self.sock.sendall(data)

    def lines(self, wait):
        r, _, _ = select.select([self.sock], [], [], wait)
        if not r:
            return []
        data = self.sock.recv(65536)
        if not data:
            raise ServerClosed("%s: server closed the connection" % self.nick)
        self.buf += data
        out = []
        while b"\n" in self.buf:
            line, self.buf = self.buf.split(b"\n", 1)
            out.append(line.rstrip(b"\r").decode("utf-8", "replace"))
        return out

    def expect(self, pattern, timeout=TIMEOUT):
        rx = re.compile(pattern)
        deadline = time.monotonic() + timeout
        while True:
            # Drain any already-read lines first, so a line that shared a
            # recv() with the one we matched last time is not lost.
            while self.queue:
                line = self.queue.pop(0)
                if line.startswith("@"):  # match on the line without its tags
                    line = line.split(" ", 1)[-1]
                if line.startswith("PING "):
                    self.send("PONG " + line[5:])
                if rx.search(line):
                    return line
            if time.monotonic() >= deadline:
                raise RuntimeError("%s: no line matching %r within %ss" % (self.nick, pattern, timeout))
            self.queue.extend(self.lines(0.2))


def wait_for_port(proc):
    deadline = time.monotonic() + TIMEOUT
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError("ircd exited with %s during startup" % proc.returncode)
        try:
            socket.create_connection(("127.0.0.1", PORT), 0.2).close()
            return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError("ircd did not open port %d" % PORT)


def drive():
    a = Client("alice", caps=("message-tags", "server-time", "echo-message"))
    b = Client("bob")

    a.send("JOIN #smoke")
    a.expect(r" 366 alice #smoke ")
    b.send("JOIN #smoke")
    a.expect(r":bob!\S+ JOIN :?#smoke")
    b.expect(r" 366 bob #smoke ")

    a.send("MODE #smoke +nt")
    a.send("TOPIC #smoke :smoke test topic")
    b.expect(r" TOPIC #smoke :smoke test topic")
    a.send("PRIVMSG #smoke :hello from alice")
    b.expect(r":alice!\S+ PRIVMSG #smoke :hello from alice")
    a.expect(r"PRIVMSG #smoke :hello from alice")  # echo-message
    b.send("NOTICE alice :hi alice")
    a.expect(r":bob!\S+ NOTICE alice :hi alice")
    a.send("@+draft/react=x TAGMSG #smoke")
    a.send("WHO #smoke")
    a.expect(r" 315 alice #smoke ")
    a.send("WHOIS bob")
    a.expect(r" 318 alice bob ")
    b.send("NICK bobby")
    a.expect(r":bob!\S+ NICK :?bobby")
    # OPER checks the password on the thread pool; try a wrong one first.
    b.send("OPER smokeoper wrongpass")
    b.expect(r" 464 bobby ")
    b.send("OPER smokeoper smokepass")
    b.expect(r" 381 bobby ")

    # Malformed and oversized input must not take the server down.  It
    # comes from a third client: fake lag (or a flood kill) may hold it
    # back, and the others should not wait behind it.
    m = Client("mallory")
    for junk in (b"", b":", b": ", b"@", b"@ ", b"@;=;= ", b"@a=" + b"\\" * 600 + b" PING x",
                 b"PRIVMSG", b"PRIVMSG #smoke", b"MODE #smoke +" + b"bkl" * 100,
                 b"JOIN " + b"#a," * 300, b"\x00\x01\x02\xff\xfe", b"A" * 9000,
                 b"CAP LS 999999999999999999999", b"USER", b"NICK :"):
        m.send_raw(junk + b"\r\n")
    # Wait until the server has read all of it (it may also drop mallory).
    m.send("PING :junk-read")
    try:
        m.expect(r"PONG .*junk-read", timeout=90)
    except ServerClosed:
        pass
    a.send("PING :still-there")
    a.expect(r"PONG .*still-there")

    b.send("PART #smoke :bye")
    a.expect(r":bobby!\S+ PART #smoke")
    b.send("QUIT :done")
    a.send("QUIT :done")


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    ircd = os.path.abspath(sys.argv[1])
    with tempfile.TemporaryDirectory(prefix="ircd-smoke-") as d:
        # ssl_init() refuses to start without a certificate.
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                        "-subj", "/CN=smoke.test", "-days", "1",
                        "-keyout", os.path.join(d, "ircd.pem"),
                        "-out", os.path.join(d, "cert.pem")],
                       check=True, capture_output=True)
        with open(os.path.join(d, "ircd.pem"), "a") as pem, \
             open(os.path.join(d, "cert.pem")) as cert:
            pem.write(cert.read())
        conf = os.path.join(d, "ircd.conf")
        with open(conf, "w") as f:
            f.write(CONF.format(port=PORT, dir=d))
        out_path = os.path.join(d, "ircd.out")
        # The server closes stderr once it is up, so a sanitizer would
        # report into nothing; send its reports to files instead.
        env = dict(os.environ)
        for var in ("ASAN_OPTIONS", "UBSAN_OPTIONS"):
            opts = [o for o in env.get(var, "").split(":") if o and not o.startswith("log_path=")]
            env[var] = ":".join(opts + ["log_path=" + os.path.join(d, "sanitizer")])
        with open(out_path, "wb") as out:
            proc = subprocess.Popen([ircd, "-n", "-d", d, "-f", conf], env=env,
                                    stdin=subprocess.DEVNULL, stdout=out, stderr=out)
        failure = None
        try:
            wait_for_port(proc)
            drive()
        except Exception as e:  # report, then still stop the server
            failure = str(e)
        if proc.poll() is None:
            proc.send_signal(signal.SIGTERM)
            try:
                proc.wait(TIMEOUT)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
                failure = failure or "ircd did not exit on SIGTERM"
        elif failure is None:
            failure = "ircd exited early with %s" % proc.returncode
        output = open(out_path, "rb").read().decode("utf-8", "replace")
        for name in sorted(os.listdir(d)):
            if name.startswith("sanitizer."):
                output += open(os.path.join(d, name), "rb").read().decode("utf-8", "replace")
        if SANITIZER.search(output):
            failure = failure or "sanitizer report in the server output"
        if failure:
            sys.stdout.write(output[-20000:])
            sys.exit("smoke: FAIL: " + failure)
        print("smoke: ok")


if __name__ == "__main__":
    main()
