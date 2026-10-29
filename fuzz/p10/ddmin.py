#!/usr/bin/env python3
"""Signature-preserving line-based delta minimizer for fuzz_p10 inputs.

  ddmin.py <input> <signature-regex> [out]

Keeps the flag byte, then removes lines (ddmin), then trims bytes inside
the remaining lines, as long as bin/repro_p10 output still matches the
regex (e.g. 's_misc.c:469' or 'heap-use-after-free.*\\n.*ms_burst').
"""
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
BIN = os.environ.get("REPRO", os.path.join(HERE, "bin", "repro_p10"))
ENV = dict(os.environ)
ENV.setdefault("FUZZ_TMPDIR", "/dev/shm/p10fuzz-store")
ENV["ASAN_OPTIONS"] = "detect_leaks=0:detect_stack_use_after_return=1:symbolize=1"
ENV["UBSAN_OPTIONS"] = "print_stacktrace=1:halt_on_error=1"
os.makedirs(ENV["FUZZ_TMPDIR"], exist_ok=True)
TMP = "/dev/shm/ddmin.%d" % os.getpid()


def crashes(flag, lines, sig):
    with open(TMP, "wb") as f:
        f.write(flag + b"".join(lines))
    try:
        p = subprocess.run([BIN, TMP], env=ENV, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, timeout=60)
    except subprocess.TimeoutExpired:
        return False
    return re.search(sig, p.stdout.decode("latin-1"), re.S) is not None


def ddmin(flag, items, sig, test):
    n = 2
    while len(items) >= 2:
        chunk = max(1, len(items) // n)
        reduced = False
        for i in range(0, len(items), chunk):
            cand = items[:i] + items[i + chunk:]
            if cand and test(flag, cand, sig):
                items = cand
                n = max(n - 1, 2)
                reduced = True
                break
        if not reduced:
            if n >= len(items):
                break
            n = min(len(items), n * 2)
    return items


def main():
    src, sig = sys.argv[1], sys.argv[2]
    out = sys.argv[3] if len(sys.argv) > 3 else src + ".dd"
    data = open(src, "rb").read()
    flag, body = data[:1], data[1:]
    lines = body.splitlines(keepends=True)
    if not crashes(flag, lines, sig):
        sys.exit("input does not reproduce the signature")
    lines = ddmin(flag, lines, sig, crashes)
    # try clearing flag bits
    for bit in (0x10, 0x08, 0x04, 0x02, 0x01):
        if flag[0] & bit:
            f2 = bytes([flag[0] & ~bit])
            if crashes(f2, lines, sig):
                flag = f2
    # shrink each line by tokens
    for idx in range(len(lines)):
        toks = re.split(rb"( )", lines[idx].rstrip(b"\r\n"))
        def t(fl, cand, s, idx=idx):
            return crashes(fl, lines[:idx] + [b"".join(cand) + b"\n"] + lines[idx + 1:], s)
        toks = ddmin(flag, toks, sig, t)
        lines[idx] = b"".join(toks) + b"\n"
    with open(out, "wb") as f:
        f.write(flag + b"".join(lines))
    os.unlink(TMP)
    print("%s: %d -> %d bytes, %d lines" % (out, len(data), os.path.getsize(out), len(lines)))


if __name__ == "__main__":
    main()
