#!/usr/bin/env python3
"""H1-H3 of bouncer_hold.py over mathematical integers.

bouncer_hold.py proves H0 (no 64-bit overflow) bit-precisely, so for the
same input ranges C arithmetic coincides with integer arithmetic and
truncating division of non-negatives is floor division.  Here every
division by a variable is replaced by its quotient q with
q*d <= n < (q+1)*d, and the halving loop (at most 63 rounds) is unrolled
over constant divisions, which keeps Z3 in a tractable fragment.

  H1  the hold never grows while the session sits idle
  H2  base <= decayed hold <= earned
  H3  bounce_arm_hold_timer re-evaluates in [1, remaining]

Each is checked with the shipped relation BOUNCER_MAX_HOLD >=
BOUNCER_SESSION_HOLD and without it (F_I features are unchecked).
"""
import sys
from z3 import Int, Ints, If, And, Or, Not, Solver, sat, unsat

MAXH = 63


def divq(s, name, n, d):
    """Fresh q = n / d for n >= 0, d > 0."""
    q = Int(name)
    s.add(q >= 0, q * d <= n, n < (q + 1) * d)
    return q


def halve(r, h):
    """r halved h times (h >= 0), r >= 0: the loop in
    bounce_compute_hold_time (it stops early once r is 0)."""
    vals = [r]
    for _ in range(MAXH):
        vals.append(vals[-1] / 2)
    out = vals[MAXH]
    for k in range(MAXH - 1, -1, -1):
        out = If(h == k, vals[k], out)
    return out


def hold(s, tag, base, e, pct, idle):
    """bounce_compute_hold_time for a HOLDING session idle for `idle`."""
    ds, du = Int('ds'), Int('du')
    q = divq(s, 'q' + tag, If(idle > ds, idle - ds, 0), If(du > 0, du, 1))
    comp = ds + halve(e - ds, q)
    comp = If(comp < base, base, comp)
    return If(And(pct > 0, idle > ds, du > 0), comp, e)


def setup(s, misconfig):
    base, mx, pct, cc, active = Ints('base max pct cc active')
    s.add(base >= 0, base <= 2**31 - 1, mx >= 0, mx <= 2**31 - 1)
    s.add(pct >= 0, pct <= 100, cc >= 0, cc < 2**24)
    s.add(active >= 0, active < 2**40)
    if not misconfig:
        s.add(mx >= base)
    comp = base + base * cc / 4 + If(active > 0, (active / 86400) * 3600, 0)
    e = Int('earned')
    s.add(e == If(cc == 0, base, If(comp > mx, mx, comp)))
    s.add(Int('ds') == e * pct / 100, Int('du') == e / 4)
    return base, pct, e


def h1(s, base, pct, e):
    i1, i2 = Ints('idle1 idle2')
    s.add(i1 >= 0, i2 >= i1, i2 < 2**40)
    a, b = Int('hold1'), Int('hold2')
    s.add(a == hold(s, '1', base, e, pct, i1), b == hold(s, '2', base, e, pct, i2))
    return b <= a


def h2(s, base, pct, e):
    i1 = Int('idle1')
    s.add(i1 >= 0, i1 < 2**40)
    a = Int('hold1')
    s.add(a == hold(s, '1', base, e, pct, i1))
    return And(a >= base, a <= e)


def h3(s, base, pct, e):
    idle = Int('idle1')
    s.add(idle >= 0, idle < 2**40)
    a = Int('hold1')
    s.add(a == hold(s, '1', base, e, pct, idle))
    ds, du = Int('ds'), Int('du')
    remaining = If(a > idle, a - idle, 0)
    k, r = Ints('k r')
    s.add(r >= 0, r < If(du > 0, du, 1), k >= 0,
          If(And(idle >= ds, du > 0), k * du + r == idle - ds, r == 0))
    nxt = If(idle < ds, ds - idle, If(du > 0, du - r, remaining))
    d = If(And(pct > 0, remaining > 0), If(nxt < remaining, nxt, remaining),
           remaining)
    d = If(d < 1, 1, d)
    return And(d >= 1, Or(remaining == 0, d <= remaining))


def run(name, misconfig, build):
    s = Solver()
    s.set('timeout', 300000)
    base, pct, e = setup(s, misconfig)
    s.add(Not(build(s, base, pct, e)))
    r = s.check()
    if r == unsat:
        print(f'  {name}: proved', flush=True)
        return True
    if r == sat:
        m = s.model()
        print(f'  {name}: COUNTEREXAMPLE', flush=True)
        for d in sorted(m.decls(), key=str):
            if not str(d).startswith('q'):
                print(f'      {d} = {m[d]}', flush=True)
        return False
    print(f'  {name}: unknown ({s.reason_unknown()})', flush=True)
    return None


def main():
    ok = True
    for misconfig in (False, True):
        print('any BOUNCER_MAX_HOLD (may be < BOUNCER_SESSION_HOLD):' if misconfig
              else 'BOUNCER_MAX_HOLD >= BOUNCER_SESSION_HOLD:', flush=True)
        for name, f in (('H1 hold never grows while idle', h1),
                        ('H2 base <= hold <= earned', h2),
                        ('H3 timer re-evaluates in [1, remaining]', h3)):
            ok = (run(name, misconfig, f) is True) and ok
    return ok


if __name__ == '__main__':
    sys.exit(0 if main() else 1)
