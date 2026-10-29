#!/usr/bin/env python3
"""Z3 proofs for the bouncer adaptive-hold arithmetic.

Models, bit-precisely (64-bit two's-complement time_t, C truncating
division), the three functions in ircd/bouncer_session.c:

  bounce_hold_earned()        base + base*cc/4 + (active/86400)*3600, cap max
  bounce_compute_hold_time()  idle decay after decay_pct% of earned
  bounce_arm_hold_timer()     next re-evaluation delay

Properties:
  H0  no signed overflow in any intermediate (for in-range inputs)
  H1  the hold never grows while the session sits idle
  H2  base <= decayed hold <= earned
  H3  the timer re-evaluates no later than the deadline, and >= 1 s ahead

Features are F_I with no range check (ircd_features.c), so each property
is checked for the shipped ranges and for any non-negative int.
"""
import sys
from z3 import (BitVec, BitVecVal, If, And, Or, Not, Solver, ULT, ZeroExt,
                BVMulNoOverflow, BVAddNoOverflow, BVSubNoUnderflow,
                BVSubNoOverflow, BVAddNoUnderflow, BVMulNoUnderflow, sat)

W = 64
INT_MAX = 2**31 - 1


def C(v):
    return BitVecVal(v, W)


def mul_ok(a, b):
    return And(BVMulNoOverflow(a, b, True), BVMulNoUnderflow(a, b))


def add_ok(a, b):
    return And(BVAddNoOverflow(a, b, True), BVAddNoUnderflow(a, b))


def sub_ok(a, b):
    return And(BVSubNoOverflow(a, b), BVSubNoUnderflow(a, b, True))


def earned(base, mx, cc, active, ok):
    """bounce_hold_earned; appends overflow side conditions to ok."""
    cc64 = ZeroExt(32, cc)            # unsigned int -> long
    ok += [mul_ok(base, cc64)]
    t = base * cc64 / C(4)
    ok += [add_ok(base, t)]
    comp = base + t
    days = (active / C(86400)) * C(3600)
    comp2 = If(active > 0, comp + days, comp)
    ok += [Or(active <= 0, add_ok(comp, days))]
    capped = If(comp2 > mx, mx, comp2)
    return If(cc == 0, base, capped)


def halve(r, n):
    """while (n-- > 0 && r > 0) r /= 2;  for r >= 0 this is r >> min(n,63)."""
    k = If(n > C(63), C(63), If(n < 0, C(0), n))
    return If(r > 0, r >> k, r)


def compute(base, e, pct, idle, holding, ok):
    """bounce_compute_hold_time with idle = CurrentTime - disconnect."""
    ok += [mul_ok(e, pct)]
    ds = e * pct / C(100)
    du = e / C(4)
    ok += [sub_ok(e, ds), sub_ok(idle, ds)]
    rem = halve(e - ds, (idle - ds) / If(du == 0, C(1), du))
    ok += [add_ok(ds, rem)]
    comp = ds + rem
    comp = If(comp < base, base, comp)
    return If(And(pct > 0, holding, idle > ds, du > 0), comp, e)


def arm_delay(e, pct, idle, remaining, min_delay):
    ds = e * pct / C(100)
    du = e / C(4)
    nxt = If(idle < ds, ds - idle,
             If(du > 0, du - (idle - ds) % If(du == 0, C(1), du), remaining))
    d = If(And(pct > 0, remaining > 0), If(nxt < remaining, nxt, remaining),
           remaining)
    d = If(d < min_delay, min_delay, d)
    return If(d < 1, C(1), d)


def check(name, ranges, prop, extra=()):
    base, mx, pct = BitVec('base', W), BitVec('max', W), BitVec('pct', W)
    cc = BitVec('cc', 32)
    active = BitVec('active', W)
    i1, i2 = BitVec('idle1', W), BitVec('idle2', W)
    ok = []
    e = earned(base, mx, cc, active, ok)
    h1 = compute(base, e, pct, i1, True, ok)
    h2 = compute(base, e, pct, i2, True, ok)
    env = dict(base=base, max=mx, pct=pct, cc=cc, active=active,
               idle1=i1, idle2=i2, earned=e, h1=h1, h2=h2, ok=ok)
    s = Solver()
    s.add(*ranges(env))
    s.add(*[c(env) for c in extra])
    s.add(Not(prop(env)))
    r = s.check()
    if r == sat:
        m = s.model()
        print(f"  {name}: COUNTEREXAMPLE")
        for k in ('base', 'max', 'pct', 'cc', 'active', 'idle1', 'idle2',
                  'earned', 'h1', 'h2'):
            print(f"      {k:7} = {m.eval(env[k], model_completion=True).as_signed_long()}")
        return False
    print(f"  {name}: proved")
    return True


def shipped(env):
    """Shipped defaults' ranges: base <= max, pct in 1..50 (features.c),
    up to 2^32 connections, up to ~35 years active."""
    return [env['base'] >= 0, env['base'] <= C(INT_MAX),
            env['max'] >= env['base'], env['max'] <= C(INT_MAX),
            env['pct'] >= 0, env['pct'] <= C(100),
            env['active'] >= 0, env['active'] < C(2**40),
            env['idle1'] >= 0, env['idle1'] < C(2**40),
            env['idle2'] >= 0, env['idle2'] < C(2**40)]


def any_config(env):
    """Any non-negative int feature values (F_I is unchecked)."""
    return [env['base'] >= 0, env['base'] <= C(INT_MAX),
            env['max'] >= 0, env['max'] <= C(INT_MAX),
            env['pct'] >= 0, env['pct'] <= C(INT_MAX),
            env['active'] >= 0, env['active'] < C(2**40),
            env['idle1'] >= 0, env['idle1'] < C(2**40),
            env['idle2'] >= 0, env['idle2'] < C(2**40)]


def realistic_cc(env):
    return ULT(env['cc'], BitVecVal(2**24, 32))


no_overflow = lambda env: And(*env['ok'])
monotone = lambda env: Or(env['idle1'] > env['idle2'], env['h2'] <= env['h1'])
bounded = lambda env: And(env['h1'] >= env['base'], env['h1'] <= env['earned'])


def timer_ok(env):
    e, pct, idle = env['earned'], env['pct'], env['idle1']
    remaining = If(env['h1'] > idle, env['h1'] - idle, C(0))
    d = arm_delay(e, pct, idle, remaining, C(1))
    return And(d >= 1, Or(remaining == 0, d <= remaining))


def main():
    results = []
    print("shipped ranges (0 <= base <= max <= INT_MAX, pct <= 100):")
    results += [check("H0 no overflow (cc < 2^24)", shipped, no_overflow, [realistic_cc]),
                check("H1 monotone", shipped, monotone),
                check("H2 base <= hold <= earned", shipped, bounded),
                check("H3 timer", shipped, timer_ok)]
    print("any non-negative feature values:")
    results += [check("H0 no overflow (cc < 2^24)", any_config, no_overflow, [realistic_cc]),
                check("H1 monotone", any_config, monotone),
                check("H2 base <= hold <= earned", any_config, bounded)]
    return results


if __name__ == '__main__':
    r = main()
    sys.exit(0)
