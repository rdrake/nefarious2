#!/usr/bin/env python3
"""Summarise a TLC -dumpTrace json trace of BouncerConverge."""
import json, sys
t = json.load(open(sys.argv[1]))
states = [x[1] for x in t["counterexample"]["state"]]
def W(st):
    if isinstance(st, dict) and "w" in st: return st["w"]
    if isinstance(st, list): 
        for x in st:
            if isinstance(x, dict) and "w" in x: return x["w"]
    return st
def m2s(m):
    t=m["t"]
    if t=="N": return f"N(c{m['c']} nick{m['nick']} ts{m['ts']} kc{m['kc']} sid{m['sid']} src{m['src']})"
    if t=="BSC": return f"BSC(sid{m['sid']} tok{m['tok']} {m['st']} src{m['src']})"
    if t in("BSA","BSD"): return f"{t}(sid{m['sid']} c{m['c']} src{m['src']})"
    if t=="BSX": return f"BSX(sid{m['sid']})"
    if t=="BXC": return f"BXC(p{m['c']} a{m['c2']}@S{m['srv']} sid{m['sid']})"
    if t=="BXX": return f"BXX(c{m['c']}@S{m['srv']})"
    if t=="BXP": return f"BXP(old c{m['c']} new c{m['c2']} sid{m['sid']})"
    if t=="KILL": return f"KILL(c{m['c']})"
    return t
def seqs(x):
    if isinstance(x, dict): return x
    return x
def sess2s(s):
    if not s["ex"]: return "-"
    return f"sid{s['sid']}/tok{s['tok']} {s['st']} prim=c{s['prim']} als={s['als']} kc{s['kc']} org{s['org']}"
def views(w, s):
    out=[]
    vw=w["vw"][s]
    for i,v in enumerate(vw):
        if v["pres"]:
            out.append(f"c{i+1}{'(al->c'+str(v['ap'])+')' if v['al'] else ''}[sid{v['sid']},n{v['nick']}]")
    return " ".join(out)
def get(d,k):
    return d[k]
prev=None
for i,st in enumerate(states):
    w=W(st)
    line=f"--- {i+1}: "
    if prev is not None:
        act=[]
        if w["nc"]!=prev["nc"]: act.append("Login/revive")
        if w["lev"]!=prev["lev"]: act.append("LinkUp/Down "+str(w["up"]))
        if w["dis"]!=prev["dis"]: act.append("Disconnect/Expire")
        if not act:
            # find consumed queue
            for k in prev["q"]:
                pq=prev["q"][k]; nq=w["q"][k]
                if len(pq)>0 and (len(nq)==0 or nq[:len(pq)-1]!=pq[1:] or True):
                    if nq[:len(pq)-1]==pq[1:] and len(pq)>=1:
                        act.append(f"Deliver {k}: {m2s(pq[0])}"); break
        line+="; ".join(act)
    print(line)
    print("   kind:", w["kind"], " ts:", w["ts"], " kc:", w["kc"], " home:", w["home"], " bad:", w["bad"])
    for s in range(len(w["sess"])):
        print(f"   S{s+1}: sess {sess2s(w['sess'][s])} | view {views(w,s)}")
    qs={k:[m2s(m) for m in v] for k,v in w["q"].items() if v}
    if qs: print("   q:", qs)
    prev=w
