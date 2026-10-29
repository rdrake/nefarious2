import sys; sys.path.insert(0,'.'); from h import *
aliases = len(sys.argv)>1 and sys.argv[1]=="alias"
S=Services(); time.sleep(1.5)
A=client("alice"); A.drain(2.5); S.login("alice","alice"); time.sleep(0.4)
A.drain(3); A.send("OPER op op"); show("A",A.drain(2),r"381"); A.send("BOUNCER TOKEN"); al=A.drain(1); show("A",al)
token=[l for l in al if " 0 alice " in l or "BOUNCER" not in l and len(l.split())==5 and l.split()[1].isdigit()][-1].split()[-1]
A.send("JOIN #c"); A.drain(0.5)
W=client("watcher"); W.drain(2); W.send("JOIN #c"); W.drain(0.5)
if aliases:
    A2=client("alice2",sasl="alice"); show("A2",A2.drain(3),r"001|NICK|ERROR|BOUNC")
print("token",token)
A.send("QUIT :bye") if False else A.close()
time.sleep(1.5)
W.send("BOUNCER INFO"); W.send("WHOIS alice"); show("W",W.drain(1),r"31[1-9]|318|ERR|FAIL")
B=client("bob"); B.drain(2.5)
S.login("bob","alice"); time.sleep(0.5)
B.drain(3); B.send("OPER op op"); show("B",B.drain(2),r"381|491")
print("== BOUNCER RESUME", token)
B.send("BOUNCER RESUME "+token); show("B",B.drain(2))
show("W",W.drain(0.5))
W.send("NAMES #c"); W.send("WHOIS alice"); W.send("WHOIS bob"); show("W",W.drain(1))
B.send("BOUNCER INFO"); show("B",B.drain(1))
