import sys; sys.path.insert(0,'.'); from h import *
trigger = sys.argv[1]=="trigger"; wait=int(sys.argv[2])
S=Services(); time.sleep(1.5)
A=client("alice",tls=True,sasl="alice"); show("A",A.drain(3),r"001|90[34]")
A.send("JOIN #z"); A.drain(0.5); A.send("MODE #z +Z"); A.send("BOUNCER INFO"); show("A",A.drain(1),r"MODE|782|FAIL|4[0-9][0-9]")
W=client("watcher"); W.drain(2.5)
A.close(); time.sleep(1.5)
W.send("WHO alice"); show("W",W.drain(1),r" 35[2-5] |401")
if trigger:
    P=client("alice",sasl="alice"); show("P",P.drain(3.5))
    P.send("BOUNCER INFO"); show("P",P.drain(1),r"78[0-9]|FAIL|NOTE")
    W.send("WHO alice"); W.send("WHO #z"); show("W",W.drain(1),r" 35[2-5] ")
    P.send("QUIT :done"); P.drain(1.5); P.close(); time.sleep(1)
    W.send("WHO alice"); show("W",W.drain(1),r" 35[2-5] ")
t0=time.time()
while time.time()-t0<wait:
    time.sleep(10); W.send("WHO alice"); show("W",W.drain(1),r" 35[2-5] |401")
