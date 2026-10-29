import sys; sys.path.insert(0,'.'); from h import *
S=Services(); time.sleep(1.5)
A=client("alice",sasl="alice"); show("A",A.drain(2.5),r"90[0-9]|BOUNCE|NOTE|FAIL|001")
A.send("JOIN #c"); A.send("OPER op op"); A.send("BOUNCER INFO"); show("A",A.drain(1.5))
