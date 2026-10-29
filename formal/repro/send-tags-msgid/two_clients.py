import socket, time, sys, re
PORT=int(sys.argv[1])
class C:
    def __init__(s,nick,caps):
        s.n=nick; s.s=socket.create_connection(("127.0.0.1",PORT)); s.s.settimeout(0.3); s.buf=b""; s.log=[]
        s.send("CAP LS 302"); s.send("CAP REQ :"+caps); s.send("NICK "+nick); s.send("USER u 0 * :r")
        s.read(2.0); s.send("CAP END"); s.read(2.5)
    def send(s,l): s.s.sendall((l+"\r\n").encode())
    def read(s,t=1.0):
        end=time.time()+t; out=[]
        while time.time()<end:
            try: d=s.s.recv(65536)
            except socket.timeout: continue
            if not d: break
            s.buf+=d
            while b"\r\n" in s.buf:
                l,s.buf=s.buf.split(b"\r\n",1); l=l.decode(errors="replace")
                if l.startswith("PING") or " PING " in l.split(" ",2)[0:2]: pass
                out.append(l)
        s.log+=out; return out
def show(tag,lines,pat):
    for l in lines:
        if re.search(pat,l): print(f"  [{tag}] {l}")
caps="message-tags server-time batch labeled-response echo-message draft/chathistory draft/event-playback"
A=C("alice",caps); B=C("bob",caps)
print("== PING/PONG (B)"); B.send("PING x"); show("B",B.read(),r"PONG")
B.send("@label=p1 PING y"); show("B",B.read(),r"PONG|ACK")
A.send("JOIN #t"); A.read()
print("== JOIN (labeled, B)"); B.send("@label=j1 JOIN #t"); show("B",B.read(),r" JOIN "); show("A",A.read(),r" JOIN ")
print("== JOIN (unlabeled, B -> #u)"); A.send("JOIN #u"); A.read(); B.send("JOIN #u"); show("B",B.read(),r" JOIN "); show("A",A.read(),r" JOIN ")
print("== NICK (labeled, B)"); B.send("@label=n1 NICK bobby"); show("B",B.read(),r" NICK "); show("A",A.read(),r" NICK ")
print("== NICK (unlabeled, B)"); B.send("NICK bob2"); show("B",B.read(),r" NICK "); show("A",A.read(),r" NICK ")
print("== PART (+D delayed member, B)"); A.send("JOIN #d"); A.read(); A.send("MODE #d +D"); A.read()
B.send("JOIN #d"); show("B",B.read(),r" JOIN "); show("A",A.read(),r" JOIN ")
B.send("PART #d"); show("B",B.read(),r" PART "); show("A",A.read(),r" PART ")
print("== PART (normal, B from #t)"); B.send("PART #t"); show("B",B.read(),r" PART "); show("A",A.read(),r" PART ")
print("== CHATHISTORY #t (A)"); A.send("CHATHISTORY LATEST #t * 20"); show("A",A.read(1.5),r"JOIN|PART|NICK|FAIL|BATCH")
print("== PRIVMSG"); A.send("PRIVMSG #u :hi"); show("A",A.read(),r"PRIVMSG"); show("B",B.read(),r"PRIVMSG")
B.send("PRIVMSG alice :dm"); show("B",B.read(),r"PRIVMSG"); show("A",A.read(),r"PRIVMSG")
