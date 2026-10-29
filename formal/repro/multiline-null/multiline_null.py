import socket,time,sys
P=int(sys.argv[1])
def mk(n):
    s=socket.create_connection(("127.0.0.1",P)); s.settimeout(0.3)
    for l in ["CAP LS 302","CAP REQ :draft/multiline batch message-tags","NICK "+n,"USER u 0 * :r","CAP END"]: s.sendall((l+"\r\n").encode())
    return s
def rd(s,t=1.5):
    b=b""; e=time.time()+t
    while time.time()<e:
        try:
            d=s.recv(65536)
            if not d: return b.decode(errors="replace")+"\n<closed>"
            b+=d
        except socket.timeout: pass
    return b.decode(errors="replace")
a=mk("crash"); w=mk("watch"); time.sleep(1); rd(a); rd(w)
for s in (a,w): s.sendall(b"JOIN #c\r\n")
time.sleep(0.5); rd(a); rd(w)
for l in ["BATCH +r draft/multiline #c","@batch=r PRIVMSG #c :first","@batch=r PRIVMSG #c","@batch=r PRIVMSG #c :third","BATCH -r","PING alive"]:
    a.sendall((l+"\r\n").encode()); time.sleep(0.2)
ra=rd(a); rw=rd(w)
print("sender:", [l for l in ra.split("\r\n") if "PONG" in l or "FAIL" in l or "closed" in l])
print("watcher:"); [print("  ",l[:120]) for l in rw.split("\r\n") if "PRIVMSG" in l or "BATCH" in l]
