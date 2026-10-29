import socket,time,sys
s=socket.create_connection(("127.0.0.1",int(sys.argv[1]))); s.settimeout(0.5)
for l in ["CAP LS 302","CAP REQ :message-tags server-time","CAP REQ :-server-time bogus","CAP LIST","CAP NOSUCH","NICK capv","USER u 0 * :r","CAP END","PING z"]:
    s.sendall((l+"\r\n").encode()); time.sleep(0.2)
buf=b""; end=time.time()+2
while time.time()<end:
    try:
        d=s.recv(65536)
        if not d: break
        buf+=d
    except socket.timeout: pass
for l in buf.decode(errors="replace").split("\r\n"):
    if " CAP " in l or "PONG" in l or "ERROR" in l or " 410 " in l: print("  ",l[:160])
