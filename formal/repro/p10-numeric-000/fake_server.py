import socket,time,sys
P=int(sys.argv[1]); payload=sys.argv[2]
s=socket.create_connection(("127.0.0.1",P)); s.settimeout(0.5)
now=int(time.time())
def tx(l): s.sendall((l+"\r\n").encode())
tx("PASS :pw"); tx(f"SERVER fake.example.net 1 {now} {now} J10 AB]]] +s6 :fake")
buf=b""; end=time.time()+3
while time.time()<end:
    try:
        d=s.recv(65536)
        if not d: break
        buf+=d
    except socket.timeout: pass
lines=buf.decode(errors="replace").split("\r\n")
print("  linked:", any(" EB" in l for l in lines), "| first:", lines[0][:60])
tx("AB EB"); tx("AB EA"); time.sleep(0.5)
tx(payload); time.sleep(0.5); tx("AB G :alive?")
buf=b""; end=time.time()+2
while time.time()<end:
    try:
        d=s.recv(65536)
        if not d: print("  link closed by ircd"); break
        buf+=d
    except socket.timeout: pass
    except ConnectionResetError: print("  link reset"); break
print("  replies:", [l[:60] for l in buf.decode(errors="replace").split("\r\n") if l][:4])
