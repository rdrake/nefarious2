# Fake peer: accept the ircd's outbound connect, stall, wait for a go-file, then complete the handshake.
import socket,time,sys,os
L=int(sys.argv[1]); go=sys.argv[2]
srv=socket.socket(); srv.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); srv.bind(("127.0.0.1",L)); srv.listen(1)
srv.settimeout(40)
c,_=srv.accept(); c.settimeout(0.5); print("  ircd connected to us", flush=True)
end=time.time()+30
while not os.path.exists(go) and time.time()<end: time.sleep(0.2)
now=int(time.time())
c.sendall(f"PASS :pw\r\nSERVER fake.example.net 1 {now} {now} J10 AB]]] +s6 :fake\r\n".encode())
buf=b""; e=time.time()+3
while time.time()<e:
    try:
        d=c.recv(65536)
        if not d: print("  link closed by ircd"); break
        buf+=d
    except socket.timeout: pass
    except ConnectionResetError: print("  link reset"); break
print("  ircd sent:", [l[:50] for l in buf.decode(errors="replace").split("\r\n") if l][:4], flush=True)
# second attempt: complete immediately and report whether we linked
try:
    c2,_=srv.accept(); c2.settimeout(0.5); now=int(time.time())
    c2.sendall(f"PASS :pw\r\nSERVER fake.example.net 1 {now} {now} J10 AB]]] +s6 :fake\r\nAB EB\r\n".encode())
    buf=b""; e=time.time()+3
    while time.time()<e:
        try:
            d=c2.recv(65536)
            if not d: break
            buf+=d
        except socket.timeout: pass
    print("  retry linked:", " EB" in buf.decode(errors="replace"), flush=True)
except Exception as ex: print("  no retry:", ex)
