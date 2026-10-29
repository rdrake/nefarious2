import socket, ssl, time, threading, re, base64, sys
PORT=16667; SPORT=16697; LPORT=14400
class Conn:
    def __init__(s, sock, tag):
        s.s=sock; s.tag=tag; s.lines=[]; s.lock=threading.Lock(); s.closed=False
        threading.Thread(target=s._rd, daemon=True).start()
    def _rd(s):
        buf=b""
        while True:
            try: d=s.s.recv(65536)
            except Exception: d=b""
            if not d: s.closed=True; return
            buf+=d
            while b"\n" in buf:
                l,buf=buf.split(b"\n",1); l=l.rstrip(b"\r").decode(errors="replace")
                s.on(l)
    def on(s,l):
        with s.lock: s.lines.append(l)
        if l.startswith("PING "): s.send("PONG "+l[5:])
    def send(s,l):
        try: s.s.sendall((l+"\r\n").encode())
        except Exception as e: print(f"[{s.tag}] send fail {e}")
    def drain(s,t=0.8):
        time.sleep(t)
        with s.lock: out=s.lines; s.lines=[]
        return out
    def close(s):
        try: s.s.shutdown(socket.SHUT_RDWR)
        except Exception: pass
        s.s.close()
def show(tag,lines,pat=r"."):
    for l in lines:
        if re.search(pat,l): print(f"  [{tag}] {l}")
class Services(Conn):
    def __init__(s):
        sk=socket.create_connection(("127.0.0.1",LPORT)); s.nums={}; s.log=[]
        super().__init__(sk,"SV")
        t=int(time.time())
        s.send("PASS :pw"); s.send(f"SERVER svc.example.net 1 {t} {t} J10 SV]]] +s6 :svc")
        s.send("SV EB")
    def on(s,l):
        s.log.append(l)
        p=l.split(" ")
        if len(p)>1 and p[1]=="G": s.send("SV Z "+" ".join(p[2:]))
        if len(p)>1 and p[1]=="EB": s.send("SV EA")
        if len(p)>1 and p[1]=="N" and len(p)>8:
            num=l.split(" :")[0].split(" ")[-1]; s.nums[p[2]]=num
        elif len(p)>2 and p[1]=="N":
            for k,v in list(s.nums.items()):
                if v==p[0]: s.nums[p[2]]=v
        if len(p)>4 and p[1]=="SASL":
            tgt,tok,sub=p[2],p[3],p[4]; srv=tok.split("!")[0]
            if sub=="S": s.send(f"SV SASL {srv} {tok} C +")
            elif sub=="C":
                parts=base64.b64decode(p[5]).split(b"\0"); acct=parts[1].decode()
                s.send(f"SV SASL {srv} {tok} L {acct} {int(time.time())}")
                s.send(f"SV SASL {srv} {tok} D S")
    def login(s,nick,acct):
        s.send(f"SV AC {s.nums[nick]} R {acct} {int(time.time())}")
def client(nick, tls=False, sasl=None, caps="message-tags server-time batch"):
    sk=socket.create_connection(("127.0.0.1",SPORT if tls else PORT))
    if tls:
        ctx=ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
        sk=ctx.wrap_socket(sk)
    c=Conn(sk,nick)
    c.send("CAP LS 302")
    if sasl: caps+=" sasl"
    c.send("CAP REQ :"+caps); c.send("NICK "+nick); c.send("USER u 0 * :r")
    if sasl:
        time.sleep(0.5); c.send("AUTHENTICATE PLAIN"); time.sleep(0.5)
        c.send("AUTHENTICATE "+base64.b64encode(f"{sasl}\0{sasl}\0pw".encode()).decode())
        time.sleep(0.8)
    c.send("CAP END")
    return c
