import json, socket, struct
guest = r'''
import socket, ssl, time, http.client, os
def t(fn):
    s = time.perf_counter(); r = fn(); return time.perf_counter() - s, r
def req(c):
    c.request("HEAD", "/"); r = c.getresponse(); r.read(); return r.status
ctx = ssl.create_default_context()
print("default CA paths:", ssl.get_default_verify_paths().cafile, "|", ssl.get_default_verify_paths().capath)
if not ssl.get_default_verify_paths().cafile or not os.path.exists(ssl.get_default_verify_paths().cafile):
    ctx = ssl.create_default_context(cafile="/etc/ssl/certs/ca-certificates.crt"); print("using /etc/ssl/certs/ca-certificates.crt")
for host in ("fly.storage.tigris.dev", "github.com"):
    print("==", host)
    for i in (1, 2):
        d, ai = t(lambda: socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)); print(f"  getaddrinfo #{i}: {d:.3f} s ({len(ai)} addrs, first {ai[0][4][0]})")
    addr = ai[0][4]
    for i in (1, 2, 3):
        d1, sk = t(lambda: socket.create_connection(addr, timeout=30))
        d2, ss = t(lambda: ctx.wrap_socket(sk, server_hostname=host))
        c = http.client.HTTPSConnection(host, 443, timeout=30, context=ctx); c.sock = ss
        d3, resp = t(lambda: req(c))
        d4, resp2 = t(lambda: req(c))
        print(f"  fresh #{i}: tcp {d1:.3f} + tls {d2:.3f} + first HEAD {d3:.3f} (HTTP {resp}) | 2nd HEAD same conn {d4:.3f} | tls={ss.version()} cipher={ss.cipher()[0]}")
        c.close()
'''
req = {"mode": "repl", "code": guest, "world": False,
       "storage_grant": {"access_key_id": "x", "secret_access_key": "y", "bucket": "b", "endpoint": "http://127.0.0.1:1", "region": "auto"}, "content_keys": []}
b = json.dumps(req).encode(); s = socket.create_connection(("127.0.0.1", 18701), timeout=900)
s.sendall(struct.pack(">I", len(b)) + b); h = b""
while len(h) < 4: h += s.recv(4 - len(h))
n = struct.unpack(">I", h)[0]; body = b""
while len(body) < n: body += s.recv(n - len(body))
r = json.loads(body); print(r.get("stdout") or "")
if not r.get("ok"): print("ERROR:", str(r.get("error"))[-700:])
