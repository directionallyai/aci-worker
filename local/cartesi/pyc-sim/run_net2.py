import json, socket, struct
guest = r'''
import ssl, time, urllib.request, urllib.error, os
def t(fn):
    s = time.perf_counter(); r = fn(); return time.perf_counter() - s, r
d, _ = t(lambda: ssl.create_default_context()); print(f"ssl.create_default_context() (system defaults): {d:.3f} s | capath={ssl.get_default_verify_paths().capath} cafile={ssl.get_default_verify_paths().cafile}")
d, _ = t(lambda: ssl.create_default_context(cafile="/etc/ssl/certs/ca-certificates.crt")); print(f"ssl.create_default_context(cafile=bundle):     {d:.3f} s")
def hit():
    try:
        urllib.request.urlopen(urllib.request.Request("https://fly.storage.tigris.dev/", method="HEAD"), timeout=30).read()
    except urllib.error.HTTPError as e:
        e.read(); return e.code
for i in (1, 2, 3):
    d, code = t(hit); print(f"urllib.request.urlopen fresh HEAD to Tigris #{i}: {d:.3f} s (HTTP {code})")
'''
req = {"mode": "repl", "code": guest, "world": False,
       "storage_grant": {"access_key_id": "x", "secret_access_key": "y", "bucket": "b", "endpoint": "http://127.0.0.1:1", "region": "auto"}, "content_keys": []}
b = json.dumps(req).encode(); s = socket.create_connection(("127.0.0.1", 18701), timeout=900)
s.sendall(struct.pack(">I", len(b)) + b); h = b""
while len(h) < 4: h += s.recv(4 - len(h))
n = struct.unpack(">I", h)[0]; body = b""
while len(body) < n: body += s.recv(n - len(body))
r = json.loads(body); print(r.get("stdout") or "")
if not r.get("ok"): print("ERROR:", str(r.get("error"))[-600:])
