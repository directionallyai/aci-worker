import json, socket, struct, sys, time
ec = open("ec.pem").read(); rsa = open("rsa.pem").read()
guest = r'''
import ssl, http.client, time, marshal, hashlib, importlib.util, statistics
HOST = "10.0.2.2"
open("/tmp/ec.pem", "w").write(EC); open("/tmp/rsa.pem", "w").write(RSA)
def med(fn, n=3):
    ts = []
    for _ in range(n):
        t = time.perf_counter(); fn(); ts.append(time.perf_counter() - t)
    return statistics.median(ts), ts
def get_fresh(port, path, pem=None):
    def go():
        if pem:
            c = http.client.HTTPSConnection(HOST, port, timeout=60, context=ssl.create_default_context(cafile=pem))
        else:
            c = http.client.HTTPConnection(HOST, port, timeout=60)
        c.request("GET", path); r = c.getresponse(); body = r.read(); c.close(); return body
    return go
out = {}
def rec(label, fn, n=3):
    m, ts = med(fn, n); out[label] = m; print(f"{label:<52} {m:7.3f} s   runs={[round(x,3) for x in ts]}", flush=True)
rec("plain HTTP, fresh connection, 4 B", get_fresh(8080, "/tiny.txt"))
rec("HTTPS P-256 cert, fresh connection, 4 B", get_fresh(8443, "/tiny.txt", "/tmp/ec.pem"))
rec("HTTPS RSA-2048 cert, fresh connection, 4 B", get_fresh(8444, "/tiny.txt", "/tmp/rsa.pem"))
c = http.client.HTTPSConnection(HOST, 8443, timeout=60, context=ssl.create_default_context(cafile="/tmp/ec.pem"))
c.request("GET", "/tiny.txt"); c.getresponse().read()
def reuse():
    c.request("GET", "/tiny.txt"); c.getresponse().read()
rec("HTTPS P-256, 2nd request on the SAME connection", reuse)
src = get_fresh(8443, "/world_core.py", "/tmp/ec.pem")()
pyc = get_fresh(8443, "/world_core.pyc", "/tmp/ec.pem")()
print("world_core.py", len(src), "B | world_core.pyc", len(pyc), "B")
rec("HTTPS P-256 fresh GET world_core.py (68 KB)", get_fresh(8443, "/world_core.py", "/tmp/ec.pem"))
rec("HTTPS P-256 fresh GET world_core.pyc (72 KB)", get_fresh(8443, "/world_core.pyc", "/tmp/ec.pem"))
rec("sha256 of the source", lambda: hashlib.sha256(src).hexdigest())
rec("compile(source)", lambda: compile(src.decode(), "<world_core:live>", "exec"))
code_from_src = compile(src.decode(), "<world_core:live>", "exec")
rec("exec module body (from compiled source)", lambda: exec(code_from_src, {"__name__": "wc_a"}))
hdr_ok = []
def load_pyc():
    assert pyc[:4] == importlib.util.MAGIC_NUMBER, "magic mismatch"
    assert pyc[8:16] == importlib.util.source_hash(src), "source hash mismatch"
    return marshal.loads(pyc[16:])
rec("verify pyc header (magic+source_hash) + marshal.loads", load_pyc)
code_from_pyc = load_pyc()
rec("exec module body (from pyc)", lambda: exec(code_from_pyc, {"__name__": "wc_b"}))
print("guest python", __import__("sys").version.split()[0], "| guest magic", importlib.util.MAGIC_NUMBER.hex())
print("RESULT_JSON", __import__("json").dumps(out))
'''
code = f"EC = {ec!r}\nRSA = {rsa!r}\n" + guest
req = {"mode": "repl", "code": code, "world": False,
       "storage_grant": {"access_key_id": "x", "secret_access_key": "y", "bucket": "b", "endpoint": "http://127.0.0.1:1", "region": "auto"},
       "content_keys": []}
b = json.dumps(req).encode(); s = socket.create_connection(("127.0.0.1", 18701), timeout=900)
s.sendall(struct.pack(">I", len(b)) + b); h = b""
while len(h) < 4: h += s.recv(4 - len(h))
n = struct.unpack(">I", h)[0]; body = b""
while len(body) < n: body += s.recv(n - len(body))
r = json.loads(body)
print(r.get("stdout") or "")
if not r.get("ok"): print("ERROR:", str(r.get("error"))[-900:])
