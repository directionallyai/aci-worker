"""Boots the uv image with the tracing warm worker, sends N real world requests with the
user's own grant/keys (built in memory, never printed), and analyses the TRACE lines."""
import importlib.machinery, importlib.util, json, os, socket, statistics as st, struct, subprocess, sys, time
N = int(sys.argv[1]) if len(sys.argv) > 1 else 7
IMG = os.environ.get("CARTESI_IMAGES", os.path.expanduser("~/workspace/cartesi-worker/v0.21.0/images"))
NAME = "cm-trace"
CMD = ("WARM_CACHE_SCOPE=global WARM_LIB=/opt/worker-runtime/lib/python3.12/site-packages WARM_SOCKET=/tmp/w.sock "
       "/opt/worker-runtime/bin/python3.12 /opt/worker-runtime/trace_server.py & "
       "LOCAL_WARM_SOCKET=/tmp/w.sock LOCAL_LISTEN=0.0.0.0:8700 LOCAL_RUNTIME_DIR=/opt/worker-runtime LOCAL_SANDBOX=none /opt/bin/session_master_local")
sh = lambda *a, **k: subprocess.run(a, capture_output=True, text=True, **k)
sh("docker", "rm", "-f", NAME)
sh("docker", "run", "-d", "--name", NAME, "-p", "127.0.0.1:18702:8700", "-v", f"{IMG}:/images:ro", "cartesi-me:0.21-local",
   "cartesi-machine", "--ram-image=/images/linux-6.5.13-ctsi-2-v0.21.0.bin",
   "--flash-drive=label:root,data_filename:/images/rootfs-worker-uv.ext2", "-n", "-p", "0.0.0.0:8700:8700", "--", CMD)
try:
    for _ in range(180):
        if "warm worker ready" in sh("docker", "logs", NAME).stdout + sh("docker", "logs", NAME).stderr: break
        time.sleep(1)
    path = os.path.realpath(os.path.expanduser("~/.directionally/agent"))
    loader = importlib.machinery.SourceFileLoader("dagent", path)
    spec = importlib.util.spec_from_loader("dagent", loader); agent = importlib.util.module_from_spec(spec); loader.exec_module(agent)
    grant = agent._issue_storage_grant(agent.get_api_base()); keys = agent._load_content_keys_for_attested_request()
    client = []
    for i in range(N):
        req = {"mode": "eval", "code": "str(world._kv.kv_get('directionally.notebook.head')[0])[:12]", "world": True,
               "profile": True, "storage_grant": grant, "content_keys": keys}
        b = json.dumps(req).encode(); t = time.time(); s = socket.create_connection(("127.0.0.1", 18702), timeout=300)
        s.sendall(struct.pack(">I", len(b)) + b); h = b""
        while len(h) < 4: h += s.recv(4 - len(h))
        n = struct.unpack(">I", h)[0]; body = b""
        while len(body) < n: body += s.recv(n - len(body))
        r = json.loads(body); client.append(time.time() - t)
        assert r.get("ok"), str(r.get("error"))[-300:]
        time.sleep(1.5)  # let the child's TRACE line flush
    logs = sh("docker", "logs", NAME); text = logs.stdout + logs.stderr
finally:
    sh("docker", "rm", "-f", NAME)

traces = {}
for line in text.splitlines():
    if line.startswith("TRACE "):
        d = json.loads(line[6:]); traces.setdefault(d["req"], {})[d["side"]] = d

def inside(events, outer):
    lo, hi = outer["at"], outer["at"] + outer["dur"] + 0.002
    return [e for e in events if e is not outer and e["kind"] in ("tcp", "tls", "wait", "body") and lo - 0.002 <= e["at"] and e["at"] + e["dur"] <= hi]

def http_stats(side):
    ev = side["events"]; calls = [e for e in ev if e["kind"] == "http"]; rows = []
    for c in calls:
        sub = {k: sum(e["dur"] for e in inside(ev, c) if e["kind"] == k) for k in ("tcp", "tls", "wait", "body")}
        sub["other"] = max(0.0, c["dur"] - sum(sub.values())); rows.append((c, sub))
    return rows

print(f"\n{'req':>3} {'client':>7} | {'parent wall':>11} {'cpu':>5} {'http#':>5} {'http s':>6} | {'child wall':>10} {'cpu':>5} {'http#':>5} {'http s':>6} | unexplained")
steady = []
for i in sorted(traces):
    p, c = traces[i].get("parent"), traces[i].get("child")
    if not (p and c): continue
    ph, ch = http_stats(p), http_stats(c); cl = client[i - 1]
    row = dict(client=cl, pw=p["wall"], pc=p["cpu"], pn=len(ph), ph=sum(x[0]["dur"] for x in ph), cw=c["wall"], cc=c["cpu"], cn=len(ch),
               ch=sum(x[0]["dur"] for x in ch), phases=c.get("phases", {}), prows=ph, crows=ch, prep=[e for e in p["events"] if e["kind"] == "prepare"][0]["dur"],
               read=[e for e in p["events"] if e["kind"] == "read"][0]["dur"])
    row["unexp"] = cl - p["wall"] - c["wall"]
    row["fork"] = (c["t_start"] - p["t_end"]) if c.get("t_start") and p.get("t_end") else float("nan")
    row["child_exit"] = (c["t_end"] - c["t_start"]) - c["wall"] if c.get("t_start") else float("nan")
    print(f"{i:>3} {cl:7.2f} | {p['wall']:11.2f} {p['cpu']:5.2f} {len(ph):5d} {row['ph']:6.2f} | {c['wall']:10.2f} {c['cpu']:5.2f} {len(ch):5d} {row['ch']:6.2f} | {row['unexp']:.2f}")
    if i >= 2: steady.append(row)
if not steady: sys.exit("no steady-state requests parsed")
m = lambda k: st.mean(r[k] for r in steady)
print(f"\nSTEADY STATE (requests 2..{len(traces)}, mean of {len(steady)}):")
print(f"  client wall                         {m('client'):6.2f} s")
print(f"  parent: read request                {m('read'):6.2f} s")
print(f"  parent: world-code prep (wall)      {m('prep'):6.2f} s   [cpu {m('pc'):.2f} s, http {m('ph'):.2f} s in {m('pn'):.1f} calls]")
print(f"  child:  total wall                  {m('cw'):6.2f} s   [cpu {m('cc'):.2f} s, http {m('ch'):.2f} s in {m('cn'):.1f} calls]")
print(f"  outside parent+child (unexplained)  {m('unexp'):6.2f} s   of which fork (parent done -> child running) {m('fork'):.3f} s; the rest is the client<->guest relay and the child's response write")
tot = {}
for r in steady:
    for rows in (r["prows"], r["crows"]):
        for c, sub in rows:
            for k, v in sub.items(): tot[k] = tot.get(k, 0) + v
print("  HTTP time by step, per request:     " + "  ".join(f"{k} {v/len(steady):.2f}s" for k, v in tot.items()))
print("  child phases (worker.handle):       " + "  ".join(f"{k} {st.mean(r['phases'].get(k, 0) for r in steady):.2f}" for k in sorted({k for r in steady for k in r['phases']}) if st.mean(r['phases'].get(k, 0) for r in steady) >= 0.01))
print("\nHTTP CALLS IN ONE STEADY REQUEST (request 3 if present):")
r = next((x for x in steady if x is steady[min(1, len(steady) - 1)]), steady[0])
for side, rows in (("parent", r["prows"]), ("child ", r["crows"])):
    for c, sub in rows:
        print(f"  {side} +{c['at']:5.2f}s {c['dur']:5.2f}s  {c['label']:<44} HTTP {c.get('status')}  tcp {sub['tcp']:.2f} tls {sub['tls']:.2f} wait {sub['wait']:.2f} body {sub['body']:.2f} other {sub['other']:.2f}")
