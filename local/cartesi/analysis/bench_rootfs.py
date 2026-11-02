"""Boots one root filesystem image in a Cartesi machine and measures it the same way every
time, so images (ext4, squashfs, erofs, compressed or not) can be compared.

  python3 bench_rootfs.py --label squashfs-zstd --image rootfs-worker-uv.squashfs

Reports: image size (apparent and on disk), the root mount as the guest sees it, boot to
listening, boot to warm worker ready, worldless request time, and real world request times
(the first one fills the world-code cache) using the caller's own storage grant and content
keys, built in memory and never printed. Needs the tracing-free warm worker in the image.
The root drive is mapped read-only and the guest mounts tmpfs for /tmp and /run.
"""
import argparse, importlib.machinery, importlib.util, json, os, socket, statistics as st, struct, subprocess, sys, time

ap = argparse.ArgumentParser()
ap.add_argument("--label", required=True)
ap.add_argument("--image", required=True, help="file name inside --dir (an .erofs, .squashfs or .ext2 root image)")
ap.add_argument("--dir", default=os.environ.get("CARTESI_IMAGES", os.path.expanduser("~/workspace/cartesi-worker/v0.22.0/images")))
ap.add_argument("--emu", default="cartesi-me:0.22-local")
ap.add_argument("--kernel", default="linux-6.18.56-ctsi-1.bin")
ap.add_argument("--port", type=int, default=18710)
ap.add_argument("--world-requests", type=int, default=4)
ap.add_argument("--ram-length", default=None, help="e.g. 256Mi")
ap.add_argument("--drive-extra", default="read_only", help="extra flash-drive keys, comma separated")
args = ap.parse_args()

NAME = f"cm-bench-{args.label}"[:60]
INIT = "mount -t tmpfs -o size=16m tmpfs /run; touch /run/resolv.conf; mount -o bind /run/resolv.conf /etc/resolv.conf"
CMD = ("mount -t tmpfs -o size=64m,mode=1777 tmpfs /tmp; "
       "WARM_CACHE_SCOPE=global WARM_LIB=/opt/worker-runtime/lib/python3.12/site-packages WARM_SOCKET=/tmp/w.sock "
       "/opt/worker-runtime/bin/python3.12 /opt/worker-runtime/warm_server.py & "
       "LOCAL_WARM_SOCKET=/tmp/w.sock LOCAL_LISTEN=0.0.0.0:8700 LOCAL_RUNTIME_DIR=/opt/worker-runtime LOCAL_SANDBOX=none /opt/bin/session_master_local")
sh = lambda *a: subprocess.run(a, capture_output=True, text=True)
logs = lambda: (lambda r: r.stdout + r.stderr)(sh("docker", "logs", NAME))

path = os.path.join(args.dir, args.image)
st_ = os.stat(path)
sh("docker", "rm", "-f", NAME)
cmd = ["docker", "run", "-d", "--name", NAME, "-p", f"127.0.0.1:{args.port}:8700", "-v", f"{args.dir}:/images:ro", args.emu,
       "cartesi-machine", f"--ram-image=/images/{args.kernel}",
       f"--flash-drive=label:root,data_filename:/images/{args.image}" + ("," + args.drive_extra if args.drive_extra else ""),
       "--append-bootargs=ro", f"--append-init={INIT}", "-n", "-p", "0.0.0.0:8700:8700"]
if args.ram_length: cmd.append(f"--ram-length={args.ram_length}")
cmd += ["--", CMD]
result = {"label": args.label, "image": args.image, "apparent_mb": round(st_.st_size / 2**20, 1), "disk_mb": round(st_.st_blocks * 512 / 2**20, 1)}
t0 = time.time(); started = sh(*cmd)
if started.returncode: sys.exit("docker run failed: " + started.stderr[-300:])
try:
    seen = {}
    for _ in range(300):
        text = logs()
        for key, marker in (("listening_s", "listening on"), ("ready_s", "warm worker ready")):
            if key not in seen and marker in text: seen[key] = round(time.time() - t0, 1)
        if "ready_s" in seen or "panic" in text.lower(): break
        time.sleep(0.5)
    result.update(seen)
    if "ready_s" not in seen:
        sys.exit("never became ready; console tail:\n" + "\n".join(logs().splitlines()[-12:]))

    def call(req, timeout=300):
        b = json.dumps(req).encode(); t = time.time(); s = socket.create_connection(("127.0.0.1", args.port), timeout=timeout)
        s.sendall(struct.pack(">I", len(b)) + b); h = b""
        while len(h) < 4: h += s.recv(4 - len(h))
        n = struct.unpack(">I", h)[0]; body = b""
        while len(body) < n: body += s.recv(n - len(body))
        return time.time() - t, json.loads(body)

    dummy = {"access_key_id": "x", "secret_access_key": "y", "bucket": "b", "endpoint": "http://127.0.0.1:1", "region": "auto"}
    probe = ("def kb(k):\n    return [int(l.split()[1]) // 1024 for l in open('/proc/meminfo') if l.startswith(k)][0]\n"
             "root = [l.split()[:4] for l in open('/proc/mounts') if l.split()[1] == '/'][0]\n"
             "fss = [l.split()[-1] for l in open('/proc/filesystems') if any(x in l for x in ('squashfs', 'erofs', 'ext4', 'ext2'))]\n"
             "import os\ns = os.statvfs('/')\n"
             "print(json.dumps({'root': root, 'fs_in_kernel': fss, 'mem_total_mb': kb('MemTotal:'), 'mem_avail_mb': kb('MemAvailable:'), 'root_used_mb': (s.f_blocks - s.f_bfree) * s.f_frsize // 2**20}))")
    _, r = call({"mode": "repl", "code": "import json\n" + probe, "world": False, "storage_grant": dummy, "content_keys": []})
    if r.get("ok"): result["guest"] = json.loads(r["stdout"])
    else: result["probe_error"] = str(r.get("error"))[-200:]
    times = [call({"mode": "eval", "code": "6*7", "world": False, "storage_grant": dummy, "content_keys": []})[0] for _ in range(5)]
    result["worldless_ms"] = round(st.median(times) * 1000)

    p = os.path.realpath(os.path.expanduser("~/.directionally/agent"))
    loader = importlib.machinery.SourceFileLoader("dagent", p)
    spec = importlib.util.spec_from_loader("dagent", loader); agent = importlib.util.module_from_spec(spec); loader.exec_module(agent)
    grant = agent._issue_storage_grant(agent.get_api_base()); keys = agent._load_content_keys_for_attested_request()
    world = []
    for _ in range(args.world_requests):
        t, r = call({"mode": "eval", "code": "str(world._kv.kv_get('directionally.notebook.head')[0])[:12]", "world": True,
                     "storage_grant": grant, "content_keys": keys})
        if not r.get("ok"): sys.exit("world request failed: " + str(r.get("error"))[-300:])
        world.append(round(t, 2))
    result["world_first_s"] = world[0]; result["world_warm_median_s"] = round(st.median(world[1:]), 2) if len(world) > 1 else None
    result["world_all_s"] = world
finally:
    sh("docker", "rm", "-f", NAME)
print(json.dumps(result))
