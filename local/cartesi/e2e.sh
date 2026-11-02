#!/bin/sh
# usage: e2e.sh <label> <guest command>
label="$1"; cmd="$2"; cd "${CARTESI_IMAGES:-$HOME/workspace/cartesi-worker/v0.21.0/images}"
docker rm -f cm-e2e >/dev/null 2>&1
T0=$(date +%s.%N)
docker run -d --name cm-e2e -p 127.0.0.1:18700:8700 -v "$PWD":/images:ro cartesi-me:0.21-local cartesi-machine --ram-image=/images/linux-6.5.13-ctsi-2-v0.21.0.bin --flash-drive=label:root,data_filename:/images/${IMG:-rootfs-worker.ext2} -n -p 0.0.0.0:8700:8700 -- "$cmd" >/dev/null
wait_for() { while ! docker logs cm-e2e 2>&1 | grep -q "$1"; do sleep 0.2; done; echo "[$label] $2: $(echo "$(date +%s.%N) - $T0" | bc | cut -c1-5) s"; }
wait_for "listening on" "start -> listening"
[ -n "$3" ] && wait_for "$3" "start -> $3"
python3 - "$label" <<'PY'
import socket, struct, json, time, sys
def call(code):
    req={"mode":"eval","code":code,"world":False,"storage_grant":{"access_key_id":"x","secret_access_key":"y","bucket":"b","endpoint":"http://127.0.0.1:1","region":"auto"},"content_keys":[]}
    t=time.time(); s=socket.create_connection(("127.0.0.1",18700),timeout=120)
    b=json.dumps(req).encode(); s.sendall(struct.pack(">I",len(b))+b); h=b""
    while len(h)<4: h+=s.recv(4-len(h))
    n=struct.unpack(">I",h)[0]; body=b""
    while len(body)<n: body+=s.recv(n-len(body))
    return round(time.time()-t,2), json.loads(body)
print(f"[{sys.argv[1]}] requests:", [ (t, r.get("result"), r.get("ok")) for t,r in (call("6*7") for _ in range(3)) ])
PY
docker rm -f cm-e2e >/dev/null 2>&1
