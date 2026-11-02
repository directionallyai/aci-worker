#!/bin/sh
# rootfs-worker-uv.ext2: the Cartesi Ubuntu base + the uv/python-build-standalone
# riscv64 runtime + session_master_local + warm_server.py. Unlike make-rootfs.sh
# it adds NO Ubuntu python packages, so nothing here can fall back to the
# system Python. Mounts: /work (rw; rootfs-ubuntu/), /artifacts (ro), /uvrt (ro;
# uv-runtime/out/runtime), /local (ro; aci-worker/local).
set -eu
SIZE_MB="${SIZE_MB:-512}"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null && apt-get install -y -qq e2fsprogs >/dev/null
rm -rf /work/stage-uv && cp -a /work/rootfs-ubuntu /work/stage-uv
mkdir -p /work/stage-uv/opt/bin
cp -a /uvrt /work/stage-uv/opt/worker-runtime
cp /local/warm_server.py /work/stage-uv/opt/worker-runtime/warm_server.py
chmod 0755 /work/stage-uv/opt/worker-runtime/warm_server.py
[ -f /local/trace_server.py ] && cp /local/trace_server.py /work/stage-uv/opt/worker-runtime/trace_server.py
cp /artifacts/session_master_local /work/stage-uv/opt/bin/session_master_local
chmod 0755 /work/stage-uv/opt/bin/session_master_local
chown -R 0:0 /work/stage-uv
rm -f /work/rootfs-worker-uv.ext2
mke2fs -q -t ext2 -b 4096 -m 0 -L rootfs -d /work/stage-uv /work/rootfs-worker-uv.ext2 "${SIZE_MB}M"
e2fsck -fn /work/rootfs-worker-uv.ext2 | tail -1
