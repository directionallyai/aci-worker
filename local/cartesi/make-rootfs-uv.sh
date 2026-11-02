#!/bin/sh
# The worker's root image: the Cartesi Ubuntu base + the uv/python-build-standalone riscv64
# runtime + session_master_local + warm_server.py (+ trace_server.py when present). Unlike
# make-rootfs.sh it adds NO Ubuntu python packages, so nothing here can fall back to the
# system Python.
#
#   FORMAT=erofs (default)  uncompressed EROFS (needs the v0.22.0 kernel): read-only by
#                           construction, no free-space or fsck concerns, and the fastest
#                           start-up measured (see README); reproducible (fixed timestamp
#                           and UUID).
#   FORMAT=ext2             the older 512 MB (SIZE_MB) ext2 image, the only one the v0.21.0
#                           kernel can mount besides squashfs.
#
# Mounts: /work (rw; rootfs-ubuntu/ in, image out), /artifacts (ro), /uvrt (ro;
# uv-runtime/out/runtime), /local (ro; aci-worker/local).
set -eu
FORMAT="${FORMAT:-erofs}"
SIZE_MB="${SIZE_MB:-512}"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null && apt-get install -y -qq e2fsprogs erofs-utils >/dev/null
rm -rf /work/stage-uv && cp -a /work/rootfs-ubuntu /work/stage-uv
mkdir -p /work/stage-uv/opt/bin
cp -a /uvrt /work/stage-uv/opt/worker-runtime
cp /local/warm_server.py /work/stage-uv/opt/worker-runtime/warm_server.py
chmod 0755 /work/stage-uv/opt/worker-runtime/warm_server.py
[ -f /local/trace_server.py ] && cp /local/trace_server.py /work/stage-uv/opt/worker-runtime/trace_server.py
cp /artifacts/session_master_local /work/stage-uv/opt/bin/session_master_local
chmod 0755 /work/stage-uv/opt/bin/session_master_local
chown -R 0:0 /work/stage-uv
case "$FORMAT" in
  erofs)
    OUT=/work/rootfs-worker-uv.erofs
    rm -f "$OUT"
    # -T 0 and -U fix the two things that would otherwise differ between builds.
    mkfs.erofs -T 0 -U 00000000-0000-0000-0000-000000000000 --all-root "$OUT" /work/stage-uv >/dev/null
    ;;
  ext2)
    OUT=/work/rootfs-worker-uv.ext2
    rm -f "$OUT"
    mke2fs -q -t ext2 -b 4096 -m 0 -L rootfs -d /work/stage-uv "$OUT" "${SIZE_MB}M"
    e2fsck -fn "$OUT" | tail -1
    ;;
  *) echo "FORMAT must be erofs or ext2" >&2; exit 2 ;;
esac
chmod a+r "$OUT"
echo "$OUT: $(wc -c < "$OUT") bytes, sha256 $(sha256sum "$OUT" | cut -d' ' -f1)"
