#!/bin/sh
# Builds read-only root images from an existing staged tree (default: the output tree of
# make-rootfs-uv.sh) in several formats, so they can be compared with analysis/bench_rootfs.py.
# Runs in ubuntu:24.04 as root. Mounts: /stage (ro; the tree), /out (rw; where images go).
set -eu
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null && apt-get install -y -qq squashfs-tools erofs-utils >/dev/null
mksquashfs -version | head -1; mkfs.erofs --version 2>&1 | head -1
B=rootfs-worker-uv
sq() { rm -f "/out/$B.$1.squashfs"; mksquashfs /stage "/out/$B.$1.squashfs" -noappend -quiet -all-root -b 128K "${@:2}" >/dev/null; }
sq zstd -comp zstd -Xcompression-level 19
sq xz -comp xz
sq lz4 -comp lz4 -Xhc
sq none -noD -noI -noF -noX
rm -f /out/$B.erofs-lz4hc.erofs /out/$B.erofs-none.erofs
mkfs.erofs -zlz4hc,12 --all-root /out/$B.erofs-lz4hc.erofs /stage >/dev/null
mkfs.erofs --all-root /out/$B.erofs-none.erofs /stage >/dev/null
chmod a+r /out/$B.*
ls -l /out/$B.* | awk '{printf "%-62s %8.1f MB\n", $9, $5/1048576}'
