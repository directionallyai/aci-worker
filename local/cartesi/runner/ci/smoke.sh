#!/bin/sh
# Boots a real guest with the runner it was given and fails unless the guest runs a command and halts cleanly.
# Uses only public downloads: the Cartesi kernel (cartesi/linux v6.18.56-ctsi-1, checked against the release's .sha512)
# and Cartesi's v0.19.0 root image (cartesi/machine-rootfs-image, sha256 pinned below). That root image is old and uses
# /opt/cartesi/bin/init, with the command given after "--" on the kernel command line. No network device.
# usage: smoke.sh RUNNER_BINARY
set -eu
RUNNER="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
W="$(mktemp -d)"; cd "$W"
KTAG=v6.18.56-ctsi-1; KERNEL=linux-6.18.56-ctsi-1.bin
ROOTFS_URL=https://github.com/cartesi/machine-rootfs-image/releases/download/v0.19.0/rootfs-v0.19.0.ext2
ROOTFS_SHA256=a3a9aa5c2ab83093585587da4e4b8e4ef620528b7859b2a9337e40bf3e564dd4
curl -fsSL -o "$KERNEL" "https://github.com/cartesi/linux/releases/download/$KTAG/$KERNEL"
curl -fsSL -o "$KERNEL.sha512" "https://github.com/cartesi/linux/releases/download/$KTAG/$KERNEL.sha512"
curl -fsSL -o rootfs.ext2 "$ROOTFS_URL"
sum512() { if command -v sha512sum >/dev/null 2>&1; then sha512sum "$1" | cut -d' ' -f1; else shasum -a 512 "$1" | cut -d' ' -f1; fi; }
sum256() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }
[ "$(sum512 "$KERNEL")" = "$(cut -d' ' -f1 "$KERNEL.sha512")" ] || { echo "kernel checksum mismatch"; exit 1; }
[ "$(sum256 rootfs.ext2)" = "$ROOTFS_SHA256" ] || { echo "root image checksum mismatch"; exit 1; }
P="$W"; if command -v cygpath >/dev/null 2>&1; then P="$(cygpath -m "$W")"; fi   # the Windows runner wants C:/... paths
LEN="$(wc -c < rootfs.ext2 | tr -d ' ')"
# The root drive starts at align_up(0x80000000 + RAM, its length rounded up to a power of two): 0x88000000 for 128 MiB of RAM
# and a 128 MiB-or-smaller image (see local/cartesi/README.md).
cat > config.json <<JSON
{"ram":{"length":134217728,"backing_store":{"data_filename":"$P/$KERNEL"}},
 "dtb":{"bootargs":"quiet earlycon=sbi console=hvc0 root=/dev/pmem0 rw init=/opt/cartesi/bin/init -- echo SMOKE-GUEST-OK"},
 "flash_drive":[{"label":"root","start":2281701376,"length":$LEN,"backing_store":{"data_filename":"$P/rootfs.ext2"}}]}
JSON
echo "runner: $RUNNER"; echo "starting guest"
"$RUNNER" config.json > out.log 2>&1 &
pid=$!; n=0
while kill -0 "$pid" 2>/dev/null && [ $n -lt 240 ]; do sleep 1; n=$((n+1)); done
if kill -0 "$pid" 2>/dev/null; then kill "$pid" 2>/dev/null || true; echo "guest did not halt within 240 s"; cat out.log; exit 1; fi
rc=0; wait "$pid" || rc=$?
cat out.log
grep -q "SMOKE-GUEST-OK" out.log || { echo "SMOKE FAILED: guest output missing"; exit 1; }
[ "$rc" -eq 0 ] || { echo "SMOKE FAILED: runner exit code $rc"; exit 1; }
echo "SMOKE OK after ${n} s (guest ran a command and halted cleanly)"
