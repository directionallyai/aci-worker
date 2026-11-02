#!/bin/sh
# Builds rootfs-worker.ext2: the Cartesi Ubuntu 24.04 riscv64 rootfs plus
# Ubuntu's own python3 + python3-cryptography, worker.py/storage.py from
# worker-python-runtime, and the unattested session_master_local binary.
#
# Runs inside an ubuntu:24.04 (amd64) container. Nothing is executed as
# riscv64: the riscv64 .debs are only downloaded and unpacked, so their
# postinst scripts do NOT run (the few links they would make are created
# below) and /var/lib/dpkg/status is not updated for them.
#
# Mounts expected:
#   /work       build dir (rw): holds rootfs-ubuntu/ (the unpacked base) and gets the output
#   /artifacts  session_master_local (riscv64)  (ro)
#   /runtime    worker-python-runtime checkout (ro): worker.py, storage.py
#   /local      aci-worker/local (ro): warm_server.py
set -eu
SIZE_MB="${SIZE_MB:-512}"

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null
apt-get install -y -qq e2fsprogs ca-certificates >/dev/null

# Resolve the riscv64 package closure from Ubuntu's ports archive.
dpkg --add-architecture riscv64
for f in /etc/apt/sources.list.d/ubuntu.sources; do
  [ -f "$f" ] && sed -i '/^Types:/a Architectures: amd64' "$f"
done
cat > /etc/apt/sources.list.d/riscv64-ports.sources <<'EOF'
Types: deb
URIs: http://ports.ubuntu.com/ubuntu-ports
Suites: noble noble-updates noble-security
Components: main universe
Architectures: riscv64
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg
EOF
apt-get update -qq >/dev/null

rm -rf /work/debs /work/stage
mkdir -p /work/debs/partial
apt-get install -y --download-only --no-install-recommends \
  -o Dir::Cache::archives=/work/debs \
  python3:riscv64 python3-cryptography:riscv64 >/dev/null

# Host python3.12, for byte-compiling below. Installed only now: with it present
# the download step above would treat Architecture: all packages (tzdata,
# netbase, media-types) as already satisfied and leave them out of the image.
apt-get install -y -qq python3.12 >/dev/null

# Start from the base rootfs, then unpack only packages it does not have.
cp -a /work/rootfs-ubuntu /work/stage
installed="$(awk '/^Package:/{p=$2} /^Architecture:/{a=$2} /^Status: install ok installed/{print p}' \
  /work/stage/var/lib/dpkg/status | sort -u)"
: > /work/added-packages.txt
: > /work/skipped-packages.txt
for deb in /work/debs/*.deb; do
  name="$(dpkg-deb -f "$deb" Package)"
  if echo "$installed" | grep -qx "$name"; then
    echo "$name $(dpkg-deb -f "$deb" Version)" >> /work/skipped-packages.txt
  else
    dpkg-deb -x "$deb" /work/stage
    echo "$name $(dpkg-deb -f "$deb" Version)" >> /work/added-packages.txt
  fi
done

# What the skipped postinst scripts would have linked.
ln -sf python3.12 /work/stage/usr/bin/python3
ln -sf python3.12 /work/stage/usr/bin/python3-config 2>/dev/null || true

# Worker runtime, in the layout session_master_local expects (LOCAL_RUNTIME_DIR/runtime).
mkdir -p /work/stage/opt/worker-runtime/lib /work/stage/opt/bin
cp /runtime/worker.py /runtime/storage.py /work/stage/opt/worker-runtime/lib/
cat > /work/stage/opt/worker-runtime/runtime <<'EOF'
#!/bin/sh
set -e
here="$(cd "$(dirname "$0")" && pwd)"
PYTHONPATH="$here/lib" exec /usr/bin/python3 -c "import worker; worker.main()"
EOF
chmod 0755 /work/stage/opt/worker-runtime/runtime
chmod 0644 /work/stage/opt/worker-runtime/lib/*.py
cp /local/warm_server.py /work/stage/opt/worker-runtime/warm_server.py
chmod 0755 /work/stage/opt/worker-runtime/warm_server.py
cp /artifacts/session_master_local /work/stage/opt/bin/session_master_local
chmod 0755 /work/stage/opt/bin/session_master_local

# The skipped postinst scripts are what byte-compile Ubuntu's Python packages,
# and the guest does not write __pycache__ itself, so without this every start
# recompiles the stdlib and cryptography on the emulated CPU (about 20 s).
# Bytecode does not depend on the CPU, so the host's python3.12 (same magic
# number as the guest's 3.12.3) can do it. unchecked-hash: no mtime/size checks
# at import; rebuild the image when any of these sources change.
python3.12 -m compileall -q -j 0 --invalidation-mode unchecked-hash \
  /work/stage/usr/lib/python3.12 /work/stage/usr/lib/python3 /work/stage/opt/worker-runtime/lib
echo "pyc files: $(find /work/stage -name '*.pyc' | wc -l)"

# Everything root-owned, as the original image is.
chown -R 0:0 /work/stage
rm -f /work/rootfs-worker.ext2
mke2fs -q -t ext2 -b 4096 -m 0 -L rootfs -d /work/stage /work/rootfs-worker.ext2 "${SIZE_MB}M"
e2fsck -fn /work/rootfs-worker.ext2 | tail -1
ls -la /work/rootfs-worker.ext2
echo "added: $(wc -l < /work/added-packages.txt) packages, skipped (already present): $(wc -l < /work/skipped-packages.txt)"
