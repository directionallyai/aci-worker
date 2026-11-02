#!/bin/sh
# Assembles out/runtime (riscv64) from the pieces make-uv-runtime.sh produced,
# following worker-python-runtime's Dockerfile: interpreter, pure packages from
# the lock via uv, the two cross-built wheels, worker.py/storage.py, trim, the
# `runtime` launcher. Kept .pyc files: the Dockerfile deletes them for
# reproducibility, but the emulated guest cannot afford recompiling on every start.
# Mounts: /work (rw; pbs/python, out/wheels), /src (ro; worker-python-runtime).
set -eu
export DEBIAN_FRONTEND=noninteractive
UV_VERSION=0.12.15
UV_SHA256=f97935763c04be3e692460a7aaeaaab8fc3b78fcf8b389da820b38ae7423a638
apt-get update -qq >/dev/null
apt-get install -y -qq curl ca-certificates unzip python3.12 >/dev/null
curl -fsSL -o /tmp/uv.tar.gz "https://github.com/astral-sh/uv/releases/download/${UV_VERSION}/uv-x86_64-unknown-linux-gnu.tar.gz"
echo "${UV_SHA256}  /tmp/uv.tar.gz" | sha256sum -c -
mkdir -p /tmp/uvx && tar -C /tmp/uvx -xzf /tmp/uv.tar.gz && install -m 0755 /tmp/uvx/*/uv /usr/local/bin/uv

R=/work/out/runtime
SP=$R/lib/python3.12/site-packages
rm -rf "$R" && mkdir -p /work/out && cp -a /work/pbs/python "$R"

uv export --project /src --frozen --no-hashes --no-emit-project -o /tmp/requirements.txt >/dev/null
grep -vE '^(cffi|cryptography)==' /tmp/requirements.txt > /tmp/pure.txt
uv pip install --no-deps --only-binary :all: --python-version 3.12 --python-platform riscv64-unknown-linux \
  --target "$SP" -r /tmp/pure.txt 2>&1 | tail -12
for w in /work/out/wheels/*.whl; do unzip -q -o "$w" -d "$SP"; done

find "$R" -name "*.dist-info" -prune -exec rm -rf {} +
rm -rf "$SP"/pip* "$R"/lib/python3.12/idlelib "$R"/lib/python3.12/lib2to3 "$R"/lib/python3.12/ensurepip \
  "$R"/lib/tcl9* "$R"/lib/tk9.0 "$R"/lib/itcl4.3.8 "$R"/lib/thread3.0.6 "$R"/lib/libtcl9* \
  "$R"/share "$R"/include "$R"/bin/idle3* "$R"/bin/2to3*

install -m 0644 /src/worker.py /src/storage.py "$SP"/
printf '%s\n' '#!/bin/sh' 'set -e' 'here="$(cd "$(dirname "$0")" && pwd)"' \
  'exec "$here/bin/python3.12" -c "import worker; worker.main()"' > "$R/runtime"
chmod 0755 "$R/runtime"

python3.12 -m compileall -q -j 0 --invalidation-mode unchecked-hash "$R/lib/python3.12"
echo "packages in site-packages:"; ls "$SP" | grep -v "__pycache__" | tr '\n' ' '; echo
echo "pyc files: $(find "$R" -name '*.pyc' | wc -l); size: $(du -sm "$R" | cut -f1) MB"
