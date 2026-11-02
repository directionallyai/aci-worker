#!/bin/sh
# Builds a riscv64 worker runtime the way worker-python-runtime's Dockerfile
# builds the x86_64 one: python-build-standalone interpreter + the locked
# dependencies + worker.py/storage.py + a `runtime` launcher, all in one
# relocatable directory. Differences from that recipe, all forced by riscv64:
#   - the interpreter is cpython 3.12.16 (checksum-verified, fetched before this
#     script runs), not the pinned 3.12.14: uv 0.12.15 has no managed riscv64
#     CPython and the pinned patch release is not published for riscv64;
#   - cffi and cryptography have no riscv64 wheels, so they are cross-compiled
#     here against that interpreter, with OpenSSL and libffi linked statically
#     (what the official manylinux wheels do), and unpacked into site-packages;
#   - .pyc files are kept, not removed: the guest is a slow emulated CPU.
#
# Runs in ubuntu:24.04 (amd64). Nothing riscv64 is executed.
# Mounts: /work (rw; has pbs/python), /src (ro; worker-python-runtime checkout).
set -eu
export DEBIAN_FRONTEND=noninteractive
UV_VERSION=0.12.15
UV_SHA256=f97935763c04be3e692460a7aaeaaab8fc3b78fcf8b389da820b38ae7423a638
RUST_TARGET=riscv64gc-unknown-linux-gnu
PBS=/work/pbs/python
OUT=/work/out
SYSROOT=/work/sysroot

apt-get update -qq >/dev/null
apt-get install -y -qq curl ca-certificates unzip pkg-config python3 python3-venv \
  gcc-riscv64-linux-gnu libc6-dev-riscv64-cross build-essential >/dev/null

# uv, pinned and verified exactly as the Dockerfile does.
curl -fsSL -o /tmp/uv.tar.gz "https://github.com/astral-sh/uv/releases/download/${UV_VERSION}/uv-x86_64-unknown-linux-gnu.tar.gz"
echo "${UV_SHA256}  /tmp/uv.tar.gz" | sha256sum -c -
mkdir -p /tmp/uvx && tar -C /tmp/uvx -xzf /tmp/uv.tar.gz && install -m 0755 /tmp/uvx/*/uv /usr/local/bin/uv

# Rust for the cryptography extension.
if ! command -v cargo >/dev/null; then
  curl -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal >/dev/null 2>&1
fi
. "${CARGO_HOME:-$HOME/.cargo}/env"
rustup target add "$RUST_TARGET" >/dev/null 2>&1

# riscv64 headers and static libs (OpenSSL, libffi): unpack the debs, do not install them.
dpkg --add-architecture riscv64
[ -f /etc/apt/sources.list.d/ubuntu.sources ] && sed -i '/^Types:/a Architectures: amd64' /etc/apt/sources.list.d/ubuntu.sources
cat > /etc/apt/sources.list.d/riscv64-ports.sources <<'EOF'
Types: deb
URIs: http://ports.ubuntu.com/ubuntu-ports
Suites: noble noble-updates noble-security
Components: main universe
Architectures: riscv64
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg
EOF
apt-get update -qq >/dev/null
rm -rf "$SYSROOT" /tmp/rvdebs && mkdir -p "$SYSROOT" /tmp/rvdebs && cd /tmp/rvdebs
apt-get download libssl-dev:riscv64 libffi-dev:riscv64 >/dev/null
for d in *.deb; do dpkg-deb -x "$d" "$SYSROOT"; done
# Only the static archives may be linkable, so the extensions carry their own copies.
rm -f "$SYSROOT"/usr/lib/riscv64-linux-gnu/libssl.so* "$SYSROOT"/usr/lib/riscv64-linux-gnu/libcrypto.so* \
      "$SYSROOT"/usr/lib/riscv64-linux-gnu/libffi.so*
ls "$SYSROOT"/usr/lib/riscv64-linux-gnu/ | grep -E '^lib(ssl|crypto|ffi)\.a$' | tr '\n' ' '; echo

# Locked versions, from the repo's own lock.
cd /src
uv export --project /src --frozen --no-hashes --no-emit-project -o /tmp/requirements.txt >/dev/null
grep -E '^(cffi|cryptography)==' /tmp/requirements.txt | sed 's/ *;.*//' > /tmp/native.txt
grep -vE '^(cffi|cryptography)==' /tmp/requirements.txt > /tmp/pure.txt
echo "native: $(tr '\n' ' ' < /tmp/native.txt)"; echo "pure:   $(grep -E '^[A-Za-z]' /tmp/pure.txt | sed 's/ *;.*//' | tr '\n' ' ')"

# Host tooling for the cross builds.
uv venv -q /tmp/venv --python /usr/bin/python3
uv pip install -q --python /tmp/venv/bin/python pip setuptools wheel 'maturin>=1,<2' 'cffi>=2' build

export PATH=/tmp/venv/bin:$PATH
mkdir -p "$OUT/wheels"
export CC=riscv64-linux-gnu-gcc LDSHARED="riscv64-linux-gnu-gcc -shared" AR=riscv64-linux-gnu-ar
export _PYTHON_HOST_PLATFORM=linux-riscv64 SETUPTOOLS_EXT_SUFFIX=.cpython-312-riscv64-linux-gnu.so
export CFLAGS="-I$PBS/include/python3.12 -I$SYSROOT/usr/include -I$SYSROOT/usr/include/riscv64-linux-gnu"
export LDFLAGS="-L$SYSROOT/usr/lib/riscv64-linux-gnu"
export PKG_CONFIG_LIBDIR="$SYSROOT/usr/lib/riscv64-linux-gnu/pkgconfig:$SYSROOT/usr/share/pkgconfig" PKG_CONFIG_SYSROOT_DIR="$SYSROOT"

CFFI="$(grep '^cffi==' /tmp/native.txt)"
echo "=== building $CFFI"
/tmp/venv/bin/pip wheel -q --no-deps --no-build-isolation --no-binary :all: -w "$OUT/wheels" "$CFFI"

CRYPTO="$(grep '^cryptography==' /tmp/native.txt)"
echo "=== building $CRYPTO"
export CARGO_BUILD_TARGET="$RUST_TARGET" CARGO_TARGET_RISCV64GC_UNKNOWN_LINUX_GNU_LINKER=riscv64-linux-gnu-gcc
export CC_riscv64gc_unknown_linux_gnu=riscv64-linux-gnu-gcc AR_riscv64gc_unknown_linux_gnu=riscv64-linux-gnu-ar
export CFLAGS_riscv64gc_unknown_linux_gnu="$CFLAGS"
export OPENSSL_DIR="$SYSROOT/usr" OPENSSL_LIB_DIR="$SYSROOT/usr/lib/riscv64-linux-gnu" OPENSSL_INCLUDE_DIR="$SYSROOT/usr/include" OPENSSL_STATIC=1
export PYO3_CROSS_LIB_DIR="$PBS/lib" PYO3_CROSS_PYTHON_VERSION=3.12 PYO3_CROSS_PYTHON_IMPLEMENTATION=CPython
export MATURIN_PEP517_ARGS="--target $RUST_TARGET --compatibility off"
/tmp/venv/bin/pip wheel -v --no-deps --no-build-isolation --no-binary :all: -w "$OUT/wheels" "$CRYPTO" 2>&1 | tail -40
ls -la "$OUT/wheels"
