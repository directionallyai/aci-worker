#!/bin/sh
# Builds run-cartesi-worker as a fully static executable, in the emulator's builder image
# (cartesi-me-builder:<version>, Debian trixie; see README). Debian ships static glib, pcre2,
# libffi, zlib and sysprof-capture but no static libslirp, so libslirp is built from source here
# (same version as Debian's, which libcartesi.a was compiled against).
# usage: build-static.sh [OUTDIR]    (default: ./out; writes run-cartesi-worker-static)
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="${1:-$HERE/out}"; mkdir -p "$OUT"
IMAGE="${BUILDER_IMAGE:-cartesi-me-builder:0.22}"
SLIRP_VERSION="${SLIRP_VERSION:-4.8.0}"
docker run --rm -v "$HERE":/runner:ro -v "$OUT":/out -e SLIRP_VERSION="$SLIRP_VERSION" "$IMAGE" sh -c '
set -eu
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null
apt-get install -y -qq meson ninja-build curl ca-certificates libglib2.0-dev libpcre2-dev libffi-dev zlib1g-dev \
    libsysprof-capture-4-dev >/dev/null
curl -fsSL "https://gitlab.freedesktop.org/slirp/libslirp/-/archive/v$SLIRP_VERSION/libslirp-v$SLIRP_VERSION.tar.gz" | tar xz -C /tmp
cd /tmp/libslirp-v$SLIRP_VERSION
meson setup build --default-library=static --buildtype=release --prefix=/opt/static --libdir=lib >/dev/null
ninja -C build install >/dev/null
export PKG_CONFIG_PATH=/opt/static/lib/pkgconfig
S=/usr/src/emulator/src
echo "static link line from pkg-config: $(pkg-config --static --libs slirp)"
g++ -O2 -Wall -Wextra -x c -I$S /runner/run-cartesi-worker.c -x none -o /out/run-cartesi-worker-static \
    $S/libcartesi.a $(pkg-config --static --libs slirp) -static -fopenmp -latomic 2>&1 | grep -v "^$" | head -20
ls -la /out/run-cartesi-worker-static | awk "{print \"built\", \$5/1048576 \" MB\", \$9}"
file /out/run-cartesi-worker-static | cut -c1-150'
