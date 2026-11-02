#!/bin/sh
# Compiles run-cartesi-worker against libcartesi in the emulator's builder image
# (cartesi-me-builder:<version>, from `docker build --target builder` of cartesi/machine-emulator).
# This builds the dynamic executable; build-static.sh builds the fully static one.
# usage: build-runner.sh [OUTDIR]    (default: ./out)
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="${1:-$HERE/out}"; mkdir -p "$OUT"
IMAGE="${BUILDER_IMAGE:-cartesi-me-builder:0.22}"
docker run --rm --user "$(id -u):$(id -g)" -v "$HERE":/runner:ro -v "$OUT":/out "$IMAGE" sh -c '
set -eu
S=/usr/src/emulator/src
gcc -O2 -Wall -Wextra -I$S /runner/run-cartesi-worker.c -L$S -lcartesi -Wl,-rpath,/usr/lib -o /out/run-cartesi-worker
echo built /out/run-cartesi-worker
'
