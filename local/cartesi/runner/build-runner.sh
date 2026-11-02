#!/bin/sh
# Compiles run-cartesi-worker against libcartesi in the emulator's builder image
# (cartesi-me-builder:<version>, from `docker build --target builder` of cartesi/machine-emulator).
# STATIC=1 links the archives statically (see README for what that needs); default is dynamic.
# usage: build-runner.sh [OUTDIR]    (default: ./out)
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="${1:-$HERE/out}"; mkdir -p "$OUT"
IMAGE="${BUILDER_IMAGE:-cartesi-me-builder:0.22}"
docker run --rm --user "$(id -u):$(id -g)" -v "$HERE":/runner:ro -v "$OUT":/out -e STATIC="${STATIC:-0}" "$IMAGE" sh -c '
set -eu
S=/usr/src/emulator/src
if [ "$STATIC" = 1 ]; then
  g++ -O2 -Wall -Wextra -x c -I$S /runner/run-cartesi-worker.c -x none -o /out/run-cartesi-worker-static \
      $S/libcartesi.a -static -fopenmp -lslirp -lglib-2.0 -latomic
  echo built /out/run-cartesi-worker-static
else
  gcc -O2 -Wall -Wextra -I$S /runner/run-cartesi-worker.c -L$S -lcartesi -Wl,-rpath,/usr/lib -o /out/run-cartesi-worker
  echo built /out/run-cartesi-worker
fi'
