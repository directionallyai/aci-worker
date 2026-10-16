#!/usr/bin/env bash
# Runs session_master.rs's #[ignore]d syd isolation tests -- the
# `syd_*` tests in `syd_isolation_tests` -- in Docker, as root, against a
# real worker-python-runtime bundle: the same shape as production (root
# session_master -> timeout -> setpriv -> syd -> worker.py), on the image's
# own Ubuntu 24.04 userland and its own statically linked syd.
#
#   aci/test-syd-sandbox.sh [path/to/worker-python-runtime]
#
# The worker-python-runtime checkout defaults to ../worker-python-runtime
# (next to this repo); it is only read and built, never modified. Needs
# docker with BuildKit and network access (crates.io, GitHub, PyPI, Ubuntu's
# snapshot mirror). Takes a while on a cold cache: it builds libseccomp and
# syd, the worker bundle, and compiles the tests.
#
# The test container runs with `--security-opt seccomp=unconfined`: Docker's
# default seccomp profile blocks the seccomp notify fd syd is built on. ACI
# already runs unconfined; this flag is for local runs only.
#
# Extra arguments after the checkout path are passed to the test binary,
# e.g. `aci/test-syd-sandbox.sh ../worker-python-runtime syd_denies_exec`.
# ACI_TEST_EGRESS_URL (default https://example.com; set to the empty string
# to skip) is the HTTPS URL the round-trip test fetches from inside the
# sandbox.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/.." && pwd)"
runtime_repo="${1:-$repo/../worker-python-runtime}"
shift || true
[ -f "$runtime_repo/Dockerfile" ] || { echo "no worker-python-runtime checkout at $runtime_repo" >&2; exit 2; }

scratch="$(mktemp -d)"
trap 'docker rm -f "aci-worker-syd-bundle-$$" >/dev/null 2>&1 || true; rm -rf "$scratch"' EXIT

echo "== building the worker bundle ($runtime_repo)"
docker build -t aci-worker-syd-test-bundle "$runtime_repo"
docker create --name "aci-worker-syd-bundle-$$" aci-worker-syd-test-bundle /runtime.tar.gz >/dev/null
docker cp "aci-worker-syd-bundle-$$:/runtime.tar.gz" "$scratch/runtime.tar.gz"
mkdir "$scratch/bundle"
tar -C "$scratch/bundle" -xzf "$scratch/runtime.tar.gz"   # -> bundle/runtime/{runtime,bin,lib}
[ -x "$scratch/bundle/runtime/runtime" ] || { echo "bundle has no runtime/runtime entry point" >&2; exit 1; }

echo "== building the syd test image"
docker build -f "$repo/aci/Dockerfile" --target syd-test -t aci-worker-syd-test "$repo"

echo "== running the syd isolation tests"
test_filter=("syd_")
[ "$#" -gt 0 ] && test_filter=("$@")
docker run --rm --security-opt seccomp=unconfined \
  -e RUST_LOG=error \
  -e "ACI_TEST_EGRESS_URL=${ACI_TEST_EGRESS_URL-https://example.com}" \
  -v "$scratch/bundle:/bundle:ro" \
  aci-worker-syd-test \
  cargo test --release --features aci-attestation --locked -- --ignored --test-threads=1 "${test_filter[@]}"
