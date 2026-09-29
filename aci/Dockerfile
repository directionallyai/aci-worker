# The Azure Confidential ACI attested Python sandbox worker.
#
# session_master (this repo's own src/bin/session_master.rs) is the only
# binary this repo builds -- unlike attested-python-execution (a separate,
# private repo), which still owns the broker/launcher side of this same
# protocol (attested_session.rs, aci_executor.rs, callback.rs) and depends
# on this repo's own session_protocol crate externally rather than owning
# a local copy. Split this way because that's the actual OSS/private
# boundary: this repo (session_master, the sandbox, the wire framing) has
# no business-sensitive content of its own; the broker/launcher side does
# (deployment topology, credential minting, MAA verification wiring).
#
# No Python at all is baked into this image -- not the interpreter, not
# worker.py/storage.py, not their dependencies. Every session names a
# `worker_bundle` by content hash in its own request; session_master's
# own fetch_worker_bundle() fetches, verifies, and extracts a
# self-contained runtime tarball (worker-python-runtime, a separate,
# public repo -- interpreter, dependencies, and worker.py/storage.py
# themselves, all inside it) and execs its own `runtime` entry point
# directly. An earlier revision of this Dockerfile baked worker.py/
# storage.py into /opt/worker/ directly; a later one dropped just those
# two but kept a python:3.12-alpine base with the dependency wheels
# pip-installed, fetching only a zip of the two files per session
# (zipimport, PYTHONPATH-mounted). Neither survives here: this image now
# carries none of it, on the strength of worker-python-runtime's own
# tarball being genuinely self-contained (confirmed via a real relocated
# build, run cold, outside any Python installation this image would
# otherwise have provided).
#
# A container built from this image is meant to be launched fresh per h2
# attested-session, accept exactly one client, run exactly one request,
# and exit -- Azure/the launching broker then tears the container group
# down. See src/bin/session_master.rs's own module doc comment for the
# full protocol and the master/worker process split this image runs.
#
# Ubuntu, not Alpine -- this was a deliberate tradeoff, not a default.
# The previous Alpine/musl revision of this file kept the CCE-measured
# TCB deliberately small (see the runtime-stage comment it used to carry,
# preserved in git history); Ubuntu's own base is meaningfully bigger.
# Traded for it: apk has no equivalent to apt's own snapshot mirrors
# (below), so a bare `apk add` always resolves against whatever Alpine's
# *live* package index currently holds at build time, no matter how
# precisely the base image itself is pinned -- confirmed the actual,
# root-caused source of the one real reproducibility bug found while
# making directionallyai/linuxkit-attestable-ami's own Azure CVM image
# reproducible (extra/azure-cve-attest's Alpine "mirror" stage). Follows
# that repo's extra/build-attest-api/Dockerfile pattern directly: an
# amd64 Ubuntu digest (not a floating tag), apt pointed at a fixed-date
# snapshot.ubuntu.com mirror instead of the live archive, and a
# checksum-verified rustup install pinned to an exact toolchain version
# (not `apt install rustc`, which floats the same way `apk add` does, and
# not a `rust:*` base image, which is itself Alpine- or Debian-slim-based
# upstream with its own separate, unpinned package set).
ARG SOURCE_DATE_EPOCH=1788613323

FROM ubuntu:24.04@sha256:a61567bd31828687156d735ea8eb01ba4e37636e225dd6a48ba94136a70d9d61 AS base
ARG SOURCE_DATE_EPOCH
ENV DEBIAN_FRONTEND=noninteractive
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    snapshot="$(/bin/bash -euc "printf \"%(%Y%m%dT%H%M%SZ)T\n\" \"${SOURCE_DATE_EPOCH}\"")" && \
    sed -i -e '/Types: deb/ a\Snapshot: true' /etc/apt/sources.list.d/ubuntu.sources && \
    sed -i "s/archive.ubuntu.com\/ubuntu\//snapshot.ubuntu.com\/ubuntu\/${snapshot}/" /etc/apt/sources.list.d/ubuntu.sources && \
    sed -i "s/security.ubuntu.com\/ubuntu\//snapshot.ubuntu.com\/ubuntu\/${snapshot}/" /etc/apt/sources.list.d/ubuntu.sources && \
    rm -f /etc/apt/apt.conf.d/docker-clean && \
    echo 'Binary::apt::APT::Keep-Downloaded-Packages "true";' >/etc/apt/apt.conf.d/keep-cache && \
    apt-get install --update -o Acquire::Check-Valid-Until=false -o Acquire::https::Verify-Peer=false -y \
      ca-certificates libgcc-s1 bash bubblewrap && \
    rm -rf /var/log/* /var/cache/ldconfig/aux-cache

# ---------------------------------------------------------------------------
# session_master build stage: rustup-installed toolchain, pinned to
# Cargo.toml's own rust-version, against the same snapshot the base stage
# already uses. No tpm2-tss packages needed: session_master's own SEV-SNP
# evidence comes from /dev/sev-guest via the `sev` crate (aci_attestation
# module), never through tpm2-tss/NitroTPM-Tools.
# ---------------------------------------------------------------------------
FROM base AS build
ARG SOURCE_DATE_EPOCH
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update -o Acquire::Check-Valid-Until=false && \
    apt-get install -y --no-install-recommends build-essential curl && \
    rm -rf /var/log/* /var/cache/ldconfig/aux-cache

# .../archive/<rustup-version>/... is rustup's own immutable, versioned
# release path (not the floating "current" dist/ bootstrapper), checksum
# verified against the real value rustup publishes for it -- same pin
# extra/build-attest-api/Dockerfile already uses in
# linuxkit-attestable-ami, reused here rather than re-derived since it
# names the same rustup release.
ARG RUSTUP_VERSION=1.29.1
ARG RUSTUP_INIT_SHA256=dda7234360b7f578ca8b0ddcb80145646fa61a67c1720a5abc7051b35c9fcb71
RUN curl -fsSL "https://static.rust-lang.org/rustup/archive/${RUSTUP_VERSION}/x86_64-unknown-linux-gnu/rustup-init" -o /tmp/rustup-init && \
    echo "${RUSTUP_INIT_SHA256}  /tmp/rustup-init" | sha256sum -c - && \
    chmod +x /tmp/rustup-init && \
    /tmp/rustup-init -y --no-modify-path --default-toolchain 1.93.1 --profile minimal
ENV PATH=/root/.cargo/bin:$PATH
ENV SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}
# Cargo.lock pins every dependency version already (cargo build --locked
# below fails outright on drift instead of silently re-resolving), but
# incremental compilation caches are keyed by things like mtimes and
# prior build state, not a pure function of the source alone -- a real
# determinism risk to leave on even though it is off by default for a
# --release profile build; irrelevant for speed in a from-scratch
# container build anyway.
ENV CARGO_INCREMENTAL=0
# Without this, rustc embeds this build's own absolute paths
# (/root/.cargo/registry/..., /app/src/...) into debug info and
# panic!()'s own file!() output -- consistent build-to-build only
# because every build happens inside this exact same pinned image at
# this exact same path, an implicit assumption this removes instead of
# relying on it silently holding (same reasoning
# extra/build-attest-api/Dockerfile's own RUSTFLAGS already documents).
ENV RUSTFLAGS="--remap-path-prefix=/root/.cargo=/cargo --remap-path-prefix=/app=/src"

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src/bin \
    && echo '' > src/lib.rs \
    && echo 'fn main() {}' > src/bin/session_master.rs \
    && cargo build --release --features aci-attestation --locked \
    && rm -rf src
COPY src ./src
RUN touch src/lib.rs src/bin/session_master.rs \
    && cargo build --release --features aci-attestation --locked

# ---------------------------------------------------------------------------
# final image
# ---------------------------------------------------------------------------
FROM base

# The unprivileged identity worker.py actually runs as -- see
# session_master.rs's own run_worker() doc comment. Fixed, explicit
# uid/gid (not left to useradd's own allocation) so the Rust binary's
# WORKER_UID/WORKER_GID defaults (10001) match without needing a
# username lookup at runtime -- same --system/no-home/no-login shape the
# Alpine addgroup/adduser invocation this replaces already had.
RUN groupadd --system --gid 10001 worker \
    && useradd --system --no-create-home --no-user-group \
         --gid worker --shell /usr/sbin/nologin --uid 10001 worker

WORKDIR /app
COPY --from=build /app/target/release/session_master /usr/local/bin/session_master

# No /opt/worker, no baked-in worker.py/storage.py -- see this file's own
# header comment. Every session's own worker_bundle is fetched fresh
# (fetch_worker_bundle(), session_master.rs) into a fresh /tmp inside the
# already-fresh-per-session container; nothing about that needs anything
# pre-staged in the image.

# No EXPOSE, no MASTER_MODE env var: this process only ever dials out to
# attested-python-execution's own attester-service callback listener (see
# session_master.rs's own module doc comment) -- it never binds a port.

# session_master runs as root -- it has to, both to open
# /dev/sev-guest (get_maa_token()'s own SNP report fetch) and to spawn
# run_worker()'s bubblewrap sandbox (mapping down to the unprivileged
# worker uid/gid *inside* bubblewrap's own new user namespace, not on
# this host process). worker.py itself never runs as root; see that
# function for where that's actually enforced.
CMD ["/usr/local/bin/session_master"]
