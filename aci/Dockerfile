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
# worker.py and storage.py are NOT baked into this image at all, unlike an
# earlier revision of this Dockerfile (attested-python-execution's own git
# history, before this repo existed) that did. Every session now names a
# `worker_bundle` by content hash in its own request; session_master's own
# fetch_worker_bundle() fetches, verifies, and runs it via Python's own
# zipimport (PYTHONPATH-mounted, never extracted) instead -- see that
# function's own doc comment. The canonical source of worker.py/storage.py
# is backend's own packages/api/assets/setup/{worker,storage}.py now
# (a separate, private repo), published to CAS at backend startup
# (ensure_worker_bundle(), that repo's own main.rs) -- this image has no
# reason to carry a copy of either file.
#
# A container built from this image is meant to be launched fresh per h2
# attested-session, accept exactly one client, run exactly one request,
# and exit -- Azure/the launching broker then tears the container group
# down. See src/bin/session_master.rs's own module doc comment for the
# full protocol and the master/worker process split this image runs.

# ---------------------------------------------------------------------------
# session_master build stage: rust:1.93-alpine3.22, matching this crate's
# own rust-version pin (Cargo.toml). No tpm2-tss packages needed: session_
# master's own SEV-SNP evidence comes from /dev/sev-guest via the `sev`
# crate (aci_attestation module), never through tpm2-tss/NitroTPM-Tools.
# ---------------------------------------------------------------------------
FROM rust:1.93-alpine3.22 AS build

RUN apk add --no-cache \
    build-base \
    && true

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
# runtime stage: python:3.12-alpine, not python:3.12-slim -- has to stay
# musl/Alpine to match the build stage's own target (rust:*-alpine3.22).
# A glibc runtime image would fail to even start this binary. libgcc is
# required too -- python:3.12-alpine doesn't ship it by default, and a
# Rust binary needs libgcc_s for unwinding; confirmed the hard way, via a
# real container run failing with "Error relocating session_master:
# _Unwind_Resume: symbol not found" before this line was added.
# ---------------------------------------------------------------------------
FROM python:3.12-alpine

RUN apk add --no-cache \
    ca-certificates \
    libgcc \
    bash \
    && true
# bash: not needed by anything in this repo -- Alpine's own busybox ash
# already covers everything session_master.rs itself shells out to.
# Present because run_worker()'s bwrap sandbox binds this image's own
# /bin into every session (`--ro-bind /bin /bin`), and code running
# *inside* that sandbox is free to assume whatever a normal Linux
# environment offers -- confirmed live as a real gap: a reviewing agent
# hit "/bin/sh: builtin: not found" on every terminal-tool command,
# because its own tool layer expects to find a real /bin/bash the way its
# native Ubuntu deployment always has one (Ubuntu's /bin/sh is dash, not
# bash, but bash is still there as a separate binary) -- busybox ash has
# no `builtin` keyword, so a fallback path that assumed one broke
# completely instead of degrading. Not specific to that one workload
# despite the repro: any sandboxed code with the same assumption hits the
# same gap, same as libgcc/ca-certificates above are here for the master
# binary and TLS, not one caller in particular.

# worker.py's own dial-out to the private repo's REGISTER_CALLBACK_PATH
# mechanism (make_local_callback(), the worker_bundle's own worker.py --
# backend repo) needs a real h2c client and AES-GCM. Installed as real,
# ordinary dependencies of this image -- the worker_bundle's own worker.py
# has no control over which Python environment it lands in (fetched fresh
# per session), so it can't bring its own wheels the way agent.py does
# for the same libraries (backend repo, H2_WHEELS) -- these have to
# already be present in the environment it's dropped into.
#
# cryptography==50.0.1: not this image's own plumbing (unlike the four
# above) -- available for submitted worker code to import, the same way
# any other stdlib/site-packages module already is inside run_worker()'s
# bwrap sandbox. A prebuilt musllinux_1_2 wheel (cp39-abi3, so it covers
# this image's cp312) exists on PyPI for this version, confirmed via the
# package's own PyPI JSON API before pinning it -- no Rust toolchain or
# openssl-dev needed at build time to compile it from source.
RUN pip install --no-cache-dir \
    hyperframe==6.1.0 \
    hpack==4.2.0 \
    h2==4.4.1 \
    tlslite-ng==0.8.2 \
    cryptography==50.0.1 \
    && true
# UNVERIFIED against a real build of this image: run_worker()'s own bwrap
# invocation (session_master.rs) binds `/usr` read-only but not
# `/usr/local` -- that's already relied on today for CPython/libpython
# itself to be reachable inside the sandbox at all (see run_worker()'s own
# doc comment), on the strength of this being Alpine's own apk-packaged
# python3 (installs under /usr/lib/python3.*, not /usr/local the way a
# from-source build would). This pip install should land these packages
# in that same /usr/lib/python3.*/site-packages/ tree for the same reason
# -- not confirmed against a real build yet. If PEP 668's
# "externally-managed-environment" guard ever blocks this pip invocation
# on a newer Alpine python3 package, that's the fix to reach for
# (--break-system-packages), not assumed needed here without hitting it.

# bubblewrap: a real, maintained system package, confining run_worker()'s
# subprocess via unprivileged user/mount/pid namespaces against this
# image's own python3, no separate guest image to package. Azure ACI's
# own node kernel lacks CONFIG_SECURITY_LANDLOCK entirely (confirmed
# live), which is why this is bwrap and not a Landlock-based sandbox --
# user namespaces are the confinement primitive confirmed available on
# this platform instead. See run_worker()'s own doc comment
# (session_master.rs) for the full story.
RUN apk add --no-cache bubblewrap

# The unprivileged identity worker.py actually runs as -- see
# session_master.rs's own run_worker() doc comment. Fixed,
# explicit uid/gid (not left to adduser's own allocation) so the Rust
# binary's WORKER_UID/WORKER_GID defaults (10001) match without needing a
# username lookup at runtime.
RUN addgroup -S -g 10001 worker \
    && adduser -S -D -H -s /sbin/nologin -u 10001 -G worker worker

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
