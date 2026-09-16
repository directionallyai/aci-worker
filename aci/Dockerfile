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
# runtime stage: bare alpine:3.22, not python:3.12-alpine -- this image
# runs no Python of its own at all anymore (see this file's own header
# comment), so a Python base image would just be unused weight in the
# CCE-measured TCB, exactly what moving the interpreter into
# worker-python-runtime's own fetched bundle was for. Still has to stay
# musl/Alpine to match the build stage's own target (rust:*-alpine3.22)
# -- a glibc runtime image would fail to even start this binary. libgcc
# is required too -- Alpine doesn't ship it by default, and a Rust binary
# needs libgcc_s for unwinding; confirmed the hard way, via a real
# container run failing with "Error relocating session_master:
# _Unwind_Resume: symbol not found" before this line was added.
# ---------------------------------------------------------------------------
FROM alpine:3.22

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

# worker.py's own dependencies (h2/hpack/hyperframe/tlslite-ng for its
# dial-out to backend's REGISTER_CALLBACK_PATH mechanism, cryptography
# for submitted worker code to import) travel inside worker-python-
# runtime's own fetched tarball now, alongside worker.py/storage.py
# themselves -- nothing for this image to pip-install.
#
# bubblewrap: a real, maintained system package, confining run_worker()'s
# subprocess via unprivileged user/mount/pid namespaces around whatever
# interpreter the fetched worker_bundle brings with it, no separate guest
# image to package. Azure ACI's own node kernel lacks
# CONFIG_SECURITY_LANDLOCK entirely (confirmed live), which is why this
# is bwrap and not a Landlock-based sandbox -- user namespaces are the
# confinement primitive confirmed available on this platform instead.
# See run_worker()'s own doc comment (session_master.rs) for the full
# story.
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
