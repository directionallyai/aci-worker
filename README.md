# aci-worker

`session_master`: the process that runs *inside* a launched Azure
Confidential Container Instance (ACI), produces real SEV-SNP/MAA
attestation evidence, and runs a caller-submitted Python worker body
inside a `bubblewrap` sandbox.

This repo used to be part of a private, broker-side repo
(`attested-python-execution`) that also handles launching containers,
minting credentials, and verifying attestation on the caller's behalf.
Split out here because this half has no business-sensitive content of its
own -- it's a generic "run an attested Python sandbox" mechanism, not
anything about who's calling it or why. The broker/launcher side stays
private and depends on this repo's own `session_protocol` crate
externally now, rather than owning a local copy of the wire framing.

## What runs inside the container

1. Dial back out to the broker's own callback listener, present a
   one-time token, do a real SEV-SNP/MAA handshake (`aci_attestation`,
   `session_master.rs`) -- no SKR sidecar; this process reads
   `/dev/sev-guest` directly.
2. Derive the session key via ECDH, read one encrypted request frame:
   `{mode, code, storage_grant, pattern_delegate, content_keys,
   worker_bundle}`.
3. `run_worker()`: fetch and verify `worker_bundle` by content hash from
   the shared/global object-store prefix (if named -- see
   `fetch_worker_bundle()`'s own doc comment), then run it natively
   inside `bubblewrap` (unprivileged user/mount/pid namespace
   confinement), feeding it the decrypted request on stdin.
4. Encrypt the result, write it back over the same session, exit. One
   container, one session, then torn down by whatever launched it.

`worker_bundle` names a zip (`worker.py`+`storage.py`) by its own SHA-256;
Python's own `zipimport` resolves it via `PYTHONPATH`, nothing is ever
extracted to disk. Nothing Python-shaped is baked into this image at
all -- every session supplies its own bundle. (The canonical source of
that bundle is a separate, private repo's own `worker.py`/`storage.py`,
published to the object store by content hash at that service's own
startup; this repo has no opinion on what's in it beyond verifying the
hash matches.)

## Building

```bash
cargo build --release --features aci-attestation
```

Built without `--features aci-attestation`, `session_master` logs an
error and exits immediately -- ACI mode is the only mode this binary
supports.

```bash
docker build -f aci/Dockerfile -t aci-session-worker .
```

## Deploying

`aci/arm-template.json` is the throwaway ARM template `az confcom
acipolicygen` generates a CCE policy against -- see that file's own
comments, and the consuming Terraform (a separate, private infra repo)
for how the resulting policy actually gets deployed.
`aci/resolve-image-digest.sh` resolves the currently-published image tag
to the exact digest that policy generation and the real container-group
launch both need to agree on.
