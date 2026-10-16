# aci-worker

`session_master`: the process that runs *inside* a launched Azure
Confidential Container Instance (ACI), produces real SEV-SNP/MAA
attestation evidence, and runs a caller-submitted Python worker body
inside a sandbox -- `bubblewrap` by default, or
[`syd`](https://gitlab.exherbo.org/sydbox/sydbox) (see
[Sandbox backends](#sandbox-backends)).

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
   inside the selected sandbox backend (see
   [Sandbox backends](#sandbox-backends)), feeding it the decrypted
   request on stdin.
4. Encrypt the result, write it back over the same session, exit. One
   container, one session, then torn down by whatever launched it.

`worker_bundle` names a tarball by its own SHA-256 --
[worker-python-runtime](https://github.com/directionallyai/worker-python-runtime)'s
own `runtime.tar.gz`, a self-contained Python interpreter, its
dependencies, and `worker.py`/`storage.py` themselves, extracted to a
fresh, hash-named `/tmp` directory and run via its own `runtime` entry
point. Nothing Python-shaped is baked into this image at all -- no
interpreter, no wheels, no worker.py/storage.py, not even as a fallback:
a request with no `worker_bundle` is refused outright. (The canonical
source of that tarball is worker-python-runtime's own repo, republished
to the object store by content hash at a separate, private broker
service's own startup; this repo has no opinion on what's in it beyond
verifying the hash matches.)

## Sandbox backends

`ACI_WORKER_SANDBOX` (set at container launch, like
`WORKER_EXECUTION_OPTIONS`) picks what confines the worker:

| value | backend | notes |
|---|---|---|
| unset, empty, `bwrap` | `bubblewrap` | The default. Unprivileged user/mount/pid namespaces: fresh `/tmp`, read-only binds of `/usr`, `/bin`, `/lib`, `/lib64`, `/etc/ssl`, `/etc/resolv.conf`, `/etc/hosts` and the bundle, a minimal `/dev`, shared network. |
| `syd` | [`syd`](https://gitlab.exherbo.org/sydbox/sydbox) | seccomp-unotify: every path, exec and network syscall of the worker is checked against a deny-by-default policy (`syd_policy()` in `src/bin/session_master.rs`, each allowance commented with the footprint item that needs it). Needs Linux >= 5.19. Built into the image at `/usr/local/bin/syd`, linked statically against libseccomp 2.6. |

Anything else is refused, not guessed. Whichever backend is selected must
pass its self-test at startup, and again lazily before any request: if it
does not, `session_master` refuses to start/run -- there is no fallback to
the other backend and none to running unsandboxed. The startup log and the
refusal both name the backend.

What `syd` does **not** do that `bubblewrap` does: no mount or pid namespace
(syd's needs a private procfs, which a Confidential ACI container refuses),
so `/tmp` is the container's own rather than a private tmpfs, and there is
no pid namespace; process isolation comes from syd hiding `/proc` and
refusing ptrace/`process_vm_readv`. See `session_master.rs`'s "worker
execution, via syd" comment before relying on it for concurrent tenants in
one container.

### Testing the syd backend

Plain `cargo test` needs neither syd nor a bundle. The syd isolation
regression tests (`syd_isolation_tests`, all `#[ignore]`d) run the real
policy against a real `worker-python-runtime` bundle, as root, in Docker:

```bash
aci/test-syd-sandbox.sh [path/to/worker-python-runtime]
```

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

`aci/arm-template-dev.json` is the throwaway ARM template `az confcom
acipolicygen` generates a CCE policy against -- see that file's own
comments, and the consuming Terraform (a separate, private infra repo)
for how the resulting policy actually gets deployed. Named per-environment
(only `dev` exists so far) because the image digest, MAA endpoint, and
resource sizing it mirrors are themselves per-environment in that
Terraform; a future second environment with different values would need
its own `arm-template-<env>.json` rather than sharing this one.
`aci/resolve-image-digest.sh` resolves the currently-published image tag
to the exact digest that policy generation and the real container-group
launch both need to agree on.
