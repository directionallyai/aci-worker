# Running the worker in a Cartesi machine (unattested experiment)

**UNATTESTED, DEV ONLY.** Nothing here proves what code is running or where. Requests
are plaintext on a TCP port and carry `content_keys` and a `storage_grant`. Use it only
with your own data on a machine you trust. None of this applies to the attested
`session_master`, which is untouched.

The experiment: take the worker half of aci-worker, remove the attestation, and run it
inside a [Cartesi machine](https://github.com/cartesi/machine-emulator) (a riscv64
emulator) with a virtio-net device and a forwarded port, so a client on the host can send
it the same request `agent.py` sends to the attested worker.

## What is here

| Path | What |
|---|---|
| `src/bin/session_master_local.rs` | The unattested listener. One framed JSON request in, one worker run, one framed response out. Feature `unattested-local`; refuses to compile together with `aci-attestation`. |
| `local/warm_server.py` | A warm Python process that pre-imports `worker`/`storage`/`cryptography` and forks one child per request, plus a parent-side cache of verified world code (see below). |
| `local/test_warm_server.py` | 19 tests: forking and isolation, timeouts, the cache (hits, repoint, scope, failure, bound, tampering). |
| `local/trace_server.py` | Tracing launcher: per-request timings of the parent and the child, split into TCP, TLS, wait and CPU. |
| `make-uv-runtime.sh`, `assemble-uv-runtime.sh` | Build a riscv64 worker runtime the way worker-python-runtime's Dockerfile does (python-build-standalone + the locked packages), cross-compiling `cffi` and `cryptography`. |
| `make-rootfs.sh`, `make-rootfs-uv.sh` | Build the root filesystem image: Cartesi's Ubuntu 24.04 rootfs plus either Ubuntu's own Python or the `uv` runtime, `session_master_local` and `warm_server.py`. |
| `e2e.sh`, `analysis/analyze_warm.py` | Boot the machine and time requests; the second one sends real world requests with your own grant and keys and prints a timeline. |
| `pyc-sim/` | The simulation of caching compiled code: a fake object store, and guest-side timing of fetch, compile and `.pyc` load. |

Everything below assumes the Docker image `cartesi-me:0.21-local` built from the
`cartesi/machine-emulator` v0.21.0 `Dockerfile`, the kernel `linux-6.5.13-ctsi-2-v0.21.0.bin`
from `cartesi/machine-linux-image`, and the base `rootfs-ubuntu.ext2` from
`cartesi/machine-rootfs-image` v0.20.0-test1 unpacked with `debugfs rdump` into `rootfs-ubuntu/`.
The scripts take their mounts as documented in each header; paths default to
`~/workspace/cartesi-worker/...` and can be overridden with `CARTESI_IMAGES`.

## Build and run

1. Cross-build the binary: in `rust:1-bookworm` with `gcc-riscv64-linux-gnu`,
   `cargo build --locked --release --target riscv64gc-unknown-linux-gnu --features unattested-local --bin session_master_local`.
2. Build the `uv` runtime: `make-uv-runtime.sh` (needs the python-build-standalone
   `cpython-3.12.16+20261026-riscv64-unknown-linux-gnu-install_only_stripped` tarball, checked
   against the release `SHA256SUMS`, unpacked to `pbs/`), then `assemble-uv-runtime.sh`.
3. Build the image: `make-rootfs-uv.sh` (writes `rootfs-worker-uv.ext2`).
4. Boot:

   ```
   cartesi-machine --ram-image=linux.bin \
     --flash-drive=label:root,data_filename:rootfs-worker-uv.ext2 -n -p 0.0.0.0:8700:8700 -- \
     'WARM_CACHE_SCOPE=global WARM_LIB=/opt/worker-runtime/lib/python3.12/site-packages WARM_SOCKET=/tmp/w.sock \
      /opt/worker-runtime/bin/python3.12 /opt/worker-runtime/warm_server.py & \
      LOCAL_WARM_SOCKET=/tmp/w.sock LOCAL_LISTEN=0.0.0.0:8700 LOCAL_RUNTIME_DIR=/opt/worker-runtime \
      LOCAL_SANDBOX=none /opt/bin/session_master_local'
   ```

   (`data_filename:`, not `filename:`. `-p` needs `-n`. The guest must listen on `0.0.0.0` because
   slirp forwards to 10.0.2.15.)

## The world-code cache

Fetching the world modules by hash and compiling them in every request costs more than the
interpreter start-up the warm process saves. Before forking, the warm **parent** loads them: it
re-reads the two pointers every request (so a repoint is visible on the next call), fetches an
asset only when its hash is new, and keeps the verified bytes and the compiled code object. The
child builds its modules from those code objects with no network. The parent never executes world
code, and children cannot write to the cache. `WARM_CACHE_SCOPE` is `account` (default: entries
are keyed by the grant's `own_prefix`, because a hit skips the fetch that proves read access),
`global` (one trusted user) or `off`. This is specific to the long-lived local worker: the attested
aci-worker starts a fresh sandboxed process per request and keeps `worker.py` pinned.

## Measured (v0.21.0 emulator, single-core guest, your own bucket)

| | Result |
|---|---|
| Boot to listening | about 4.5 s |
| Warm worker ready | about 9 s after start |
| Worldless request, warm | 0.07 s |
| World request, no cache | about 10 s |
| World request, with cache (steady state) | about 5.5 s |
| Python imports of worker+storage+cryptography (uv runtime) | about 3 s (Ubuntu's Python: 4.6 s) |
| `compile()` of `world_core.py` (68 KB) in the guest | 0.6 s |

Where the ~5.5 s goes: five sequential authenticated reads from Tigris on fresh connections
(about 0.9 s each in the guest): TCP 0.02 s, TLS handshake 0.44 s (0.018 s natively), waiting for
the answer 0.15-0.52 s (0.46 s natively: real server latency, not the emulator). Two of the five are
the world's own review-schedule check. Fork costs 0.015 s. The guest clock runs about 12% slower than
real time when CPU-bound, so guest CPU figures undercount. Guest Python compute is about 100x slower
than native. Bytecode is CPU-architecture independent: a `.pyc` compiled on x86_64 with 3.12.3 loads in
the riscv64 guest's 3.12.16, so a cache key needs (source hash, Python magic number), not an
architecture.

## Known gaps

- **No sandbox**: `LOCAL_SANDBOX=none` (the Cartesi kernel's support for the user namespaces bubblewrap
  needs was not checked); warm mode requires it.
- **No `queue_eval` / `local` channel**, so the scheduled reviewer cannot launch from this worker.
- **The reviewer bundle is x86_64 only.** `_run_reviewer_agent` fetches one bundle by pointer (account
  `reviewer_bundle`, falling back to the shared one) with no architecture in the key; it is the x86_64
  worker runtime plus Hermes 0.19.0 and x86_64 `git`/`ripgrep`, so it would not exec in this guest. Of its 62
  resolved packages, 47 are pure Python and 15 ship platform wheels, 6 of those with a riscv64 wheel on PyPI.
- **Not reproducible or attestable like the x86_64 runtime**: the interpreter is 3.12.16 (the repo pins
  3.12.14), `.pyc` files are kept, and the two cross-built wheels are not hash-pinned. They statically link
  Ubuntu noble's OpenSSL 3.0.x, not the newer OpenSSL the official wheels bundle.
- **Not done**: a write test through this worker, v0.22.0 boot (kernel 6.18.56-ctsi-1 and emulator v0.22.0
  are downloaded and built, nothing booted), supervision to restart the warm process, TLS session
  resumption, and an arm64/macOS/Windows check (TAP is Linux-only; no macOS or Windows CI upstream).
