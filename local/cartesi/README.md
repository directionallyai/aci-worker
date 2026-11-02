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
| `make-rootfs-uv.sh` | Builds the root image: Cartesi's Ubuntu 24.04 rootfs plus the `uv` runtime, `session_master_local` and `warm_server.py`. Uncompressed EROFS by default (reproducible), `FORMAT=ext2` for the older image. `make-rootfs.sh` is the earlier variant with Ubuntu's own Python. |
| `make-rootfs-compressed.sh` | Builds the same tree as squashfs (zstd, xz, lz4, uncompressed) and EROFS (lz4hc, uncompressed) for comparison. |
| `analysis/bench_rootfs.py` | Boots one root image the same way every time and measures boot, warm-up and real world requests (your own grant and keys, built in memory). |
| `analysis/analyze_warm.py` | Per-request timeline of the warm worker (parent prep, child phases, TCP/TLS/wait/CPU per HTTPS call). |
| `runner/` | `run-cartesi-worker.c`: boots a machine from a JSON configuration through libcartesi's C API, with no Lua. See below. |
| `pyc-sim/` | The simulation of caching compiled code: a fake object store, and guest-side timing of fetch, compile and `.pyc` load. |

Everything below assumes emulator **v0.22.0** (Docker image `cartesi-me:0.22-local` built from the
`cartesi/machine-emulator` `Dockerfile`; `--target builder` gives `cartesi-me-builder:0.22` with the
static archives and headers), the kernel `linux-6.18.56-ctsi-1.bin` from `cartesi/linux` (the
v0.21.0 kernel has no EROFS), and the base `rootfs-ubuntu.ext2` from `cartesi/machine-rootfs-image`
v0.20.0-test1 unpacked with `debugfs rdump` into `rootfs-ubuntu/`.
The scripts take their mounts as documented in each header; paths default to
`~/workspace/cartesi-worker/...` and can be overridden with `CARTESI_IMAGES`.

## Build and run

1. Cross-build the binary: in `rust:1-bookworm` with `gcc-riscv64-linux-gnu`,
   `cargo build --locked --release --target riscv64gc-unknown-linux-gnu --features unattested-local --bin session_master_local`.
2. Build the `uv` runtime: `make-uv-runtime.sh` (needs the python-build-standalone
   `cpython-3.12.16+20261026-riscv64-unknown-linux-gnu-install_only_stripped` tarball, checked
   against the release `SHA256SUMS`, unpacked to `pbs/`), then `assemble-uv-runtime.sh`.
3. Build the image: `make-rootfs-uv.sh` (writes `rootfs-worker-uv.erofs`; `FORMAT=ext2` for ext2). Two builds
   from the same inputs give the same sha256.
4. Boot with the command line (root mapped read-only, RAM tmpfs for `/tmp` and `/run`):

   ```
   cartesi-machine --ram-image=linux-6.18.56-ctsi-1.bin \
     --flash-drive=label:root,data_filename:rootfs-worker-uv.erofs,read_only --append-bootargs=ro \
     --append-init='mount -t tmpfs -o size=16m tmpfs /run; touch /run/resolv.conf; mount -o bind /run/resolv.conf /etc/resolv.conf' \
     -n -p 0.0.0.0:8700:8700 -- \
     'mount -t tmpfs -o size=64m,mode=1777 tmpfs /tmp; WARM_CACHE_SCOPE=global WARM_LIB=/opt/worker-runtime/lib/python3.12/site-packages WARM_SOCKET=/tmp/w.sock \
      /opt/worker-runtime/bin/python3.12 /opt/worker-runtime/warm_server.py & \
      LOCAL_WARM_SOCKET=/tmp/w.sock LOCAL_LISTEN=0.0.0.0:8700 LOCAL_RUNTIME_DIR=/opt/worker-runtime LOCAL_SANDBOX=none /opt/bin/session_master_local'
   ```

   (`data_filename:`, not `filename:`. `-p` needs `-n`. The guest must listen on `0.0.0.0` because slirp
   forwards to 10.0.2.15. The `--append-init` goes before `-n`: on a read-only root `-n` would fail to write
   `/etc/resolv.conf`, so a RAM file is bind-mounted over it first.)

5. Or boot it with the C runner, no Lua: write the machine's configuration once with the command line
   (`... --max-mcycle=0 --store-config=worker.json`), replace the `date -s @<epoch>` boot command with
   `date -s @{{NOW}}` (see `runner/worker.config.example.json`), then
   `runner/build-runner.sh && run-cartesi-worker worker.json`.

## The C runner

`runner/run-cartesi-worker.c` (about 170 lines) creates the machine with `cm_create_new(config_json, ...)`
and loops `cm_run`. The C API has no virtio functions of its own: the `virtio` array in the configuration
(`net-user` with its `hostfwd`) is all there is, and libcartesi creates the devices and drives libslirp
inside `cm_run` (it imports `slirp_new`, `slirp_add_hostfwd`, `slirp_pollfds_fill/poll`, `slirp_input`).
Lua is not needed by libcartesi; only the command-line front end uses it. `{{NOW}}` in the configuration
is replaced with the current Unix time at start so the guest clock is right (a guest at the epoch fails
every TLS handshake with "certificate is not yet valid"). Guest console goes to stdout; SIGINT/SIGTERM stop
it between slices of 2^27 cycles (exit 130); a halt exits with the guest's own code.

Built against the dynamic library it boots the worker and serves real world requests. A fully static
executable (`STATIC=1 runner/build-runner.sh`) currently fails to link on exactly three libraries,
`libslirp`, `glib-2.0` and `pcre2-8`: Debian's `-dev` packages ship no static archives for them. Everything
else (libcartesi.a, libstdc++, libgomp, libatomic, glibc) resolves statically. The next step is building
those three statically from source (libslirp needs glib, glib needs pcre2, libffi and zlib), or a musl build.

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

## Measured (emulator v0.22.0, kernel 6.18.56, single-core guest, your own bucket)

| | Result |
|---|---|
| Boot to listening / warm worker ready | about 5 s / about 9 s |
| Worldless request, warm | 0.04-0.06 s |
| World request, no cache | about 10 s |
| World request, with cache (steady state) | about 5.4 s via the Lua command line, about 4 s via the C runner (unexplained; single runs) |
| Python imports of worker+storage+cryptography (uv runtime) | about 3 s (Ubuntu's Python: 4.6 s) |
| `compile()` of `world_core.py` (68 KB) in the guest | 0.6 s |

Where the ~5.5 s goes: five sequential authenticated reads from Tigris on fresh connections (about 0.9 s
each in the guest): TCP 0.02 s, TLS handshake 0.44 s (0.018 s natively), waiting for the answer 0.15-0.52 s
(0.46 s natively: real server latency, not the emulator). Two of the five are the world's own review-schedule
check. Fork costs 0.015 s. The guest clock runs about 12% slower than real time when CPU-bound, so guest CPU
figures undercount. Guest Python compute is about 100x slower than native. Bytecode is CPU-architecture
independent: a `.pyc` compiled on x86_64 with 3.12.3 loads in the riscv64 guest's 3.12.16, so a cache key
needs (source hash, Python magic number), not an architecture.

### Root filesystem format (read-only root, one run each, so world-request times carry about +-0.5 s)

| Format | File size | Boot to listening | Warm worker ready | Warm world request |
|---|---|---|---|---|
| ext2 | 512 MB (105 MB real data) | 6.1 s | 10.9 s | 5.35 s |
| squashfs xz | 61 MB | 14.5 s | 40.4 s | 5.80 s |
| squashfs zstd | 67 MB | 8.0 s | 21.2 s | 5.38 s |
| squashfs lz4 | 85 MB | 5.8 s | 12.9 s | 6.00 s |
| erofs lz4hc | 110 MB | 6.1 s | 10.8 s | 5.44 s |
| squashfs uncompressed | 182 MB | 6.5 s | 11.3 s | 5.07 s |
| **erofs uncompressed (default)** | **187 MB** | **4.9-5.7 s** | **8.6-10.1 s** | **5.2-5.4 s** |

Once the worker runs the format does not matter; decompression on the slow emulated CPU only costs at
start-up (xz +30 s, zstd +10 s, squashfs lz4 +2 s, erofs lz4hc +0). Uncompressed erofs was chosen: it boots
fastest and is reproducible. The host filesystem used here is ZFS, which compresses, so on-disk usage
understates uncompressed images: use file sizes.

### Read-only root footprint

With the root read-only and RAM tmpfs mounts the worker needs almost no writable space: after three real
world requests `/tmp` held 0 MB (only the socket) and `/run` about 0 MB. The guest has 109-111 MB of RAM by
default; after the requests about 77 MB was still available (warm process 28 MB, 33 MB once the cache is
filled; a child 20-23 MB, mostly shared via fork). Not measured: several children at once.

### Mapping and stored images

The emulator maps both files with `mmap`, privately: the kernel image is a `rw-p` mapping at the start of
guest RAM (the rest of RAM is anonymous), the erofs root is a read-only mapping (186.8 MB mapped, 29 MB
resident after boot). Loading costs almost nothing; the boot is the guest kernel running on the emulated CPU.
A stored machine (`--max-mcycle=0 --store`, or a snapshot after boot) is not possible while the machine uses
`-n`: user-mode networking sets the unreproducible flag, and the command line, `--create` and the library's
own `machine:store` all refuse it (and `--initial-hash` is refused too). The virtio device configuration
itself is plain data in the machine configuration.

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
- **Not done**: a write test through this worker, supervision to restart the warm process, TLS session
  resumption, a static executable, DAX for the erofs root, and an arm64/macOS/Windows check (TAP is
  Linux-only; no macOS or Windows CI upstream).
