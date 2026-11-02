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
| `make-rootfs-uv.sh` also takes an optional `/reviewer` tree (the extracted reviewer bundle, put at `/opt/reviewer` with empty `home/` and `work/`), a `/smoke.sh`, and `NAME=` for the output name; see `directionallyai/reviewer-agent`, branch `riscv64-bundle`. |
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
   from the same staged tree give the same sha256; the tree's own bytecode is compiled serially with a fixed
   hash seed (`compileall -j 0` made it differ between builds).
4. Boot with the command line (root mapped read-only; init already mounts RAM tmpfs on `/tmp`, `/run` and `/dev/shm`):

   ```
   cartesi-machine --ram-image=linux-6.18.56-ctsi-1.bin \
     --flash-drive=label:root,data_filename:rootfs-worker-uv.erofs,read_only --append-bootargs=ro \
     --append-init='mount -t tmpfs -o size=16m tmpfs /run; touch /run/resolv.conf; mount -o bind /run/resolv.conf /etc/resolv.conf' \
     -n -p 0.0.0.0:8700:8700 -- \
     'WARM_CACHE_SCOPE=global WARM_LIB=/opt/worker-runtime/lib/python3.12/site-packages WARM_SOCKET=/tmp/w.sock \
      /opt/worker-runtime/bin/python3.12 /opt/worker-runtime/warm_server.py & \
      LOCAL_WARM_SOCKET=/tmp/w.sock LOCAL_LISTEN=0.0.0.0:8700 LOCAL_RUNTIME_DIR=/opt/worker-runtime LOCAL_SANDBOX=none /opt/bin/session_master_local'
   ```

   (`data_filename:`, not `filename:`. `-p` needs `-n`. The guest must listen on `0.0.0.0` because slirp
   forwards to 10.0.2.15. The `--append-init` goes before `-n`: on a read-only root `-n` would fail to write
   `/etc/resolv.conf`, so a RAM file is bind-mounted over it first. The entrypoint runs as the unprivileged
   user `dapp`, so it cannot mount anything; mounts belong in `--append-init`, which runs as root.)

5. Or boot it with the C runner, no Lua: write the machine's configuration once with the command line
   (`... --max-mcycle=0 --store-config=worker.json`), replace the `date -s @<epoch>` boot command with
   `date -s @{{NOW}}` (see `runner/worker.config.example.json`), then
   `runner/build-runner.sh && run-cartesi-worker worker.json`.

## What boots

Read from a running machine (emulator v0.22.0, static runner):

- **Kernel:** Linux 6.18.56-ctsi-1 for RISC-V (rv64imafdc plus the Zicntr/Zicsr/Zifencei/Zihpm/Zaamo/Zalrsc/Zca/Zcd
  extensions, Sv39 paging), one hart. Command line: `quiet earlycon=sbi console=hvc0 root=/dev/pmem0 ro
  init=/usr/sbin/cartesi-init`. Built in: erofs, ext2/3/4, squashfs, fuseblk. The virtio drivers present are net,
  console, blk, rng, balloon, 9p and vsock; the machine has one virtio device (the network).
- **Init:** PID 1 is `cartesi-init`, a 2.7 KB busybox shell script, not a service manager. It mounts `/proc`,
  `/dev/pts`, `/dev/shm`, `/sys`, `/tmp` and `/run` (tmpfs, `/tmp` about half of RAM), sets the hostname, runs
  the configuration's `init` commands **as root** (here: a RAM tmpfs on `/run`, the `eth0` address
  10.0.2.15/24, route via 10.0.2.2, DNS 10.0.2.3, the clock), then runs the configuration's `entrypoint` **as
  the unprivileged user `dapp`** (uid 1001, via `busybox su -p`, working directory `/home/dapp`). When the
  entrypoint ends it remounts `/` read-only, unmounts everything and powers off, with the exit code passed to
  the host if it is not zero.
- **Processes:** five user processes and 23 kernel threads, nothing else (no sshd, cron or udev): `cartesi-init`
  (1.2 MB), the entrypoint shell, the warm worker (27 MB), `session_master_local` (2.4 MB, the only listening
  socket, TCP 8700) and, while a request runs, its forked child (about 21 MB).
- **Memory:** 109 MB of RAM (the default 128 MiB less the kernel), about 50 MB free and 77 MB available shortly
  after boot, 29 MB cache.
- **Filesystems:** `/` is the erofs image on `/dev/pmem0` (186 MB, read-only); tmpfs on `/dev`, `/dev/shm`, `/tmp`
  and `/run`; the bind-mounted `/etc/resolv.conf`. Writable space is RAM only.
- **Network:** `eth0` (virtio-net, host user-mode network via libslirp), `lo`. The only way in is the host
  port forward to 8700.
- **Console:** `hvc0` (virtio console), going to the host's stdout.

## The C runner

`runner/run-cartesi-worker.c` (about 170 lines) creates the machine with `cm_create_new(config_json, ...)`
and loops `cm_run`. The C API has no virtio functions of its own: the `virtio` array in the configuration
(`net-user` with its `hostfwd`) is all there is, and libcartesi creates the devices and drives libslirp
inside `cm_run` (it imports `slirp_new`, `slirp_add_hostfwd`, `slirp_pollfds_fill/poll`, `slirp_input`).
Lua is not needed by libcartesi; only the command-line front end uses it. `{{NOW}}` in the configuration
is replaced with the current Unix time at start so the guest clock is right (a guest at the epoch fails
every TLS handshake with "certificate is not yet valid"). Guest console goes to stdout; SIGINT/SIGTERM stop
it between slices of 2^27 cycles (exit 130); a halt exits with the guest's own code.

Built against the dynamic library it boots the worker and serves real world requests (`runner/build-runner.sh`).
`runner/build-static.sh` builds the same program as a **fully static executable** (45 MB with debug
information, 9.9 MB stripped; `file` says "statically linked", `ldd` "not a dynamic executable"), and the
machine boots and serves real world requests from it inside a bare `busybox` container, which has no glibc,
glib, libslirp or libstdc++. What it takes, checked against Debian trixie:

- The emulator uses neither glib nor pcre2 directly. It calls libslirp from one file
  (`src/virtio-net-user-address-range.cpp`, the user-mode network behind `-n`/`-p`); libslirp imports 28 glib
  functions (memory, strings, random numbers, logging, and process spawning for a guest-forward-to-command
  feature we do not use); glib's only user of pcre2 is its regular-expression support.
- Static glib, pcre2, libffi, zlib and sysprof-capture all ship in Debian: `libglib-2.0.a` comes from
  `libgio-2.0-dev` (which `libglib2.0-dev` depends on, so listing `libglib2.0-dev` alone shows nothing),
  the others from `libpcre2-dev`, `libffi-dev`, `zlib1g-dev` and `libsysprof-capture-4-dev`.
- **libslirp is the only missing static library**: `libslirp-dev` (4.8.0) ships headers, `slirp.pc` and the
  `.so` symlink, and no package in the trixie archive contains a `libslirp*.a`. `build-static.sh` builds it from
  source (meson, static, same 4.8.0 that `libcartesi.a` was compiled against).
- Static glibc warns that `dlopen` (libgomp's offload plugin loader) and the user-database lookups in glib
  (`getpwnam_r`, `getpwuid`) need the matching shared glibc at run time; neither is used here.
- Speed: interleaved with the dynamic build (same grant, two rounds, six world requests each) the world
  requests are the same within noise (warm median 4.47 s static, 4.85 s dynamic; ready 8.6 s and 8.3 s);
  worldless requests are consistently about 10 ms slower (58 ms against 48 ms).

TAP networking (`--virtio-net=<iface>`) would avoid glib and libslirp altogether, but needs root and a
bridge on the host.

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
| World request, with cache (steady state) | about 4-5.4 s. Runs on different occasions differ by up to a second because Tigris latency varies; an interleaved dynamic-vs-static runner test showed no difference beyond noise. Whether the C runner beats the Lua command line was not tested in an interleaved run, so treat the earlier 4 s against 5.4 s as unproven. |
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

### What a guest costs the host (emulator v0.22.0, static runner, `/proc/<pid>/status` of the emulator)

Guest RAM that is never touched is not resident on the host, but everything the guest touches stays resident
even after the guest frees it (the guest has a balloon driver; nothing here uses it). The host sees two kinds of
memory: anonymous (the guest RAM it touched) and file-backed (the mapped root image, clean, shared and
reclaimable by the host).

| Guest | Host resident (RSS) | anonymous / file |
|---|---|---|
| 1.5 GiB, idle after boot | 129 MiB | 105 / 24 MiB |
| 512 MiB, Hermes start-up check | 318 MiB | 243 / 74 MiB |
| 1.5 GiB, Hermes start-up check | 335 MiB | 261 / 74 MiB |
| 1.5 GiB, after reading ~470 MiB of files (`tar` of `/opt /usr /lib /bin /sbin /etc`) | **1,035 MiB** | 601 / 433 MiB |

So tripling the guest's RAM costs nothing by itself (318 against 335 MiB), but file reads do: the guest keeps
a copy of every file it reads in its own page cache (3.5 to 469 MiB here) while the host also holds the mapped
image pages (433 MiB), so a read-heavy guest costs the host roughly twice the data it read. A long-lived guest
can creep toward its full RAM size plus the mapped image; a guest sized to the real working set (256-512 MiB for
the reviewer's start-up) caps that, and the machine boots in about 5 s, so one machine per task is cheap.
Not tried: mounting the erofs root with DAX, which should let the guest read the pmem directly instead of
copying into its page cache.

### Mapping and stored images

The emulator maps both files with `mmap`, privately: the kernel image is a `rw-p` mapping at the start of
guest RAM (the rest of RAM is anonymous), the erofs root is a read-only mapping (186.8 MB mapped, 29 MB
resident after boot). Loading costs almost nothing; the boot is the guest kernel running on the emulated CPU.
A stored machine (`--max-mcycle=0 --store`, or a snapshot after boot) is not possible while the machine uses
`-n`: user-mode networking sets the unreproducible flag, and the command line, `--create` and the library's
own `machine:store` all refuse it (and `--initial-hash` is refused too). The virtio device configuration
itself is plain data in the machine configuration.

## Known gaps

- **No sandbox inside the guest**: `LOCAL_SANDBOX=none` (the Cartesi kernel's support for the user namespaces
  bubblewrap needs was not checked); warm mode requires it. The boundary is the virtual machine itself: the
  worker and any submitted code run as the unprivileged user `dapp` on a read-only root, and the boot commands
  run as root before that.
- **No `queue_eval` / `local` channel**, so the scheduled reviewer cannot launch from this worker.
- **The reviewer bundle is x86_64 only.** `_run_reviewer_agent` fetches one bundle by pointer (account
  `reviewer_bundle`, falling back to the shared one) with no architecture in the key; it is the x86_64
  worker runtime plus Hermes 0.19.0 and x86_64 `git`/`ripgrep`, so it would not exec in this guest. Of its 62
  resolved packages, 47 are pure Python and 15 ship platform wheels, 6 of those with a riscv64 wheel on PyPI.
- **Not reproducible or attestable like the x86_64 runtime**: the interpreter is 3.12.16 (the repo pins
  3.12.14), `.pyc` files are kept, and the two cross-built wheels are not hash-pinned. They statically link
  Ubuntu noble's OpenSSL 3.0.x, not the newer OpenSSL the official wheels bundle.
- **The static build is not reproducible yet, and should move to a reproducible Ubuntu snapshot Docker
  environment.** `build-static.sh` runs in the emulator's Debian trixie builder image and does a live
  `apt-get update && install` (meson, ninja, glib, pcre2, libffi, zlib, sysprof-capture) at build time, then
  fetches the libslirp tarball by tag with no checksum, so two builds on different days can differ. The
  riscv64 builds of `cffi` and `cryptography` and the root-image scripts have the same shape (an
  `ubuntu:24.04` tag, live apt, packages from `ports.ubuntu.com`). The pattern to follow is already in the
  reviewer-agent and worker-python-runtime Dockerfiles: a digest-pinned base image, apt pointed at a dated
  `snapshot.ubuntu.com`, tools fetched with a pinned version and sha256. Ideally the emulator itself
  (`libcartesi.a`) is built in that same environment, so the static glibc, glib and libslirp all come from one
  snapshot, and Ubuntu 24.04 matches the guest's userland. The erofs image already builds to the same sha256
  twice from the same inputs; the static executable should too.
- **Not done**: a write test through this worker, supervision to restart the warm process, TLS session
  resumption, DAX for the erofs root, an interleaved C-runner-versus-Lua-CLI timing, and an
  arm64/macOS/Windows check (TAP is Linux-only; no macOS or Windows CI upstream).
