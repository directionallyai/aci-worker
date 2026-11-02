#!/usr/bin/env python3
"""Warm worker for session_master_local (UNATTESTED, DEV ONLY).

Starting a fresh interpreter for every request costs seconds on a slow
emulated CPU, almost all of it importing worker.py, storage.py and
`cryptography`. This process imports them once, then serves requests from a
unix socket and forks one child per request. Each request therefore still runs
in its own process, with its own memory and its own exit: a request cannot leave
state behind for the next one, which is what a long-lived in-process loop would
risk.

There is no sandbox. The children are plain forks of this process, running as
whoever started it. Use it where the machine itself is the boundary (a
disposable emulator guest), not as a replacement for the bubblewrap sandbox.

World-code cache. The world modules (world_core.py, the account's world.py) are
fetched from the bucket by content hash and compiled from source in every
request, which on a slow emulated CPU costs more than the interpreter start-up
this process already saves. Before forking, this process (not the child) loads
them itself: it re-reads the two pointers on every request (so a repoint still
takes effect on the very next call, as worker.py documents), fetches an asset
only when its hash has not been seen, and keeps the verified bytes and the
compiled code object by sha256. The child then builds its modules from those
code objects without any network access. Because the cache lives in this
process's memory, submitted code running in a child cannot write to it. Nothing
here executes world code in the parent: it is fetched, hash-checked and compiled,
never exec'd. If anything in this step fails, the child simply takes the normal
path and reports the normal error.

This cache exists only for this long-lived local worker. The attested aci-worker
starts a fresh sandboxed process per request and keeps worker.py pinned, so none
of this applies there.

Wire format on the socket, both directions: u32 big-endian length, then that
many bytes of JSON. The request is what worker.py reads on stdin, the response
is what it would write on stdout.

Environment:
  WARM_SOCKET        path of the unix socket (default /run/worker-warm.sock)
  WARM_TIMEOUT_SECS  per-request limit, enforced with an alarm in the child
                     (default 300)
  WARM_LIB           directory holding worker.py and storage.py; put on
                     sys.path (default: the lib/ directory next to this file's
                     runtime, i.e. /opt/worker-runtime/lib)
  WARM_MAX_FRAME     largest accepted request in bytes (default 67108864)
  WARM_PREP_TIMEOUT_SECS  limit for the parent's world-code step (default 60)
  WARM_CACHE_ENTRIES      how many distinct world-code hashes to keep (default 16)
  WARM_CACHE_SCOPE        `account` (default): entries are per storage account;
                          `global`: shared across accounts; `off`: no cache
"""

import contextlib
import hashlib
import importlib.util
import json
import os
import signal
import socket
import struct
import sys
import types

DEFAULT_SOCKET = "/run/worker-warm.sock"
DEFAULT_LIB = "/opt/worker-runtime/lib"
DEFAULT_TIMEOUT_SECS = 300
DEFAULT_MAX_FRAME = 64 * 1024 * 1024
DEFAULT_PREP_TIMEOUT_SECS = 60
DEFAULT_READ_TIMEOUT_SECS = 10
DEFAULT_CACHE_ENTRIES = 16


def read_exactly(conn, n):
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise EOFError("connection closed mid-frame")
        buf += chunk
    return buf


def read_frame(conn, max_frame):
    (length,) = struct.unpack(">I", read_exactly(conn, 4))
    if length > max_frame:
        raise ValueError(f"frame of {length} bytes exceeds the {max_frame} byte limit")
    return read_exactly(conn, length)


def write_frame(conn, payload):
    conn.sendall(struct.pack(">I", len(payload)) + payload)


def failure(message):
    return {"ok": False, "result": None, "error": message, "stdout": ""}



CORE_MODULE = "directionally_world_core"
WORLD_MODULE = "directionally_world"


class WorldCache:
    """Parent-side cache of verified world-code assets and their compiled code.

    `prepare(request)` runs in the parent before fork and returns a `setup`
    callable for the child (or None when there is nothing to do). `worker` is the
    imported worker module, passed in so tests can supply a stand-in.

    Scope. Entries are keyed by content hash, but a cache hit skips the fetch, and
    the fetch is what proves the caller may read that asset. With scope `account`
    (the default) the key also carries the storage grant's own_prefix, so one
    account cannot receive another account's private code by pointing at its hash.
    Scope `global` shares entries across accounts: only for a worker that serves
    one person, or whose assets are all public.
    """

    def __init__(self, worker, max_entries=16, compiler=compile, scope="account"):
        if scope not in ("account", "global"):
            raise ValueError("scope must be `account` or `global`")
        self.scope = scope
        self._scope_key = ""
        self.worker = worker
        self.max_entries = max(1, max_entries)
        self.compiler = compiler
        self.assets = {}  # sha256 -> verified bytes
        self.codes = {}  # sha256 of source -> code object
        self.hits = {"assets": 0, "codes": 0}
        self.misses = {"assets": 0, "codes": 0}
        self._original_verified_asset = worker._verified_asset

    def _remember(self, table, key, value):
        table[key] = value
        while len(table) > self.max_entries:
            table.pop(next(iter(table)))

    def _cached_asset(self, bucket, digest, label):
        digest_key = (self._scope_key, digest)
        body = self.assets.get(digest_key)
        if body is not None:
            self.hits["assets"] += 1
            return body
        self.misses["assets"] += 1
        body = self._original_verified_asset(bucket, digest, label)  # checks the sha256
        self._remember(self.assets, digest_key, body)
        return body

    def prepare(self, request):
        if not request.get("world", True):
            return None
        prepared = {}
        grant = request.get("storage_grant")
        self._scope_key = (
            str(grant.get("own_prefix", "")) if self.scope == "account" and isinstance(grant, dict) else ""
        )

        def record(name, source):
            key = (self._scope_key, hashlib.sha256(source.encode("utf-8")).hexdigest())
            code = self.codes.get(key)
            if code is None:
                self.misses["codes"] += 1
                code = self.compiler(source, f"<{name}:live>", "exec")
                self._remember(self.codes, key, code)
            else:
                self.hits["codes"] += 1
            prepared[name] = code
            return types.ModuleType(name)  # never exec'd here

        worker = self.worker
        saved = (worker._verified_asset, worker.load_module_from_source)
        worker._verified_asset, worker.load_module_from_source = self._cached_asset, record
        try:
            bucket, _kv = worker.build_bucket_and_kv(
                request["storage_grant"], request.get("content_keys") or []
            )
            worker.load_world_core_module(bucket)
            worker.load_world_module(bucket)
        except BaseException:
            return None  # the child takes the normal path and reports the real error
        finally:
            worker._verified_asset, worker.load_module_from_source = saved
        if set(prepared) != {CORE_MODULE, WORLD_MODULE}:
            return None
        return lambda: self._install(prepared)

    def _install(self, prepared):
        """In the child: build the modules from the cached code objects."""
        worker = self.worker

        def build(name):
            def load(_bucket):
                spec = importlib.util.spec_from_loader(name, loader=None)
                module = importlib.util.module_from_spec(spec)
                sys.modules[name] = module
                try:
                    exec(prepared[name], module.__dict__)
                except Exception:
                    sys.modules.pop(name, None)
                    raise
                return module

            return load

        worker.load_world_core_module = build(CORE_MODULE)
        worker.load_world_module = build(WORLD_MODULE)


def _on_alarm(signum, frame):
    # Ask nicely once, so the caller gets an answer instead of a closed socket;
    # if submitted code swallows the exception, the default action (terminate)
    # follows five seconds later.
    signal.signal(signal.SIGALRM, signal.SIG_DFL)
    signal.alarm(5)
    raise TimeoutError("request exceeded the warm worker's time limit")


def serve_one(conn, handle, timeout_secs, request, setup=None):
    """Runs in the forked child: one prepared request in, one response out, then exit."""
    signal.signal(signal.SIGALRM, _on_alarm)
    signal.alarm(timeout_secs)
    try:
        if setup is not None:
            setup()
        response = handle(request)
    except BaseException as exc:  # SystemExit from submitted code included
        response = failure(f"{type(exc).__name__}: {exc}")
    try:
        write_frame(conn, json.dumps(response).encode("utf-8"))
    except OSError:
        pass


def _prep_alarm(signum, frame):
    raise TimeoutError("world-code preparation exceeded its time limit")


def _prepare_in_parent(prepare, request, prep_timeout):
    """The parent's trusted step before fork; any failure just means no setup."""
    if prepare is None:
        return None
    previous = signal.signal(signal.SIGALRM, _prep_alarm)
    signal.alarm(prep_timeout)
    try:
        return prepare(request)
    except BaseException:
        return None
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)


def _read_request(conn, max_frame):
    """Returns (request, None) or (None, error message)."""
    try:
        request = json.loads(read_frame(conn, max_frame))
    except BaseException as exc:
        return None, f"{type(exc).__name__}: {exc}"
    if not isinstance(request, dict):
        return None, "request must be a JSON object"
    return request, None


def serve(
    listener,
    handle,
    timeout_secs=DEFAULT_TIMEOUT_SECS,
    max_frame=DEFAULT_MAX_FRAME,
    prepare=None,
    prep_timeout=DEFAULT_PREP_TIMEOUT_SECS,
    read_timeout=DEFAULT_READ_TIMEOUT_SECS,
):
    # Children are never waited for: let the kernel reap them.
    signal.signal(signal.SIGCHLD, signal.SIG_IGN)
    while True:
        try:
            conn, _ = listener.accept()
        except InterruptedError:
            continue
        # The parent reads the request itself, so a stalled client must not hold it.
        conn.settimeout(read_timeout)
        request, error = _read_request(conn, max_frame)
        if error is not None:
            try:
                write_frame(conn, json.dumps(failure(error)).encode("utf-8"))
            except OSError:
                pass
            conn.close()
            continue
        setup = _prepare_in_parent(prepare, request, prep_timeout)
        conn.settimeout(None)
        pid = os.fork()
        if pid == 0:
            status = 1
            try:
                listener.close()
                serve_one(conn, handle, timeout_secs, request, setup)
                status = 0
            finally:
                os._exit(status)
        conn.close()


def main():
    lib = os.environ.get("WARM_LIB", DEFAULT_LIB)
    sys.path.insert(0, lib)
    # The whole point: pay for these imports once, before any request.
    import worker  # noqa: E402
    import storage  # noqa: E402,F401

    path = os.environ.get("WARM_SOCKET", DEFAULT_SOCKET)
    timeout_secs = int(os.environ.get("WARM_TIMEOUT_SECS", DEFAULT_TIMEOUT_SECS))
    max_frame = int(os.environ.get("WARM_MAX_FRAME", DEFAULT_MAX_FRAME))
    prep_timeout = int(os.environ.get("WARM_PREP_TIMEOUT_SECS", DEFAULT_PREP_TIMEOUT_SECS))
    scope = os.environ.get("WARM_CACHE_SCOPE", "account")
    prepare = None
    if scope != "off":
        cache = WorldCache(
            worker,
            max_entries=int(os.environ.get("WARM_CACHE_ENTRIES", DEFAULT_CACHE_ENTRIES)),
            scope=scope,
        )
        prepare = cache.prepare
    if os.path.exists(path):
        os.unlink(path)
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(path)
    os.chmod(path, 0o600)
    listener.listen(16)
    print(f"warm worker ready on {path} (no sandbox, unattested, world-code cache: {scope})", flush=True)
    serve(listener, worker.handle, timeout_secs, max_frame, prepare, prep_timeout)


if __name__ == "__main__":
    main()
