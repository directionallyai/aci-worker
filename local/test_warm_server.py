import hashlib
import json
import multiprocessing
import os
import socket
import struct
import sys
import tempfile
import time
import types
import unittest

import warm_server

COUNTER = {"n": 0}


def fake_handle(request):
    COUNTER["n"] += 1  # must never accumulate: each request is a fresh fork
    if request.get("sleep"):
        time.sleep(request["sleep"])
    if request.get("exit"):
        raise SystemExit(3)
    return {"ok": True, "result": request.get("code"), "pid": os.getpid(), "count": COUNTER["n"]}


def run_server(path, timeout_secs):
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(path)
    listener.listen(8)
    warm_server.serve(listener, fake_handle, timeout_secs=timeout_secs, max_frame=1024)


def call(path, payload):
    conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    conn.settimeout(20)
    with conn:
        conn.connect(path)
        warm_server.write_frame(conn, payload)
        return json.loads(warm_server.read_frame(conn, 1 << 20))


class WarmServerTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "w.sock")
        self.proc = multiprocessing.get_context("fork").Process(
            target=run_server, args=(self.path, 1)
        )
        self.proc.start()
        for _ in range(100):
            if os.path.exists(self.path):
                break
            time.sleep(0.05)

    def tearDown(self):
        self.proc.kill()
        self.proc.join()

    def test_round_trip(self):
        reply = call(self.path, json.dumps({"code": "6*7"}).encode())
        self.assertEqual(reply["ok"], True)
        self.assertEqual(reply["result"], "6*7")

    def test_every_request_gets_its_own_process_and_clean_state(self):
        first = call(self.path, b'{"code": 1}')
        second = call(self.path, b'{"code": 2}')
        self.assertNotEqual(first["pid"], second["pid"])
        self.assertNotEqual(first["pid"], self.proc.pid)
        self.assertEqual((first["count"], second["count"]), (1, 1))

    def test_non_object_and_garbage_are_refused(self):
        self.assertEqual(call(self.path, b"[1]")["ok"], False)
        self.assertIn("JSON", call(self.path, b"not json")["error"])

    def test_oversized_frame_is_refused(self):
        self.assertIn("exceeds", call(self.path, b" " * 2000)["error"])

    def test_system_exit_in_submitted_code_still_gets_an_answer(self):
        reply = call(self.path, b'{"exit": true}')
        self.assertEqual(reply["ok"], False)
        self.assertIn("SystemExit", reply["error"])

    def test_a_slow_request_times_out_with_an_answer_and_the_server_survives(self):
        reply = call(self.path, b'{"sleep": 5}')
        self.assertEqual(reply["ok"], False)
        self.assertIn("time limit", reply["error"])
        self.assertEqual(call(self.path, b'{"code": 1}')["ok"], True)


CORE_SRC = "VALUE = 'core'\n"
WORLD_SRC = "class World:\n    pass\nVALUE = 'world'\n"


def sha(text):
    return hashlib.sha256(text.encode()).hexdigest()


class FakeWorker:
    """Stands in for worker.py: same call shape (loaders look the helpers up by name
    at call time), with counters for what touches the 'network'."""

    def __init__(self):
        self.store = {}
        self.pointers = {"core": sha(CORE_SRC), "world": sha(WORLD_SRC)}
        self.counts = {"pointer": 0, "asset": 0, "bucket": 0}
        self.fail_pointer = False
        self.store[sha(CORE_SRC)] = CORE_SRC.encode()
        self.store[sha(WORLD_SRC)] = WORLD_SRC.encode()

    def _verified_asset(self, bucket, digest, label):
        self.counts["asset"] += 1
        body = self.store[digest]
        assert hashlib.sha256(body).hexdigest() == digest
        return body

    def load_module_from_source(self, name, source):
        module = types.ModuleType(name)
        sys.modules[name] = module
        exec(compile(source, f"<{name}>", "exec"), module.__dict__)
        return module

    def build_bucket_and_kv(self, grant, keys):
        self.counts["bucket"] += 1
        return object(), object()

    def _pointer(self, which):
        self.counts["pointer"] += 1
        if self.fail_pointer:
            raise RuntimeError("pointer unreadable")
        return self.pointers[which]

    def load_world_core_module(self, bucket):
        digest = self._pointer("core")
        return self.load_module_from_source(
            warm_server.CORE_MODULE, self._verified_asset(bucket, digest, "core").decode()
        )

    def load_world_module(self, bucket):
        digest = self._pointer("world")
        return self.load_module_from_source(
            warm_server.WORLD_MODULE, self._verified_asset(bucket, digest, "world").decode()
        )


def world_request(prefix="acct-a/"):
    return {"mode": "eval", "code": "1", "storage_grant": {"own_prefix": prefix}, "content_keys": []}


class WorldCacheTest(unittest.TestCase):
    def setUp(self):
        self.worker = FakeWorker()
        self.compiled = []

        def counting_compile(source, filename, mode):
            self.compiled.append(filename)
            return compile(source, filename, mode)

        self.make = lambda **kw: warm_server.WorldCache(self.worker, compiler=counting_compile, **kw)
        self.original_asset = self.worker._verified_asset
        self.original_loader = self.worker.load_module_from_source

    def tearDown(self):
        for name in (warm_server.CORE_MODULE, warm_server.WORLD_MODULE):
            sys.modules.pop(name, None)

    def test_second_request_skips_asset_fetches_and_compiles_but_rereads_pointers(self):
        cache = self.make()
        self.assertIsNotNone(cache.prepare(world_request()))
        self.assertEqual((self.worker.counts["asset"], len(self.compiled)), (2, 2))
        self.assertIsNotNone(cache.prepare(world_request()))
        self.assertEqual((self.worker.counts["asset"], len(self.compiled)), (2, 2))
        # live-swap semantics: the pointers are read again on every request
        self.assertEqual(self.worker.counts["pointer"], 4)

    def test_a_repointed_world_is_picked_up_on_the_very_next_request(self):
        cache = self.make()
        cache.prepare(world_request())
        new_src = "VALUE = 'world v2'\n"
        self.worker.store[sha(new_src)] = new_src.encode()
        self.worker.pointers["world"] = sha(new_src)
        setup = cache.prepare(world_request())
        self.assertEqual(self.worker.counts["asset"], 3)  # only the new world.py was fetched
        setup()
        self.assertEqual(self.worker.load_world_module(None).VALUE, "world v2")

    def test_the_child_builds_its_modules_from_the_cache_without_touching_storage(self):
        cache = self.make()
        setup = cache.prepare(world_request())
        before = dict(self.worker.counts)
        setup()
        core = self.worker.load_world_core_module(None)
        world = self.worker.load_world_module(None)
        self.assertEqual((core.VALUE, world.VALUE), ("core", "world"))
        self.assertIs(sys.modules[warm_server.CORE_MODULE], core)
        self.assertEqual(self.worker.counts, before)

    def test_account_scope_does_not_share_entries_between_accounts(self):
        cache = self.make(scope="account")
        cache.prepare(world_request("acct-a/"))
        cache.prepare(world_request("acct-b/"))
        self.assertEqual(self.worker.counts["asset"], 4)  # b had to prove access itself

    def test_global_scope_shares_entries_between_accounts(self):
        cache = self.make(scope="global")
        cache.prepare(world_request("acct-a/"))
        cache.prepare(world_request("acct-b/"))
        self.assertEqual(self.worker.counts["asset"], 2)

    def test_unknown_scope_is_refused(self):
        with self.assertRaises(ValueError):
            self.make(scope="everyone")

    def test_a_failed_preparation_returns_no_setup_and_restores_the_worker(self):
        cache = self.make()
        self.worker.fail_pointer = True
        self.assertIsNone(cache.prepare(world_request()))
        self.assertEqual(self.worker._verified_asset, self.original_asset)
        self.assertEqual(self.worker.load_module_from_source, self.original_loader)

    def test_worldless_requests_are_left_alone(self):
        cache = self.make()
        request = world_request()
        request["world"] = False
        self.assertIsNone(cache.prepare(request))
        self.assertEqual(self.worker.counts, {"pointer": 0, "asset": 0, "bucket": 0})

    def test_the_cache_is_bounded(self):
        cache = self.make(max_entries=2)
        for i in range(4):
            src = f"VALUE = {i}\n"
            self.worker.store[sha(src)] = src.encode()
            self.worker.pointers["world"] = sha(src)
            cache.prepare(world_request())
        self.assertLessEqual(len(cache.assets), 2)
        self.assertLessEqual(len(cache.codes), 2)

    def test_a_tampered_asset_is_still_refused_on_first_fetch(self):
        cache = self.make()
        self.worker.store[sha(WORLD_SRC)] = b"VALUE = 'evil'\n"
        # The core was genuine and may be cached; the tampered world.py must not be.
        self.assertIsNone(cache.prepare(world_request()))  # the hash check failed
        self.assertNotIn(("acct-a/", sha(WORLD_SRC)), cache.assets)
        self.assertEqual(len(cache.codes), 1)


PARENT = {"n": 0}
CHILD = {"n": None}


def run_prepared_server(path, explode):
    def prepare(request):
        if explode and request.get("explode"):
            raise RuntimeError("prepare failed")
        PARENT["n"] += 1
        n = PARENT["n"]
        return lambda: CHILD.update(n=n)

    def handle(request):
        return {"ok": True, "n": CHILD["n"], "pid": os.getpid()}

    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(path)
    listener.listen(8)
    warm_server.serve(listener, handle, timeout_secs=5, max_frame=1024, prepare=prepare,
                      prep_timeout=5, read_timeout=0.5)


class PreparedServeTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "w.sock")
        self.proc = multiprocessing.get_context("fork").Process(
            target=run_prepared_server, args=(self.path, True))
        self.proc.start()
        for _ in range(100):
            if os.path.exists(self.path):
                break
            time.sleep(0.05)

    def tearDown(self):
        self.proc.kill()
        self.proc.join()

    def test_prepare_runs_in_the_parent_and_its_state_persists_across_requests(self):
        first = call(self.path, b"{}")
        second = call(self.path, b"{}")
        self.assertEqual((first["n"], second["n"]), (1, 2))
        self.assertNotEqual(first["pid"], second["pid"])

    def test_a_failing_prepare_does_not_stop_the_request(self):
        reply = call(self.path, b'{"explode": true}')
        self.assertEqual(reply["ok"], True)
        self.assertIsNone(reply["n"])  # no setup ran, the child took the normal path

    def test_a_client_that_never_sends_does_not_block_the_next_one(self):
        stalled = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        stalled.connect(self.path)
        started = time.time()
        reply = call(self.path, b"{}")
        stalled.close()
        self.assertEqual(reply["ok"], True)
        self.assertLess(time.time() - started, 5)


if __name__ == "__main__":
    unittest.main()
