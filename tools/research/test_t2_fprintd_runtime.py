# SPDX-License-Identifier: MIT
import asyncio
import hashlib
import importlib.util
from pathlib import Path
import runpy
import sys
import tempfile
import unittest
from unittest.mock import AsyncMock, Mock, patch

SPEC = importlib.util.spec_from_file_location("fprintd_overlay", Path(__file__).with_name("t2-fprintd-runtime.py"))
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class OverlayTests(unittest.TestCase):
    def test_stop_does_not_acknowledge_failed_child_cleanup(self):
        from types import SimpleNamespace
        device = SimpleNamespace(verify_task=None, backend=SimpleNamespace(_t2_child_cleanup_failed=True))
        with self.assertRaisesRegex(RuntimeError, 'cleanup incomplete'):
            asyncio.run(MODULE.cancel_verification_before_process(AsyncMock())(device, False))

    def test_direct_creation_cancellation_reaps_eventual_child(self):
        async def exercise():
            started, release = asyncio.Event(), asyncio.Event()
            process = Mock(returncode=None, wait=AsyncMock())
            async def spawn(*args, **kwargs):
                started.set()
                await release.wait()
                return process
            with patch.object(MODULE.asyncio, 'create_subprocess_exec', side_effect=spawn):
                task = asyncio.create_task(MODULE.direct_discovery_port())
                await started.wait()
                task.cancel()
                release.set()
                with self.assertRaises(asyncio.CancelledError):
                    await task
            process.kill.assert_called_once()
            process.wait.assert_awaited_once()
        asyncio.run(exercise())

    def test_pinned_probe_and_discovery_cancellation_reap_owned_children(self):
        try:
            import dbus_next  # noqa: F401
        except ImportError:
            self.skipTest('installed runtime venv required')
        self.assertEqual(hashlib.sha256(MODULE.SOURCE.read_bytes()).hexdigest(), MODULE.EXPECTED_SHA256)
        async def exercise(stage, project):
            namespace = runpy.run_path(str(MODULE.SOURCE), run_name='_owned_child_integration')
            MODULE.install_overlay(namespace)
            backend = namespace['T2Backend'].__new__(namespace['T2Backend'])
            backend.project_dir = project
            backend.port = None
            backend.process = None
            backend.probe_command = lambda port: [sys.executable, '-c', 'import time; time.sleep(60)']
            with patch.object(MODULE, 'direct_discovery_port', AsyncMock(side_effect=RuntimeError())):
                task = asyncio.create_task(backend.discover() if stage == 'discover' else backend._run_probe(50123))
                async def created():
                    while backend.process is None:
                        await asyncio.sleep(0.001)
                    return backend.process
                child = await asyncio.wait_for(created(), 3)
                task.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await asyncio.wait_for(task, 3)
                self.assertIsNotNone(child.returncode)
                self.assertIsNone(backend.process)
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            (project / 'src').mkdir()
            (project / 'src/discover-biometric-port.py').write_text('import time; time.sleep(60)\n')
            for stage in ('discover', 'probe'):
                asyncio.run(exercise(stage, project))

    def test_pinned_stop_race_does_not_rediscover_and_reaps_child(self):
        try:
            import dbus_next  # noqa: F401
        except ImportError:
            self.skipTest("installed runtime venv required")
        self.assertEqual(hashlib.sha256(MODULE.SOURCE.read_bytes()).hexdigest(), MODULE.EXPECTED_SHA256)

        async def exercise(fixed):
            namespace = runpy.run_path(str(MODULE.SOURCE), run_name="_test_stop_race")
            backend_type = namespace["T2Backend"]
            backend = backend_type.__new__(backend_type)
            backend.port_from_cache = True
            backend.port = 50123
            backend.process = None
            backend.notify_feedback = AsyncMock()
            terminated = asyncio.Event()
            started = asyncio.Event()

            class Process:
                returncode = None

                def terminate(self):
                    self.returncode = -15
                    terminated.set()

                async def wait(self):
                    await terminated.wait()
                    # Allow a child-exit failure to race the stop coroutine,
                    # as real asyncio subprocess notification can do.
                    await asyncio.sleep(0)
                    await asyncio.sleep(0)

            process = Process()
            process.terminate = Mock(wraps=process.terminate)
            process.wait = AsyncMock(wraps=process.wait)

            async def probe(port):
                backend.process = process
                started.set()
                try:
                    await terminated.wait()
                    raise RuntimeError("terminated child")
                finally:
                    backend.process = None

            async def discover():
                if backend.port is None:
                    await asyncio.Future()
                return backend.port

            backend.discover = AsyncMock(side_effect=discover)
            backend._run_probe = probe
            device = namespace["FprintDevice"](backend)
            device.verify_task = asyncio.create_task(device._run_verification())
            await started.wait()
            stop = type(device)._stop_verification
            if fixed:
                stop = MODULE.cancel_verification_before_process(stop)
            await stop(device, require_running=True)
            self.assertIsNone(device.verify_task)
            self.assertIsNone(backend.process)
            process.terminate.assert_called_once()
            process.wait.assert_awaited_once()
            backend.notify_feedback.assert_not_awaited()
            return backend.discover.await_count

        # The pinned original reproduces the bug entirely without device I/O.
        self.assertEqual(asyncio.run(exercise(False)), 2)
        self.assertEqual(asyncio.run(exercise(True)), 1)

    def test_prearm_timing_logs_only_allowlisted_line_and_preserves_stream(self):
        async def original(self, stream):
            result = []
            while line := await stream.readline():
                result.append(line)
            return result
        lines = [b"PRIVATE_SENTINEL\n", b"Touch ID timing: prearm elapsed_ms=101.2 early_marker=true\n",
                 b"Touch ID timing: prearm elapsed_ms=SECRET early_marker=true\n", b"TOUCH NOW\n"]
        stream = Mock(readline=AsyncMock(side_effect=lines + [b""]))
        with patch("builtins.print") as output:
            result = asyncio.run(MODULE.report_prearm_timing(original)(None, stream))
        self.assertEqual(result, lines)
        output.assert_called_once_with(lines[1].decode().rstrip(), flush=True)

    def test_probe_substitution_preserves_lock_and_all_options(self):
        argv = ["flock", "--exclusive", "lock", "python", MODULE.PROBE_SOURCE, "--prearm-seconds", "0.5"]
        command = MODULE.event_driven_probe_command(lambda self, port: argv)
        result = command(None, 50123)
        self.assertEqual(result, argv[:4] + [MODULE.PROBE_RUNTIME] + argv[5:])
        self.assertEqual(argv[4], MODULE.PROBE_SOURCE)
        for bad in ([], [MODULE.PROBE_SOURCE, MODULE.PROBE_SOURCE], ["/unexpected/probe.py"]):
            command = MODULE.event_driven_probe_command(lambda self, port: bad)
            with self.assertRaises(RuntimeError):
                command(None, 50123)

    def test_cached_endpoint_does_not_query_directory(self):
        original = AsyncMock(return_value=50123)
        backend = Mock(port=50123, port_from_cache=True)
        with patch.object(MODULE, "direct_discovery_port", new_callable=AsyncMock) as direct:
            self.assertEqual(asyncio.run(MODULE.prefer_direct_discovery(original)(backend)), 50123)
        direct.assert_not_called()
        original.assert_awaited_once_with(backend)
        self.assertTrue(backend.port_from_cache)

    def test_direct_directory_avoids_scan_and_refreshes_endpoint(self):
        original = AsyncMock()
        backend = Mock(port=None, port_from_cache=True)
        with patch.object(MODULE, "direct_discovery_port", new_callable=AsyncMock, return_value=50124):
            self.assertEqual(asyncio.run(MODULE.prefer_direct_discovery(original)(backend)), 50124)
        original.assert_not_called()
        self.assertEqual(backend.port, 50124)
        self.assertFalse(backend.port_from_cache)

    def test_directory_failure_falls_back_but_cancellation_does_not(self):
        for error in (OSError(), RuntimeError(), TimeoutError(), asyncio.CancelledError()):
            original = AsyncMock(return_value=50125)
            backend = Mock(port=None, port_from_cache=False)
            with patch.object(MODULE, "direct_discovery_port", new_callable=AsyncMock, side_effect=error):
                call = MODULE.prefer_direct_discovery(original)(backend)
                if isinstance(error, asyncio.CancelledError):
                    with self.assertRaises(asyncio.CancelledError):
                        asyncio.run(call)
                    original.assert_not_called()
                else:
                    self.assertEqual(asyncio.run(call), 50125)
                    original.assert_awaited_once_with(backend)

    def test_direct_subprocess_validates_output(self):
        for stdout, code, valid in ((b"50123\n", 0, True), (b"1\n", 0, False),
                                    (b"50123", 1, False), (b"secret", 0, False),
                                    (b"5" * 65, 0, False), (b"", 0, False)):
            process = Mock(returncode=code, communicate=AsyncMock(return_value=(stdout, b"PRIVATE")))
            with patch.object(MODULE.asyncio, "create_subprocess_exec", new_callable=AsyncMock, return_value=process):
                if valid:
                    self.assertEqual(asyncio.run(MODULE.direct_discovery_port()), 50123)
                else:
                    with self.assertRaises(RuntimeError):
                        asyncio.run(MODULE.direct_discovery_port())

    def test_direct_subprocess_is_reaped_on_timeout_and_cancel(self):
        for error in (TimeoutError(), asyncio.CancelledError()):
            process = Mock(returncode=None, communicate=AsyncMock(side_effect=error), wait=AsyncMock())
            with patch.object(MODULE.asyncio, "create_subprocess_exec", new_callable=AsyncMock, return_value=process):
                with self.assertRaises(type(error)):
                    asyncio.run(MODULE.direct_discovery_port())
            process.kill.assert_called_once()
            process.wait.assert_awaited_once()

    def test_timing_preserves_return_and_arguments(self):
        original = AsyncMock(return_value={"result": "unchanged"})
        wrapped = MODULE.timed_stage("test", original)
        instance = object()
        with patch("builtins.print"):
            result = asyncio.run(wrapped(instance, 123, option=True))
        self.assertEqual(result, {"result": "unchanged"})
        original.assert_awaited_once_with(instance, 123, option=True)

    def test_timing_preserves_exception_and_hides_payload(self):
        for error in (RuntimeError("PRIVATE_SENTINEL"), asyncio.CancelledError()):
            wrapped = MODULE.timed_stage("test", AsyncMock(side_effect=error))
            with patch("builtins.print") as output:
                with self.assertRaises(type(error)) as caught:
                    asyncio.run(wrapped(object()))
            self.assertIs(caught.exception, error)
            self.assertNotIn("PRIVATE_SENTINEL", str(output.call_args_list))

    def namespace(self):
        # Isolated function globals reproduce runpy behavior without D-Bus dependencies.
        namespace = {}
        exec('''
def verdict_from_result(result):
    return result["original_verdict"]
class T2Backend:
    async def verify(self):
        return verdict_from_result
    async def notify_feedback(self, verdict):
        self.feedback.append(verdict)
    async def notify_finger_requested(self):
        pass
''', namespace)
        MODULE.install_overlay(dict(namespace))
        return namespace

    def test_preserves_original_auth_decisions(self):
        namespace = self.namespace()
        for verdict in ("verify-match", "verify-no-match"):
            self.assertEqual(namespace["verdict_from_result"]({"match_events": [{"event_kind": "match_result"}], "original_verdict": verdict}), verdict)

    def test_missing_terminal_result_is_error(self):
        namespace = self.namespace()
        for result in (None, {}, {"match_events": []}, {"match_events": [{}]}, {"match_events": "invalid"}, {"match_events": [{"event_kind": "statistics"}]}):
            with self.assertRaisesRegex(RuntimeError, "no terminal"):
                namespace["verdict_from_result"](result)

    def test_errors_do_not_notify_rejection(self):
        backend = self.namespace()["T2Backend"]()
        backend.feedback = []
        for verdict in ("verify-match", "verify-no-match", "verify-unknown-error"):
            asyncio.run(backend.notify_feedback(verdict))
        self.assertEqual(backend.feedback, ["verify-match", "verify-no-match"])

    def test_ready_published_only_by_sensor_cue(self):
        backend = self.namespace()["T2Backend"]()
        with patch.object(MODULE, "publish") as publish:
            asyncio.run(backend.verify())
            self.assertEqual([call.args for call in publish.call_args_list], [("scan", "starting"), ("scan", "idle")])
            publish.reset_mock()
            asyncio.run(backend.notify_finger_requested())
            publish.assert_called_once_with("scan", "ready")

    def test_failure_or_cancel_clears_ready(self):
        for error, expected in ((RuntimeError("probe failed"), "unavailable"), (asyncio.CancelledError(), "idle")):
            async def original_verify(self):
                await self.notify_finger_requested()
                raise error

            async def original_cue(self):
                pass

            backend_type = type("TestBackend", (), {
                "verify": original_verify,
                "notify_finger_requested": original_cue,
                "notify_feedback": original_cue,
            })
            MODULE.install_overlay({"verdict_from_result": lambda result: "verify-no-match", "T2Backend": backend_type})
            with patch.object(MODULE, "publish") as publish:
                with self.assertRaises(type(error)):
                    asyncio.run(backend_type().verify())
                self.assertEqual([call.args for call in publish.call_args_list], [("scan", "starting"), ("scan", "ready"), ("scan", expected)])

    def test_source_change_prevents_execution(self):
        with patch.object(MODULE.Path, "read_bytes", return_value=b"changed"), patch.object(MODULE.runpy, "run_path") as run:
            with self.assertRaisesRegex(RuntimeError, "source changed"):
                MODULE.main()
            run.assert_not_called()

    def test_pinned_runtime_integration_when_available(self):
        if not MODULE.SOURCE.is_file():
            self.skipTest("pinned runtime unavailable")
        try:
            import dbus_next  # noqa: F401
        except ImportError:
            self.skipTest("run with installed runtime venv for D-Bus import smoke test")
        self.assertEqual(hashlib.sha256(MODULE.SOURCE.read_bytes()).hexdigest(), MODULE.EXPECTED_SHA256)
        namespace = runpy.run_path(str(MODULE.SOURCE), run_name="_test_fprintd_overlay")
        MODULE.install_overlay(namespace)
        verdict = namespace["T2Backend"]._t2_verdict
        result = {"match_user_id": 0xffffffff, "prearm_lifecycle": {"completed": True}, "match_start_reply": {"status": 0}, "match_events": [{"event_kind": "match_result", "version": 2, "matched": True, "matches_enrolled_identity": True}]}
        self.assertEqual(verdict(result), "verify-match")
        result["match_events"][0]["matches_enrolled_identity"] = False
        self.assertEqual(verdict(result), "verify-no-match")
        result["match_events"][0]["matched"] = False
        self.assertEqual(verdict(result), "verify-no-match")
        backend_type = namespace["T2Backend"]
        backend = backend_type.__new__(backend_type)
        backend.project_dir = Path("/opt/t2-touchid")
        backend.match_seconds = 20
        argv = backend.probe_command(50123)
        self.assertEqual(argv.count(MODULE.PROBE_RUNTIME), 1)
        self.assertNotIn(MODULE.PROBE_SOURCE, argv)
        self.assertEqual(argv[argv.index("--prearm-seconds") + 1], "0.5")
        backend.port, backend.port_from_cache = 50123, True
        backend._run_probe = AsyncMock(return_value=result)
        backend.notify_feedback = AsyncMock()
        with patch.object(MODULE, "publish"), patch.object(MODULE, "direct_discovery_port", new_callable=AsyncMock) as direct:
            self.assertEqual(asyncio.run(backend.verify())[0], "verify-no-match")
            direct.assert_not_called()
        backend._run_probe.assert_awaited_once_with(50123)
        # A stale cached endpoint gets exactly the original one retry, using
        # the newly advertised endpoint; success still requires real evidence.
        result["match_events"][0]["matched"] = True
        result["match_events"][0]["matches_enrolled_identity"] = True
        backend._run_probe = AsyncMock(side_effect=[RuntimeError("stale endpoint"), result])
        with patch.object(MODULE, "publish"), patch.object(MODULE, "direct_discovery_port", new_callable=AsyncMock, return_value=50124) as direct:
            self.assertEqual(asyncio.run(backend.verify())[0], "verify-match")
            direct.assert_awaited_once()
        self.assertEqual([call.args for call in backend._run_probe.await_args_list], [(50123,), (50124,)])
        self.assertFalse(backend.port_from_cache)
        result["match_events"] = []
        with self.assertRaises(RuntimeError):
            verdict(result)


if __name__ == "__main__":
    unittest.main()
