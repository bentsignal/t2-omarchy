# SPDX-License-Identifier: MIT
import asyncio
import hashlib
import importlib.util
from pathlib import Path
import runpy
import unittest
from unittest.mock import AsyncMock, patch

SPEC = importlib.util.spec_from_file_location("fprintd_overlay", Path(__file__).with_name("t2-fprintd-runtime.py"))
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class OverlayTests(unittest.TestCase):
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
        result["match_events"] = []
        with self.assertRaises(RuntimeError):
            verdict(result)


if __name__ == "__main__":
    unittest.main()
