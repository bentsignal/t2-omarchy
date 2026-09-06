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
        verdict = namespace["T2Backend"].verify.__globals__["verdict_from_result"]
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
