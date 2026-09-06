# SPDX-License-Identifier: MIT
import hashlib
import importlib.util
from pathlib import Path
import runpy
import struct
import unittest
from unittest.mock import Mock, patch

SPEC = importlib.util.spec_from_file_location("bridge_overlay", Path(__file__).with_name("t2-bridge-probe-runtime.py"))
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def status(code=90, *, version=1, reserved=0, timestamp=1, extra=b""):
    return [9, 3825172480, struct.pack("<QIIQIIQ", reserved, 0xe3ff8001, version,
                                    timestamp, code, 0, 0) + extra, 0, 0]


class PrearmTests(unittest.TestCase):
    def setUp(self):
        if not MODULE.SOURCE.is_file():
            self.skipTest("pinned external probe unavailable")
        self.assertEqual(hashlib.sha256(MODULE.SOURCE.read_bytes()).hexdigest(), MODULE.EXPECTED_SHA256)
        self.namespace = runpy.run_path(str(MODULE.SOURCE), run_name="_test_probe")
        self.original = self.namespace["run_prearm_lifecycle"]
        self.scope = self.original.__globals__
        self.now = 0.0
        self.commands = []
        self.collected = []
        self.command_events = []
        self.batches = []
        self.reject_start = False
        self.reject_sleep = False
        self.failure = None
        self.command_failure = None

        def command(sock, opcode, **kwargs):
            self.commands.append((opcode, kwargs))
            if opcode == self.command_failure:
                raise ValueError("PRIVATE_FAILURE")
            rejected = (opcode == 4 and self.reject_start) or (opcode == 0x57 and kwargs.get("value") == 1 and self.reject_sleep)
            return [1 if rejected else 0, None], self.command_events.copy() if opcode == 4 else []

        def collect(sock, seconds, records, user):
            self.collected.append(seconds)
            self.now += seconds
            if self.failure:
                raise self.failure
            return self.batches.pop(0) if self.batches else []

        self.command, self.collect = command, collect
        self.scope["biometric_command"] = command
        self.scope["collect_timed_events"] = collect
        MODULE.install_overlay(self.namespace)

    def run_prearm(self):
        with patch.object(MODULE.time, "monotonic", side_effect=lambda: self.now), patch("builtins.print"):
            return self.scope["run_prearm_lifecycle"](Mock(), 0xffffffff, (bytes(20),), 0.5, 3.0)

    def test_marker_validation(self):
        summarize = self.scope["summarize_event"]
        self.assertTrue(MODULE.prearm_marker([status()], summarize))
        for event in (status(89), status(version=2), status(reserved=1), status(timestamp=0),
                      status(extra=b"extra"), [9, 0, b"bad", 0, 0], {}, []):
            self.assertFalse(MODULE.prearm_marker([event], summarize))

    def test_marker_in_start_reply_skips_only_wait(self):
        self.command_events = [status()]
        result = self.run_prearm()
        self.assertTrue(result["completed"])
        self.assertEqual(self.collected, [])
        self.assertEqual([op for op, _ in self.commands], [0x57, 4, 0x57, 12])
        self.assertEqual(self.commands[0][1], {"value": 1})
        self.assertEqual(self.commands[2][1], {"value": 0})
        self.assertEqual(struct.unpack_from("<II", self.commands[1][1]["data"]), (0x100, 0xffffffff))
        self.assertEqual(len(result["events"]), 1)
        self.assertNotIn("matched", result)

    def test_marker_after_one_batch_retains_all_events(self):
        self.batches = [[status(89)], [status(), status(63)]]
        result = self.run_prearm()
        self.assertAlmostEqual(self.now, 0.2)
        self.assertEqual([e["status_code"] for e in result["events"]], [89, 90, 63])
        self.assertTrue(result["completed"])

    def test_no_marker_keeps_original_wait_budget(self):
        self.batches = [[status(89)]]
        result = self.run_prearm()
        self.assertAlmostEqual(self.now, 0.5)
        self.assertEqual(len(result["events"]), 1)
        self.assertTrue(result["completed"])

    def test_rejected_start_is_not_shortcut_success(self):
        self.reject_start = True
        self.command_events = [status()]
        result = self.run_prearm()
        self.assertFalse(result["completed"])
        self.assertEqual(self.collected, [])
        self.assertEqual([op for op, _ in self.commands][-2:], [0x57, 12])

    def test_rejected_sleep_never_starts_capture(self):
        self.reject_sleep = True
        result = self.run_prearm()
        self.assertFalse(result["completed"])
        self.assertEqual(len(self.commands), 1)

    def test_receive_failure_cleans_up_and_restores_functions(self):
        self.failure = ValueError("PRIVATE_FAILURE")
        with self.assertRaises(ValueError):
            self.run_prearm()
        self.assertEqual([op for op, _ in self.commands][-2:], [0x57, 12])
        self.assertIs(self.scope["biometric_command"], self.command)
        self.assertIs(self.scope["collect_timed_events"], self.collect)

    def test_cancel_failure_propagates_and_restores(self):
        self.command_events = [status()]
        self.command_failure = 12
        with self.assertRaises(ValueError):
            self.run_prearm()
        self.assertIs(self.scope["biometric_command"], self.command)
        self.assertIs(self.scope["collect_timed_events"], self.collect)

    def test_success_restores_actual_match_collector(self):
        self.command_events = [status()]
        self.run_prearm()
        self.assertIs(self.scope["collect_timed_events"], self.collect)
        self.assertIs(self.scope["biometric_command"], self.command)

    def test_pin_failure_prevents_import(self):
        with patch.object(MODULE.Path, "read_bytes", return_value=b"changed"), patch.object(MODULE.runpy, "run_path") as run:
            with self.assertRaisesRegex(RuntimeError, "source changed"):
                MODULE.main()
            run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
