# SPDX-License-Identifier: MIT
import importlib.util
from pathlib import Path
import subprocess
import unittest
from unittest.mock import Mock, patch

SPEC = importlib.util.spec_from_file_location("sleep_ui", Path(__file__).with_name("t2-touchid-sleep-ui.py"))
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class SleepUiTests(unittest.TestCase):
    def test_acknowledged_preparation_has_bounded_render_grace(self):
        with patch.object(MODULE.subprocess, "run", return_value=Mock(returncode=0, stdout="prepared\n")) as run, patch.object(MODULE.time, "sleep") as sleep:
            self.assertTrue(MODULE.prepare_ui())
        self.assertEqual(run.call_args.args[0], ["omarchy", "shell", "lock", "prepareTouchIdSleep"])
        self.assertEqual(run.call_args.kwargs["timeout"], 1.0)
        sleep.assert_called_once_with(0.25)

    def test_failure_or_timeout_releases_without_grace(self):
        for failure in (OSError(), subprocess.TimeoutExpired("ipc", 1)):
            with patch.object(MODULE.subprocess, "run", side_effect=failure), patch.object(MODULE.time, "sleep") as sleep:
                self.assertFalse(MODULE.prepare_ui())
            sleep.assert_not_called()
        for code, stdout in ((0, "unknown method"), (1, "prepared")):
            with patch.object(MODULE.subprocess, "run", return_value=Mock(returncode=code, stdout=stdout)), patch.object(MODULE.time, "sleep") as sleep:
                self.assertFalse(MODULE.prepare_ui())
            sleep.assert_not_called()

    def test_only_true_signal_prepares_and_monitor_is_reaped(self):
        child = Mock(stdout=iter(["boolean false\n", "   boolean true\n"]), poll=Mock(return_value=None))
        with patch.object(MODULE.subprocess, "Popen", return_value=child), patch.object(MODULE, "prepare_ui") as prepare:
            MODULE.monitor()
        prepare.assert_called_once()
        child.terminate.assert_called_once()
        child.wait.assert_called_once_with(timeout=1)

    def test_eof_does_not_prepare_or_leave_child(self):
        child = Mock(stdout=iter([]), poll=Mock(return_value=1))
        with patch.object(MODULE.subprocess, "Popen", return_value=child), patch.object(MODULE, "prepare_ui") as prepare:
            MODULE.monitor()
        prepare.assert_not_called()
        child.wait.assert_called_once()


if __name__ == "__main__":
    unittest.main()
