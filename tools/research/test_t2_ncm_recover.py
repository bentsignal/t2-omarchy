# SPDX-License-Identifier: MIT
import errno
from contextlib import ExitStack
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

SPEC = importlib.util.spec_from_file_location("ncm_recover", Path(__file__).with_name("t2-ncm-recover.py"))
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
CONFIG = 'T2_TOUCHID_HOST="fe80::1"\nT2_TOUCHID_INTERFACE=enp4s0f1u1\n'


class RecoveryTests(unittest.TestCase):
    def test_endpoint(self):
        self.assertEqual(MODULE.parse_endpoint(CONFIG, "50000\n"), ("fe80::1", "enp4s0f1u1", 50000))

    def test_reject_ambiguous_or_unsafe_endpoint(self):
        for config in (
            CONFIG + "T2_TOUCHID_INTERFACE=eth0\n",
            CONFIG.replace("fe80::1", "::1"),
            CONFIG.replace("fe80::1", "fe80::1%eth0"),
            CONFIG.replace("enp4s0f1u1", "../eth0"),
            CONFIG + "T2_TOUCHID_PORT_FILE=/tmp/port\n",
        ):
            with self.subTest(config=config), self.assertRaises((MODULE.RecoveryError, ValueError)):
                MODULE.parse_endpoint(config, "50000")
        with self.assertRaises(MODULE.RecoveryError):
            MODULE.parse_endpoint(CONFIG, "80")

    def fixture(self, root):
        driver = root / "bus/usb/drivers/cdc_ncm"
        driver.mkdir(parents=True)
        device = root / "devices/t2bce_vhci/usb7/7-1/7-1:1.0"
        device.mkdir(parents=True)
        (device / "driver").symlink_to(driver)
        (device.parent / "idVendor").write_text("05ac\n")
        (device.parent / "idProduct").write_text("8233\n")
        net = root / "class/net/enp4s0f1u1"
        net.mkdir(parents=True)
        (net / "device").symlink_to(device)
        (net / "operstate").write_text("up\n")
        (net / "statistics").mkdir()
        (net / "statistics/tx_errors").write_text("4\n")
        return driver, device

    def test_exact_internal_device_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            driver, device = self.fixture(root)
            self.assertEqual(MODULE.validate_target("enp4s0f1u1", root), (driver, "7-1:1.0"))
            for filename, value in (("idVendor", "106b"), ("idProduct", "9999")):
                path = device.parent / filename
                original = path.read_text()
                path.write_text(value)
                with self.assertRaises(MODULE.RecoveryError):
                    MODULE.validate_target("enp4s0f1u1", root)
                path.write_text(original)
            (root / "class/net/enp4s0f1u1/operstate").write_text("down")
            with self.assertRaises(MODULE.RecoveryError):
                MODULE.validate_target("enp4s0f1u1", root)

    def test_healthy_and_transient_failure_never_rebind(self):
        for answers in ([True], [False, True]):
            with patch.object(MODULE, "validate_target"), patch.object(MODULE, "transport_reachable", side_effect=answers), patch.object(MODULE, "rebind") as rebind, patch.object(MODULE.time, "sleep"):
                self.assertFalse(MODULE.recover("fe80::1", "test", 50000))
                rebind.assert_not_called()

    def test_interface_up_is_awaited_before_probing(self):
        target = ("driver", "7-1:1.0")
        with patch.object(MODULE, "validate_target", side_effect=[MODULE.InterfaceNotReady(), MODULE.InterfaceNotReady(), target]), patch.object(MODULE, "transport_reachable", return_value=True) as probe, patch.object(MODULE, "rebind") as rebind, patch.object(MODULE.time, "sleep") as sleep, patch.object(MODULE.time, "monotonic", return_value=0):
            self.assertFalse(MODULE.recover("fe80::1", "test", 50000))
            self.assertEqual(sleep.call_count, 2)
            self.assertEqual([call.args for call in sleep.call_args_list], [(0.05,), (0.05,)])
            probe.assert_called_once()
            rebind.assert_not_called()

    def test_persistently_down_interface_is_not_probed_or_rebound(self):
        with patch.object(MODULE, "validate_target", side_effect=MODULE.InterfaceNotReady()), patch.object(MODULE, "transport_reachable") as probe, patch.object(MODULE, "rebind") as rebind, patch.object(MODULE.time, "monotonic", side_effect=[0, 11]):
            with self.assertRaisesRegex(MODULE.RecoveryError, "still down"):
                MODULE.recover("fe80::1", "test", 50000)
            probe.assert_not_called()
            rebind.assert_not_called()

    def test_unsafe_target_is_not_retried_as_interface_down(self):
        with patch.object(MODULE, "validate_target", side_effect=MODULE.RecoveryError("wrong device")) as validate, patch.object(MODULE.time, "sleep") as sleep:
            with self.assertRaisesRegex(MODULE.RecoveryError, "wrong device"):
                MODULE.wait_for_target("test")
            validate.assert_called_once()
            sleep.assert_not_called()

    def test_down_then_delayed_watchdog_then_link_recovery(self):
        target = ("driver", "7-1:1.0")
        with patch.object(MODULE, "validate_target", side_effect=[MODULE.InterfaceNotReady(), target, target, target, target]), patch.object(MODULE, "tx_errors", side_effect=[0, 0, 1]), patch.object(MODULE, "transport_reachable", side_effect=[False] * 4 + [True]), patch.object(MODULE, "rebind") as rebind, patch.object(MODULE.time, "sleep"), patch.object(MODULE.time, "monotonic", return_value=0):
            self.assertTrue(MODULE.recover("fe80::1", "test", 50000))
            rebind.assert_called_once_with(*target)

    def test_stalled_link_rebinds_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            driver, _device = self.fixture(root)
            # Default validate_target argument is explicit because it binds SYS at import.
            with patch.object(MODULE, "SYS", root), patch.object(MODULE, "validate_target", return_value=(driver, "7-1:1.0")), patch.object(MODULE, "transport_reachable", side_effect=[False, False, False, True]), patch.object(MODULE, "rebind") as rebind, patch.object(MODULE.time, "sleep"):
                self.assertTrue(MODULE.recover("fe80::1", "enp4s0f1u1", 50000))
                rebind.assert_called_once_with(driver, "7-1:1.0")

    def test_missing_tx_evidence_never_rebinds(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.fixture(root)
            (root / "class/net/enp4s0f1u1/statistics/tx_errors").write_text("0")
            with patch.object(MODULE, "SYS", root), patch.object(MODULE, "validate_target"), patch.object(MODULE, "transport_reachable", return_value=False), patch.object(MODULE, "rebind") as rebind, patch.object(MODULE.time, "sleep"), patch.object(MODULE.time, "monotonic", side_effect=[0, 0, 13]):
                with self.assertRaisesRegex(MODULE.RecoveryError, "without TX-error"):
                    MODULE.recover("fe80::1", "enp4s0f1u1", 50000)
                rebind.assert_not_called()

    def test_delayed_watchdog_evidence_allows_one_rebind(self):
        with patch.object(MODULE, "validate_target", return_value=("driver", "7-1:1.0")), patch.object(MODULE, "tx_errors", side_effect=[0, 0, 0, 1]), patch.object(MODULE, "transport_reachable", side_effect=[False] * 5 + [True]), patch.object(MODULE, "rebind") as rebind, patch.object(MODULE.time, "sleep"), patch.object(MODULE.time, "monotonic", return_value=0):
            self.assertTrue(MODULE.recover("fe80::1", "test", 50000))
            rebind.assert_called_once_with("driver", "7-1:1.0")

    def test_peer_recovery_during_grace_does_not_rebind(self):
        with patch.object(MODULE, "validate_target"), patch.object(MODULE, "tx_errors", return_value=0), patch.object(MODULE, "transport_reachable", side_effect=[False] * 3 + [True]), patch.object(MODULE, "rebind") as rebind, patch.object(MODULE.time, "sleep"), patch.object(MODULE.time, "monotonic", return_value=0):
            self.assertFalse(MODULE.recover("fe80::1", "test", 50000))
            rebind.assert_not_called()

    def test_target_change_during_grace_does_not_rebind(self):
        with patch.object(MODULE, "validate_target", side_effect=[("driver", "7-1:1.0"), ("driver", "8-1:1.0")]), patch.object(MODULE, "tx_errors", return_value=0), patch.object(MODULE, "transport_reachable", return_value=False), patch.object(MODULE, "rebind") as rebind, patch.object(MODULE.time, "sleep"), patch.object(MODULE.time, "monotonic", return_value=0):
            with self.assertRaisesRegex(MODULE.RecoveryError, "target changed"):
                MODULE.recover("fe80::1", "test", 50000)
            rebind.assert_not_called()

    def test_connection_refused_is_reachable(self):
        for error, expected in ((ConnectionRefusedError(errno.ECONNREFUSED, "refused"), True), (TimeoutError(), False), (OSError(errno.EHOSTUNREACH, "unreachable"), False)):
            connection = MagicMock()
            connection.__enter__.return_value = connection
            connection.connect.side_effect = error
            with patch.object(MODULE.socket, "if_nametoindex", return_value=2), patch.object(MODULE.socket, "socket", return_value=connection):
                self.assertEqual(MODULE.transport_reachable("fe80::1", "test", 50000), expected)

    def test_rebind_always_attempts_bind_on_unbind_failure(self):
        driver = MagicMock()
        unbind, bind, member = MagicMock(), MagicMock(), MagicMock()
        driver.__truediv__.side_effect = lambda name: {"unbind": unbind, "bind": bind, "7-1:1.0": member}[name]
        member.exists.return_value = False
        unbind.write_text.side_effect = OSError("unbind interrupted")
        with self.assertRaises(OSError):
            MODULE.rebind(driver, "7-1:1.0")
        bind.write_text.assert_called_once_with("7-1:1.0")

    def test_busy_operation_lock_prevents_recovery(self):
        with tempfile.TemporaryDirectory() as tmp:
            lock = Path(tmp) / "operation.lock"
            lock.touch(mode=0o600)
            info = lock.stat()
            root_info = MagicMock(st_mode=info.st_mode, st_uid=0)
            holder = os.open(lock, os.O_RDWR)
            try:
                MODULE.fcntl.flock(holder, MODULE.fcntl.LOCK_EX | MODULE.fcntl.LOCK_NB)
                with patch.object(MODULE, "LOCK", lock), patch.object(MODULE.os, "fstat", return_value=root_info):
                    with self.assertRaisesRegex(MODULE.RecoveryError, "operation busy"):
                        MODULE.lock_operation(0)
            finally:
                os.close(holder)

    def test_changed_target_prevents_rebind(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.fixture(root)
            with patch.object(MODULE, "SYS", root), patch.object(MODULE, "validate_target", side_effect=[("driver", "7-1:1.0"), ("driver", "8-1:1.0")]), patch.object(MODULE, "transport_reachable", return_value=False), patch.object(MODULE, "rebind") as rebind, patch.object(MODULE.time, "sleep"):
                with self.assertRaisesRegex(MODULE.RecoveryError, "target changed"):
                    MODULE.recover("fe80::1", "enp4s0f1u1", 50000)
                rebind.assert_not_called()

    def test_failed_recovery_does_not_repeat_rebind(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.fixture(root)
            with patch.object(MODULE, "SYS", root), patch.object(MODULE, "validate_target"), patch.object(MODULE, "transport_reachable", return_value=False), patch.object(MODULE, "rebind") as rebind, patch.object(MODULE.time, "sleep"), patch.object(MODULE.time, "monotonic", side_effect=[0, 0, 0, 0, 13]):
                with self.assertRaisesRegex(MODULE.RecoveryError, "still unreachable"):
                    MODULE.recover("fe80::1", "enp4s0f1u1", 50000)
                rebind.assert_called_once()

    def test_confirmed_resume_recovers_early_without_reading_watchdog(self):
        target = ("driver", "7-1:1.0")
        with patch.object(MODULE, "validate_target", return_value=target), patch.object(MODULE, "consume_resume_ticket", return_value=True) as ticket, patch.object(MODULE, "transport_reachable", side_effect=[False] * 3 + [True]) as probe, patch.object(MODULE, "tx_errors") as errors, patch.object(MODULE, "rebind") as rebind, patch.object(MODULE.time, "sleep"), patch.object(MODULE.time, "monotonic", return_value=0):
            self.assertTrue(MODULE.recover("fe80::1", "test", 50000, after_resume=True))
            ticket.assert_called_once_with("fe80::1", "test", target)
            errors.assert_not_called()
            rebind.assert_called_once_with(*target)
            self.assertEqual([call.kwargs["timeout"] for call in probe.call_args_list], [0.35] * 3 + [0.25])

    def test_resume_with_missing_guard_retains_watchdog_requirement(self):
        with patch.object(MODULE, "validate_target"), patch.object(MODULE, "consume_resume_ticket", return_value=False), patch.object(MODULE, "transport_reachable", return_value=False), patch.object(MODULE, "tx_errors", return_value=0), patch.object(MODULE, "rebind") as rebind, patch.object(MODULE.time, "sleep"), patch.object(MODULE.time, "monotonic", side_effect=[0, 0, 13]):
            with self.assertRaisesRegex(MODULE.RecoveryError, "without TX-error"):
                MODULE.recover("fe80::1", "test", 50000, after_resume=True)
            rebind.assert_not_called()

    def test_early_healthy_or_transient_link_is_not_rebound(self):
        for replies in ([True], [False, True], [False, False, True]):
            with patch.object(MODULE, "validate_target"), patch.object(MODULE, "consume_resume_ticket", return_value=True) as ticket, patch.object(MODULE, "transport_reachable", side_effect=replies), patch.object(MODULE, "rebind") as rebind, patch.object(MODULE.time, "sleep"):
                self.assertFalse(MODULE.recover("fe80::1", "test", 50000, after_resume=True))
                ticket.assert_called_once()
                rebind.assert_not_called()

    def test_early_target_change_still_prevents_rebind(self):
        with patch.object(MODULE, "validate_target", side_effect=[("driver", "7-1:1.0"), ("driver", "8-1:1.0")]), patch.object(MODULE, "consume_resume_ticket", return_value=True), patch.object(MODULE, "transport_reachable", return_value=False), patch.object(MODULE, "rebind") as rebind, patch.object(MODULE.time, "sleep"):
            with self.assertRaisesRegex(MODULE.RecoveryError, "target changed"):
                MODULE.recover("fe80::1", "test", 50000, after_resume=True)
            rebind.assert_not_called()


class ResumeTicketTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        root = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.ticket = root / "resume-ticket.json"
        self.boot = root / "boot_id"
        self.count = root / "success"
        self.boot.write_text("fixture-boot\n")
        self.count.write_text("11\n")
        for name, value in (("RESUME_TICKET", self.ticket), ("BOOT_ID", self.boot), ("SUSPEND_SUCCESS", self.count)):
            self.stack.enter_context(patch.object(MODULE, name, value))
        self.stack.enter_context(patch.object(MODULE, "ticket_directory_safe"))
        self.stack.enter_context(patch.object(MODULE, "private_read", side_effect=lambda path: path.read_text()))
        self.stack.enter_context(patch.object(MODULE.time, "monotonic", return_value=100))
        self.record = {"schema_version": 1, "boot_id": "fixture-boot", "suspend_success": 10, "monotonic": 70, "host": "fe80::1", "interface": "test", "target": ["driver", "7-1:1.0"]}

    def consume(self):
        return MODULE.consume_resume_ticket("fe80::1", "test", ("driver", "7-1:1.0"))

    def test_successful_resume_guard_is_single_use(self):
        self.ticket.write_text(json.dumps(self.record))
        self.assertTrue(self.consume())
        self.assertFalse(self.ticket.exists())
        self.assertFalse(self.consume())

    def test_stale_failed_sleep_changed_boot_or_target_rejected(self):
        for key, value in (("suspend_success", 11), ("suspend_success", 9), ("suspend_success", True),
                           ("monotonic", -1000), ("monotonic", 101), ("monotonic", float("nan")),
                           ("monotonic", "70"), ("boot_id", "different-boot"),
                           ("host", "fe80::2"), ("interface", "other"),
                           ("target", ["driver", "8-1:1.0"]), ("schema_version", 2)):
            with self.subTest(key=key, value=value):
                self.ticket.write_text(json.dumps({**self.record, key: value}))
                self.assertFalse(self.consume())
                self.assertFalse(self.ticket.exists())

    def test_malformed_ticket_consumed_without_enabling_fast_path(self):
        for text in ("not json", "[]", "{}"):
            self.ticket.write_text(text)
            self.assertFalse(self.consume())
            self.assertFalse(self.ticket.exists())

    def test_unsafe_file_does_not_enable_fast_path(self):
        self.ticket.write_text(json.dumps(self.record))
        with patch.object(MODULE, "private_read", side_effect=MODULE.RecoveryError("unsafe file")):
            self.assertFalse(self.consume())

    def test_prepare_only_records_and_does_not_probe_or_rebind(self):
        with patch.object(MODULE, "private_read", side_effect=[CONFIG, "50000"]), patch.object(MODULE, "validate_target", return_value=("driver", "7-1:1.0")) as target, patch.object(MODULE, "transport_reachable") as probe, patch.object(MODULE, "rebind") as rebind, patch.object(MODULE, "publish"):
            MODULE.prepare_sleep()
        target.assert_called_once_with("enp4s0f1u1", require_up=False)
        probe.assert_not_called()
        rebind.assert_not_called()
        record = json.loads(self.ticket.read_text())
        self.assertEqual(record["suspend_success"], 11)
        self.assertEqual(record["monotonic"], 100)
        self.assertEqual(self.ticket.stat().st_mode & 0o777, 0o600)

    def test_prepare_failure_removes_old_guard_and_does_not_block_sleep(self):
        self.ticket.write_text(json.dumps(self.record))
        with patch.object(MODULE, "private_read", side_effect=OSError()), patch.object(MODULE, "publish"):
            MODULE.prepare_sleep()
        self.assertFalse(self.ticket.exists())


if __name__ == "__main__":
    unittest.main()
