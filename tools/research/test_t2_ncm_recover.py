# SPDX-License-Identifier: MIT
import errno
import importlib.util
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
            with patch.object(MODULE, "SYS", root), patch.object(MODULE, "validate_target"), patch.object(MODULE, "transport_reachable", return_value=False), patch.object(MODULE, "rebind") as rebind, patch.object(MODULE.time, "sleep"), patch.object(MODULE.time, "monotonic", side_effect=[0, 13]):
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
            with patch.object(MODULE, "SYS", root), patch.object(MODULE, "validate_target"), patch.object(MODULE, "transport_reachable", return_value=False), patch.object(MODULE, "rebind") as rebind, patch.object(MODULE.time, "sleep"), patch.object(MODULE.time, "monotonic", side_effect=[0, 13]):
                with self.assertRaisesRegex(MODULE.RecoveryError, "still unreachable"):
                    MODULE.recover("fe80::1", "enp4s0f1u1", 50000)
                rebind.assert_called_once()


if __name__ == "__main__":
    unittest.main()
