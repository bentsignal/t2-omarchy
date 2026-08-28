import importlib.util
from pathlib import Path
import sys
import unittest
from unittest import mock


PATH = Path(__file__).with_name("t2ncm-device-reset.py")
SPEC = importlib.util.spec_from_file_location("t2ncm_device_reset", PATH)
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class DeviceResetTests(unittest.TestCase):
    def test_live_reset_is_source_disabled(self):
        self.assertFalse(MODULE.LIVE_T2_NCM_DEVICE_RESET_ENABLED)
        with self.assertRaisesRegex(MODULE.ResetError, "disabled in source"):
            MODULE.reset()

    def test_disabled_gate_precedes_identity_and_ioctl(self):
        with mock.patch.object(MODULE, "verified_devnode") as verified, \
             mock.patch.object(MODULE.fcntl, "ioctl") as ioctl:
            with self.assertRaises(MODULE.ResetError):
                MODULE.reset()
        verified.assert_not_called()
        ioctl.assert_not_called()

    def test_exact_ioctl_number_and_target_are_literal(self):
        source = PATH.read_text()
        self.assertEqual(MODULE.USBDEVFS_RESET, 0x5514)
        self.assertIn('Path("/sys/bus/usb/devices/7-1")', source)
        self.assertIn('("05ac", "8233")', source)
        self.assertIn('"0000:04:00.1/t2bce_core"', source)

    def test_capture_wrapper_restores_exact_driver_binding(self):
        source = PATH.with_name("capture-t2ncm-device-reset.sh").read_text()
        self.assertIn("interface=7-1:1.0", source)
        self.assertIn('> "$driver/unbind"', source)
        self.assertGreaterEqual(source.count('> "$driver/bind"'), 2)
        self.assertIn("trap cleanup EXIT HUP INT TERM", source)

    def test_reauthorize_wrapper_is_source_disabled_and_restores_authorization(self):
        source = PATH.with_name("capture-t2ncm-reauthorize.sh").read_text()
        self.assertIn("LIVE_T2_NCM_REAUTHORIZE_ENABLED=false", source)
        self.assertIn("device=/sys/bus/usb/devices/7-1", source)
        self.assertIn('printf \'0\' > "$device/authorized"', source)
        self.assertGreaterEqual(source.count('printf \'1\' > "$device/authorized"'), 2)
        self.assertIn("trap cleanup EXIT HUP INT TERM", source)


if __name__ == "__main__":
    unittest.main()
