from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parent


class T2NCMFlagsProbeTests(unittest.TestCase):
    def test_live_gate_and_exact_request_are_source_pinned(self):
        source = (ROOT / "t2ncm-flags-probe.c").read_text()
        self.assertIn("#define LIVE_T2_NCM_FLAGS_READ_ENABLED 0", source)
        self.assertIn("control_transfer(fd, 0xa1, 0xa0, 0,", source)
        for request in ("0x8a", "0x84", "0x88", "0x86"):
            self.assertIn(f"control_transfer(fd, 0x21, {request},", source)
        self.assertIn("vendor != 0x05ac", source)
        self.assertIn("product != 0x8233", source)
        self.assertIn("*interface_number != 0", source)
        self.assertIn("O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600", source)

    def test_wrapper_has_exact_interface_and_rebind_trap(self):
        source = (ROOT / "run-t2ncm-flags-probe.sh").read_text()
        self.assertIn("interface=7-1:1.0", source)
        self.assertIn("trap rebind EXIT HUP INT TERM", source)
        self.assertIn('> "$driver/unbind"', source)
        self.assertIn('> "$driver/bind"', source)


if __name__ == "__main__":
    unittest.main()
