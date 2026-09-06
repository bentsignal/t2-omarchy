# SPDX-License-Identifier: MIT
from pathlib import Path
import runpy
import unittest
from unittest.mock import Mock

MODULE = runpy.run_path(str(Path(__file__).with_name("measure-t2-nm-activation.py")))


class ProfileGuardTests(unittest.TestCase):
    def test_restoration_attempts_both_sysctls_on_failure(self):
        first, second = Mock(), Mock()
        first.write_text.side_effect = OSError("failed")
        with self.assertRaises(OSError):
            MODULE["restore_sysctls"]({first: "0\n", second: "0\n"})
        first.write_text.assert_called_once_with("0\n")
        second.write_text.assert_called_once_with("0\n")

    def test_sigterm_unwinds_cleanup(self):
        with self.assertRaises(SystemExit) as caught:
            MODULE["terminate"](15, None)
        self.assertEqual(caught.exception.code, 124)

    def test_eui64_matches_existing_fixed_address(self):
        self.assertEqual(str(MODULE["eui64_address"]("ac:de:48:00:11:22")), "fe80::aede:48ff:fe00:1122")

    def test_only_dedicated_matching_manual_profile_accepted(self):
        fields = ["test", "disabled", "manual", "fe80::aede:48ff:fe00:1122/64", "default", ""]
        self.assertEqual(MODULE["validate_profile"](fields, "test", "ac:de:48:00:11:22"), "default")
        for index, value in ((0, "wifi"), (1, "auto"), (2, "auto"), (3, "fe80::1/64"),
                             (3, "fe80::aede:48ff:fe00:1122/128"), (4, "stable-privacy"), (5, "::1234")):
            bad = fields.copy()
            bad[index] = value
            with self.assertRaises(ValueError):
                MODULE["validate_profile"](bad, "test", "ac:de:48:00:11:22")


if __name__ == "__main__":
    unittest.main()
