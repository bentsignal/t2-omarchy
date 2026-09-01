#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Static safety invariants for the one-shot warm-transition capture."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parent
SCRIPT = (ROOT / "t2-warm-identity-capture.sh").read_text()
UNIT = (ROOT / "t2-warm-identity-capture.service").read_text()
GUARD = (ROOT / "t2-warm-transition-guard.conf").read_text()


class WarmIdentityCaptureSafetyTests(unittest.TestCase):
    def test_probe_is_read_only_and_identity_only(self):
        command = SCRIPT.split('"$python" "$source_dir/bridge-xpc-probe.py"', 1)[1]
        command = command.split('>"$RAW"', 1)[0]
        self.assertIn("--initialize --identity-list", command)
        for forbidden in (
            "--reset-sensor",
            "--load-calibration",
            "--load-catacomb",
            "--match-seconds",
            "--enroll",
        ):
            self.assertNotIn(forbidden, command)

    def test_authentication_consumers_must_be_inactive(self):
        self.assertNotIn("systemctl is-enabled --quiet", SCRIPT)
        self.assertIn("systemctl is-active --quiet", SCRIPT)
        self.assertIn("fprintd.service t2-biometric-ready.service", SCRIPT)
        self.assertNotIn("allow-reset-capable-services", SCRIPT)

    def test_persisted_result_excludes_raw_identity_and_peer_fields(self):
        persisted = SCRIPT.split("jq -e", 1)[1].split("' \"$RAW\"", 1)[0]
        self.assertIn("identity_record_count", persisted)
        self.assertIn("output_length == null", persisted)
        self.assertNotIn("peer_helo", persisted)
        self.assertNotIn("identity_uuid", persisted)

    def test_capture_orders_before_authentication_consumers(self):
        self.assertIn(
            "Before=t2-biometric-ready.service fprintd.service",
            UNIT,
        )

    def test_obsolete_runtime_override_is_cleared(self):
        self.assertIn("ConditionPathExists=", GUARD)
        self.assertNotIn("allow-reset-capable-services", GUARD)


if __name__ == "__main__":
    unittest.main()
