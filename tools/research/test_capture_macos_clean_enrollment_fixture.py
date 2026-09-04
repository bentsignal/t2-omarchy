#!/usr/bin/env python3
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("capture-macos-clean-enrollment-fixture.sh")
SOURCE = SCRIPT.read_text()


class CaptureMacOSCleanEnrollmentFixtureTests(unittest.TestCase):
    def test_requires_macos_root_tty_and_exact_private_sources(self):
        self.assertIn("[[ $(uname -s) == Darwin ]]", SOURCE)
        self.assertIn("[[ $EUID -eq 0 ]]", SOURCE)
        self.assertIn("/dev/tty", SOURCE)
        self.assertIn("/Library/Catacomb", SOURCE)
        self.assertIn("validate-current-macos-catacomb.py", SOURCE)
        self.assertIn("catacomb-identity-shape-delta.py", SOURCE)

    def test_snapshots_each_phase_while_daemon_is_frozen(self):
        self.assertIn('kill -STOP "$daemon_pid"', SOURCE)
        self.assertIn('kill -CONT "$daemon_pid"', SOURCE)
        self.assertLess(SOURCE.index('kill -STOP "$daemon_pid"'), SOURCE.index('/usr/bin/tar -czf'))
        self.assertIn("snapshot starting", SOURCE)
        self.assertIn("snapshot empty", SOURCE)
        self.assertIn("snapshot clean", SOURCE)

    def test_fingerprint_changes_are_human_settings_instructions_only(self):
        self.assertIn("remove every visible fingerprint", SOURCE)
        self.assertIn("add exactly ONE fingerprint", SOURCE)
        for forbidden in (
            "performRemoveIdentityCommand",
            "remove_identity_fields",
            "ordinary_enroll_fields",
            "authorized_enroll_fields",
            "/dev/t2-acm",
        ):
            self.assertNotIn(forbidden, SOURCE)

    def test_encrypts_only_clean_archive_and_removes_plaintext(self):
        self.assertIn("t2-touchid-catacomb-clean-single.cms", SOURCE)
        self.assertIn('-in "$private_dir/clean.tar.gz"', SOURCE)
        self.assertIn("cms -cmsout", SOURCE)
        self.assertIn("remove_private", SOURCE)
        self.assertIn('"plaintext_removed": True', SOURCE)

    def test_public_summary_is_identifier_redacted(self):
        self.assertIn('"identifiers_redacted": True', SOURCE)
        self.assertIn('"raw_values_retained": False', SOURCE)
        for forbidden in ("BKIdentityUUID", "identity_uuid", ".hex()", "archive_sha256"):
            self.assertNotIn(forbidden, SOURCE)


if __name__ == "__main__":
    unittest.main()
