#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Static safety contract for the current-Catacomb exporter."""

from pathlib import Path
import unittest


SCRIPT = Path(__file__).with_name("export-current-macos-catacomb.sh")


class CurrentCatacombExportSafetyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = SCRIPT.read_text(encoding="utf-8")

    def test_is_bounded_to_macos_and_root(self) -> None:
        self.assertIn("[[ $(uname -s) == Darwin ]]", self.source)
        self.assertIn("[[ $EUID -eq 0 ]]", self.source)
        self.assertIn("[[ $# -eq 0 ]]", self.source)

    def test_does_not_replace_the_baseline_artifact(self) -> None:
        self.assertIn("t2-touchid-catacomb-current.cms", self.source)
        self.assertNotIn('destination="$efi_mount/t2-touchid-catacomb.cms"', self.source)

    def test_snapshot_is_private_and_daemon_is_always_resumed(self) -> None:
        self.assertIn("umask 077", self.source)
        self.assertIn("mktemp -d /private/var/tmp/t2-current-catacomb.XXXXXX", self.source)
        self.assertIn('kill -STOP "$daemon_pid"', self.source)
        self.assertIn('kill -CONT "$daemon_pid"', self.source)
        self.assertIn("trap cleanup EXIT HUP INT TERM", self.source)
        self.assertLess(
            self.source.index('/usr/bin/tar -czf "$archive"'),
            self.source.index("resume_daemon\n\n"),
        )

    def test_validation_is_redacted_and_nonempty(self) -> None:
        self.assertIn('>"$validation"', self.source)
        self.assertIn('result.get("component_count") == 3', self.source)
        self.assertIn("identity_count > 0", self.source)
        self.assertNotIn('cat "$validation"', self.source)

    def test_validation_uses_only_the_in_repo_checker(self) -> None:
        self.assertIn('checker="$script_dir/validate-current-macos-catacomb.py"', self.source)
        self.assertIn("validator=in-repo", self.source)
        self.assertNotIn("gpl_checkout", self.source)
        self.assertNotIn("t2-touchid-linux", self.source)

    def test_encryption_is_validated_before_atomic_promotion(self) -> None:
        encrypt = self.source.index("cms -encrypt -binary -aes-256-cbc")
        parse = self.source.index("cms -cmsout -inform DER")
        promote = self.source.index('mv -f -- "$destination_tmp" "$destination"')
        self.assertLess(encrypt, parse)
        self.assertLess(parse, promote)

    def test_plaintext_is_removed_before_success_is_reported(self) -> None:
        self.assertLess(
            self.source.rindex('remove_private || fail "private plaintext cleanup failed"'),
            self.source.index('echo "current Catacomb transfer complete:'),
        )
        self.assertIn("plaintext_removed=yes", self.source)


if __name__ == "__main__":
    unittest.main()
