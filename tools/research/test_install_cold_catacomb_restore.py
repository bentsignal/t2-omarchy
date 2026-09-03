#!/usr/bin/env python3
"""Static fail-closed contract for cold-restore deployment."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
INSTALL = (ROOT / "tools/research/install-cold-catacomb-restore.sh").read_text()
UNINSTALL = (ROOT / "tools/research/uninstall-cold-catacomb-restore.sh").read_text()
UNIT = (ROOT / "files/t2-current-catacomb-restore.service").read_text()
DROPIN = (ROOT / "files/t2-biometric-ready-cold-restore.conf").read_text()


class ColdRestoreDeploymentTests(unittest.TestCase):
    def test_install_does_not_arm_or_start_restore(self):
        self.assertNotIn("cold-restore-enabled\"", INSTALL)
        self.assertNotIn("systemctl start", INSTALL)
        self.assertNotIn("systemctl restart", INSTALL)
        self.assertIn("systemctl enable t2-current-catacomb-restore.service", INSTALL)

    def test_unit_is_ordered_and_explicitly_armed(self):
        self.assertIn("Requires=t2-credential-unlock.service", UNIT)
        self.assertIn("Before=t2-biometric-ready.service fprintd.service", UNIT)
        self.assertIn(
            "ConditionPathExists=/var/lib/t2-touchid/cold-restore-enabled", UNIT
        )
        self.assertIn("NoNewPrivileges=yes", UNIT)
        self.assertNotIn("reset", UNIT.lower().replace("cold-boot restore", ""))

    def test_readiness_requires_successful_restore_when_armed(self):
        self.assertIn("Requires=t2-current-catacomb-restore.service", DROPIN)
        self.assertIn("After=t2-current-catacomb-restore.service", DROPIN)

    def test_uninstall_disarms_but_preserves_private_stores(self):
        self.assertIn("rm -f -- /var/lib/t2-touchid/cold-restore-enabled", UNINSTALL)
        self.assertNotIn("catacomb-zero-identity-backup", UNINSTALL)
        self.assertNotIn("rm -rf -- /var/lib/t2-touchid", UNINSTALL)


if __name__ == "__main__":
    unittest.main()
