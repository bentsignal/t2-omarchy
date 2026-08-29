from pathlib import Path
import unittest


SOURCE = Path(__file__).with_name("run-dual-credential-ool-capture.sh").read_text()


class DualCredentialRunnerSafetyTests(unittest.TestCase):
    def test_requires_exact_confirmation_and_fresh_cursor(self):
        self.assertIn(
            "I_UNDERSTAND_NONSECRET_DUAL_CREDENTIAL_OOL_CAPTURE", SOURCE)
        self.assertIn("journalctl -k --show-cursor -n 0", SOURCE)
        self.assertIn("journalctl -k --after-cursor", SOURCE)

    def test_enables_only_nonsecret_dual_registration_mode(self):
        self.assertIn("apple_capture_dual_credential_ool_acks=1", SOURCE)
        self.assertIn(
            "dual_credential_ool_confirmation=0x4455414c4f4f4c41", SOURCE)
        self.assertNotIn("apple_probe_aks_capabilities=1", SOURCE)
        self.assertNotIn("apple_probe_acm_context_lifecycle=1", SOURCE)
        self.assertNotIn("password", SOURCE.lower())
        self.assertIn("verify-dual-credential-ool-log.py", SOURCE)


if __name__ == "__main__":
    unittest.main()
