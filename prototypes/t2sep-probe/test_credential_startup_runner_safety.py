from pathlib import Path
import unittest


SOURCE = Path(__file__).with_name("run-credential-startup-probe.sh").read_text()


class CredentialStartupRunnerSafetyTests(unittest.TestCase):
    def test_runner_has_exact_gate_cleanup_and_verifier(self):
        for fragment in (
                "I_UNDERSTAND_NONSECRET_COMBINED_CREDENTIAL_STARTUP",
                "credential_startup_confirmation=0x414b5341434d5354",
                "trap cleanup EXIT", "rmmod t2sep_probe",
                "verify-credential-startup-log.py"):
            self.assertIn(fragment, SOURCE)

    def test_runner_checks_freshness_identity_and_final_state(self):
        for fragment in ("module is stale", "MacBookPro16,1", "0x106b",
                         "0x1802", "SEP remained bound",
                         "module remained loaded"):
            self.assertIn(fragment, SOURCE)


if __name__ == "__main__":
    unittest.main()
