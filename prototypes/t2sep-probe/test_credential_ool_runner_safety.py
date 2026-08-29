from pathlib import Path
import unittest


SOURCE = Path(__file__).with_name("run-credential-ool-capture.sh").read_text()


class CredentialOolRunnerSafetyTests(unittest.TestCase):
    def test_all_identity_and_confirmation_checks_precede_insmod(self):
        insmod = SOURCE.index('insmod "$module"')
        for marker in (
            "I_UNDERSTAND_FIXED_CREDENTIAL_OOL_CAPTURE",
            "MacBookPro16,1",
            "0x106b",
            "0x1802",
            "SEP PCI function already has a driver",
            "t2sep_probe is already loaded",
        ):
            self.assertLess(SOURCE.index(marker), insmod)

    def test_runner_sends_no_service_operation_and_verifies_cleanup(self):
        self.assertNotIn("verify_secret", SOURCE.lower())
        self.assertNotIn("contextcreate", SOURCE.lower())
        self.assertIn("verify-credential-ool-log.py", SOURCE)
        self.assertIn("trap cleanup EXIT", SOURCE)
        self.assertIn("rmmod t2sep_probe", SOURCE)


if __name__ == "__main__":
    unittest.main()
