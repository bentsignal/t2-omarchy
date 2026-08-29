from pathlib import Path
import unittest


SOURCE = Path(__file__).with_name("run-aks-capabilities-probe.sh").read_text()


class AksCapabilitiesRunnerSafetyTests(unittest.TestCase):
    def test_all_identity_and_confirmation_checks_precede_insmod(self):
        insmod = SOURCE.index('insmod "$module"')
        for marker in (
            "I_UNDERSTAND_NONMUTATING_AKS_CAPABILITIES_PROBE",
            "kernel module is stale",
            "MacBookPro16,1",
            "0x106b",
            "0x1802",
            "SEP PCI function already has a driver",
            "t2sep_probe is already loaded",
        ):
            self.assertLess(SOURCE.index(marker), insmod)

    def test_runner_is_single_operation_and_verifies_cleanup(self):
        self.assertIn("apple_probe_aks_capabilities=1", SOURCE)
        self.assertIn("verify-aks-capabilities-log.py", SOURCE)
        self.assertIn("could not obtain a fresh kernel-journal cursor", SOURCE)
        self.assertNotIn("journalctl -k -n 100", SOURCE)
        self.assertNotIn("verify_secret", SOURCE.lower())
        self.assertNotIn("contextcreate", SOURCE.lower())
        self.assertIn("trap cleanup EXIT", SOURCE)
        self.assertIn("rmmod t2sep_probe", SOURCE)


if __name__ == "__main__":
    unittest.main()
