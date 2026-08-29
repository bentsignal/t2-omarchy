from pathlib import Path
import unittest


SOURCE = Path(__file__).with_name("run-aks-time-sweep-probe.sh").read_text()


class AksTimeSweepRunnerSafetyTests(unittest.TestCase):
    def test_runner_has_exact_gate_and_cleanup(self):
        self.assertIn("I_UNDERSTAND_NONSECRET_AKS_TIME_SWEEP", SOURCE)
        self.assertIn("aks_time_sweep_confirmation=0x414b5354494d4553", SOURCE)
        self.assertIn("trap cleanup EXIT", SOURCE)
        self.assertIn("rmmod t2sep_probe", SOURCE)

    def test_runner_checks_identity_freshness_and_transcript(self):
        for fragment in ("MacBookPro16,1", "0x106b", "0x1802",
                         "module is stale", "verify-aks-time-sweep-log.py",
                         "SEP remained bound", "module remained loaded"):
            self.assertIn(fragment, SOURCE)


if __name__ == "__main__":
    unittest.main()
