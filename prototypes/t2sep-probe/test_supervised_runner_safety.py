from pathlib import Path
import unittest


DIRECTORY = Path(__file__).parent


class SupervisedRunnerSafetyTests(unittest.TestCase):
    def test_nop_and_discovery_fail_closed_before_insmod(self):
        expectations = {
            "run-control-nop.sh": "I_UNDERSTAND_CONTROL_NOP_PROBE",
            "run-discovery.sh": "I_UNDERSTAND_PASSIVE_SEP_DISCOVERY",
        }
        for filename, confirmation in expectations.items():
            with self.subTest(filename=filename):
                source = (DIRECTORY / filename).read_text()
                insmod = source.index('insmod "$module"')
                for marker in (
                    confirmation,
                    "kernel module is stale",
                    "MacBookPro16,1",
                    "0x106b",
                    "0x1802",
                    "SEP PCI function already has a driver",
                    "t2sep_probe is already loaded",
                    "could not obtain a fresh kernel-journal cursor",
                ):
                    self.assertLess(source.index(marker), insmod)
                self.assertNotIn("journalctl -k -n ", source)
                self.assertIn("trap cleanup EXIT", source)
                self.assertIn("rmmod t2sep_probe", source)


if __name__ == "__main__":
    unittest.main()
