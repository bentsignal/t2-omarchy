import importlib.util
from pathlib import Path
import struct
import sys
import unittest

SPEC = importlib.util.spec_from_file_location(
    "macos_multiverse_bootstrap_evidence",
    Path(__file__).with_name("macos-multiverse-bootstrap-evidence.py"))
evidence = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = evidence
SPEC.loader.exec_module(evidence)


def fixture(*, cpu=evidence.CPU_TYPE_X86_64, sequences=1):
    header = struct.pack("<IIIIIIII", evidence.MH_MAGIC_64, cpu, 3, 2,
                         0, 0, 0, 0)
    return (header + b"".join(evidence.REQUIRED_STRINGS)
            + evidence.MULTIVERSE_CONNECT_SEQUENCE * sequences)


class MacosMultiverseBootstrapEvidenceTests(unittest.TestCase):
    def test_accepts_exact_internal_device_connect_sequence(self):
        result = evidence.inspect(fixture())
        self.assertEqual(result["class"], "RSDRemoteMultiverseHostDevice")
        self.assertEqual(result["method"], "needsConnect")
        self.assertEqual(result["port"], 59602)
        self.assertEqual(result["transport"], "multiverse-internal-device")

    def test_rejects_wrong_architecture_missing_and_ambiguous_sequence(self):
        with self.assertRaisesRegex(evidence.EvidenceError, "x86_64"):
            evidence.inspect(fixture(cpu=0x0100000C))
        for count in (0, 2):
            with self.subTest(count=count):
                with self.assertRaisesRegex(evidence.EvidenceError, "one exact"):
                    evidence.inspect(fixture(sequences=count))


if __name__ == "__main__":
    unittest.main()
