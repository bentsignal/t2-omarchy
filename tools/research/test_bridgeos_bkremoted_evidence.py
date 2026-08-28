import importlib.util
from pathlib import Path
import struct
import sys
import unittest


MODULE = Path(__file__).with_name("bridgeos-bkremoted-evidence.py")
SPEC = importlib.util.spec_from_file_location("bridgeos_bkremoted_evidence", MODULE)
assert SPEC and SPEC.loader
evidence = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = evidence
SPEC.loader.exec_module(evidence)


def fixture():
    data = bytearray(64)
    struct.pack_into("<III", data, 0, evidence.MH_MAGIC,
                     evidence.CPU_TYPE_ARM, evidence.CPU_SUBTYPE_ARM_V7K)
    for item in evidence.REQUIRED:
        data += item
    data += evidence.UNCONDITIONAL_VERSION_REPLY
    data += evidence.METHOD_DISPATCH_0_TO_10
    return bytes(data)


class BridgeOSBkremotedEvidenceTests(unittest.TestCase):
    def test_accepts_exact_evidence(self):
        result = evidence.inspect(fixture())
        self.assertEqual(result["method0"], "unconditional-status0-version2")
        self.assertEqual(result["dispatch"], "methods0-through10")

    def test_rejects_architecture_and_missing_sequences(self):
        bad = bytearray(fixture())
        struct.pack_into("<I", bad, 4, 0x01000007)
        with self.assertRaises(evidence.EvidenceError):
            evidence.inspect(bytes(bad))
        for sequence in (evidence.UNCONDITIONAL_VERSION_REPLY,
                         evidence.METHOD_DISPATCH_0_TO_10):
            bad = fixture().replace(sequence, b"\0" * len(sequence))
            with self.assertRaises(evidence.EvidenceError):
                evidence.inspect(bad)


if __name__ == "__main__":
    unittest.main()
