import importlib.util
from pathlib import Path
import struct
import sys
import unittest


MODULE = Path(__file__).with_name("bridgeos106-bkremoted-evidence.py")
SPEC = importlib.util.spec_from_file_location(
    "bridgeos106_bkremoted_evidence", MODULE)
assert SPEC and SPEC.loader
evidence = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = evidence
SPEC.loader.exec_module(evidence)


def fixture():
    data = bytearray(64)
    struct.pack_into("<II", data, 0, evidence.MH_MAGIC_64,
                     evidence.CPU_TYPE_ARM64)
    for marker in evidence.REQUIRED:
        data += marker
    data += evidence.UNCONDITIONAL_VERSION_REPLY
    data += evidence.TWO_NUMBER_REPLY
    data += evidence.METHOD_ZERO_DISPATCH
    return bytes(data)


class BridgeOS106BkremotedEvidenceTests(unittest.TestCase):
    def test_accepts_exact_current_method_zero(self):
        result = evidence.inspect(fixture())
        self.assertEqual(result["bridgeos"], "10.6-23P6068")
        self.assertEqual(result["method0"], "unconditional-status0-version3")
        self.assertEqual(result["reply"], "array-int32-status-uint64-version")

    def test_rejects_architecture_and_each_missing_sequence(self):
        bad = bytearray(fixture())
        struct.pack_into("<I", bad, 4, 0x01000007)
        with self.assertRaises(evidence.EvidenceError):
            evidence.inspect(bytes(bad))
        for sequence in (evidence.UNCONDITIONAL_VERSION_REPLY,
                         evidence.TWO_NUMBER_REPLY,
                         evidence.METHOD_ZERO_DISPATCH):
            bad = fixture().replace(sequence, b"\0" * len(sequence))
            with self.assertRaises(evidence.EvidenceError):
                evidence.inspect(bad)


if __name__ == "__main__":
    unittest.main()
