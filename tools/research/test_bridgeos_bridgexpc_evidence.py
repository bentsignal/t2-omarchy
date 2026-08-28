import importlib.util
from pathlib import Path
import struct
import sys
import unittest


MODULE = Path(__file__).with_name("bridgeos-bridgexpc-evidence.py")
SPEC = importlib.util.spec_from_file_location("bridgeos_bridgexpc_evidence", MODULE)
assert SPEC and SPEC.loader
evidence = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = evidence
SPEC.loader.exec_module(evidence)


def fixture():
    data = bytearray(64)
    struct.pack_into("<III", data, 0, evidence.MH_MAGIC,
                     evidence.CPU_TYPE_ARM, evidence.CPU_SUBTYPE_ARM_V7K)
    for marker in evidence.REQUIRED:
        data += marker
    data += evidence.CONNECTED_2_TO_3
    data += evidence.SEND_STATE_1_2_3
    data += evidence.FRAME_KIND_1_THEN_2
    data += evidence.HELO_DESERIALIZE_PREFIX
    return bytes(data)


class BridgeOSBridgeXPCEvidenceTests(unittest.TestCase):
    def test_accepts_exact_state_machine(self):
        result = evidence.inspect(fixture())
        self.assertEqual(result["receive"], "kind1-HELO-kind2-message")
        self.assertEqual(result["helo"], "deserialize-and-log-no-field-gate")

    def test_rejects_architecture_and_each_missing_sequence(self):
        bad = bytearray(fixture())
        struct.pack_into("<I", bad, 4, 0x01000007)
        with self.assertRaises(evidence.EvidenceError):
            evidence.inspect(bytes(bad))
        for sequence in (evidence.CONNECTED_2_TO_3,
                         evidence.SEND_STATE_1_2_3,
                         evidence.FRAME_KIND_1_THEN_2,
                         evidence.HELO_DESERIALIZE_PREFIX):
            bad = fixture().replace(sequence, b"\0" * len(sequence))
            with self.assertRaises(evidence.EvidenceError):
                evidence.inspect(bad)


if __name__ == "__main__":
    unittest.main()
