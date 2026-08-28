import importlib.util
from pathlib import Path
import struct
import sys
import unittest


SPEC = importlib.util.spec_from_file_location(
    "macos_multiverse_service_connect_evidence",
    Path(__file__).with_name("macos-multiverse-service-connect-evidence.py"))
evidence = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = evidence
SPEC.loader.exec_module(evidence)


def fixture(*, cpu=evidence.CPU_TYPE_X86_64, duplicate=False):
    header = struct.pack("<IIIIIIII", evidence.MH_MAGIC_64, cpu, 3, 2,
                         0, 0, 0, 0)
    sequences = (evidence.ATOI_RESULT_SEQUENCE
                 + evidence.CONNECT_WITH_TIMEOUT_SEQUENCE
                 + evidence.CONNECT_SEQUENCE)
    return header + b"".join(evidence.REQUIRED_STRINGS) + sequences * (2 if duplicate else 1)


class MacosMultiverseServiceConnectEvidenceTests(unittest.TestCase):
    def test_accepts_direct_service_socket_sequences(self):
        result = evidence.inspect(fixture())
        self.assertEqual(result["class"], "RSDRemoteMultiverseDevice")
        self.assertEqual(result["handoff"], "direct-multiverse-connect")

    def test_rejects_wrong_architecture_missing_and_ambiguous_sequences(self):
        with self.assertRaisesRegex(evidence.EvidenceError, "x86_64"):
            evidence.inspect(fixture(cpu=0x0100000C))
        with self.assertRaisesRegex(evidence.EvidenceError, "one exact"):
            evidence.inspect(fixture().replace(evidence.CONNECT_SEQUENCE, b"", 1))
        with self.assertRaisesRegex(evidence.EvidenceError, "one exact"):
            evidence.inspect(fixture(duplicate=True))


if __name__ == "__main__":
    unittest.main()
