import importlib.util
from pathlib import Path
import struct
import sys
import unittest


SPEC = importlib.util.spec_from_file_location(
    "macos_bridgexpc_evidence",
    Path(__file__).with_name("macos-bridgexpc-evidence.py"))
evidence = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = evidence
SPEC.loader.exec_module(evidence)


def fixture(*, cpu=evidence.CPU_TYPE_X86_64, omit=b"", duplicate=b""):
    header = struct.pack("<IIIIIIII", evidence.MH_MAGIC_64, cpu, 3, 6, 0, 0, 0, 0)
    markers = (evidence.HELO_HEADER_LOAD, evidence.MESSAGE_HEADER_LOAD,
               evidence.BINARY_PLIST_FORMAT_LOAD)
    return (header + b"".join(item for item in evidence.REQUIRED if item != omit)
            + b"".join(item for item in markers if item != omit) + duplicate)


class MacosBridgeXPCEvidenceTests(unittest.TestCase):
    def test_accepts_exact_current_framing_markers(self):
        result = evidence.inspect(fixture())
        self.assertEqual((result["magic"], result["version"]), (0xB892, 1))
        self.assertEqual((result["helo_kind"], result["message_kind"]), (1, 2))
        self.assertEqual(result["plist_format"], 0xC8)

    def test_rejects_architecture_missing_and_ambiguous_evidence(self):
        with self.assertRaisesRegex(evidence.EvidenceError, "x86_64"):
            evidence.inspect(fixture(cpu=0x0100000C))
        for required in (*evidence.REQUIRED, evidence.HELO_HEADER_LOAD,
                         evidence.MESSAGE_HEADER_LOAD,
                         evidence.BINARY_PLIST_FORMAT_LOAD):
            with self.subTest(required=required):
                with self.assertRaises(evidence.EvidenceError):
                    evidence.inspect(fixture(omit=required))
        with self.assertRaisesRegex(evidence.EvidenceError, "one exact"):
            evidence.inspect(fixture(duplicate=evidence.MESSAGE_HEADER_LOAD))


if __name__ == "__main__":
    unittest.main()
