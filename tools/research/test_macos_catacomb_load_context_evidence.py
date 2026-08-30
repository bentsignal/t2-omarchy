import importlib.util
from pathlib import Path
import struct
import sys
import unittest


SPEC = importlib.util.spec_from_file_location(
    "macos_catacomb_load_context_evidence",
    Path(__file__).with_name("macos-catacomb-load-context-evidence.py"))
evidence = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = evidence
SPEC.loader.exec_module(evidence)


def fixture(*, cpu=evidence.CPU_TYPE_X86_64, omit=b""):
    header = struct.pack("<IIIIIIII", evidence.MH_MAGIC_64, cpu, 3, 2, 0, 0, 0, 0)
    required = b"".join(item for item in evidence.REQUIRED if item != omit)
    return header + required + b"".join(evidence.SEQUENCES)


class CatacombLoadContextEvidenceTests(unittest.TestCase):
    def test_accepts_exact_load_and_context(self):
        result = evidence.inspect(fixture())
        self.assertEqual(result["command"], 0x40)
        self.assertEqual(result["version"], 1)
        self.assertEqual(result["in_value"], 0)
        self.assertEqual(result["output_size"], 0)
        self.assertEqual(result["status_257"], "unchanged")

    def test_rejects_architecture_and_missing_facts(self):
        with self.assertRaisesRegex(evidence.EvidenceError, "x86_64"):
            evidence.inspect(fixture(cpu=0x0100000C))
        for required in evidence.REQUIRED:
            with self.subTest(required=required):
                with self.assertRaisesRegex(evidence.EvidenceError, "missing"):
                    evidence.inspect(fixture(omit=required))

    def test_rejects_each_modified_instruction_sequence(self):
        for sequence in evidence.SEQUENCES:
            with self.subTest(sequence=sequence):
                damaged = fixture().replace(sequence, bytes([sequence[0] ^ 1]) + sequence[1:], 1)
                with self.assertRaisesRegex(evidence.EvidenceError, "exact"):
                    evidence.inspect(damaged)


if __name__ == "__main__":
    unittest.main()
