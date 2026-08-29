import importlib.util
from pathlib import Path
import struct
import sys
import unittest


SPEC = importlib.util.spec_from_file_location(
    "macos_enrollment_authorization_evidence",
    Path(__file__).with_name("macos-enrollment-authorization-evidence.py"))
evidence = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = evidence
SPEC.loader.exec_module(evidence)


def fixture(*, cpu=evidence.CPU_TYPE_X86_64, omit=b""):
    header = struct.pack("<IIIIIIII", evidence.MH_MAGIC_64, cpu, 3, 2, 0, 0, 0, 0)
    return (header + b"".join(item for item in evidence.REQUIRED if item != omit)
            + evidence.VERIFY_CALL_SEQUENCE + evidence.VERIFY_FALSE_FLAGS_WRAPPER)


class EnrollmentAuthorizationEvidenceTests(unittest.TestCase):
    def test_accepts_exact_authorization_path(self):
        result = evidence.inspect(fixture())
        self.assertEqual(result["keybag_selector"], -3)
        self.assertEqual(result["device_state"], 0)
        self.assertEqual(result["post_verify_session_call"], "none")

    def test_rejects_wrong_architecture_and_missing_symbols(self):
        with self.assertRaisesRegex(evidence.EvidenceError, "x86_64"):
            evidence.inspect(fixture(cpu=0x0100000C))
        for required in evidence.REQUIRED:
            with self.subTest(required=required):
                with self.assertRaisesRegex(evidence.EvidenceError, "missing"):
                    evidence.inspect(fixture(omit=required))

    def test_rejects_modified_instruction_evidence(self):
        for sequence in (evidence.VERIFY_CALL_SEQUENCE,
                         evidence.VERIFY_FALSE_FLAGS_WRAPPER):
            with self.subTest(sequence=sequence):
                damaged = fixture().replace(sequence, bytes([sequence[0] ^ 1]) + sequence[1:], 1)
                with self.assertRaisesRegex(evidence.EvidenceError, "exact"):
                    evidence.inspect(damaged)


if __name__ == "__main__":
    unittest.main()
