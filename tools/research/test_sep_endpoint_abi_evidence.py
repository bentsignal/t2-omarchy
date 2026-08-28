import importlib.util
from pathlib import Path
import struct
import sys
import unittest


MODULE = Path(__file__).with_name("sep-endpoint-abi-evidence.py")
SPEC = importlib.util.spec_from_file_location("sep_endpoint_abi_evidence", MODULE)
assert SPEC and SPEC.loader
evidence = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = evidence
SPEC.loader.exec_module(evidence)


def macho(cpu, *sequences):
    data = bytearray(32)
    struct.pack_into("<II", data, 0, evidence.MH_MAGIC_64, cpu)
    for sequence in sequences:
        data += sequence
    return bytes(data)


def fixtures():
    manager = macho(evidence.CPU_X86_64, evidence.INTEL_ENDPOINT_FORWARD,
                    evidence.INTEL_FIRST_POINTER_RECORD)
    generic = macho(evidence.CPU_ARM64, evidence.ARM_STORE_QWORD,
                    evidence.ARM_ENDPOINT_CALL_ARGS)
    return manager, generic


class SepEndpointAbiEvidenceTests(unittest.TestCase):
    def test_accepts_exact_architecture_split(self):
        result = evidence.inspect(*fixtures())
        self.assertEqual(result["intel_second_pointer"], "ignored")
        self.assertEqual(result["third_word"],
                         "not-established-cross-architecture")

    def test_rejects_swapped_architectures_and_missing_sequences(self):
        manager, generic = fixtures()
        with self.assertRaises(evidence.EvidenceError):
            evidence.inspect(generic, manager)
        for sequence in (evidence.INTEL_ENDPOINT_FORWARD,
                         evidence.INTEL_FIRST_POINTER_RECORD):
            with self.assertRaises(evidence.EvidenceError):
                evidence.inspect(manager.replace(sequence, b"\0" * len(sequence)),
                                 generic)
        for sequence in (evidence.ARM_STORE_QWORD,
                         evidence.ARM_ENDPOINT_CALL_ARGS):
            with self.assertRaises(evidence.EvidenceError):
                evidence.inspect(manager,
                                 generic.replace(sequence, b"\0" * len(sequence)))


if __name__ == "__main__":
    unittest.main()
