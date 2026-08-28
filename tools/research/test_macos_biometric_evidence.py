import importlib.util
from pathlib import Path
import struct
import sys
import unittest


SPEC = importlib.util.spec_from_file_location(
    "macos_biometric_evidence",
    Path(__file__).with_name("macos-biometric-evidence.py"))
evidence = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = evidence
SPEC.loader.exec_module(evidence)


def fixture(*, cpu=evidence.CPU_TYPE_X86_64, omit=b""):
    header = struct.pack("<IIIIIIII", evidence.MH_MAGIC_64, cpu, 3, 2, 0, 0, 0, 0)
    return header + b"".join(item for item in evidence.REQUIRED if item != omit)


class MacosBiometricEvidenceTests(unittest.TestCase):
    def test_accepts_coupled_intel_route_evidence(self):
        result = evidence.inspect(fixture())
        self.assertEqual(result["service"], "com.apple.eos.BiometricKit")
        self.assertEqual(result["directory"], "RemoteServiceDiscovery")
        self.assertEqual(result["transport"], "BiometricKitBridgeTransport")
        self.assertEqual(result["logical_abi"], "methods 0,1,3")
        self.assertEqual(len(result["sha256"]), 64)

    def test_rejects_wrong_architecture_and_each_missing_fact(self):
        with self.assertRaisesRegex(evidence.EvidenceError, "x86_64"):
            evidence.inspect(fixture(cpu=0x0100000C))
        for required in evidence.REQUIRED:
            with self.subTest(required=required):
                with self.assertRaisesRegex(evidence.EvidenceError, "missing"):
                    evidence.inspect(fixture(omit=required))


if __name__ == "__main__":
    unittest.main()
