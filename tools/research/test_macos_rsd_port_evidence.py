import importlib.util
from pathlib import Path
import struct
import sys
import unittest


SPEC = importlib.util.spec_from_file_location(
    "macos_rsd_port_evidence",
    Path(__file__).with_name("macos-rsd-port-evidence.py"))
evidence = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = evidence
SPEC.loader.exec_module(evidence)


def fixture(*, cpu=evidence.CPU_TYPE_X86_64, stores=1):
    header = struct.pack("<IIIIIIII", evidence.MH_MAGIC_64, cpu, 3, 2, 0, 0, 0, 0)
    return (header + b"RSDRemoteNCMDeviceDevice\0createPortListener\0"
            + evidence.PORT_STORE * stores)


class MacosRsdPortEvidenceTests(unittest.TestCase):
    def test_accepts_one_exact_listener_port_store(self):
        result = evidence.inspect(fixture())
        self.assertEqual(result["port"], 58783)

    def test_rejects_wrong_architecture_missing_and_ambiguous_store(self):
        with self.assertRaisesRegex(evidence.EvidenceError, "x86_64"):
            evidence.inspect(fixture(cpu=0x0100000C))
        for stores in (0, 2):
            with self.assertRaisesRegex(evidence.EvidenceError, "one exact"):
                evidence.inspect(fixture(stores=stores))


if __name__ == "__main__":
    unittest.main()
