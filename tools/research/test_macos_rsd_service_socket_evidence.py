import importlib.util
from pathlib import Path
import struct
import sys
import unittest


MODULE = Path(__file__).with_name("macos-rsd-service-socket-evidence.py")
SPEC = importlib.util.spec_from_file_location("macos_rsd_service_socket_evidence", MODULE)
assert SPEC and SPEC.loader
evidence = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = evidence
SPEC.loader.exec_module(evidence)


def fixture(*, request=True, returned_fd=True):
    data = bytearray(32)
    struct.pack_into("<II", data, 0, evidence.MH_MAGIC_64,
                     evidence.CPU_TYPE_X86_64)
    data.extend(b"".join(evidence.REQUIRED_STRINGS))
    if request:
        data.extend(evidence.CONNECT_REQUEST_SEQUENCE)
    if returned_fd:
        data.extend(evidence.RETURNED_FD_SEQUENCE)
    return bytes(data)


class ServiceSocketEvidenceTests(unittest.TestCase):
    def test_accepts_exact_contract(self):
        result = evidence.inspect(fixture())
        self.assertEqual(result["request_keys"], "cmd,connect_timeout")
        self.assertEqual(result["reply_key"], "fd")
        self.assertEqual(result["post_handoff"], "poll-connect-only")

    def test_rejects_wrong_architecture(self):
        data = bytearray(fixture())
        struct.pack_into("<I", data, 4, 12)
        with self.assertRaises(evidence.EvidenceError):
            evidence.inspect(bytes(data))

    def test_rejects_missing_or_duplicate_sequences(self):
        with self.assertRaises(evidence.EvidenceError):
            evidence.inspect(fixture(request=False))
        with self.assertRaises(evidence.EvidenceError):
            evidence.inspect(fixture(returned_fd=False))
        with self.assertRaises(evidence.EvidenceError):
            evidence.inspect(fixture() + evidence.CONNECT_REQUEST_SEQUENCE)

    def test_rejects_missing_keys(self):
        with self.assertRaises(evidence.EvidenceError):
            evidence.inspect(fixture().replace(b"connect_timeout", b"connect_timeouX", 1))


if __name__ == "__main__":
    unittest.main()
