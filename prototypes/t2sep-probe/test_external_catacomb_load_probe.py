import importlib.util
from pathlib import Path
import plistlib
import struct
import sys
import tempfile
import unittest


SPEC = importlib.util.spec_from_file_location(
    "external_catacomb_load_tested",
    Path(__file__).with_name("external-catacomb-load-probe.py"))
probe = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = probe
SPEC.loader.exec_module(probe)
protocol = probe.state.coupled.bridge_query.protocol


def frame(body):
    return protocol.encode_frame_header(protocol.FRAME_MESSAGE, len(body)) + body


def envelope(reply_id, payload):
    return frame(plistlib.dumps([1, True, reply_id, payload], fmt=plistlib.FMT_BINARY))


class FakeSocket:
    def __init__(self, incoming):
        self.incoming = bytearray(incoming)
        self.sent = bytearray()
    def sendall(self, data): self.sent.extend(data)
    def recv(self, size):
        result = self.incoming[:size]
        del self.incoming[:size]
        return bytes(result)


class ExternalCatacombLoadTests(unittest.TestCase):
    IDS = tuple(f"{index}7654321-89AB-4CDE-8FAB-0123456789AB" for index in range(6))

    def test_one_shot_load_reports_only_policy_length_and_count(self):
        identity = struct.pack("<I16s", 501, bytes(16))
        incoming = (envelope(self.IDS[0], [0, 3])
                    + envelope(self.IDS[1], [0])
                    + envelope(self.IDS[2], [0, True])
                    + envelope(self.IDS[3], [0, protocol.NO_REPLY_UUID.lower()])
                    + envelope(self.IDS[4], [0, bytes(32)])
                    + envelope(self.IDS[5], [0, identity]))
        ids = iter(self.IDS)
        original = probe.state.coupled.bridge_query.uuid.uuid4
        probe.state.coupled.bridge_query.uuid.uuid4 = lambda: next(ids)
        try:
            result = probe.probe_socket(FakeSocket(incoming), user_id=501,
                                        secure_data=b"opaque-current-data")
        finally:
            probe.state.coupled.bridge_query.uuid.uuid4 = original
        self.assertEqual(result, probe.ExternalCatacombLoadResult(0, 32, 1))

    def test_input_file_must_be_private_and_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / "secure-data.bin"
            path.write_bytes(b"opaque")
            path.chmod(0o600)
            self.assertEqual(probe.read_secure_data(path), b"opaque")
            path.chmod(0o644)
            with self.assertRaises(probe.ExternalCatacombLoadError):
                probe.read_secure_data(path)

    def test_live_gate_closed(self):
        self.assertFalse(probe.LIVE_LOAD_ENABLED)
        with self.assertRaises(probe.ExternalCatacombLoadError):
            probe.live_probe(user_id=501, path=Path("/private"))


if __name__ == "__main__":
    unittest.main()
