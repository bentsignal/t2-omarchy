import importlib.util
from pathlib import Path
import plistlib
import struct
import sys
import unittest


SPEC = importlib.util.spec_from_file_location(
    "catacomb_load_tested", Path(__file__).with_name("catacomb-load-probe.py"))
probe = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = probe
SPEC.loader.exec_module(probe)
protocol = probe.state.coupled.bridge_query.protocol


def envelope(reply_id, payload):
    body = plistlib.dumps([1, True, reply_id, payload], fmt=plistlib.FMT_BINARY)
    return protocol.encode_frame_header(protocol.FRAME_MESSAGE, len(body)) + body


class FakeSocket:
    def __init__(self, incoming): self.incoming, self.sent = bytearray(incoming), bytearray()
    def sendall(self, data): self.sent.extend(data)
    def recv(self, size):
        result = self.incoming[:size]
        del self.incoming[:size]
        return bytes(result)


class CatacombLoadProbeTests(unittest.TestCase):
    IDS = tuple(f"{index:08d}-89AB-4CDE-8FAB-0123456789AB" for index in range(6))

    def test_load_requires_policy_and_identity_readback(self):
        uid = 501
        blob = bytearray(128)
        struct.pack_into("<I", blob, 8, uid)
        identity = probe.state.biometric.IDENTITY.pack(uid, bytes(range(16)))
        incoming = b"".join((
            envelope(self.IDS[0], [0, 3]), envelope(self.IDS[1], [0]),
            envelope(self.IDS[2], [0, True]),
            envelope(self.IDS[3], [0, protocol.NO_REPLY_UUID.lower()]),
            envelope(self.IDS[4], [0, bytes(32)]),
            envelope(self.IDS[5], [0, identity])))
        ids = iter(self.IDS)
        original = probe.state.coupled.bridge_query.uuid.uuid4
        probe.state.coupled.bridge_query.uuid.uuid4 = lambda: next(ids)
        try:
            result = probe.probe_socket(FakeSocket(incoming), user_id=uid, blob=bytes(blob))
        finally:
            probe.state.coupled.bridge_query.uuid.uuid4 = original
        self.assertEqual(result, probe.CatacombLoadResult(0, 32, 1))

    def test_live_gate_is_closed(self):
        self.assertFalse(probe.LIVE_LOAD_ENABLED)
        with self.assertRaises(probe.CatacombLoadError):
            probe.live_probe(user_id=501, path=Path("/var/lib/t2-touchid/501.catacomb"))


if __name__ == "__main__":
    unittest.main()
