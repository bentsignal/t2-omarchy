import importlib.util
from pathlib import Path
import plistlib
import sys
import unittest


SPEC = importlib.util.spec_from_file_location(
    "no_catacomb_tested", Path(__file__).with_name("no-catacomb-probe.py"))
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


class NoCatacombProbeTests(unittest.TestCase):
    IDS = tuple(f"{index}3456789-89AB-4CDE-8FAB-0123456789AB" for index in range(7))

    def test_exact_codec_and_sanitized_post_state(self):
        self.assertEqual(probe.state.biometric.no_catacomb_fields(user_id=501),
                         (0x31, 1, 0, b"\xf5\x01\0\0", 0))
        incoming = b"".join((
            envelope(self.IDS[0], [0, 3]), envelope(self.IDS[1], [0]),
            envelope(self.IDS[2], [0, True]),
            envelope(self.IDS[3], [0, protocol.NO_REPLY_UUID.lower()]),
            envelope(self.IDS[4], [0, bytes(32)]),
            envelope(self.IDS[5], [0, bytes(8)]),
            envelope(self.IDS[6], [0, bytes(56)])))
        ids = iter(self.IDS)
        original = probe.state.coupled.bridge_query.uuid.uuid4
        probe.state.coupled.bridge_query.uuid.uuid4 = lambda: next(ids)
        try:
            status, result = probe.probe_socket(FakeSocket(incoming), user_id=501)
        finally:
            probe.state.coupled.bridge_query.uuid.uuid4 = original
        self.assertEqual(status, 0)
        self.assertEqual(result, probe.state.UserStateResult(
            0, 32, (0, 0, 0, 0), (0, 0, 0, 0),
            -1, None, -1, None, -1, None, -1, None, 0, 1, 0, 1))

    def test_live_gate_closed(self):
        self.assertFalse(probe.LIVE_NO_CATACOMB_ENABLED)
        with self.assertRaises(probe.NoCatacombProbeError):
            probe.live_probe(user_id=501)


if __name__ == "__main__":
    unittest.main()
