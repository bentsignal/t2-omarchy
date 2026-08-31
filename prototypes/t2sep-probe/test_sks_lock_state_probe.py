import importlib.util
from pathlib import Path
import plistlib
import struct
import sys
import unittest


SPEC = importlib.util.spec_from_file_location(
    "sks_lock_state_tested", Path(__file__).with_name("sks-lock-state-probe.py"))
probe = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = probe
SPEC.loader.exec_module(probe)
protocol = probe.coupled.bridge_query.protocol


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


class SKSLockStateProbeTests(unittest.TestCase):
    IDS = tuple(f"{index:08d}-89AB-4CDE-8FAB-0123456789AB" for index in range(6))

    def run_probe(self, incoming):
        ids = iter(self.IDS)
        original = probe.coupled.bridge_query.uuid.uuid4
        probe.coupled.bridge_query.uuid.uuid4 = lambda: next(ids)
        try:
            return probe.probe_socket(FakeSocket(incoming), user_id=501)
        finally:
            probe.coupled.bridge_query.uuid.uuid4 = original

    def test_version_sweep_returns_only_status_and_u32_state(self):
        incoming = (envelope(self.IDS[0], [0, 3])
                    + envelope(self.IDS[1], [0])
                    + envelope(self.IDS[2], [0, True])
                    + envelope(self.IDS[3], [-536870206, protocol.NO_REPLY_UUID.lower()])
                    + envelope(self.IDS[4], [0, struct.pack("<I", 8)])
                    + envelope(self.IDS[5], [-536870206, protocol.NO_REPLY_UUID.lower()]))
        self.assertEqual(self.run_probe(incoming), (
            probe.SKSLockStateResult(0, -536870206, None, None),
            probe.SKSLockStateResult(1, 0, 8, 4),
            probe.SKSLockStateResult(2, -536870206, None, None)))

    def test_invalid_success_shape_fails_closed(self):
        incoming = (envelope(self.IDS[0], [0, 3])
                    + envelope(self.IDS[1], [0])
                    + envelope(self.IDS[2], [0, True])
                    + envelope(self.IDS[3], [0, b"x"]))
        with self.assertRaises(probe.SKSLockStateError):
            self.run_probe(incoming)

    def test_live_gate_is_closed(self):
        self.assertFalse(probe.LIVE_SKS_LOCK_QUERY_ENABLED)
        with self.assertRaises(probe.SKSLockStateError):
            probe.live_probe(user_id=501)


if __name__ == "__main__":
    unittest.main()
