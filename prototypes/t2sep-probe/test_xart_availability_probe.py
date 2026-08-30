import importlib.util
from pathlib import Path
import plistlib
import struct
import sys
import unittest


SPEC = importlib.util.spec_from_file_location(
    "xart_availability_tested",
    Path(__file__).with_name("xart-availability-probe.py"))
probe = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = probe
SPEC.loader.exec_module(probe)
protocol = probe.context.state.coupled.bridge_query.protocol


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


class XartAvailabilityProbeTests(unittest.TestCase):
    IDS = tuple(f"{index:08d}-89AB-4CDE-8FAB-0123456789AB" for index in range(11))

    def replies(self, value=b"\1"):
        record = probe.context.state.biometric.BIO_DEVICE_RECORD.pack(
            1, bytes(16), 1, bytes(16), 6)
        info = bytearray(23)
        info[22] = 1
        return (envelope(self.IDS[0], [0, 3])
                + envelope(self.IDS[1], [0])
                + envelope(self.IDS[2], [0, True])
                + envelope(self.IDS[3], [0, b"\1"])
                + envelope(self.IDS[4], [0, struct.pack("<I", 5)])
                + envelope(self.IDS[5], [0, protocol.NO_REPLY_UUID.lower()])
                + envelope(self.IDS[6], [0, protocol.NO_REPLY_UUID.lower()])
                + envelope(self.IDS[7], [0, struct.pack("<3I", 1, 12, 7)])
                + envelope(self.IDS[8], [0, bytes(info)])
                + envelope(self.IDS[9], [0, record])
                + envelope(self.IDS[10], [0, value]))

    def run_probe(self, incoming):
        ids = iter(self.IDS)
        original = probe.context.state.coupled.bridge_query.uuid.uuid4
        probe.context.state.coupled.bridge_query.uuid.uuid4 = lambda: next(ids)
        try:
            return probe.probe_socket(FakeSocket(incoming))
        finally:
            probe.context.state.coupled.bridge_query.uuid.uuid4 = original

    def test_reports_only_canonical_availability(self):
        self.assertTrue(self.run_probe(self.replies()))
        self.assertFalse(self.run_probe(self.replies(b"\0")))

    def test_invalid_success_shape_fails_closed(self):
        with self.assertRaises(probe.XartAvailabilityError):
            self.run_probe(self.replies(b"\2"))

    def test_live_gate_is_closed(self):
        self.assertFalse(probe.LIVE_XART_QUERY_ENABLED)
        with self.assertRaises(probe.XartAvailabilityError):
            probe.live_probe()


if __name__ == "__main__":
    unittest.main()
