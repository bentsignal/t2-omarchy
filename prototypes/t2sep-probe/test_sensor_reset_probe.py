import importlib.util
from pathlib import Path
import struct
import sys
import unittest


SPEC = importlib.util.spec_from_file_location(
    "sensor_reset_probe", Path(__file__).with_name("sensor-reset-probe.py"))
probe = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = probe
SPEC.loader.exec_module(probe)


class FakeSession:
    def __init__(self, replies):
        self.replies = iter(replies)
        self.requests = []

    def call(self, request):
        self.requests.append(request)
        return next(self.replies)


class SensorResetProbeTests(unittest.TestCase):
    def run_probe(self, replies):
        session = FakeSession(replies)
        original = probe.context.coupled.bridge_query.BridgeSession
        probe.context.coupled.bridge_query.BridgeSession = lambda sock: session
        try:
            result = probe.probe_socket(object())
        finally:
            probe.context.coupled.bridge_query.BridgeSession = original
        return session, result

    @staticmethod
    def successful_tail():
        record = probe.context.biometric.BIO_DEVICE_RECORD.pack(
            1, bytes(16), 1, bytes(16), 6)
        return ([0, struct.pack("<3I", 1, 12, 7)], [0, record])

    def test_exact_order_and_success(self):
        session, result = self.run_probe((
            [0, 3], [0], [0, True], [0, b"\x01"],
            [0, struct.pack("<I", 5)], [0, None], *self.successful_tail(),
        ))
        self.assertEqual(result, probe.SensorResetResult(1, 0, 12, 1, 1))
        inner = [request[2] for request in session.requests[3:]]
        self.assertEqual([payload[2:4] for payload in inner],
                         [b"\x53\0", b"\x10\0", b"\x02\0",
                          b"\x35\0", b"\x52\0"])
        self.assertEqual(inner[2][4:8], b"\x02\0\0\0")

    def test_retries_no_more_than_three_times(self):
        replies = ([0, 3], [0], [0, True], [0, b"\x01"],
                   [0, struct.pack("<I", 5)],
                   [7, None], [8, None], [9, None])
        with self.assertRaisesRegex(probe.SensorResetProbeError,
                                    "3 attempts.*status 9"):
            self.run_probe(replies)

    def test_live_path_is_source_gated(self):
        with self.assertRaisesRegex(probe.SensorResetProbeError, "disabled"):
            probe.live_probe()


if __name__ == "__main__":
    unittest.main()
