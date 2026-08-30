import importlib.util
from pathlib import Path
import sys
import unittest


SPEC = importlib.util.spec_from_file_location(
    "sensor_context_probe", Path(__file__).with_name("sensor-context-probe.py"))
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


class SensorContextProbeTests(unittest.TestCase):
    def run_probe(self, replies):
        session = FakeSession(replies)
        original = probe.coupled.bridge_query.BridgeSession
        probe.coupled.bridge_query.BridgeSession = lambda sock: session
        try:
            result = probe.probe_socket(object())
        finally:
            probe.coupled.bridge_query.BridgeSession = original
        return session, result

    def test_reads_only_recovered_sensor_context_shapes(self):
        session, result = self.run_probe((
            [0, 3], [0], [0, True],
            [0, b"\x01"], [0, b"\x05\0\0\0"], [0, bytes(12)],
        ))
        self.assertEqual(result, probe.SensorContextResult(0, 1, 0, 5, 0, 12))
        inner = [request[2] for request in session.requests[3:]]
        self.assertEqual([payload[2:4] for payload in inner],
                         [b"\x53\0", b"\x10\0", b"\x35\0"])
        self.assertNotIn(b"\x02\0", inner)

    def test_preserves_service_errors_without_decoding_output(self):
        _, result = self.run_probe((
            [0, 3], [0], [0, True], [257, None], [7, None], [9, None],
        ))
        self.assertEqual(result,
                         probe.SensorContextResult(257, None, 7, None, 9, None))

    def test_rejects_malformed_success_and_wrong_bridge(self):
        with self.assertRaisesRegex(probe.SensorContextProbeError, "generation 3"):
            self.run_probe(([0, 2],))
        with self.assertRaisesRegex(probe.SensorContextProbeError, "invalid shape"):
            self.run_probe(([0, 3], [0], [0, True], [0, b""],))

    def test_live_path_is_source_gated(self):
        with self.assertRaisesRegex(probe.SensorContextProbeError, "disabled"):
            probe.live_probe()


if __name__ == "__main__":
    unittest.main()
