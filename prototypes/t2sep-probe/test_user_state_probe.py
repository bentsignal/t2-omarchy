import importlib.util
from pathlib import Path
import plistlib
import sys
import unittest


SPEC = importlib.util.spec_from_file_location(
    "user_state_probe_tested", Path(__file__).with_name("user-state-probe.py"))
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


class UserStateProbeTests(unittest.TestCase):
    IDS = tuple(f"{index}2345678-89AB-4CDE-8FAB-0123456789AB" for index in range(6))

    def run_probe(self, replies):
        ids = iter(self.IDS)
        original = probe.coupled.bridge_query.uuid.uuid4
        probe.coupled.bridge_query.uuid.uuid4 = lambda: next(ids)
        try:
            return probe.probe_socket(FakeSocket(replies), user_id=501)
        finally:
            probe.coupled.bridge_query.uuid.uuid4 = original

    def test_reports_only_status_lengths_and_counts(self):
        replies = (envelope(self.IDS[0], [0, 3])
                   + envelope(self.IDS[1], [0])
                   + envelope(self.IDS[2], [0, True])
                   + envelope(self.IDS[3], [0, bytes(32)])
                   + envelope(self.IDS[4], [0, bytes(16)])
                   + envelope(self.IDS[5], [0, bytes(112)]))
        result = self.run_probe(replies)
        self.assertEqual(result, probe.UserStateResult(0, 32, 0, 2, 0, 2))
        self.assertNotIn("bytes", repr(result))

    def test_invalid_success_shapes_fail_closed(self):
        prefix = (envelope(self.IDS[0], [0, 3])
                  + envelope(self.IDS[1], [0])
                  + envelope(self.IDS[2], [0, True]))
        with self.assertRaises(probe.UserStateProbeError):
            self.run_probe(prefix + envelope(self.IDS[3], [0, bytes(31)]))

    def test_live_gate_is_closed(self):
        self.assertFalse(probe.LIVE_USER_STATE_ENABLED)
        with self.assertRaises(probe.UserStateProbeError):
            probe.live_probe(user_id=501)


if __name__ == "__main__":
    unittest.main()
