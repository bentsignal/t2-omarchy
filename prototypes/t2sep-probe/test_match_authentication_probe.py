import importlib.util
from pathlib import Path
import plistlib
import socket
import struct
import sys
import unittest


SPEC = importlib.util.spec_from_file_location(
    "match_probe_tested", Path(__file__).with_name("match-authentication-probe.py"))
probe = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = probe
SPEC.loader.exec_module(probe)
protocol = probe.coupled.bridge_query.protocol


def frame(body):
    return protocol.encode_frame_header(protocol.FRAME_MESSAGE, len(body)) + body


def envelope(reply_id, payload, *, reply=True):
    return frame(plistlib.dumps([1, reply, reply_id, payload],
                                fmt=plistlib.FMT_BINARY))


def service_event(status, data=b"", ordinal=1):
    record = bytearray(40 + len(data))
    struct.pack_into("<II", record, 8, status, 1)
    struct.pack_into("<Q", record, 24, ordinal)
    struct.pack_into("<Q", record, 32, len(data))
    record[40:] = data
    return envelope(protocol.NO_REPLY_UUID.lower(),
                    [9, 0xE3FF8000, bytes(record), 10, 20], reply=False)


def match_result(user_id, identity_uuid):
    data = bytearray(probe.biometric.CATALINA_MATCH_RESULT_BASE_SIZE)
    struct.pack_into("<I16s", data, 0, user_id, identity_uuid)
    return bytes(data)


class FakeSocket:
    def __init__(self, incoming):
        self.incoming = bytearray(incoming)
        self.sent = bytearray()
    def sendall(self, data): self.sent.extend(data)
    def recv(self, size):
        result = self.incoming[:size]
        del self.incoming[:size]
        return bytes(result)


class TimeoutSocket(FakeSocket):
    def recv(self, size):
        if not self.incoming:
            raise socket.timeout("fixture timeout")
        return super().recv(size)


class MatchProbeTests(unittest.TestCase):
    USER = 501
    UUID = bytes(range(16))
    IDS = (
        "01234567-89AB-4CDE-8FAB-0123456789AB",
        "11234567-89AB-4CDE-8FAB-0123456789AB",
        "21234567-89AB-4CDE-8FAB-0123456789AB",
    )

    def incoming(self, terminal_user=USER, terminal_uuid=UUID):
        identity = probe.biometric.IDENTITY.pack(self.USER, self.UUID)
        return (envelope(self.IDS[0], [0, identity])
                + envelope(self.IDS[1], [0, protocol.NO_REPLY_UUID.lower()])
                + service_event(0xE3FF8001, b"bounded-touch-metadata")
                + service_event(0xE3FF8004, b"p" * 12, 2)
                + service_event(0xE3FF800B, b"123456789", 3)
                + service_event(0xE3FF8002,
                                match_result(terminal_user, terminal_uuid), 4)
                + envelope(self.IDS[2], [0, protocol.NO_REPLY_UUID.lower()]))

    def run_probe(self, incoming):
        ids = iter(self.IDS)
        original = probe.coupled.bridge_query.uuid.uuid4
        probe.coupled.bridge_query.uuid.uuid4 = lambda: next(ids)
        try:
            return probe.probe_socket(FakeSocket(incoming), user_id=self.USER)
        finally:
            probe.coupled.bridge_query.uuid.uuid4 = original

    def run_probe_socket(self, sock):
        ids = iter(self.IDS)
        original = probe.coupled.bridge_query.uuid.uuid4
        probe.coupled.bridge_query.uuid.uuid4 = lambda: next(ids)
        try:
            return probe.probe_socket(sock, user_id=self.USER)
        finally:
            probe.coupled.bridge_query.uuid.uuid4 = original

    def test_exact_trusted_match_succeeds(self):
        result = self.run_probe(self.incoming())
        self.assertTrue(result.matched)
        self.assertEqual(result.matched_user_id, self.USER)
        self.assertEqual(result.trusted_identity_count, 1)
        self.assertEqual(result.observed_statuses,
                         (0xE3FF8001, 0xE3FF8004,
                          0xE3FF800B, 0xE3FF8002))
        self.assertEqual(result.cancel_status, 0)
        self.assertEqual(result.observed_events[0][0], 0xE3FF8001)

    def test_no_match_is_not_success(self):
        result = self.run_probe(self.incoming(0xFFFFFFFF, bytes(16)))
        self.assertFalse(result.matched)
        self.assertIsNone(result.matched_user_id)

    def test_unknown_identity_fails_closed_and_still_cancels(self):
        with self.assertRaisesRegex(probe.MatchProbeError, "rejected"):
            self.run_probe(self.incoming(self.USER, b"x" * 16))

    def test_timeout_fails_closed(self):
        identity = probe.biometric.IDENTITY.pack(self.USER, self.UUID)
        incoming = (envelope(self.IDS[0], [0, identity])
                    + envelope(self.IDS[1], [0, protocol.NO_REPLY_UUID.lower()]))
        with self.assertRaisesRegex(probe.MatchProbeError, "timed out"):
            self.run_probe_socket(TimeoutSocket(incoming))

    def test_unexpected_event_fails_closed_then_cancels(self):
        identity = probe.biometric.IDENTITY.pack(self.USER, self.UUID)
        incoming = (envelope(self.IDS[0], [0, identity])
                    + envelope(self.IDS[1], [0, protocol.NO_REPLY_UUID.lower()])
                    + service_event(0xE3FF80FF)
                    + envelope(self.IDS[2], [0, protocol.NO_REPLY_UUID.lower()]))
        with self.assertRaisesRegex(probe.MatchProbeError, "unexpected"):
            self.run_probe(incoming)

    def test_live_gate_is_false(self):
        self.assertFalse(probe.LIVE_MATCH_ENABLED)
        with self.assertRaisesRegex(probe.MatchProbeError, "disabled"):
            probe.live_probe(user_id=self.USER)


if __name__ == "__main__":
    unittest.main()
