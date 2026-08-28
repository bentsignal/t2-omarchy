import importlib.util
from pathlib import Path
import plistlib
import struct
import sys
import unittest


SPEC = importlib.util.spec_from_file_location(
    "presence_probe_tested", Path(__file__).with_name("presence-event-probe.py"))
probe = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = probe
SPEC.loader.exec_module(probe)


def frame(kind, body):
    protocol = probe.coupled.bridge_query.protocol
    return protocol.encode_frame_header(kind, len(body)) + body


class FakeSocket:
    def __init__(self, incoming):
        self.incoming = bytearray(incoming)
        self.sent = bytearray()

    def sendall(self, data): self.sent.extend(data)
    def recv(self, size):
        result = self.incoming[:size]
        del self.incoming[:size]
        return bytes(result)


class PresenceProbeTests(unittest.TestCase):
    def test_event_is_bounded_and_cancel_is_sent(self):
        protocol = probe.coupled.bridge_query.protocol
        start_id = "01234567-89AB-4CDE-8FAB-0123456789AB"
        cancel_id = "11234567-89AB-4CDE-8FAB-0123456789AB"
        record = bytearray(40)
        struct.pack_into("<II", record, 8, 0xE3FF8001, 1)
        struct.pack_into("<Q", record, 24, 59)
        second_record = bytearray(record)
        struct.pack_into("<II", second_record, 8, 0xE3FF8004, 1)
        struct.pack_into("<Q", second_record, 24, 60)
        replies = (
            [1, True, start_id, [0, protocol.NO_REPLY_UUID.lower()]],
            [1, False, protocol.NO_REPLY_UUID.lower(),
             [9, 0xE3FF8000, bytes(record), 1, 2]],
            [1, False, protocol.NO_REPLY_UUID.lower(),
             [9, 0xE3FF8000, bytes(second_record), 3, 4]],
            [1, True, cancel_id, [0, protocol.NO_REPLY_UUID.lower()]],
        )
        incoming = b"".join(frame(protocol.FRAME_MESSAGE, plistlib.dumps(item))
                            for item in replies)
        sock = FakeSocket(incoming)
        ids = iter((start_id, cancel_id))
        original = probe.coupled.bridge_query.uuid.uuid4
        probe.coupled.bridge_query.uuid.uuid4 = lambda: next(ids)
        try:
            result = probe.probe_socket(sock)
        finally:
            probe.coupled.bridge_query.uuid.uuid4 = original
        self.assertEqual((result.start_status, result.cancel_status), (0, 0))
        self.assertEqual(result.event_types,
                         ("int", "int", "bytes", "int", "int"))
        self.assertEqual(result.event_integers,
                         (9, 0xE3FF8000, None, 1, 2))
        self.assertEqual((result.event_status, result.event_version,
                          result.event_ordinal, result.event_data_length),
                         (0xE3FF8001, 1, 59, 0))
        self.assertEqual(result.service_events,
                         ((0xE3FF8001, 1, 59, 0),
                          (0xE3FF8004, 1, 60, 0)))


if __name__ == "__main__":
    unittest.main()
