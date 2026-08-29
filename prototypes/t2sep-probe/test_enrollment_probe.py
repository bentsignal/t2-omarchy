import importlib.util
from pathlib import Path
import plistlib
import struct
import sys
import unittest


SPEC = importlib.util.spec_from_file_location(
    "enrollment_probe_tested", Path(__file__).with_name("enrollment-probe.py"))
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


class FakeSocket:
    def __init__(self, incoming):
        self.incoming = bytearray(incoming)
        self.sent = bytearray()
    def sendall(self, data): self.sent.extend(data)
    def recv(self, size):
        result = self.incoming[:size]
        del self.incoming[:size]
        return bytes(result)


class EnrollmentProbeTests(unittest.TestCase):
    USER = 1000
    UUID = bytes(range(16))
    IDS = tuple(f"{index:08d}-89AB-4CDE-8FAB-0123456789AB"
                for index in range(13))

    def incoming(self, *, after_record=True, terminal_uuid=UUID):
        identity = probe.biometric.IDENTITY.pack(self.USER, self.UUID)
        terminal = probe.biometric.IDENTITY.pack(self.USER, terminal_uuid)
        after = identity if after_record else b""
        return (envelope(self.IDS[0], [0, 3])
                + envelope(self.IDS[1], [0])
                + envelope(self.IDS[2], [0, True])
                + envelope(self.IDS[3], [0, protocol.NO_REPLY_UUID.lower()])
                + envelope(self.IDS[4], [0, protocol.NO_REPLY_UUID.lower()])
                + service_event(0xE3FF8001)
                + service_event(0xE3FF8004, b"x" * 12, 2)
                + service_event(0xE3FF8003, terminal, 3)
                + envelope(self.IDS[5], [0, after])
                + envelope(self.IDS[6], [0, protocol.NO_REPLY_UUID.lower()]))

    def run_probe(self, incoming):
        ids = iter(self.IDS)
        original = probe.coupled.bridge_query.uuid.uuid4
        probe.coupled.bridge_query.uuid.uuid4 = lambda: next(ids)
        try:
            return probe.probe_socket(FakeSocket(incoming), user_id=self.USER)
        finally:
            probe.coupled.bridge_query.uuid.uuid4 = original

    def test_terminal_and_exact_identity_delta_complete(self):
        result = self.run_probe(self.incoming())
        self.assertEqual((result.identities_before, result.identities_after), (0, 1))
        self.assertEqual(result.observed_statuses,
                         (0xE3FF8001, 0xE3FF8004, 0xE3FF8003))
        self.assertEqual(result.observed_events,
                         ((0xE3FF8001, 1, 0),
                          (0xE3FF8004, 1, 12),
                          (0xE3FF8003, 1, 20)))
        self.assertEqual(result.cancel_status, 0)

    def test_authorized_current_request_is_sent_and_closed(self):
        credential = bytearray(range(16))
        request = probe.biometric.consume_builtin_enrollment_credential(
            user_id=self.USER, credential_set=credential)
        view = request.view()
        ids = iter(self.IDS)
        original = probe.coupled.bridge_query.uuid.uuid4
        probe.coupled.bridge_query.uuid.uuid4 = lambda: next(ids)
        try:
            result = probe.probe_socket(
                FakeSocket(self.incoming()), user_id=self.USER,
                authorized_request=request)
        finally:
            probe.coupled.bridge_query.uuid.uuid4 = original
        self.assertEqual(result.identities_after, 1)
        self.assertTrue(request.closed)
        self.assertEqual(bytes(view), bytes(68))

    def test_policy_is_created_read_back_then_enrollment_runs(self):
        enroll_request = probe.biometric.consume_builtin_enrollment_credential(
            user_id=self.USER, credential_set=bytearray(range(16)))
        policy_request = probe.biometric.consume_user_policy_credential(
            user_id=self.USER,
            policy=probe.biometric.UserProtectedPolicy(1, 1, 1, 0),
            credential_set=bytearray(range(16)))
        identity = probe.biometric.IDENTITY.pack(self.USER, self.UUID)
        policy_reply = struct.pack("<8I", 1, 1, 1, 0, 1, 1, 1, 0)
        incoming = (envelope(self.IDS[0], [0, 3])
                    + envelope(self.IDS[1], [0])
                    + envelope(self.IDS[2], [0, True])
                    + envelope(self.IDS[3], [0, protocol.NO_REPLY_UUID.lower()])
                    + envelope(self.IDS[4], [0, protocol.NO_REPLY_UUID.lower()])
                    + envelope(self.IDS[5], [0, policy_reply])
                    + envelope(self.IDS[6], [0, protocol.NO_REPLY_UUID.lower()])
                    + envelope(self.IDS[7], [0, protocol.NO_REPLY_UUID.lower()])
                    + service_event(0xE3FF8001)
                    + service_event(0xE3FF8003, identity, 2)
                    + envelope(self.IDS[8], [0, identity])
                    + envelope(self.IDS[9], [0, protocol.NO_REPLY_UUID.lower()]))
        ids = iter(self.IDS)
        original = probe.coupled.bridge_query.uuid.uuid4
        probe.coupled.bridge_query.uuid.uuid4 = lambda: next(ids)
        try:
            result = probe.probe_socket(
                FakeSocket(incoming), user_id=self.USER,
                authorized_request=enroll_request, policy_request=policy_request)
        finally:
            probe.coupled.bridge_query.uuid.uuid4 = original
        self.assertTrue(result.policy_initialized)
        self.assertTrue(policy_request.closed)
        self.assertTrue(enroll_request.closed)

    def test_successful_enrollment_is_persisted_before_confirmation(self):
        identity = probe.biometric.IDENTITY.pack(self.USER, self.UUID)
        blob = bytearray(128)
        struct.pack_into("<I", blob, 8, self.USER)
        incoming = (envelope(self.IDS[0], [0, 3])
                    + envelope(self.IDS[1], [0])
                    + envelope(self.IDS[2], [0, True])
                    + envelope(self.IDS[3], [0, protocol.NO_REPLY_UUID.lower()])
                    + envelope(self.IDS[4], [0, protocol.NO_REPLY_UUID.lower()])
                    + service_event(0xE3FF8001)
                    + service_event(0xE3FF8003, identity, 2)
                    + envelope(self.IDS[5], [0, identity])
                    + envelope(self.IDS[6], [0, struct.pack("<I", len(blob))])
                    + envelope(self.IDS[7], [0, bytes(blob)])
                    + envelope(self.IDS[8], [0, protocol.NO_REPLY_UUID.lower()])
                    + envelope(self.IDS[9], [0, protocol.NO_REPLY_UUID.lower()]))
        saved = []
        ids = iter(self.IDS)
        original = probe.coupled.bridge_query.uuid.uuid4
        probe.coupled.bridge_query.uuid.uuid4 = lambda: next(ids)
        try:
            result = probe.probe_socket(FakeSocket(incoming), user_id=self.USER,
                                        catacomb_sink=saved.append)
        finally:
            probe.coupled.bridge_query.uuid.uuid4 = original
        self.assertEqual(saved, [bytes(blob)])
        self.assertTrue(result.catacomb_saved)

    def test_progress_callback_gets_metadata_only(self):
        seen = []
        self.run_probe_with_progress(self.incoming(), seen.append)
        self.assertEqual(seen[-1], (0xE3FF8003, 1, 20))

    def run_probe_with_progress(self, incoming, progress):
        ids = iter(self.IDS)
        original = probe.coupled.bridge_query.uuid.uuid4
        probe.coupled.bridge_query.uuid.uuid4 = lambda: next(ids)
        try:
            return probe.probe_socket(FakeSocket(incoming), user_id=self.USER,
                                      progress=progress)
        finally:
            probe.coupled.bridge_query.uuid.uuid4 = original

    def test_missing_delta_and_terminal_mismatch_fail_closed(self):
        with self.assertRaisesRegex(probe.EnrollmentProbeError, "delta"):
            self.run_probe(self.incoming(after_record=False))
        with self.assertRaisesRegex(probe.EnrollmentProbeError, "does not equal"):
            self.run_probe(self.incoming(terminal_uuid=b"x" * 16))

    def test_live_gate_is_false(self):
        self.assertFalse(probe.LIVE_ENROLLMENT_ENABLED)
        with self.assertRaisesRegex(probe.EnrollmentProbeError, "disabled"):
            probe.live_probe(user_id=self.USER)


if __name__ == "__main__":
    unittest.main()
