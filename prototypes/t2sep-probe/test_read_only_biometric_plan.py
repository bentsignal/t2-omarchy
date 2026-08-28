import importlib.util
from pathlib import Path
import plistlib
import struct
import sys
import unittest
import uuid


SPEC = importlib.util.spec_from_file_location(
    "read_only_biometric_plan",
    Path(__file__).with_name("read-only-biometric-plan.py"))
plan = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = plan
SPEC.loader.exec_module(plan)
rsd = plan.discovery.rsd


def directory_transcript(port=49165):
    value = {
        "MessageType": "Handshake",
        "MessagingProtocolVersion": rsd.Int64(3),
        "Properties": {},
        "Services": {plan.discovery.BIOMETRIC_SERVICE: {
            "Port": str(port),
            "Properties": {"UsesRemoteXPC": False},
        }},
        "UUID": uuid.UUID(int=1),
    }
    message = rsd.encode_xpc_message(value, message_id=0)
    return (rsd.encode_http2_frame(rsd.HTTP2_SETTINGS, 0, 0,
                                   struct.pack("!HI", 3, 100))
            + rsd.encode_http2_frame(rsd.HTTP2_DATA, 0,
                                     rsd.ROOT_CHANNEL, message))


def decode_perform(frame):
    size = plan.bridge.BRIDGE_FRAME_HEADER.size
    header = plan.bridge.decode_frame_header(frame[:size], max_body=plan.BODY_CAP)
    assert header.kind == plan.bridge.FRAME_MESSAGE
    outer = plistlib.loads(frame[size:])
    inner = plan.bridge.decode_biometric_request(outer[2], max_payload=1280)
    return outer, inner


class ReadOnlyBiometricPlanTests(unittest.TestCase):
    def test_builds_only_three_identity_queries_after_methods_zero_one(self):
        result = plan.build_from_rsd_transcript(
            directory_transcript(), 7, user_id=501, os_build="25G83",
            process_name="biometrickitd")
        self.assertEqual(result.endpoint, (rsd.T2_LINK_LOCAL_ADDRESS_CANDIDATE,
                                           49165, 0, 7))
        header_size = plan.bridge.BRIDGE_FRAME_HEADER.size
        self.assertEqual(plistlib.loads(result.bridge_version[header_size:]), [0])
        self.assertEqual(plistlib.loads(result.service_opened[header_size:]), [1])
        expected = (
            (result.maximum_identity_count, 0x0F, b"", 4),
            (result.free_identity_count, 0x41, struct.pack("<I", 501), 4),
            (result.identity_list, 0x42, struct.pack("<I", 501), 1280),
        )
        for frame, command, payload, capacity in expected:
            outer, inner = decode_perform(frame)
            self.assertEqual((outer[0], outer[1], outer[3]), (3, 0, capacity))
            self.assertEqual((inner.command, inner.version, inner.value),
                             (command, 1, 0))
            self.assertEqual(inner.payload, payload)

    def test_rejects_invalid_transcript_user_and_identity_cap(self):
        cases = (
            (b"bad", 7, 501, 64),
            (directory_transcript(), 0, 501, 64),
            (directory_transcript(), 7, -1, 64),
            (directory_transcript(), 7, 501, 0),
            (directory_transcript(), 7, 501, 65),
        )
        for transcript, ifindex, user, maximum in cases:
            with self.subTest(ifindex=ifindex, user=user, maximum=maximum):
                with self.assertRaises(plan.ReadOnlyPlanError):
                    plan.build_from_rsd_transcript(
                        transcript, ifindex, user_id=user,
                        max_identities=maximum)

    def test_module_exposes_no_mutating_or_socket_api(self):
        names = set(vars(plan))
        for forbidden in ("socket", "enroll", "match", "remove", "cancel",
                          "presence"):
            self.assertNotIn(forbidden, names)


if __name__ == "__main__":
    unittest.main()
