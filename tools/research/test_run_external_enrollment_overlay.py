import importlib.util
from pathlib import Path
import struct
import sys
import unittest


SCRIPT = Path(__file__).with_name("run-external-enrollment-overlay.py")
SPEC = importlib.util.spec_from_file_location("external_enrollment_overlay", SCRIPT)
overlay = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = overlay
SPEC.loader.exec_module(overlay)

PROTOCOL = Path("/home/shawn/dev/t2-touchid-linux-latest/src/t2_enrollment_protocol.py")
PROTOCOL_SPEC = importlib.util.spec_from_file_location("overlay_test_protocol", PROTOCOL)
protocol = importlib.util.module_from_spec(PROTOCOL_SPEC)
assert PROTOCOL_SPEC and PROTOCOL_SPEC.loader
sys.modules[PROTOCOL_SPEC.name] = protocol
PROTOCOL_SPEC.loader.exec_module(protocol)


def event(user_id: int, *, version: int = 1, trailing: bytes = b""):
    return protocol.ServiceEvent(
        1,
        protocol.SERVICE_SKS_LOCK_STATE,
        version,
        0,
        protocol.SKS_LOCK_STATE_PAYLOAD.pack(user_id, 0x15) + trailing,
    )


class ExternalEnrollmentOverlayTests(unittest.TestCase):
    def setUp(self):
        overlay.permit_system_scoped_sks_event(protocol)

    def test_accepts_only_pinned_user_or_system_scope(self):
        protocol.validate_sks_lock_state_payload(event(501), expected_user_id=501)
        protocol.validate_sks_lock_state_payload(
            event(0, trailing=bytes(16)), expected_user_id=501
        )
        with self.assertRaisesRegex(
            protocol.EnrollmentProtocolError, "unrelated Apple user"
        ):
            protocol.validate_sks_lock_state_payload(event(502), expected_user_id=501)

    def test_preserves_version_and_minimum_shape_validation(self):
        with self.assertRaisesRegex(
            protocol.EnrollmentProtocolError, "unsupported.*version"
        ):
            protocol.validate_sks_lock_state_payload(
                event(0, version=2), expected_user_id=501
            )
        malformed = protocol.ServiceEvent(
            1, protocol.SERVICE_SKS_LOCK_STATE, 1, 0, bytes(5)
        )
        with self.assertRaisesRegex(protocol.EnrollmentProtocolError, "truncated"):
            protocol.validate_sks_lock_state_payload(
                malformed, expected_user_id=501
            )

    def test_pinned_source_attestation_passes(self):
        self.assertTrue(overlay.validate_source().is_file())


if __name__ == "__main__":
    unittest.main()
