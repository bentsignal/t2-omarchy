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
        overlay.permit_system_lifecycle_status_90(protocol)

    def machine(self):
        return protocol.EnrollmentStateMachine(
            expected_user_id=501,
            connection_generation="generation",
            operation_id="operation",
        )

    def accept(self, machine, value):
        return machine.accept(
            value,
            connection_generation="generation",
            operation_id="operation",
        )

    def status(self, sequence: int, ordinal: int, *, malformed: bool = False):
        payload = (
            bytes(15)
            if malformed
            else protocol.STATUS_PAYLOAD_HEADER.pack(ordinal, 0)
        )
        return protocol.ServiceEvent(
            sequence,
            protocol.SERVICE_STATUS,
            1,
            ordinal,
            payload,
        )

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

    def test_status_90_is_an_ordered_noncontinuing_noop(self):
        machine = self.machine()
        transition = self.accept(machine, self.status(10, 90))
        self.assertEqual(
            transition.action, protocol.EnrollmentAction.IGNORE_AUXILIARY
        )
        self.assertFalse(transition.continue_required)
        self.assertEqual(machine.state, protocol.EnrollmentState.ACTIVE)

        with self.assertRaisesRegex(
            protocol.EnrollmentProtocolError, "duplicate enrollment event"
        ):
            self.accept(machine, self.status(10, 90))
        self.assertEqual(machine.state, protocol.EnrollmentState.FROZEN)

    def test_status_90_preserves_payload_and_cancellation_checks(self):
        malformed = self.machine()
        with self.assertRaisesRegex(
            protocol.EnrollmentProtocolError, "invalid generic status event"
        ):
            self.accept(malformed, self.status(10, 90, malformed=True))

        cancelled = self.machine()
        cancelled.request_cancel()
        with self.assertRaisesRegex(
            protocol.EnrollmentProtocolError,
            "nonterminal event arrived after cancellation was requested",
        ):
            self.accept(cancelled, self.status(10, 90))

    def test_neighboring_unknown_statuses_remain_rejected(self):
        for ordinal in (89, 91):
            with self.subTest(ordinal=ordinal):
                machine = self.machine()
                with self.assertRaisesRegex(
                    protocol.EnrollmentProtocolError,
                    f"unknown enrollment status {ordinal}",
                ):
                    self.accept(machine, self.status(10, ordinal))
                self.assertEqual(machine.state, protocol.EnrollmentState.FROZEN)


if __name__ == "__main__":
    unittest.main()
