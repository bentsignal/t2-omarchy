import importlib.util
import contextlib
import io
from pathlib import Path
import struct
import subprocess
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
        overlay.permit_nonadvancing_status_events(protocol)

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
        for ordinal in (62, 65, 80, 81, 89, 92, 99):
            with self.subTest(ordinal=ordinal):
                machine = self.machine()
                with self.assertRaisesRegex(
                    protocol.EnrollmentProtocolError,
                    f"unknown enrollment status {ordinal}",
                ):
                    self.accept(machine, self.status(10, ordinal))
                self.assertEqual(machine.state, protocol.EnrollmentState.FROZEN)

    def test_presence_and_lifecycle_sequence_needs_real_progress_and_result(self):
        machine = self.machine()
        for sequence, ordinal in enumerate((90, 63, 91, 64, 90, 63), 1):
            # Exact T2 presence events carry a 36-byte status detail record.
            detail = bytes(36) if ordinal in (63, 64) else b""
            value = protocol.ServiceEvent(
                sequence, protocol.SERVICE_STATUS, 1, ordinal,
                protocol.STATUS_PAYLOAD_HEADER.pack(ordinal, len(detail)) + detail,
            )
            transition = self.accept(machine, value)
            self.assertEqual(transition.action, protocol.EnrollmentAction.IGNORE_AUXILIARY)
            self.assertFalse(transition.continue_required)
            self.assertIsNone(transition.identity)
            self.assertIsNone(transition.progress_percent)
            self.assertEqual(machine.state, protocol.EnrollmentState.ACTIVE)
        progress = self.accept(machine, self.status(7, 263))
        self.assertTrue(progress.continue_required)
        self.assertEqual(progress.progress_percent, 63)
        identity = protocol.ServiceEvent(
            8, protocol.SERVICE_ENROLLMENT_RESULT, 1, 0,
            struct.pack("<I16s", 501, bytes(range(16))),
        )
        result = self.accept(machine, identity)
        self.assertEqual(result.action, protocol.EnrollmentAction.IDENTITY_OBSERVED)
        with self.assertRaisesRegex(protocol.EnrollmentProtocolError, "terminal"):
            self.accept(machine, self.status(9, 64))

    def test_every_allowed_status_retains_all_guards(self):
        for ordinal in overlay.NONADVANCING_STATUSES:
            for case in ("version", "length", "payload-ordinal", "generation",
                         "operation", "decreasing", "duplicate", "cancelled"):
                with self.subTest(ordinal=ordinal, case=case):
                    machine = self.machine()
                    value = self.status(10, ordinal)
                    kwargs = dict(connection_generation="generation", operation_id="operation")
                    if case in ("version", "length", "payload-ordinal"):
                        value = protocol.ServiceEvent(
                            10, protocol.SERVICE_STATUS, 2 if case == "version" else 1,
                            ordinal, protocol.STATUS_PAYLOAD_HEADER.pack(
                                ordinal + (case == "payload-ordinal"),
                                1 if case == "length" else 0,
                            ),
                        )
                    elif case == "generation":
                        kwargs["connection_generation"] = "other"
                    elif case == "operation":
                        kwargs["operation_id"] = "other"
                    elif case == "decreasing":
                        self.accept(machine, self.status(11, 90))
                    elif case == "duplicate":
                        self.accept(machine, value)
                    elif case == "cancelled":
                        machine.request_cancel()
                    with self.assertRaises(protocol.EnrollmentProtocolError):
                        machine.accept(value, **kwargs)
                    self.assertEqual(machine.state, protocol.EnrollmentState.FROZEN)

    def test_failures_are_still_terminal_after_presence(self):
        for ordinal, state in ((66, protocol.EnrollmentState.CANCELLED),
                               (67, protocol.EnrollmentState.FAILED),
                               (68, protocol.EnrollmentState.TIMED_OUT)):
            machine = self.machine()
            self.accept(machine, self.status(1, 63))
            self.accept(machine, self.status(2, ordinal))
            self.assertEqual(machine.state, state)

    def test_enrollment_error_notification_does_not_claim_no_match(self):
        output = io.StringIO()
        with contextlib.redirect_stderr(output):
            overlay.report_enrollment_notification("unused", "t2-touchid-alert.service")
            self.assertEqual(output.getvalue(), "")
            overlay.report_enrollment_notification("unused", "t2-touchid-failure.service")
        self.assertIn("Enrollment did not complete", output.getvalue())
        self.assertNotIn("Fingerprint not recognized", output.getvalue())

    def test_broker_entrypoint_help_without_hardware(self):
        completed = subprocess.run(
            [sys.executable, str(SCRIPT), "--overlay-acknowledge-system-sks-event",
             "--overlay-acknowledge-status-90-noop", "--overlay-acknowledge-presence-events",
             "--help"], capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("--preflight-only", completed.stdout)


if __name__ == "__main__":
    unittest.main()
