import importlib.util
from pathlib import Path
import struct
import sys
import unittest


SPEC = importlib.util.spec_from_file_location(
    "credential_authorization",
    Path(__file__).with_name("credential-authorization.py"))
authorization = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = authorization
SPEC.loader.exec_module(authorization)
acm = authorization.acm
aks = authorization.aks


def identity(version=2):
    return aks.build_identity_header(
        version, continuous_usec=7, process_unique_id=0,
        audit_session_id=0, cdhash=bytes(20),
        calendar_seconds=9 if version == 2 else None)


def protected(payload, version=2):
    return struct.pack("<I", 0x50) + aks.protect_header(
        identity(version), payload) + payload


def initialize_context(plan):
    plan.initialize_acm()
    plan.accept_acm_initialization(acm.encode_envelope(1, 0, 0), b"")
    plan.create_context()
    response = bytearray(range(17))
    plan.accept_context(acm.encode_envelope(1, 17, 0), response)
    return response


def initialize_aks(plan, version=2):
    plan.request_aks_capabilities(4)
    capabilities = protected(struct.pack("<iQI", 0, version, 0), 1)
    negotiated = plan.accept_aks_capabilities(
        bytes.fromhex("07cd04000000640000000000"), capabilities)
    plan.request_aks_environment(5)
    environment = protected(struct.pack("<i", 0), negotiated)
    plan.accept_aks_environment(
        bytes.fromhex("07aa05000000580000000000"), environment)
    return negotiated


class CredentialAuthorizationTests(unittest.TestCase):
    def test_complete_lifecycle_retains_then_scrubs_same_context(self):
        plan = authorization.CredentialAuthorizationPlan()
        response = initialize_context(plan)
        self.assertEqual(initialize_aks(plan), 2)
        plan.plan_verification(
            6, 8, keybag_handle=aks.SessionKeybagHandle(7),
            selector=aks.SessionKeybagSelector(-501))
        password = bytearray(b"example!")
        request = plan.consume_verification_secrets(
            identity(), password, device_state_active=False)
        request_view = request.view()
        self.assertEqual(password, bytearray(8))
        self.assertEqual(response, bytearray(range(17)))
        self.assertNotIn("example", repr(plan))

        reply = protected(struct.pack("<IQ", 1, 0x82))
        result = plan.accept_verification(
            bytes.fromhex("07a106000000600000000000"), reply)
        self.assertEqual(result, aks.VerifySecretReply(0x82))
        self.assertTrue(plan.authorized)
        self.assertEqual(bytes(request_view), bytes(len(request_view)))
        self.assertEqual(response, bytearray(range(17)))

        delete_envelope, delete_view = plan.prepare_context_delete()
        self.assertEqual(acm.decode_envelope(delete_envelope),
                         acm.ACMEnvelope(1, 24, 0))
        self.assertEqual(delete_view[:8], b"DRCS\x02\0\x10\x01")
        self.assertEqual(delete_view[8:], bytearray(range(16)))
        plan.accept_context_delete(acm.encode_envelope(1, 0, 0), b"")
        self.assertTrue(plan.closed)
        self.assertEqual(response, bytearray(17))
        self.assertEqual(bytes(delete_view), bytes(24))

    def test_bad_reply_fails_closed_but_still_permits_delete(self):
        plan = authorization.CredentialAuthorizationPlan()
        response = initialize_context(plan)
        plan.request_aks_capabilities(4)
        with self.assertRaises(authorization.CredentialAuthorizationError):
            plan.accept_aks_capabilities(
                bytes.fromhex("07cd05000000640000000000"),
                protected(struct.pack("<iQI", 0, 2, 0), 1))
        self.assertTrue(plan.failed)
        with self.assertRaises(authorization.CredentialAuthorizationError):
            plan.request_aks_environment(5)
        envelope, command = plan.prepare_context_delete()
        self.assertEqual(command[8:], bytearray(range(16)))
        plan.accept_context_delete(acm.encode_envelope(1, 0, 0), b"")
        self.assertEqual(response, bytearray(17))
        self.assertEqual(bytes(command), bytes(24))
        self.assertEqual(acm.decode_envelope(envelope).payload_length, 24)

    def test_abort_scrubs_request_and_transport_stop_scrubs_context(self):
        plan = authorization.CredentialAuthorizationPlan()
        response = initialize_context(plan)
        initialize_aks(plan)
        plan.plan_verification(
            6, 3, keybag_handle=aks.SessionKeybagHandle(7),
            selector=aks.SessionKeybagSelector(-4))
        request = plan.consume_verification_secrets(
            identity(), bytearray(b"abc"), device_state_active=True)
        request_view = request.view()
        plan.abort()
        self.assertEqual(bytes(request_view), bytes(len(request_view)))
        self.assertEqual(response, bytearray(range(17)))
        plan.scrub_after_transport_stop()
        self.assertTrue(plan.closed)
        self.assertTrue(plan.failed)
        self.assertEqual(response, bytearray(17))

    def test_reordering_never_creates_an_authorized_context(self):
        plan = authorization.CredentialAuthorizationPlan()
        with self.assertRaises(authorization.CredentialAuthorizationError):
            plan.plan_verification(
                1, 1, keybag_handle=aks.SessionKeybagHandle(7),
                selector=aks.SessionKeybagSelector(-4))
        self.assertTrue(plan.failed)
        self.assertFalse(plan.authorized)
        self.assertNotIn("bytearray", repr(plan))
        plan.scrub_after_transport_stop()
        with self.assertRaises(authorization.CredentialAuthorizationError):
            plan.initialize_acm()

    def test_rejected_context_payload_is_scrubbed_before_failure(self):
        plan = authorization.CredentialAuthorizationPlan()
        plan.initialize_acm()
        plan.accept_acm_initialization(acm.encode_envelope(1, 0, 0), b"")
        plan.create_context()
        malformed = bytearray(range(16))
        with self.assertRaises(authorization.CredentialAuthorizationError):
            plan.accept_context(acm.encode_envelope(1, 16, 0), malformed)
        self.assertEqual(malformed, bytearray(16))
        self.assertTrue(plan.failed)

    def test_delete_with_pending_verification_aborts_and_scrubs_it(self):
        plan = authorization.CredentialAuthorizationPlan()
        initialize_context(plan)
        initialize_aks(plan)
        plan.plan_verification(
            6, 3, keybag_handle=aks.SessionKeybagHandle(7),
            selector=aks.SessionKeybagSelector(-4))
        request = plan.consume_verification_secrets(
            identity(), bytearray(b"abc"), device_state_active=False)
        request_view = request.view()
        plan.prepare_context_delete()
        self.assertTrue(plan.failed)
        self.assertFalse(plan.authorized)
        self.assertEqual(bytes(request_view), bytes(len(request_view)))
        with self.assertRaises(authorization.CredentialAuthorizationError):
            plan.accept_verification(
                bytes.fromhex("07a106000000600000000000"),
                protected(struct.pack("<IQ", 1, 0)))


if __name__ == "__main__":
    unittest.main()
