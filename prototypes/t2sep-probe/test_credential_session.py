import importlib.util
from pathlib import Path
import struct
import sys
import unittest


SPEC = importlib.util.spec_from_file_location(
    "credential_session", Path(__file__).with_name("credential-session.py"))
session_module = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = session_module
SPEC.loader.exec_module(session_module)
acm = session_module.authorization.acm
aks = session_module.authorization.aks


def control_reply(request, target):
    return [(request[0] & 0xff00) | 1 << 16 | target << 24, 0, 0, 0]


def ready_session():
    state = session_module.CredentialSession()
    requests = state.registration_requests(
        0x100000, 0x200000, 0x300000, 0x400000)
    targets = (session_module.bootstrap.AKS.endpoint,) * 2 + (
        session_module.bootstrap.ACM.endpoint,) * 2
    state.accept_registration_replies(
        *(control_reply(request, target)
          for request, target in zip(requests, targets)))
    return state


def identity():
    return aks.build_identity_header(
        2, continuous_usec=7, process_unique_id=0,
        audit_session_id=0, cdhash=bytes(20), calendar_seconds=9)


def protected(payload, version=2):
    return struct.pack("<I", 0x50) + aks.protect_header(
        identity() if version == 2 else aks.build_identity_header(
            1, continuous_usec=7, process_unique_id=0,
            audit_session_id=0, cdhash=bytes(20)), payload) + payload


class CredentialSessionTests(unittest.TestCase):
    def test_authorization_cannot_mutate_before_dual_registration(self):
        state = session_module.CredentialSession()
        with self.assertRaises(session_module.CredentialSessionError):
            state.initialize_acm()
        self.assertFalse(state.failed)
        requests = state.registration_requests(
            0x100000, 0x200000, 0x300000, 0x400000)
        targets = (7, 7, 10, 10)
        state.accept_registration_replies(
            *(control_reply(request, target)
              for request, target in zip(requests, targets)))
        state.initialize_acm()

    def test_active_exchange_blocks_parallel_work_and_global_shutdown(self):
        state = ready_session()
        state.initialize_acm()
        with self.assertRaises(session_module.CredentialSessionError):
            state.request_aks_capabilities(4)
        with self.assertRaises(session_module.CredentialSessionError):
            state.abort_and_shutdown()
        self.assertFalse(state.bootstrap.aks.ownership.transport_stopped)
        self.assertFalse(state.bootstrap.acm.ownership.transport_stopped)
        self.assertEqual(state.bootstrap.acm.ownership.operations, 1)

    def test_full_authorization_delete_and_shutdown(self):
        state = ready_session()
        state.initialize_acm()
        state.accept_acm_initialization(acm.encode_envelope(1, 0, 0), b"")
        state.create_context()
        context = bytearray(range(21))
        state.accept_context(acm.encode_envelope(1, 21, 0), context)

        state.request_aks_capabilities(4)
        capabilities = protected(struct.pack("<iQI", 0, 2, 0), 1)
        state.accept_aks_capabilities(
            bytes.fromhex("07cd04000000640000000000"), capabilities)
        state.request_aks_environment(5)
        state.accept_aks_environment(
            bytes.fromhex("07aa05000000580000000000"),
            protected(struct.pack("<i", 0)))
        state.plan_verification(
            6, 3, keybag_handle=aks.SessionKeybagHandle(7),
            selector=aks.SessionKeybagSelector(-4))
        request = state.consume_verification_secrets(
            identity(), bytearray(b"abc"), device_state_active=False)
        request_view = request.view()
        state.accept_verification(
            bytes.fromhex("07a106000000600000000000"),
            protected(struct.pack("<IQ", 1, 0x82)))
        self.assertTrue(state.authorized)
        self.assertEqual(bytes(request_view), bytes(len(request_view)))

        enroll = state.build_builtin_enrollment_request(501)
        enroll_view = enroll.view()
        self.assertEqual(len(enroll_view), 68)
        self.assertEqual(enroll_view[16:32], bytes(range(16)))
        state.finish_builtin_enrollment_request(enroll)
        self.assertEqual(bytes(enroll_view), bytes(68))

        state.prepare_context_delete()
        state.accept_context_delete(acm.encode_envelope(1, 0, 0), b"")
        tokens = state.shutdown()
        self.assertEqual(
            tokens, ("acm-receive", "acm-send", "aks-receive", "aks-send"))
        self.assertTrue(state.closed)
        self.assertEqual(context, bytearray(21))

    def test_live_context_requires_delete_or_explicit_abort_shutdown(self):
        state = ready_session()
        state.initialize_acm()
        state.accept_acm_initialization(acm.encode_envelope(1, 0, 0), b"")
        state.create_context()
        context = bytearray(range(21))
        state.accept_context(acm.encode_envelope(1, 21, 0), context)
        with self.assertRaises(session_module.CredentialSessionError):
            state.shutdown()
        self.assertFalse(state.bootstrap.aks.ownership.transport_stopped)
        state.abort_and_shutdown()
        self.assertTrue(state.closed)
        self.assertTrue(state.failed)
        self.assertEqual(context, bytearray(21))

    def test_malformed_reply_drains_operation_before_fail_closed_cleanup(self):
        state = ready_session()
        state.request_aks_capabilities(4)
        with self.assertRaises(session_module.authorization.CredentialAuthorizationError):
            state.accept_aks_capabilities(
                bytes.fromhex("07cd05000000640000000000"),
                protected(struct.pack("<iQI", 0, 2, 0), 1))
        self.assertEqual(state.bootstrap.aks.ownership.operations, 0)
        self.assertTrue(state.failed)
        state.abort_and_shutdown()
        self.assertTrue(state.closed)


if __name__ == "__main__":
    unittest.main()
