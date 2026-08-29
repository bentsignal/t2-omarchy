import importlib.util
from pathlib import Path
import sys
import unittest


SPEC = importlib.util.spec_from_file_location(
    "linux_auth_broker", Path(__file__).with_name("linux-auth-broker.py"))
broker = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = broker
SPEC.loader.exec_module(broker)


class LinuxAuthBrokerTests(unittest.TestCase):
    def request(self, request_id=7, user_id=501, timeout_ms=10_000):
        return broker.encode_verify_request(
            request_id=request_id, user_id=user_id, timeout_ms=timeout_ms)

    def peer(self, uid=0):
        return broker.PeerCredentials(pid=123, uid=uid, gid=0)

    def decision(self, matched, user_id=501):
        identity = None
        if matched:
            identity = broker.authentication.biometric.BiometricIdentity(
                user_id, bytes(range(16)))
        return broker.authentication.AuthenticationDecision(matched, identity)

    def test_exact_request_and_correlated_match_response(self):
        raw = self.request()
        self.assertEqual(len(raw), 24)
        self.assertEqual(broker.decode_verify_request(raw),
                         broker.VerifyRequest(7, 501, 10_000))
        operation = broker.BrokerAuthorization()
        self.assertEqual(operation.begin(
            raw, peer=self.peer(), now_ns=1_000),
            broker.VerifyRequest(7, 501, 10_000))
        response_raw = operation.complete(
            request_id=7, decision=self.decision(True), now_ns=2_000)
        response = broker.decode_verify_response(
            response_raw, expected_request_id=7)
        self.assertEqual(response, broker.VerifyResponse(7, broker.STATUS_MATCH))
        self.assertTrue(response.authenticated)
        with self.assertRaises(broker.BrokerProtocolError):
            operation.complete(
                request_id=7, decision=self.decision(True), now_ns=3_000)

    def test_explicit_no_match_never_authenticates(self):
        operation = broker.BrokerAuthorization()
        operation.begin(self.request(), peer=self.peer(), now_ns=0)
        raw = operation.complete(
            request_id=7, decision=self.decision(False), now_ns=1)
        response = broker.decode_verify_response(raw, expected_request_id=7)
        self.assertEqual(response.status, broker.STATUS_NO_MATCH)
        self.assertFalse(response.authenticated)

    def test_unprivileged_or_malformed_request_permanently_fails(self):
        malformed = (
            self.request(),
            self.request().replace(b"T2AU", b"FAIL", 1),
            self.request()[:-1],
        )
        peers = (self.peer(uid=1000), self.peer(), self.peer())
        for raw, peer in zip(malformed, peers):
            with self.subTest(raw=raw, peer=peer):
                operation = broker.BrokerAuthorization()
                with self.assertRaises(broker.BrokerProtocolError):
                    operation.begin(raw, peer=peer, now_ns=0)
                with self.assertRaises(broker.BrokerProtocolError):
                    operation.begin(self.request(), peer=self.peer(), now_ns=0)

    def test_request_encoder_rejects_ambiguous_scalars(self):
        cases = (
            dict(request_id=0, user_id=501, timeout_ms=1),
            dict(request_id=True, user_id=501, timeout_ms=1),
            dict(request_id=1, user_id=0xffffffff, timeout_ms=1),
            dict(request_id=1, user_id=True, timeout_ms=1),
            dict(request_id=1, user_id=501, timeout_ms=0),
            dict(request_id=1, user_id=501, timeout_ms=60_001),
        )
        for values in cases:
            with self.subTest(values=values):
                with self.assertRaises(broker.BrokerProtocolError):
                    broker.encode_verify_request(**values)

    def test_wrong_user_request_id_type_or_deadline_fails_closed(self):
        cases = (
            dict(request_id=8, decision=self.decision(True), now_ns=1),
            dict(request_id=7, decision=self.decision(True, 502), now_ns=1),
            dict(request_id=7, decision=object(), now_ns=1),
            dict(request_id=7,
                 decision=broker.authentication.AuthenticationDecision(
                     True, object()), now_ns=1),
            dict(request_id=7, decision=self.decision(True),
                 now_ns=10_000_000_001),
        )
        for values in cases:
            with self.subTest(values=values):
                operation = broker.BrokerAuthorization()
                operation.begin(self.request(), peer=self.peer(), now_ns=0)
                with self.assertRaises(broker.BrokerProtocolError):
                    operation.complete(**values)
                with self.assertRaises(broker.BrokerProtocolError):
                    operation.complete(
                        request_id=7, decision=self.decision(True), now_ns=1)

    def test_abort_is_correlated_error_and_response_parser_is_strict(self):
        operation = broker.BrokerAuthorization()
        operation.begin(self.request(), peer=self.peer(), now_ns=0)
        raw = operation.abort()
        self.assertEqual(
            broker.decode_verify_response(raw, expected_request_id=7).status,
            broker.STATUS_ERROR)
        mutations = (
            (raw, 8),
            (raw.replace(b"T2AU", b"FAIL", 1), 7),
            (raw[:-1], 7),
            (raw[:16] + (2).to_bytes(4, "little", signed=True) + raw[20:], 7),
        )
        for response, expected in mutations:
            with self.subTest(expected=expected):
                with self.assertRaises(broker.BrokerProtocolError):
                    broker.decode_verify_response(
                        response, expected_request_id=expected)


if __name__ == "__main__":
    unittest.main()
