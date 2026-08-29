import importlib.util
from pathlib import Path
import socket
import struct
import sys
import unittest


PATH = Path(__file__).with_name("linux-auth-broker-server.py")
SPEC = importlib.util.spec_from_file_location("broker_server_tested", PATH)
assert SPEC and SPEC.loader
server = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = server
SPEC.loader.exec_module(server)


class FakeConnection:
    def __init__(self, raw, *, peer=(123, 0, 0), flags=0):
        self.raw = raw
        self.peer = peer
        self.flags = flags
        self.timeout = None
        self.sent = []

    def recvmsg(self, size, ancillary, flags):
        return self.raw[:size], [], self.flags, None

    def getsockopt(self, level, option, size):
        return struct.pack("3i", *self.peer)

    def settimeout(self, timeout):
        self.timeout = timeout

    def sendall(self, raw):
        self.sent.append(raw)


class LinuxAuthBrokerServerTests(unittest.TestCase):
    def request(self, request_id=9):
        return server.broker.encode_verify_request(
            request_id=request_id, user_id=501, timeout_ms=5_000)

    def decision(self, matched=True):
        identity = None
        if matched:
            identity = server.broker.authentication.biometric.BiometricIdentity(
                501, bytes(range(16)))
        return server.broker.authentication.AuthenticationDecision(matched, identity)

    def test_root_peer_exact_match_gets_correlated_success(self):
        connection = FakeConnection(self.request())
        status = server.serve_connection(
            connection, lambda request: self.decision(), now_ns=iter((1, 2)).__next__)
        self.assertEqual(status, server.broker.STATUS_MATCH)
        self.assertEqual(connection.timeout, 5.0)
        reply = server.broker.decode_verify_response(
            connection.sent[0], expected_request_id=9)
        self.assertTrue(reply.authenticated)

    def test_no_match_and_matcher_failure_never_authenticate(self):
        for matcher, expected in (
                (lambda request: self.decision(False), server.broker.STATUS_NO_MATCH),
                (lambda request: (_ for _ in ()).throw(RuntimeError("hardware")),
                 server.broker.STATUS_ERROR)):
            with self.subTest(expected=expected):
                connection = FakeConnection(self.request())
                status = server.serve_connection(
                    connection, matcher, now_ns=iter((1, 2)).__next__)
                self.assertEqual(status, expected)
                reply = server.broker.decode_verify_response(
                    connection.sent[0], expected_request_id=9)
                self.assertFalse(reply.authenticated)

    def test_unprivileged_truncated_or_oversized_request_has_no_reply(self):
        cases = (
            FakeConnection(self.request(), peer=(123, 1000, 1000)),
            FakeConnection(self.request()[:-1]),
            FakeConnection(self.request(), flags=socket.MSG_TRUNC),
        )
        for connection in cases:
            with self.subTest(connection=connection):
                with self.assertRaises(server.BrokerServerError):
                    server.serve_connection(
                        connection, lambda request: self.decision(), now_ns=lambda: 1)
                self.assertEqual(connection.sent, [])

    def test_wrong_user_decision_becomes_correlated_error(self):
        connection = FakeConnection(self.request())
        bad = server.broker.authentication.AuthenticationDecision(
            True, server.broker.authentication.biometric.BiometricIdentity(
                502, bytes(range(16))))
        status = server.serve_connection(
            connection, lambda request: bad, now_ns=iter((1, 2)).__next__)
        self.assertEqual(status, server.broker.STATUS_ERROR)
        self.assertEqual(server.broker.decode_verify_response(
            connection.sent[0], expected_request_id=9).status,
            server.broker.STATUS_ERROR)


if __name__ == "__main__":
    unittest.main()
