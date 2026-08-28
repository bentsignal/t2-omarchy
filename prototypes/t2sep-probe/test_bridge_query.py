import importlib.util
from pathlib import Path
import plistlib
import sys
import unittest
from unittest import mock


MODULE_PATH = Path(__file__).with_name("bridge-query.py")
SPEC = importlib.util.spec_from_file_location("bridge_query", MODULE_PATH)
query = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = query
SPEC.loader.exec_module(query)


class FakeSocket:
    def __init__(self, incoming, chunk=7):
        self.incoming = bytearray(incoming)
        self.chunk = chunk
        self.sent = bytearray()
        self.events = []

    def recv(self, size):
        self.events.append("recv")
        size = min(size, self.chunk, len(self.incoming))
        result = self.incoming[:size]
        del self.incoming[:size]
        return bytes(result)

    def sendall(self, data):
        self.events.append("send")
        self.sent.extend(data)


def frame(kind, body):
    return query.protocol.encode_frame_header(kind, len(body)) + body


class PassiveQueryTests(unittest.TestCase):
    def test_live_path_is_disabled_pending_current_port_evidence(self):
        with mock.patch.object(query, "verify_t2_interface") as verify:
            with mock.patch.object(query.socket, "socket") as constructor:
                with self.assertRaisesRegex(query.QueryError, "current bridgeOS"):
                    query.live_query("does-not-matter", 1.0)
        verify.assert_not_called()
        constructor.assert_not_called()

    def test_accepts_peer_helo_then_one_version_reply(self):
        reply = plistlib.dumps([0, 42], fmt=plistlib.FMT_BINARY)
        peer_helo = query.protocol.encode_helo_frame(
            "19H15", 37.0, "peer", max_body=query.BODY_CAP
        )[query.protocol.BRIDGE_FRAME_HEADER.size:]
        incoming = (frame(query.protocol.FRAME_HELO, peer_helo)
                    + frame(query.protocol.FRAME_MESSAGE, reply))
        sock = FakeSocket(incoming)
        self.assertEqual(query.query_connected_socket(sock), (0, 42))
        first = query.protocol.decode_frame_header(bytes(sock.sent[:16]),
                                                   max_body=query.BODY_CAP)
        self.assertEqual(first.kind, query.protocol.FRAME_HELO)
        self.assertEqual(sock.events[:2], ["send", "send"])

    def test_handles_noop_and_fragmented_reads(self):
        reply = plistlib.dumps([-1, 0], fmt=plistlib.FMT_BINARY)
        incoming = (frame(query.protocol.FRAME_NOOP, b"")
                    + frame(query.protocol.FRAME_MESSAGE, reply))
        self.assertEqual(query.query_connected_socket(FakeSocket(incoming, 1)),
                         (-1, 0))

    def test_rejects_eof_malformed_reply_and_frame_flood(self):
        with self.assertRaises(query.QueryError):
            query.query_connected_socket(FakeSocket(b""))
        malformed = frame(query.protocol.FRAME_MESSAGE, b"bad")
        with self.assertRaises(query.protocol.BridgeProtocolError):
            query.query_connected_socket(FakeSocket(malformed))
        noops = frame(query.protocol.FRAME_NOOP, b"") * 4
        with self.assertRaises(query.QueryError):
            query.query_connected_socket(FakeSocket(noops))

    def test_rejects_malformed_peer_helo(self):
        incoming = frame(query.protocol.FRAME_HELO, b'{"peer":1}')
        with self.assertRaises(query.protocol.BridgeProtocolError):
            query.query_connected_socket(FakeSocket(incoming))

    def test_malformed_gate_and_timeout_precede_io(self):
        malformed = (query.protocol.BIOMETRIC_KIT_PORT, "")
        with mock.patch.object(query, "CURRENT_PORT_VERIFICATION", malformed):
            with mock.patch.object(query, "verify_t2_interface") as verify:
                with mock.patch.object(query.socket, "socket") as constructor:
                    with self.assertRaisesRegex(query.QueryError, "malformed"):
                        query.live_query("enp4s0f1u1", 2.0)
        verify.assert_not_called()
        constructor.assert_not_called()

        verified = (query.protocol.BIOMETRIC_KIT_PORT, "fixture evidence")
        for timeout in (0, 6, float("inf"), float("nan"), True, "2"):
            with self.subTest(timeout=timeout):
                with mock.patch.object(query, "CURRENT_PORT_VERIFICATION", verified):
                    with mock.patch.object(query, "verify_t2_interface") as verify:
                        with mock.patch.object(query.socket, "socket") as constructor:
                            with self.assertRaisesRegex(query.QueryError, "timeout"):
                                query.live_query("enp4s0f1u1", timeout)
                verify.assert_not_called()
                constructor.assert_not_called()

    def test_interface_name_rejects_path_traversal(self):
        for name in ("", "../eth0", "/tmp/x", "bad name", None):
            with self.assertRaises(query.QueryError):
                query.verify_t2_interface(name)


if __name__ == "__main__":
    unittest.main()
