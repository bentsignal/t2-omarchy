import importlib.util
import io
import json
from pathlib import Path
import struct
import sys
import unittest
from unittest import mock
import uuid


MODULE_PATH = Path(__file__).with_name("rsd-query.py")
SPEC = importlib.util.spec_from_file_location("rsd_query", MODULE_PATH)
query = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = query
SPEC.loader.exec_module(query)
protocol = query.protocol


class FakeSocket:
    def __init__(self, incoming: bytes, *, chunk_size=7):
        self.incoming = bytearray(incoming)
        self.chunk_size = chunk_size
        self.sent = []

    def recv(self, size):
        if not self.incoming:
            return b""
        count = min(size, self.chunk_size, len(self.incoming))
        result = bytes(self.incoming[:count])
        del self.incoming[:count]
        return result

    def sendall(self, data):
        self.sent.append(data)


def directory_message(port="52032"):
    return protocol.encode_xpc_message({
        "MessageType": "Handshake",
        "MessagingProtocolVersion": protocol.Int64(3),
        "Properties": {"BuildVersion": "23J631"},
        "Services": {
            query.BIOMETRIC_SERVICE: {
                "Port": port,
                "Properties": {"UsesRemoteXPC": False},
            }
        },
        "UUID": uuid.UUID(int=1),
    }, message_id=0)


def valid_server_transcript(port="52032"):
    message = directory_message(port)
    return b"".join((
        protocol.encode_http2_frame(protocol.HTTP2_WINDOW_UPDATE, 0, 0,
                                    struct.pack(">I", 4096)),
        protocol.encode_http2_frame(protocol.HTTP2_SETTINGS, 0, 0,
                                    struct.pack(">HI", 3, 100)),
        protocol.encode_http2_frame(protocol.HTTP2_SETTINGS,
                                    protocol.HTTP2_ACK, 0),
        protocol.encode_http2_frame(protocol.HTTP2_DATA, 0,
                                    protocol.ROOT_CHANNEL, message[:31]),
        protocol.encode_http2_frame(protocol.HTTP2_DATA, 0,
                                    protocol.ROOT_CHANNEL, message[31:]),
    ))


class RSDQueryTests(unittest.TestCase):
    def test_fragmented_passive_query_sequence(self):
        identifier = uuid.UUID(int=2)
        incoming = valid_server_transcript()
        sock = FakeSocket(incoming, chunk_size=1)
        capture = query.capture_connected_socket(sock, identifier)
        self.assertEqual(capture.advertised_port, 52032)
        self.assertEqual(capture.server_transcript, incoming)
        self.assertEqual(sock.incoming, b"")
        self.assertEqual(sock.sent, [
            protocol.candidate_rsd_transport_opening(),
            protocol.candidate_rsd_settings_ack(),
            protocol.candidate_rsd_device_handshake(identifier),
        ])

    def test_port_only_wrapper_preserves_existing_api(self):
        self.assertEqual(query.query_connected_socket(
            FakeSocket(valid_server_transcript()), uuid.UUID(int=2)), 52032)

    def test_never_sends_device_handshake_before_peer_settings(self):
        sock = FakeSocket(protocol.encode_http2_frame(
            protocol.HTTP2_WINDOW_UPDATE, 0, 0, struct.pack(">I", 1)
        ))
        with self.assertRaises(query.QueryError):
            query.query_connected_socket(sock, uuid.UUID(int=0))
        self.assertEqual(sock.sent, [protocol.candidate_rsd_transport_opening()])

    def test_rejects_eof_oversize_and_malformed_directory(self):
        oversized = (query.FRAME_CAP + 1).to_bytes(3, "big") + b"\0" * 6
        malformed = valid_server_transcript(port="0")
        for incoming in (b"", b"\0" * 8, oversized, malformed):
            with self.subTest(incoming=incoming[:16].hex()):
                with self.assertRaises(query.QueryError):
                    query.query_connected_socket(FakeSocket(incoming),
                                                 uuid.UUID(int=0))

    def test_rejects_invalid_client_uuid(self):
        with self.assertRaises(query.QueryError):
            query.query_connected_socket(FakeSocket(b""), "not-a-uuid")

    def test_live_gate_precedes_interface_and_socket_work(self):
        self.assertFalse(query.LIVE_DIRECTORY_CAPTURE_ENABLED)
        self.assertEqual(query.CURRENT_T2_ADDRESS_VERIFICATION[0],
                         "fe80::aede:48ff:fe33:4455")
        self.assertEqual(query.SAME_BOOT_DIRECTORY_PORT_VERIFICATION[0], 59602)
        self.assertTrue(query.SAME_BOOT_DIRECTORY_PORT_VERIFICATION[1])
        with mock.patch.object(query, "verify_t2_interface") as verify:
            with mock.patch.object(query.socket, "socket") as socket_constructor:
                with self.assertRaisesRegex(query.QueryError, "disabled"):
                    query.live_query("enp4s0f1u1", 2.0)
        verify.assert_not_called()
        socket_constructor.assert_not_called()

    def test_live_query_is_only_a_capture_wrapper(self):
        capture = query.PassiveDirectoryCapture(49152, b"evidence")
        with mock.patch.object(query, "live_capture", return_value=capture) as live:
            self.assertEqual(query.live_query("t2", 1.0), 49152)
        live.assert_called_once_with("t2", 1.0)

    def test_private_capture_is_exclusive_and_self_verifying(self):
        capture = query.PassiveDirectoryCapture(49165, b"private transcript")
        with self.subTest("new file"):
            import tempfile
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "capture.json"
                query.write_capture(path, capture)
                payload = json.loads(path.read_text())
                self.assertEqual(payload["advertised_port"], 49165)
                self.assertEqual(bytes.fromhex(payload["server_transcript_hex"]),
                                 capture.server_transcript)
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                self.assertIsNone(payload["validation_error"])
                with self.assertRaises(query.QueryError):
                    query.write_capture(path, capture)

    def test_parser_failure_retains_bounded_transcript(self):
        settings = protocol.encode_http2_frame(protocol.HTTP2_SETTINGS, 0, 0)
        malformed = protocol.encode_xpc_message(
            {"unexpected": "data"}, message_id=0,
            flags=protocol.XPC_ALWAYS_SET)
        data = protocol.encode_http2_frame(
            protocol.HTTP2_DATA, 0, protocol.ROOT_CHANNEL, malformed)
        with self.assertRaises(query.PartialCaptureError) as caught:
            query.capture_connected_socket(
                FakeSocket(settings + data), uuid.UUID(int=2))
        self.assertEqual(caught.exception.server_transcript, settings + data)

    def test_malformed_live_verification_still_precedes_all_io(self):
        for malformed in ("yes", (), ("address", 59602, "evidence"),
                          (protocol.T2_LINK_LOCAL_ADDRESS_CANDIDATE, "", "")):
            with self.subTest(malformed=malformed):
                with mock.patch.object(query, "LIVE_DIRECTORY_CAPTURE_ENABLED", True):
                    with mock.patch.object(query, "CURRENT_T2_ADDRESS_VERIFICATION",
                                           malformed):
                        with mock.patch.object(query, "verify_t2_interface") as verify:
                            with mock.patch.object(query.socket, "socket") as constructor:
                                with self.assertRaisesRegex(query.QueryError, "malformed"):
                                    query.live_query("enp4s0f1u1", 2.0)
                verify.assert_not_called()
                constructor.assert_not_called()

    def test_bad_timeout_with_valid_gate_still_precedes_all_io(self):
        verified = (protocol.T2_LINK_LOCAL_ADDRESS_CANDIDATE, "fixture evidence")
        for timeout in (0, -1, 6, float("inf"), float("nan"), True, "2"):
            with self.subTest(timeout=timeout):
                with mock.patch.object(query, "CURRENT_T2_ADDRESS_VERIFICATION",
                                       verified):
                    with mock.patch.object(query, "LIVE_DIRECTORY_CAPTURE_ENABLED", True):
                        with mock.patch.object(
                                query, "SAME_BOOT_DIRECTORY_PORT_VERIFICATION",
                                (59602, "same-boot fixture evidence")):
                            with mock.patch.object(query, "verify_t2_interface") as verify:
                                with mock.patch.object(query.socket, "socket") as constructor:
                                    with self.assertRaisesRegex(query.QueryError, "timeout"):
                                        query.live_query("enp4s0f1u1", timeout)
                verify.assert_not_called()
                constructor.assert_not_called()

    def test_malformed_verified_port_still_precedes_all_io(self):
        address = (protocol.T2_LINK_LOCAL_ADDRESS_CANDIDATE, "fixture evidence")
        for malformed in (None, (), (59602, ""), (0, "evidence"),
                          (65536, "evidence"), (True, "evidence")):
            with self.subTest(malformed=malformed):
                with mock.patch.object(query, "CURRENT_T2_ADDRESS_VERIFICATION", address):
                    with mock.patch.object(query, "LIVE_DIRECTORY_CAPTURE_ENABLED", True):
                        with mock.patch.object(query, "SAME_BOOT_DIRECTORY_PORT_VERIFICATION",
                                               malformed):
                            with mock.patch.object(query, "verify_t2_interface") as verify:
                                with mock.patch.object(query.socket, "socket") as constructor:
                                    with self.assertRaisesRegex(query.QueryError, "malformed"):
                                        query.live_query("enp4s0f1u1", 2.0)
                verify.assert_not_called()
                constructor.assert_not_called()

    def test_default_main_is_offline(self):
        with mock.patch.object(sys, "argv", ["rsd-query.py"]):
            with mock.patch.object(query.socket, "socket") as socket_constructor:
                with mock.patch("sys.stdout", new_callable=io.StringIO) as output:
                    query.main()
        socket_constructor.assert_not_called()
        self.assertIn("offline only", output.getvalue())

    def test_interface_name_rejects_path_traversal_before_sysfs(self):
        for name in ("", "../eth0", "/tmp/x", "bad name", None):
            with self.assertRaises(query.QueryError):
                query.verify_t2_interface(name)


if __name__ == "__main__":
    unittest.main()
