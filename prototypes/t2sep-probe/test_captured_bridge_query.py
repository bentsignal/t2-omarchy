import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest import mock
import uuid


SPEC = importlib.util.spec_from_file_location(
    "captured_bridge_query", Path(__file__).with_name("captured-bridge-query.py"))
query = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = query
SPEC.loader.exec_module(query)
rsd = query.rsd


def transcript(port=49165):
    message = rsd.encode_xpc_message({
        "MessageType": "Handshake",
        "MessagingProtocolVersion": rsd.Int64(3),
        "Properties": {},
        "Services": {query.rsd_query.BIOMETRIC_SERVICE: {
            "Port": str(port), "Properties": {"UsesRemoteXPC": False}}},
        "UUID": uuid.UUID(int=1),
    }, message_id=0)
    return (rsd.encode_http2_frame(rsd.HTTP2_SETTINGS, 0, 0,
                                   struct.pack("!HI", 3, 100))
            + rsd.encode_http2_frame(rsd.HTTP2_DATA, 0,
                                     rsd.ROOT_CHANNEL, message))


def write_capture(directory: str, *, port=49165, wire=None):
    wire = transcript(port) if wire is None else wire
    path = Path(directory) / "capture.json"
    path.write_text(json.dumps({
        "advertised_port": port,
        "server_transcript_hex": wire.hex(),
        "server_transcript_sha256": hashlib.sha256(wire).hexdigest(),
        "validation_error": None,
    }))
    path.chmod(0o600)
    return path


class CapturedBridgeQueryTests(unittest.TestCase):
    def test_independently_recovers_only_transcript_port(self):
        with tempfile.TemporaryDirectory() as directory:
            path = write_capture(directory)
            port, wire = query.validate_capture(path)
            self.assertEqual(port, 49165)
            self.assertEqual(wire, transcript())

    def test_rejects_tamper_permissions_and_failed_capture(self):
        with tempfile.TemporaryDirectory() as directory:
            path = write_capture(directory)
            payload = json.loads(path.read_text())
            cases = []
            payload["advertised_port"] = 49166
            cases.append(dict(payload))
            payload["advertised_port"] = 49165
            payload["server_transcript_sha256"] = "0" * 64
            cases.append(dict(payload))
            payload["server_transcript_sha256"] = hashlib.sha256(transcript()).hexdigest()
            payload["validation_error"] = "failed"
            cases.append(dict(payload))
            for index, value in enumerate(cases):
                candidate = Path(directory) / f"bad-{index}.json"
                candidate.write_text(json.dumps(value))
                candidate.chmod(0o600)
                with self.assertRaises(query.CapturedBridgeError):
                    query.validate_capture(candidate)
            path.chmod(0o644)
            with self.assertRaisesRegex(query.CapturedBridgeError, "permissions"):
                query.validate_capture(path)

    def test_live_gate_precedes_capture_and_socket(self):
        self.assertFalse(query.LIVE_CAPTURED_BRIDGE_QUERY_ENABLED)
        with mock.patch.object(query, "validate_capture") as validate:
            with mock.patch.object(query.socket, "socket") as constructor:
                with self.assertRaisesRegex(query.CapturedBridgeError, "disabled"):
                    query.live_query(Path("capture"), "t2", 2)
        validate.assert_not_called()
        constructor.assert_not_called()


if __name__ == "__main__":
    unittest.main()
