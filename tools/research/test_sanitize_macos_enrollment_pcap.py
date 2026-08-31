import importlib.util
import json
from pathlib import Path
import plistlib
import struct
import sys
import tempfile
import unittest


MODULE_PATH = Path(__file__).with_name("sanitize-macos-enrollment-pcap.py")
SPEC = importlib.util.spec_from_file_location(
    "sanitize_macos_enrollment_pcap", MODULE_PATH
)
sanitizer = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = sanitizer
SPEC.loader.exec_module(sanitizer)


HOST = bytes.fromhex("fe800000000000000000000000000001")
T2 = bytes.fromhex("fe80000000000000aede48fffe334455")


def bridge_frame(kind, value):
    if kind == 1:
        body = json.dumps(value, separators=(",", ":")).encode()
    else:
        body = plistlib.dumps(value, fmt=plistlib.FMT_BINARY, sort_keys=False)
    return struct.pack("<HHIQ", 0xB892, 1, kind, len(body)) + body


def tcp_packet(source, destination, source_port, destination_port, sequence, payload):
    ethernet = bytes.fromhex("acde48001122acde4833445586dd")
    tcp = struct.pack(
        "!HHIIHHHH",
        source_port,
        destination_port,
        sequence,
        0,
        (5 << 12) | 0x18,
        0,
        0,
        0,
    ) + payload
    ipv6 = bytes.fromhex("60000000") + struct.pack("!HBB", len(tcp), 6, 64)
    return ethernet + ipv6 + source + destination + tcp


def pcap(records):
    result = bytearray(
        bytes.fromhex("d4c3b2a1") + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1)
    )
    for packet in records:
        result += struct.pack("<IIII", 0, 0, len(packet), len(packet)) + packet
    return bytes(result)


class EnrollmentPcapSanitizerTests(unittest.TestCase):
    def fixture(self):
        reply_id = "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"
        secret = b"DO-NOT-LEAK-1234"
        enrollment = struct.pack("<4I", 0, 501, 0, 16) + secret + bytes(16) + bytes(20)
        inner = struct.pack("<HHHH", 0x4D42, 3, 2, 0) + enrollment
        host_stream = bridge_frame(
            1,
            {
                "MaxSupportedProtocolVersion": 1,
                "OSBuild": "25G83",
                "BridgeXPCVersion": 39,
                "ProcessName": "biometrickitd",
            },
        ) + bridge_frame(2, [1, False, reply_id, [3, 0, inner, 0]])
        t2_stream = bridge_frame(
            1,
            {
                "MaxSupportedProtocolVersion": 1,
                "OSBuild": "23P6068",
                "BridgeXPCVersion": 39,
                "ProcessName": "bkremoted",
            },
        ) + bridge_frame(
            2,
            [1, True, reply_id, [22, sanitizer.NIL_OUTPUT_SENTINEL]],
        )
        records = [
            tcp_packet(HOST, T2, 49152, 59602, 100, host_stream),
            tcp_packet(T2, HOST, 59602, 49152, 900, t2_stream),
        ]
        return pcap(records), secret, reply_id

    def test_redacts_credential_and_reply_identifier(self):
        capture, secret, reply_id = self.fixture()
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "private.pcap"
            path.write_bytes(capture)
            result = sanitizer.sanitize(path)
        self.assertEqual(result["connection_count"], 1)
        command = result["connections"][0]["commands"][0]
        self.assertEqual(command["command"], "0x03")
        self.assertEqual(command["reply_status"], 22)
        self.assertEqual(command["input_length"], 68)
        self.assertTrue(command["enrollment"]["credential_present"])
        self.assertTrue(command["enrollment"]["credential_padding_zero"])
        rendered = repr(result)
        self.assertNotIn(secret.hex(), rendered)
        self.assertNotIn(secret.decode(), rendered)
        self.assertNotIn(reply_id, rendered)
        self.assertNotIn("fe80", rendered)

    def test_infers_directions_when_helo_predates_capture(self):
        reply_id = "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"
        secret = b"DO-NOT-LEAK-1234"
        enrollment = struct.pack("<4I", 0, 501, 0, 16) + secret + bytes(16)
        inner = struct.pack("<HHHH", 0x4D42, 3, 1, 0) + enrollment
        host_stream = bridge_frame(2, [1, False, reply_id, [3, 0, inner, 0]])
        t2_stream = bridge_frame(
            2,
            [1, True, reply_id, [0, sanitizer.NIL_OUTPUT_SENTINEL]],
        )
        capture = pcap(
            [
                tcp_packet(HOST, T2, 49152, 59602, 100, host_stream),
                tcp_packet(T2, HOST, 59602, 49152, 900, t2_stream),
            ]
        )
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "private.pcap"
            path.write_bytes(capture)
            result = sanitizer.sanitize(path)
        self.assertEqual(result["connection_count"], 1)
        command = result["connections"][0]["commands"][0]
        self.assertEqual(command["reply_status"], 0)
        rendered = repr(result)
        self.assertNotIn(secret.decode(), rendered)
        self.assertNotIn(reply_id, rendered)
        self.assertNotIn("fe80", rendered)

    def test_rejects_disagreeing_tcp_retransmission(self):
        capture, _secret, _reply_id = self.fixture()
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "private.pcap"
            data = bytearray(capture)
            # Append a packet at the host stream's original sequence with
            # conflicting bytes; the sanitizer must not choose one silently.
            conflict = tcp_packet(HOST, T2, 49152, 59602, 100, b"not-the-frame")
            data += struct.pack("<IIII", 0, 0, len(conflict), len(conflict)) + conflict
            path.write_bytes(data)
            with self.assertRaisesRegex(sanitizer.SanitizerError, "retransmission"):
                sanitizer.sanitize(path)

    def test_accepts_fully_contained_identical_retransmission(self):
        self.assertEqual(
            sanitizer._reassemble([(100, b"abcdef"), (102, b"cd")]),
            b"abcdef",
        )

    def test_event_summary_never_returns_payload(self):
        raw = struct.pack("<QIIQ", 0, 0xE3FF800A, 1, 9)
        raw += struct.pack("<IH", 501, 0x15) + b"PRIVATE"
        event = sanitizer._event_summary([9, 0xE3FF8000, raw, 0, 0])
        self.assertEqual(
            event,
            {
                "type": "0xe3ff800a",
                "version": 1,
                "ordinal": 0,
                "payload_length": 13,
            },
        )
        self.assertNotIn("PRIVATE", repr(event))


if __name__ == "__main__":
    unittest.main()
