import importlib.util
from pathlib import Path
import struct
import sys
import unittest
import uuid


MODULE_PATH = Path(__file__).with_name("rsd-protocol.py")
SPEC = importlib.util.spec_from_file_location("rsd_protocol", MODULE_PATH)
rsd = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = rsd
SPEC.loader.exec_module(rsd)


class XPCCodecTests(unittest.TestCase):
    def test_exact_empty_dictionary_wrapper(self):
        encoded = rsd.encode_xpc_message({}, message_id=0)
        self.assertEqual(
            encoded.hex(),
            "920bb029010000001400000000000000000000000000000042371342"
            "0500000000f000000400000000000000",
        )
        decoded = rsd.decode_xpc_message(encoded)
        self.assertEqual(decoded.flags, rsd.XPC_ALWAYS_SET)
        self.assertEqual(decoded.message_id, 0)
        self.assertEqual(decoded.value, {})

    def test_supported_types_round_trip(self):
        identifier = uuid.UUID("00112233-4455-6677-8899-aabbccddeeff")
        value = {
            "string": "value",
            "unsigned": rsd.UInt64(0xFEDCBA9876543210),
            "signed": rsd.Int64(-5),
            "boolean": True,
            "uuid": identifier,
            "data": b"abc",
            "array": ["feature", rsd.UInt64(2)],
            "nested": {"nil": None},
        }
        encoded = rsd.encode_xpc_message(value, message_id=9)
        self.assertEqual(rsd.decode_xpc_message(encoded).value, value)

    def test_rejects_unsupported_and_invalid_encoder_inputs(self):
        for value in ({"x": 1}, {"": "x"}, {"x": 1.5}):
            with self.assertRaises(rsd.RSDProtocolError):
                rsd.encode_xpc_message(value, message_id=0)
        for bad in (-1, 1 << 64, True):
            with self.assertRaises(rsd.RSDProtocolError):
                rsd.encode_xpc_message({}, message_id=bad)
        with self.assertRaises(rsd.RSDProtocolError):
            rsd.UInt64(-1)
        with self.assertRaises(rsd.RSDProtocolError):
            rsd.encode_xpc_message({}, message_id=0, max_body=1)

    def test_wrapper_fails_closed(self):
        good = rsd.encode_xpc_message({"x": "y"}, message_id=3)
        mutations = [
            b"",
            b"bad!" + good[4:],
            good[:8] + (1).to_bytes(8, "little") + good[16:],
            good + b"surplus",
            good[:-1],
        ]
        for bad in mutations:
            with self.subTest(bad=bad[:16].hex()):
                with self.assertRaises(rsd.RSDProtocolError):
                    rsd.decode_xpc_message(bad)
        with self.assertRaises(rsd.RSDProtocolError):
            rsd.decode_xpc_message(good, max_body=8)

    def test_rejects_duplicate_keys_and_noncanonical_boolean(self):
        encoded = bytearray(rsd.encode_xpc_message({"a": True, "b": False}, message_id=0))
        encoded[52] = ord("a")
        with self.assertRaises(rsd.RSDProtocolError):
            rsd.decode_xpc_message(bytes(encoded))

        encoded = bytearray(rsd.encode_xpc_message({"a": True}, message_id=0))
        encoded[-4:] = struct.pack("<I", 2)
        with self.assertRaises(rsd.RSDProtocolError):
            rsd.decode_xpc_message(bytes(encoded))

    def test_depth_cap(self):
        value = {}
        for _ in range(rsd.MAX_PROTOCOL_DEPTH + 2):
            value = {"x": value}
        with self.assertRaises(rsd.RSDProtocolError):
            rsd.encode_xpc_message(value, message_id=0)


class HTTP2CodecTests(unittest.TestCase):
    def test_exact_frame_and_round_trip(self):
        encoded = rsd.encode_http2_frame(rsd.HTTP2_DATA, 1, 3, b"abc")
        self.assertEqual(encoded.hex(), "000003000100000003616263")
        self.assertEqual(rsd.decode_http2_frame(encoded), (0, 1, 3, b"abc"))

    def test_frame_fails_closed(self):
        good = rsd.encode_http2_frame(rsd.HTTP2_DATA, 0, 1, b"x")
        for bad in (b"", good[:-1], good + b"x",
                    good[:5] + (0x80000001).to_bytes(4, "big") + good[9:]):
            with self.assertRaises(rsd.RSDProtocolError):
                rsd.decode_http2_frame(bad)
        with self.assertRaises(rsd.RSDProtocolError):
            rsd.decode_http2_frame(good, max_payload=0)

    def test_candidate_preface_is_offline_and_bounded(self):
        identifier = uuid.UUID(int=0)
        wire = rsd.candidate_rsd_handshake(identifier)
        self.assertTrue(wire.startswith(rsd.HTTP2_PREFACE))
        cursor = len(rsd.HTTP2_PREFACE)
        frames = []
        while cursor < len(wire):
            size = int.from_bytes(wire[cursor:cursor + 3], "big")
            frame = wire[cursor:cursor + 9 + size]
            frames.append(rsd.decode_http2_frame(frame))
            cursor += len(frame)
        self.assertEqual(cursor, len(wire))
        self.assertEqual([frame[0] for frame in frames], [4, 8, 1, 0, 1, 0, 0, 0])
        handshake = rsd.decode_xpc_message(frames[-1][3])
        self.assertEqual(handshake.value["MessageType"], "Handshake")
        self.assertEqual(handshake.value["MessagingProtocolVersion"], rsd.UInt64(7))


class ServiceDirectoryTests(unittest.TestCase):
    SERVICE = "com.apple.eos.BiometricKit"

    def test_accepts_only_named_valid_port(self):
        directory = {
            "MessageType": "Handshake",
            "Services": {
                self.SERVICE: {
                    "Port": rsd.UInt64(52032),
                    "Properties": {"UsesRemoteXPC": True},
                }
            },
        }
        self.assertEqual(
            rsd.validate_service_directory(directory, wanted_service=self.SERVICE),
            52032,
        )
        directory["Services"][self.SERVICE]["Port"] = "52032"
        self.assertEqual(
            rsd.validate_service_directory(directory, wanted_service=self.SERVICE),
            52032,
        )

    def test_rejects_absence_extra_shape_and_bad_ports(self):
        cases = [
            {},
            {"Services": {}},
            {"Services": {self.SERVICE: {"Port": 52032}}},
            {"Services": {self.SERVICE: {"Port": rsd.UInt64(0)}}},
            {"Services": {self.SERVICE: {"Port": rsd.UInt64(65536)}}},
            {"Services": {self.SERVICE: {"Port": "052032"}}},
            {"Services": {self.SERVICE: {"Port": "65536"}}},
            {"Services": {self.SERVICE: {"Port": rsd.UInt64(1), "extra": True}}},
            {"Services": {self.SERVICE: {"Port": rsd.UInt64(1), "Properties": "bad"}}},
            {"MessageType": "Wrong", "Services": {self.SERVICE: {"Port": rsd.UInt64(1)}}},
            {"MessageType": "Handshake", "Properties": "bad", "Services": {
                self.SERVICE: {"Port": rsd.UInt64(1)}
            }},
            {"MessageType": "Handshake", "Services": {
                self.SERVICE: {"Port": rsd.UInt64(1), "Entitlement": True}
            }},
            {"Services": {}, "unexpected": True},
        ]
        for directory in cases:
            with self.subTest(directory=directory):
                with self.assertRaises(rsd.RSDProtocolError):
                    rsd.validate_service_directory(directory, wanted_service=self.SERVICE)


if __name__ == "__main__":
    unittest.main()
