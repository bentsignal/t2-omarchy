import importlib.util
from pathlib import Path
import random
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
    def test_candidate_endpoint_is_offline_and_scoped(self):
        self.assertEqual(
            rsd.candidate_rsd_sockaddr(3),
            ("fe80::aede:48ff:fe33:4455", 58783, 0, 3),
        )
        for bad in (0, -1, 1 << 32, True, "3"):
            with self.assertRaises(rsd.RSDProtocolError):
                rsd.candidate_rsd_sockaddr(bad)

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
        wire = rsd.candidate_rsd_transport_opening()
        self.assertTrue(wire.startswith(rsd.HTTP2_PREFACE))
        cursor = len(rsd.HTTP2_PREFACE)
        frames = []
        while cursor < len(wire):
            size = int.from_bytes(wire[cursor:cursor + 3], "big")
            frame = wire[cursor:cursor + 9 + size]
            frames.append(rsd.decode_http2_frame(frame))
            cursor += len(frame)
        self.assertEqual(cursor, len(wire))
        self.assertEqual([frame[0] for frame in frames], [4, 8, 1, 0, 1, 0, 0])
        self.assertEqual(
            rsd.decode_http2_frame(rsd.candidate_rsd_settings_ack()),
            (rsd.HTTP2_SETTINGS, rsd.HTTP2_ACK, 0, b""),
        )
        handshake_frame = rsd.decode_http2_frame(
            rsd.candidate_rsd_device_handshake(identifier)
        )
        self.assertEqual(handshake_frame[:3], (rsd.HTTP2_DATA, 0, rsd.ROOT_CHANNEL))
        handshake = rsd.decode_xpc_message(handshake_frame[3])
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


class PassiveTranscriptTests(unittest.TestCase):
    SERVICE = "com.apple.eos.BiometricKit"

    @classmethod
    def directory_message(cls):
        return rsd.encode_xpc_message({
            "MessageType": "Handshake",
            "MessagingProtocolVersion": rsd.Int64(3),
            "Properties": {"BuildVersion": "23J631"},
            "Services": {
                cls.SERVICE: {
                    "Entitlement": "com.apple.private.BiometricKit",
                    "Port": "52032",
                    "Properties": {"UsesRemoteXPC": False},
                }
            },
            "UUID": uuid.UUID(int=1),
        }, message_id=0)

    @classmethod
    def transcript(cls, *, fragments=1):
        message = cls.directory_message()
        cuts = [len(message) * index // fragments for index in range(fragments + 1)]
        frames = [
            rsd.encode_http2_frame(rsd.HTTP2_SETTINGS, 0, 0,
                                   struct.pack(">HI", 3, 100)),
            rsd.encode_http2_frame(rsd.HTTP2_WINDOW_UPDATE, 0, 0,
                                   struct.pack(">I", 4096)),
            rsd.encode_http2_frame(rsd.HTTP2_HEADERS, rsd.HTTP2_END_HEADERS,
                                   rsd.ROOT_CHANNEL),
        ]
        frames.extend(
            rsd.encode_http2_frame(rsd.HTTP2_DATA, 0, rsd.ROOT_CHANNEL,
                                   message[cuts[index]:cuts[index + 1]])
            for index in range(fragments)
        )
        return b"".join(frames)

    def test_fragmented_wire_and_xpc_round_trip(self):
        wire = self.transcript(fragments=5)
        parser = rsd.PassiveRSDTranscript(wanted_service=self.SERVICE)
        for byte in wire:
            parser.feed(bytes((byte,)))
        self.assertEqual(parser.finish(), 52032)

    def test_allows_bounded_empty_xpc_control(self):
        control = rsd.encode_xpc_message(
            None, message_id=0, flags=rsd.XPC_ALWAYS_SET | rsd.XPC_REPLY
        )
        settings = rsd.encode_http2_frame(rsd.HTTP2_SETTINGS, 0, 0)
        control_frame = rsd.encode_http2_frame(rsd.HTTP2_DATA, 0,
                                               rsd.REPLY_CHANNEL, control)
        directory = rsd.encode_http2_frame(rsd.HTTP2_DATA, 0, rsd.ROOT_CHANNEL,
                                           self.directory_message())
        parser = rsd.PassiveRSDTranscript(wanted_service=self.SERVICE)
        parser.feed(settings + control_frame + directory)
        self.assertEqual(parser.finish(), 52032)

    def test_rejects_data_before_peer_settings_and_wrong_stream(self):
        directory = rsd.encode_http2_frame(rsd.HTTP2_DATA, 0, rsd.ROOT_CHANNEL,
                                           self.directory_message())
        ack = rsd.encode_http2_frame(rsd.HTTP2_SETTINGS, rsd.HTTP2_ACK, 0)
        for wire in (directory, ack + directory,
                     rsd.encode_http2_frame(rsd.HTTP2_SETTINGS, 0, 0)
                     + rsd.encode_http2_frame(rsd.HTTP2_DATA, 0, 5,
                                              self.directory_message())):
            parser = rsd.PassiveRSDTranscript(wanted_service=self.SERVICE)
            with self.assertRaises(rsd.RSDProtocolError):
                parser.feed(wire)

    def test_rejects_truncation_surplus_and_interleaving(self):
        wire = self.transcript(fragments=2)
        parser = rsd.PassiveRSDTranscript(wanted_service=self.SERVICE)
        parser.feed(wire[:-1])
        with self.assertRaises(rsd.RSDProtocolError):
            parser.finish()

        parser = rsd.PassiveRSDTranscript(wanted_service=self.SERVICE)
        with self.assertRaises(rsd.RSDProtocolError):
            parser.feed(wire + rsd.encode_http2_frame(rsd.HTTP2_SETTINGS, 0, 0))

        message = self.directory_message()
        settings = rsd.encode_http2_frame(rsd.HTTP2_SETTINGS, 0, 0)
        first = rsd.encode_http2_frame(rsd.HTTP2_DATA, 0, rsd.ROOT_CHANNEL,
                                       message[:20])
        wrong = rsd.encode_http2_frame(rsd.HTTP2_DATA, 0, rsd.REPLY_CHANNEL,
                                       message[20:])
        parser = rsd.PassiveRSDTranscript(wanted_service=self.SERVICE)
        with self.assertRaises(rsd.RSDProtocolError):
            parser.feed(settings + first + wrong)

    def test_rejects_frame_flood_and_byte_caps(self):
        settings = rsd.encode_http2_frame(rsd.HTTP2_SETTINGS, 0, 0)
        window = rsd.encode_http2_frame(rsd.HTTP2_WINDOW_UPDATE, 0, 0,
                                        struct.pack(">I", 1))
        parser = rsd.PassiveRSDTranscript(wanted_service=self.SERVICE,
                                          max_frames=2)
        with self.assertRaises(rsd.RSDProtocolError):
            parser.feed(settings + window + window)

        parser = rsd.PassiveRSDTranscript(wanted_service=self.SERVICE,
                                          max_total=8)
        with self.assertRaises(rsd.RSDProtocolError):
            parser.feed(b"123456789")

        parser = rsd.PassiveRSDTranscript(wanted_service=self.SERVICE,
                                          max_frame=4)
        with self.assertRaises(rsd.RSDProtocolError):
            parser.feed((5).to_bytes(3, "big") + b"\0" * 6)

    def test_rejects_malformed_control_frames(self):
        malformed = [
            rsd.encode_http2_frame(rsd.HTTP2_SETTINGS, rsd.HTTP2_ACK, 0, b"x"),
            rsd.encode_http2_frame(rsd.HTTP2_SETTINGS, 0, 1),
            rsd.encode_http2_frame(rsd.HTTP2_SETTINGS, 0, 0, b"x"),
            rsd.encode_http2_frame(rsd.HTTP2_SETTINGS, 0, 0,
                                   struct.pack(">HIHI", 3, 1, 3, 2)),
            rsd.encode_http2_frame(rsd.HTTP2_SETTINGS, 0, 0,
                                   struct.pack(">HI", 5, 100)),
            rsd.encode_http2_frame(rsd.HTTP2_WINDOW_UPDATE, 0, 0, b"\0" * 4),
            rsd.encode_http2_frame(rsd.HTTP2_WINDOW_UPDATE, 0, 5,
                                   struct.pack(">I", 1)),
            rsd.encode_http2_frame(9, 0, 0),
        ]
        for wire in malformed:
            parser = rsd.PassiveRSDTranscript(wanted_service=self.SERVICE)
            with self.subTest(wire=wire.hex()):
                with self.assertRaises(rsd.RSDProtocolError):
                    parser.feed(wire)

    def test_deterministic_garbage_never_completes_or_escapes_protocol_error(self):
        generator = random.Random(0x523544)
        for _ in range(250):
            wire = generator.randbytes(generator.randrange(0, 256))
            parser = rsd.PassiveRSDTranscript(wanted_service=self.SERVICE,
                                              max_total=512)
            try:
                for offset in range(0, len(wire), 7):
                    parser.feed(wire[offset:offset + 7])
                parser.finish()
            except rsd.RSDProtocolError:
                continue
            self.fail("random garbage unexpectedly formed a valid RSD transcript")


if __name__ == "__main__":
    unittest.main()
