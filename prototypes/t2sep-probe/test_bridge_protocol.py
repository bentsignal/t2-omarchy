import importlib.util
from pathlib import Path
import plistlib
import sys
import unittest


MODULE_PATH = Path(__file__).with_name("bridge-protocol.py")
SPEC = importlib.util.spec_from_file_location("bridge_protocol", MODULE_PATH)
bridge = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = bridge
SPEC.loader.exec_module(bridge)


class BiometricEnvelopeTests(unittest.TestCase):
    def test_exact_inner_wire_bytes(self):
        encoded = bridge.encode_biometric_request(0x1234, 2, 3, b"ab")
        self.assertEqual(encoded, bytes.fromhex("424d3412020003006162"))

    def test_round_trip(self):
        encoded = bridge.encode_biometric_request(7, 8, 9, b"payload")
        self.assertEqual(
            bridge.decode_biometric_request(encoded, max_payload=7),
            bridge.BiometricRequest(7, 8, 9, b"payload"),
        )

    def test_rejects_bad_magic_short_input_and_oversize(self):
        with self.assertRaises(bridge.BridgeProtocolError):
            bridge.decode_biometric_request(b"", max_payload=0)
        with self.assertRaises(bridge.BridgeProtocolError):
            bridge.decode_biometric_request(b"XX" + b"\0" * 6, max_payload=0)
        with self.assertRaises(bridge.BridgeProtocolError):
            bridge.decode_biometric_request(bytes.fromhex("424d01000200030000"), max_payload=0)

    def test_rejects_invalid_fields(self):
        for bad in (-1, 0x10000, True):
            with self.assertRaises(bridge.BridgeProtocolError):
                bridge.encode_biometric_request(bad, 0, 0)
        with self.assertRaises(bridge.BridgeProtocolError):
            bridge.encode_biometric_request(0, 0, 0, bytearray())


class BridgeEnvelopeTests(unittest.TestCase):
    def test_recovered_biometric_endpoint(self):
        self.assertEqual(
            bridge.biometric_sockaddr(3),
            ("fe80::aede:48ff:fe33:4455", 52032, 0, 3),
        )
        for bad in (0, -1, True, 0x100000000):
            with self.assertRaises(bridge.BridgeProtocolError):
                bridge.biometric_sockaddr(bad)

    def test_exact_biometric_wrapper(self):
        self.assertEqual(
            bridge.biometric_perform_request(0x20, 1, 4, b"x", 512),
            (3, 0, bytes.fromhex("424d20000100040078"), 512),
        )

    def test_perform_request_rejects_wrong_types_and_ranges(self):
        for args in ((-1, None, 0), (0x100000000, None, 0),
                     (0, "bad", 0), (0, None, -1)):
            with self.assertRaises(bridge.BridgeProtocolError):
                bridge.perform_command_request(*args)

    def test_reply_validation(self):
        self.assertEqual(
            bridge.decode_perform_command_reply((0, b"ok"), max_output=2),
            (0, b"ok"),
        )
        self.assertEqual(
            bridge.decode_perform_command_reply((5, None), max_output=0),
            (5, None),
        )
        for reply in ((0,), (0, "bad"), (True, None), (-1, None)):
            with self.assertRaises(bridge.BridgeProtocolError):
                bridge.decode_perform_command_reply(reply, max_output=16)
        with self.assertRaises(bridge.BridgeProtocolError):
            bridge.decode_perform_command_reply((0, b"too long"), max_output=2)

    def test_exact_frame_header(self):
        header = bridge.encode_frame_header(bridge.FRAME_MESSAGE, 0x1234)
        self.assertEqual(header.hex(), "92b80100020000003412000000000000")
        self.assertEqual(
            bridge.decode_frame_header(header, max_body=0x1234),
            bridge.BridgeFrameHeader(bridge.FRAME_MESSAGE, 0x1234),
        )

    def test_frame_header_fails_closed(self):
        good = bridge.encode_frame_header(bridge.FRAME_HELO, 9)
        for bad in (b"", b"bad" + good[3:],
                    good[:4] + (9).to_bytes(4, "little") + good[8:]):
            with self.assertRaises(bridge.BridgeProtocolError):
                bridge.decode_frame_header(bad, max_body=9)
        with self.assertRaises(bridge.BridgeProtocolError):
            bridge.decode_frame_header(good, max_body=8)

    def test_binary_plist_message_frame(self):
        request = bridge.biometric_perform_request(4, 5, 6, b"data", 64)
        frame = bridge.encode_perform_command_frame(request, max_body=1024)
        header = bridge.decode_frame_header(frame[:16], max_body=1024)
        self.assertEqual(header.body_size, len(frame) - 16)
        self.assertEqual(plistlib.loads(frame[16:]), list(request))

    def test_frame_encoder_does_not_guess_btnil(self):
        with self.assertRaises(bridge.BridgeProtocolError):
            bridge.encode_perform_command_frame((3, 0, None, 0), max_body=1024)
        with self.assertRaises(bridge.BridgeProtocolError):
            bridge.encode_perform_command_frame((3, 0, b"x", 0), max_body=1)


if __name__ == "__main__":
    unittest.main()
