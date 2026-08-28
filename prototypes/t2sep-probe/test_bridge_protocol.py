import importlib.util
import json
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
        self.assertEqual(
            bridge.decode_perform_command_reply((-1, None), max_output=0),
            (-1, None),
        )
        for reply in ((0,), (0, "bad"), (True, None), (0x80000000, None)):
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
                    good[:2] + (9).to_bytes(2, "little") + good[4:],
                    good[:4] + (9).to_bytes(4, "little") + good[8:]):
            with self.assertRaises(bridge.BridgeProtocolError):
                bridge.decode_frame_header(bad, max_body=9)
        with self.assertRaises(bridge.BridgeProtocolError):
            bridge.decode_frame_header(good, max_body=8)

    def test_noop_must_have_zero_body(self):
        noop = bridge.encode_frame_header(bridge.FRAME_NOOP, 0)
        self.assertEqual(bridge.decode_frame_header(noop, max_body=0).kind, 0)
        with self.assertRaises(bridge.BridgeProtocolError):
            bridge.encode_frame_header(bridge.FRAME_NOOP, 1)

    def test_binary_plist_message_frame(self):
        request = bridge.biometric_perform_request(4, 5, 6, b"data", 64)
        frame = bridge.encode_perform_command_frame(request, max_body=1024)
        header = bridge.decode_frame_header(frame[:16], max_body=1024)
        self.assertEqual(header.body_size, len(frame) - 16)
        self.assertEqual(plistlib.loads(frame[16:]), list(request))

    def test_helo_frame(self):
        frame = bridge.encode_helo_frame("19H15", 37.0, "probe", max_body=512)
        header = bridge.decode_frame_header(frame[:16], max_body=512)
        self.assertEqual(header.kind, bridge.FRAME_HELO)
        self.assertEqual(header.body_size, len(frame) - 16)
        self.assertEqual(json.loads(frame[16:]), {
            "MaxSupportedProtocolVersion": 1,
            "OSBuild": "19H15",
            "BridgeXPCVersion": 37.0,
            "ProcessName": "probe",
        })
        self.assertEqual(
            bridge.decode_helo_body(frame[16:], max_body=512)["OSBuild"],
            "19H15",
        )

    def test_helo_encoder_rejects_strings_the_decoder_would_reject(self):
        for os_build, process_name in (("bad\0build", "probe"),
                                       ("x" * 129, "probe"),
                                       ("Linux", "bad\0name"),
                                       ("Linux", "x" * 257)):
            with self.subTest(os_build=os_build, process_name=process_name):
                with self.assertRaises(bridge.BridgeProtocolError):
                    bridge.encode_helo_frame(os_build, 39, process_name,
                                             max_body=1024)

    def test_helo_decoder_fails_closed(self):
        valid = {
            "MaxSupportedProtocolVersion": 1,
            "OSBuild": "19H15",
            "BridgeXPCVersion": 37.0,
            "ProcessName": "peer",
        }
        malformed = [
            b"bad",
            json.dumps({**valid, "extra": 1}).encode(),
            json.dumps({**valid, "MaxSupportedProtocolVersion": True}).encode(),
            json.dumps({**valid, "MaxSupportedProtocolVersion": 1.0}).encode(),
            json.dumps({**valid, "OSBuild": ""}).encode(),
            json.dumps({**valid, "BridgeXPCVersion": -1}).encode(),
            json.dumps({**valid, "ProcessName": "x" * 257}).encode(),
            (b'{"MaxSupportedProtocolVersion":1,"OSBuild":"19H15",'
             b'"BridgeXPCVersion":37,"ProcessName":"a","ProcessName":"b"}'),
        ]
        for body in malformed:
            with self.assertRaises(bridge.BridgeProtocolError):
                bridge.decode_helo_body(body, max_body=1024)
        with self.assertRaises(bridge.BridgeProtocolError):
            bridge.decode_helo_body(json.dumps(valid).encode(), max_body=1)

    def test_passive_bridge_version_query_and_reply(self):
        frame = bridge.encode_bridge_version_query_frame(max_body=256)
        self.assertEqual(plistlib.loads(frame[16:]), [0])
        body = plistlib.dumps([0, 123], fmt=plistlib.FMT_BINARY)
        self.assertEqual(
            bridge.decode_bridge_version_reply_body(body, max_body=len(body)),
            (0, 123),
        )
        signed = plistlib.dumps([-1, 0], fmt=plistlib.FMT_BINARY)
        self.assertEqual(
            bridge.decode_bridge_version_reply_body(signed, max_body=len(signed)),
            (-1, 0),
        )

    def test_transport_request_and_correlated_reply(self):
        reply_id = "01234567-89AB-4CDE-8FAB-0123456789AB"
        frame = bridge.encode_transport_request_frame([0], reply_id, max_body=256)
        self.assertEqual(plistlib.loads(frame[16:]), [1, False, reply_id, [0]])
        body = plistlib.dumps([1, True, reply_id, [0, 3]],
                              fmt=plistlib.FMT_BINARY, sort_keys=False)
        self.assertEqual(bridge.decode_transport_reply_body(
            body, reply_id, max_body=256), [0, 3])

    def test_transport_envelope_fails_closed(self):
        reply_id = "01234567-89AB-4CDE-8FAB-0123456789AB"
        other_id = "11234567-89AB-4CDE-8FAB-0123456789AB"
        malformed = (
            b"bad", plistlib.dumps([1, True, reply_id]),
            plistlib.dumps([True, True, reply_id, [0, 3]]),
            plistlib.dumps([1, False, reply_id, [0, 3]]),
            plistlib.dumps([1, True, other_id, [0, 3]]),
            plistlib.dumps([1, True, reply_id, {"status": 0}]),
        )
        for body in malformed:
            with self.assertRaises(bridge.BridgeProtocolError):
                bridge.decode_transport_reply_body(body, reply_id, max_body=256)
        with self.assertRaises(bridge.BridgeProtocolError):
            bridge.encode_transport_request_frame(
                [0], bridge.NO_REPLY_UUID, max_body=256)

    def test_bridge_version_reply_fails_closed(self):
        bad_replies = (b"bad", plistlib.dumps([0]), plistlib.dumps([True, 1]),
                       plistlib.dumps([0, -1]), plistlib.dumps({"status": 0}))
        for body in bad_replies:
            with self.assertRaises(bridge.BridgeProtocolError):
                bridge.decode_bridge_version_reply_body(body, max_body=len(body))

    def test_current_service_opened_query_and_reply(self):
        frame = bridge.encode_service_opened_query_frame(max_body=256)
        self.assertEqual(plistlib.loads(frame[16:]), [1])
        for status, opened in ((0, True), (-1, False)):
            body = plistlib.dumps([status, opened], fmt=plistlib.FMT_BINARY)
            self.assertEqual(
            bridge.decode_service_opened_reply_body(body, max_body=len(body)),
                (status, opened),
            )

    def test_complete_perform_reply_body_decoder(self):
        body = plistlib.dumps([0, b"\x05\0\0\0"], fmt=plistlib.FMT_BINARY)
        self.assertEqual(
            bridge.decode_perform_command_reply_body(
                body, max_body=len(body), max_output=4),
            (0, b"\x05\0\0\0"))
        for bad in (plistlib.dumps({"status": 0}), b"bad"):
            with self.assertRaises(bridge.BridgeProtocolError):
                bridge.decode_perform_command_reply_body(
                    bad, max_body=1024, max_output=4)
        with self.assertRaisesRegex(bridge.BridgeProtocolError, "body exceeds"):
            bridge.decode_perform_command_reply_body(
                body, max_body=len(body) - 1, max_output=4)

    def test_service_opened_reply_fails_closed(self):
        malformed = (
            b"bad", plistlib.dumps([0]), plistlib.dumps([0, 1]),
            plistlib.dumps([True, False]), plistlib.dumps([0, False, "extra"]),
            plistlib.dumps({"status": 0, "opened": False}),
        )
        for body in malformed:
            with self.subTest(body=body):
                with self.assertRaises(bridge.BridgeProtocolError):
                    bridge.decode_service_opened_reply_body(body,
                                                            max_body=len(body))
        good = plistlib.dumps([0, True], fmt=plistlib.FMT_BINARY)
        with self.assertRaises(bridge.BridgeProtocolError):
            bridge.decode_service_opened_reply_body(good, max_body=len(good) - 1)

    def test_frame_encoder_does_not_guess_btnil(self):
        with self.assertRaises(bridge.BridgeProtocolError):
            bridge.encode_perform_command_frame((3, 0, None, 0), max_body=1024)
        with self.assertRaises(bridge.BridgeProtocolError):
            bridge.encode_perform_command_frame((3, 0, b"x", 0), max_body=1)


if __name__ == "__main__":
    unittest.main()
