import importlib.util
from pathlib import Path
import sys
import unittest


MODULE = Path(__file__).with_name("aks-transport.py")
SPEC = importlib.util.spec_from_file_location("aks_transport", MODULE)
assert SPEC and SPEC.loader
aks = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = aks
SPEC.loader.exec_module(aks)


class AKSTransportTests(unittest.TestCase):
    def test_exact_request_layout_and_decode(self):
        wire = aks.encode_request(0x21, 0x5a, 0x98)
        self.assertEqual(wire.hex(), "07215a000000980000000000")
        self.assertEqual(aks.decode_envelope(wire),
                         aks.AKSEnvelope(0x21, 0x5a, 0x98, False))

    def test_correlated_reply(self):
        request = aks.decode_envelope(aks.encode_request(0x21, 9, 0x98))
        reply = bytes.fromhex("07a109000000110000000000")
        self.assertEqual(aks.validate_reply(request, reply),
                         aks.AKSEnvelope(0x21, 9, 0x11, True))

    def test_rejects_invalid_requests(self):
        for selector, tag, length in ((0x80, 1, 0), (1, -1, 0),
                                      (1, 1, -1), (1, 1, 0x4001)):
            with self.assertRaises(aks.AKSTransportError):
                aks.encode_request(selector, tag, length)

    def test_rejects_malformed_and_uncorrelated_replies(self):
        request = aks.decode_envelope(aks.encode_request(0x21, 9, 0x98))
        bad = [
            b"", bytes.fromhex("08a109000000110000000000"),
            bytes.fromhex("07a109010000110000000000"),
            bytes.fromhex("07a109000100110000000000"),
            bytes.fromhex("07a109000000114000000000"),
            bytes.fromhex("072109000000110000000000"),
            bytes.fromhex("07a10a000000110000000000"),
            bytes.fromhex("07a209000000110000000000"),
        ]
        for wire in bad:
            with self.subTest(wire=wire.hex()):
                with self.assertRaises(aks.AKSTransportError):
                    aks.validate_reply(request, wire)

    def test_header_negotiation_matches_apple_fallback_and_cap(self):
        self.assertEqual(aks.negotiated_header_version(-1, None), 1)
        self.assertEqual(aks.negotiated_header_version(0, 0), 0)
        self.assertEqual(aks.negotiated_header_version(0, 1), 1)
        self.assertEqual(aks.negotiated_header_version(0, 2), 2)
        self.assertEqual(aks.negotiated_header_version(0, 99), 2)
        with self.assertRaises(aks.AKSTransportError):
            aks.negotiated_header_version(-1, 2)
        with self.assertRaises(aks.AKSTransportError):
            aks.negotiated_header_version(0, None)

    def test_verify_secret_size_plan_never_accepts_secret_bytes(self):
        self.assertEqual(aks.verify_secret_serialized_size(0), 132)
        self.assertEqual(aks.verify_secret_serialized_size(1), 136)
        self.assertEqual(aks.verify_secret_serialized_size(4), 136)
        self.assertEqual(aks.verify_secret_serialized_size(5), 140)
        with self.assertRaises(aks.AKSTransportError):
            aks.verify_secret_serialized_size(1, 15)
        with self.assertRaises(aks.AKSTransportError):
            aks.verify_secret_serialized_size(0x4000)
        with self.assertRaises(aks.AKSTransportError):
            aks.verify_secret_serialized_size(b"password")


if __name__ == "__main__":
    unittest.main()
