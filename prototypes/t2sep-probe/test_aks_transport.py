import importlib.util
import hashlib
import struct
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
    def test_payload_digest_version_1(self):
        header = bytearray(range(aks.IPC_HEADER_SIZE))
        struct.pack_into("<I", header, 0x10, 1)
        payload = b"payload"
        expected = hashlib.sha256(bytes(header[0x10:0x48]) + payload).digest()[:16]
        self.assertEqual(aks.payload_digest(bytes(header), payload), expected)

    def test_payload_digest_version_2_covers_extended_identity(self):
        header = bytearray(range(aks.IPC_HEADER_SIZE))
        struct.pack_into("<I", header, 0x10, 2)
        digest = aks.payload_digest(bytes(header), b"")
        header[0x4f] ^= 1
        self.assertNotEqual(aks.payload_digest(bytes(header), b""), digest)

    def test_protected_header_validation(self):
        header = bytearray(aks.IPC_HEADER_SIZE)
        struct.pack_into("<I", header, 0x10, 1)
        protected = aks.protect_header(bytes(header), b"body")
        aks.validate_protected_header(protected, b"body")
        with self.assertRaises(aks.AKSTransportError):
            aks.validate_protected_header(protected, b"changed")

    def test_payload_digest_rejects_malformed_inputs(self):
        for header, payload in ((b"", b""), (bytes(0x50), "not bytes")):
            with self.assertRaises(aks.AKSTransportError):
                aks.payload_digest(header, payload)
        header = bytearray(aks.IPC_HEADER_SIZE)
        struct.pack_into("<I", header, 0x10, 3)
        with self.assertRaises(aks.AKSTransportError):
            aks.payload_digest(bytes(header), b"")

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

    def test_authorization_plan_requires_capabilities_before_verify(self):
        plan = aks.AuthorizationPlan()
        with self.assertRaises(aks.AKSTransportError):
            plan.plan_verify_secret(2, 12)
        request_wire = plan.request_capabilities(1)
        self.assertEqual(aks.decode_envelope(request_wire),
                         aks.AKSEnvelope(0x4d, 1, 100, False))
        reply_wire = bytes.fromhex("07cd010000000c0000000000")
        self.assertEqual(plan.accept_capabilities_transport(
            reply_wire, status=0, remote_version=4), 2)
        verify_wire = plan.plan_verify_secret(2, 12)
        self.assertEqual(aks.decode_envelope(verify_wire),
                         aks.AKSEnvelope(0x21, 2, 144, False))
        with self.assertRaises(aks.AKSTransportError):
            plan.plan_verify_secret(3, 12)

    def test_authorization_plan_rejects_uncorrelated_capabilities_reply(self):
        plan = aks.AuthorizationPlan()
        plan.request_capabilities(1)
        with self.assertRaises(aks.AKSTransportError):
            plan.accept_capabilities_transport(
                bytes.fromhex("07cd020000000c0000000000"),
                status=0, remote_version=2)


if __name__ == "__main__":
    unittest.main()
