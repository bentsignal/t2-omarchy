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
    def _identity(self, version=1):
        kwargs = dict(continuous_usec=1, process_unique_id=2,
                      audit_session_id=3, cdhash=bytes(range(20)))
        if version == 2:
            kwargs["calendar_seconds"] = 4
        return aks.build_identity_header(version, **kwargs)

    def test_capabilities_request_exact_layout(self):
        wire = aks.encode_capabilities_request(self._identity())
        self.assertEqual(len(wire), 100)
        self.assertEqual(struct.unpack_from("<I", wire)[0], 0x50)
        self.assertEqual(wire[0x54:], struct.pack("<IQI", 0, 1, 0))
        aks.validate_protected_header(wire[4:0x54], wire[0x54:])

    def test_capabilities_request_fixed_kernproc_vector(self):
        identity = aks.build_identity_header(
            1, continuous_usec=0x0102030405060708,
            process_unique_id=0, audit_session_id=0, cdhash=bytes(20))
        self.assertEqual(
            aks.encode_capabilities_request(identity).hex(),
            "50000000c109beea6de62551b0f38ca9865a2aa80100000008070605040302010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000")

    def test_capabilities_reply_validation(self):
        payload = struct.pack("<iQI", 0, 2, 0)
        header = aks.protect_header(self._identity(2), payload)
        wire = struct.pack("<I", 0x50) + header + payload
        self.assertEqual(aks.decode_capabilities_reply(wire),
                         aks.CapabilitiesReply(0, 2))
        for offset in (0, 4, 0x54, 0x5c):
            changed = bytearray(wire)
            changed[offset] ^= 1
            with self.assertRaises(aks.AKSTransportError):
                aks.decode_capabilities_reply(bytes(changed))

    def test_capabilities_codec_rejects_noncanonical_inputs(self):
        protected = aks.protect_header(self._identity(), bytes(16))
        with self.assertRaises(aks.AKSTransportError):
            aks.encode_capabilities_request(protected)
        for wire in (b"", bytes(99), bytes(101)):
            with self.assertRaises(aks.AKSTransportError):
                aks.decode_capabilities_reply(wire)
        payload = struct.pack("<iQI", -1, 1, 1)
        header = aks.protect_header(self._identity(), payload)
        with self.assertRaises(aks.AKSTransportError):
            aks.decode_capabilities_reply(struct.pack("<I", 0x50) + header + payload)

    def test_verify_secret_success_reply(self):
        body = struct.pack("<IQ", 1, 0x1122334455667788)
        header = aks.protect_header(self._identity(2), body)
        wire = struct.pack("<I", 0x50) + header + body
        self.assertEqual(aks.decode_verify_secret_reply(wire, 2),
                         aks.VerifySecretReply(0x1122334455667788))
        for expected in (0, 1, 3):
            with self.assertRaises(aks.AKSTransportError):
                aks.decode_verify_secret_reply(wire, expected)
        for offset in (0, 4, 0x54):
            changed = bytearray(wire)
            changed[offset] ^= 1
            with self.assertRaises(aks.AKSTransportError):
                aks.decode_verify_secret_reply(bytes(changed), 2)

    def test_authorization_plan_validates_verify_reply_transport(self):
        plan = aks.AuthorizationPlan()
        plan.capabilities_request = aks.AKSEnvelope(0x4d, 1, 100, False)
        plan.header_version = 1
        plan.plan_verify_secret(2, 12)
        body = struct.pack("<IQ", 1, 7)
        header = aks.protect_header(self._identity(), body)
        payload = struct.pack("<I", 0x50) + header + body
        reply = bytes.fromhex("07a102000000600000000000")
        self.assertEqual(plan.accept_verify_secret_success(reply, payload),
                         aks.VerifySecretReply(7))
        with self.assertRaises(aks.AKSTransportError):
            plan.accept_verify_secret_success(
                bytes.fromhex("07a103000000600000000000"), payload)

    def test_build_identity_header_layout(self):
        cdhash = bytes(range(20))
        header = aks.build_identity_header(
            2, continuous_usec=0x1122334455667788,
            process_unique_id=0x8877665544332211,
            audit_session_id=0xaabbccdd, cdhash=cdhash,
            calendar_seconds=0x0102030405060708)
        self.assertEqual(len(header), 0x50)
        self.assertEqual(struct.unpack_from("<I", header, 0x10)[0], 2)
        self.assertEqual(struct.unpack_from("<Q", header, 0x14)[0],
                         0x1122334455667788)
        self.assertEqual(header[0x1c:0x20], bytes(4))
        self.assertEqual(struct.unpack_from("<Q", header, 0x20)[0], 0)
        self.assertEqual(struct.unpack_from("<Q", header, 0x28)[0],
                         0x8877665544332211)
        self.assertEqual(struct.unpack_from("<I", header, 0x30)[0], 0xaabbccdd)
        self.assertEqual(header[0x34:0x48], cdhash)
        self.assertEqual(struct.unpack_from("<Q", header, 0x48)[0],
                         0x0102030405060708)

    def test_build_identity_header_version_rules(self):
        kwargs = dict(continuous_usec=1, process_unique_id=2,
                      audit_session_id=3, cdhash=bytes(20))
        self.assertEqual(aks.build_identity_header(1, **kwargs)[0x48:], bytes(8))
        with self.assertRaises(aks.AKSTransportError):
            aks.build_identity_header(1, **kwargs, calendar_seconds=4)
        with self.assertRaises(aks.AKSTransportError):
            aks.build_identity_header(2, **kwargs)
        for bad_hash in (b"", bytes(19), bytes(21)):
            with self.assertRaises(aks.AKSTransportError):
                aks.build_identity_header(1, **{**kwargs, "cdhash": bad_hash})
        with self.assertRaises(aks.AKSTransportError):
            aks.build_identity_header(1, **{**kwargs, "audit_session_id": -1})

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

    def test_verify_secret_layout_has_exact_nonoverlapping_boundaries(self):
        layout = aks.verify_secret_layout(12)
        self.assertEqual(layout, aks.VerifySecretLayout(
            total_size=144,
            variant_offset=84,
            keybag_offset=88,
            selector_offset=96,
            password_length_offset=100,
            password_data_offset=104,
            password_padded_end=116,
            context_length_offset=116,
            context_data_offset=120,
            context_padded_end=136,
            device_state_offset=136))
        for length, expected_total in ((0, 132), (1, 136), (4, 136), (5, 140)):
            with self.subTest(length=length):
                item = aks.verify_secret_layout(length)
                self.assertEqual(item.total_size, expected_total)
                self.assertEqual(item.password_padded_end,
                                 item.context_length_offset)
                self.assertEqual(item.context_padded_end,
                                 item.device_state_offset)

    def test_authorization_plan_requires_capabilities_before_verify(self):
        plan = aks.AuthorizationPlan()
        with self.assertRaises(aks.AKSTransportError):
            plan.plan_verify_secret(2, 12)
        request_wire = plan.request_capabilities(1)
        self.assertEqual(aks.decode_envelope(request_wire),
                         aks.AKSEnvelope(0x4d, 1, 100, False))
        payload_body = struct.pack("<iQI", 0, 4, 0)
        payload_header = aks.protect_header(self._identity(), payload_body)
        payload = struct.pack("<I", 0x50) + payload_header + payload_body
        reply_wire = bytes.fromhex("07cd01000000640000000000")
        self.assertEqual(plan.accept_capabilities_transport(
            reply_wire, payload), 2)
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
                bytes.fromhex("07cd02000000640000000000"), bytes(100))


if __name__ == "__main__":
    unittest.main()
