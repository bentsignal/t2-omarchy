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

    def test_compact_version_one_capabilities_reply_validation(self):
        payload = struct.pack("<iQI", 0, 2, 0)
        identity = self._identity(1)[:0x48]
        header = aks.protect_header(identity, payload)
        wire = struct.pack("<I", 0x48) + header + payload
        self.assertEqual(len(wire), 92)
        self.assertEqual(aks.decode_capabilities_reply(wire),
                         aks.CapabilitiesReply(0, 2))

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

    def test_startup_environment_request_exact_nonsecret_layout(self):
        blob = aks.startup_environment_blob(0x11223344)
        self.assertEqual(len(blob), 0x40c)
        self.assertEqual(struct.unpack_from("<IIIQ", blob),
                         (1, 0x11223344, 4, 0))
        self.assertEqual(blob[20:], bytes(0x3f8))
        wire = aks.encode_startup_environment_request(
            self._identity(2), 0x11223344)
        self.assertEqual(len(wire), 0x470)
        self.assertEqual(struct.unpack_from("<I", wire)[0], 0x50)
        self.assertEqual(struct.unpack_from("<IQI", wire, 0x54),
                         (0, 1, 0x40c))
        self.assertEqual(wire[0x64:], blob)
        aks.validate_protected_header(wire[4:0x54], wire[0x54:])
        for value in (-1, 1 << 32, True, b"0"):
            with self.subTest(value=value):
                with self.assertRaises(aks.AKSTransportError):
                    aks.startup_environment_blob(value)

    def test_set_environment_reply_is_exact_protected_zero_status(self):
        body = struct.pack("<i", 0)
        header = aks.protect_header(self._identity(2), body)
        wire = struct.pack("<I", 0x50) + header + body
        self.assertIsNone(aks.decode_set_environment_reply(wire, 2))
        bad = (wire[:-1], wire + b"\0",
               wire[:0x54] + struct.pack("<i", -1))
        for value in bad:
            with self.subTest(length=len(value)):
                with self.assertRaises(aks.AKSTransportError):
                    aks.decode_set_environment_reply(value, 2)
        with self.assertRaises(aks.AKSTransportError):
            aks.decode_set_environment_reply(wire, 1)

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

    def test_verify_secret_fixed_success_vector(self):
        identity = aks.build_identity_header(
            1, continuous_usec=0x0102030405060708,
            process_unique_id=0, audit_session_id=0, cdhash=bytes(20))
        body = struct.pack("<IQ", 1, 0x1122334455667788)
        wire = struct.pack("<I", 0x50) + aks.protect_header(identity, body) + body
        self.assertEqual(
            wire.hex(),
            "500000001c3f43f92b051af9f53206a27222b4fb01000000080706050403020100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000008877665544332211")
        self.assertEqual(aks.decode_verify_secret_reply(wire, 1),
                         aks.VerifySecretReply(0x1122334455667788))

    def test_consumed_verify_secret_request_is_exact_and_scrubbable(self):
        password = bytearray(b"not-a-real-password")
        context = bytearray(range(16))
        original_password = bytes(password)
        original_context = bytes(context)
        request = aks.consume_verify_secret_inputs(
            self._identity(2), password, context,
            keybag_handle=aks.SessionKeybagHandle(0x1122334455667788),
            selector=aks.SessionKeybagSelector(-501),
            device_state_active=True)
        self.assertEqual(password, bytearray(len(original_password)))
        self.assertEqual(context, bytearray(16))

        layout = aks.verify_secret_layout(len(original_password))
        wire = request.view()
        self.assertEqual(len(wire), layout.total_size)
        self.assertEqual(struct.unpack_from("<I", wire)[0], 0x50)
        self.assertEqual(struct.unpack_from(
            "<IQiI", wire, layout.variant_offset),
            (1, 0x1122334455667788, -501, len(original_password)))
        self.assertEqual(
            wire[layout.password_data_offset:
                 layout.password_data_offset + len(original_password)],
            original_password)
        self.assertEqual(
            wire[layout.password_data_offset + len(original_password):
                 layout.password_padded_end],
            bytes(layout.password_padded_end -
                  layout.password_data_offset - len(original_password)))
        self.assertEqual(struct.unpack_from(
            "<I", wire, layout.context_length_offset)[0], 16)
        self.assertEqual(
            wire[layout.context_data_offset:layout.context_data_offset + 16],
            original_context)
        self.assertEqual(struct.unpack_from(
            "<Q", wire, layout.device_state_offset)[0], 0x80)
        aks.validate_protected_header(bytes(wire[4:0x54]), bytes(wire[0x54:]))
        self.assertNotIn(original_password, repr(request).encode())
        request.close()
        self.assertEqual(bytes(wire), bytes(len(wire)))
        with self.assertRaises(aks.AKSTransportError):
            request.view()

    def test_verify_secret_context_manager_scrubs_on_exception(self):
        password = bytearray(b"temporary")
        context = bytearray(range(16))
        wire = None
        with self.assertRaisesRegex(RuntimeError, "stop"):
            with aks.consume_verify_secret_inputs(
                    self._identity(1), password, context,
                    keybag_handle=aks.SessionKeybagHandle(7),
                    selector=aks.SessionKeybagSelector(-4),
                    device_state_active=False) as request:
                wire = request.view()
                offset = aks.verify_secret_layout(9).device_state_offset
                self.assertEqual(struct.unpack_from("<Q", wire, offset)[0], 0)
                raise RuntimeError("stop")
        self.assertIsNotNone(wire)
        self.assertEqual(bytes(wire), bytes(len(wire)))

    def test_verify_secret_consumption_rejects_bad_input_ownership(self):
        metadata = (aks.SessionKeybagHandle(7),
                    aks.SessionKeybagSelector(-4))
        cases = (
            (b"immutable", bytearray(16), False),
            (bytearray(b"ok"), bytes(16), False),
            (bytearray(b"ok"), bytearray(15), False),
            (bytearray(b"ok"), bytearray(16), 1),
        )
        for password, context, state in cases:
            with self.subTest(password_type=type(password),
                              context_type=type(context), state=state):
                with self.assertRaises(aks.AKSTransportError):
                    aks.consume_verify_secret_inputs(
                        self._identity(2), password, context,
                        keybag_handle=metadata[0], selector=metadata[1],
                        device_state_active=state)

    def test_verify_secret_consumption_scrubs_after_internal_failure(self):
        header = bytearray(self._identity(2))
        struct.pack_into("<I", header, 0x10, 3)
        password = bytearray(b"temporary")
        context = bytearray(range(16))
        with self.assertRaises(aks.AKSTransportError):
            aks.consume_verify_secret_inputs(
                bytes(header), password, context,
                keybag_handle=aks.SessionKeybagHandle(7),
                selector=aks.SessionKeybagSelector(-4),
                device_state_active=False)
        self.assertEqual(password, bytearray(9))
        self.assertEqual(context, bytearray(16))

    def test_authorization_plan_validates_verify_reply_transport(self):
        plan = aks.AuthorizationPlan()
        plan.capabilities_request = aks.AKSEnvelope(0x4d, 1, 100, False)
        plan.header_version = 1
        plan.environment_initialized = True
        plan.plan_verify_secret(
            2, 12, keybag_handle=aks.SessionKeybagHandle(7),
            selector=aks.SessionKeybagSelector(-2))
        secret_request = plan.consume_verify_secret_payload(
            self._identity(), bytearray(12), bytearray(16),
            device_state_active=False)
        secret_request.close()
        body = struct.pack("<IQ", 1, 7)
        header = aks.protect_header(self._identity(), body)
        payload = struct.pack("<I", 0x50) + header + body
        reply = bytes.fromhex("07a102000000600000000000")
        self.assertEqual(plan.accept_verify_secret_success(reply, payload),
                         aks.VerifySecretReply(7))
        with self.assertRaises(aks.AKSTransportError):
            plan.accept_verify_secret_success(
                bytes.fromhex("07a103000000600000000000"), payload)

    def test_authorization_plan_correlates_owned_secret_payload(self):
        plan = aks.AuthorizationPlan()
        plan.header_version = 2
        plan.environment_initialized = True
        plan.plan_verify_secret(
            9, 5, keybag_handle=aks.SessionKeybagHandle(7),
            selector=aks.SessionKeybagSelector(-4))
        with self.assertRaises(aks.AKSTransportError):
            plan.consume_verify_secret_payload(
                self._identity(1), bytearray(5), bytearray(16),
                device_state_active=False)
        password = bytearray(b"12345")
        context = bytearray(16)
        request = plan.consume_verify_secret_payload(
            self._identity(2), password, context, device_state_active=False)
        self.assertEqual(len(request.view()),
                         plan.verify_request.payload_length)
        self.assertEqual(password, bytearray(5))
        self.assertEqual(context, bytearray(16))
        with self.assertRaises(aks.AKSTransportError):
            plan.consume_verify_secret_payload(
                self._identity(2), bytearray(5), bytearray(16),
                device_state_active=False)
        request.close()

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

    def test_create_keybag_layout_is_exact_and_nonoverlapping(self):
        self.assertEqual(aks.create_keybag_layout(3), aks.CreateKeybagLayout(
            total_size=116,
            variant_offset=84,
            namespace_offset=88,
            store_type_offset=96,
            requested_selector_offset=100,
            primary_length_offset=104,
            primary_data_offset=108,
            primary_padded_end=112,
            secondary_length_offset=112,
            secondary_data_offset=116,
            secondary_padded_end=116))
        self.assertEqual(aks.create_keybag_layout(4, 5).total_size, 124)
        for primary, secondary in ((0, 0), (257, 0), (1, 257),
                                   (b"secret", 0)):
            with self.subTest(primary=primary, secondary=secondary):
                with self.assertRaises(aks.AKSTransportError):
                    aks.create_keybag_layout(primary, secondary)

    def test_create_keybag_consumes_secrets_and_scrubs_request(self):
        primary = bytearray(b"abc")
        secondary = bytearray(b"12345")
        original_primary = bytes(primary)
        original_secondary = bytes(secondary)
        request = aks.consume_create_keybag_inputs(
            self._identity(2), primary, secondary,
            namespace=aks.SessionKeybagHandle(0x1122334455667788),
            store_type=aks.KeybagStoreType(1),
            requested_selector=aks.SessionKeybagSelector(-501))
        self.assertEqual(primary, bytearray(3))
        self.assertEqual(secondary, bytearray(5))
        layout = aks.create_keybag_layout(3, 5)
        wire = request.view()
        self.assertEqual(struct.unpack_from(
            "<IQIiI", wire, layout.variant_offset),
            (1, 0x1122334455667788, 1, -501, 3))
        self.assertEqual(bytes(wire[layout.primary_data_offset:
                                    layout.primary_data_offset + 3]),
                         original_primary)
        self.assertEqual(bytes(wire[layout.secondary_data_offset:
                                    layout.secondary_data_offset + 5]),
                         original_secondary)
        aks.validate_protected_header(bytes(wire[4:0x54]), bytes(wire[0x54:]))
        self.assertNotIn(original_primary, repr(request).encode())
        request.close()
        self.assertEqual(bytes(wire), bytes(len(wire)))

    def test_create_keybag_rejects_untyped_metadata_and_immutable_secrets(self):
        cases = (
            (b"secret", bytearray(), aks.KeybagStoreType(1)),
            (bytearray(b"secret"), b"", aks.KeybagStoreType(1)),
            (bytearray(b"secret"), bytearray(), 1),
            (bytearray(b"secret"), bytearray(), aks.KeybagStoreType(-1)),
        )
        for primary, secondary, store_type in cases:
            with self.subTest(store_type=store_type):
                with self.assertRaises(aks.AKSTransportError):
                    aks.consume_create_keybag_inputs(
                        self._identity(), primary, secondary,
                        namespace=aks.SessionKeybagHandle(7),
                        store_type=store_type,
                        requested_selector=aks.SessionKeybagSelector(-501))

    def test_create_keybag_success_reply_is_strict(self):
        body = struct.pack("<Ii", 1, 9)
        header = aks.protect_header(self._identity(2), body)
        wire = struct.pack("<I", 0x50) + header + body
        self.assertEqual(aks.decode_create_keybag_reply(wire, 2),
                         aks.CreateKeybagReply(aks.SessionKeybagSelector(9)))
        for changed in (
                wire[:-1],
                wire[:84] + struct.pack("<Ii", 0, 9),
                wire[:84] + struct.pack("<Ii", 1, -1),
                struct.pack("<I", 0x48) + wire[4:]):
            with self.subTest(length=len(changed)):
                with self.assertRaises(aks.AKSTransportError):
                    aks.decode_create_keybag_reply(changed, 2)

    def test_unload_keybag_request_and_reply_are_exact(self):
        request = aks.encode_unload_keybag_request(
            self._identity(2), namespace=aks.SessionKeybagHandle(7),
            selector=aks.SessionKeybagSelector(9))
        self.assertEqual(len(request), 100)
        self.assertEqual(struct.unpack_from("<IQi", request, 84), (0, 7, 9))
        aks.validate_protected_header(request[4:84], request[84:])
        body = struct.pack("<I", 0)
        header = aks.protect_header(self._identity(2), body)
        reply = struct.pack("<I", 0x50) + header + body
        self.assertIsNone(aks.decode_unload_keybag_reply(reply, 2))
        for changed in (reply[:-1], reply[:84] + struct.pack("<I", 1)):
            with self.subTest(length=len(changed)):
                with self.assertRaises(aks.AKSTransportError):
                    aks.decode_unload_keybag_reply(changed, 2)

    def test_copy_keybag_request_and_bounded_reply_are_exact(self):
        request = aks.encode_copy_keybag_request(
            self._identity(2), namespace=aks.SessionKeybagHandle(7),
            selector=aks.SessionKeybagSelector(9))
        self.assertEqual(len(request), 100)
        self.assertEqual(struct.unpack_from("<IQi", request, 84), (0, 7, 9))
        aks.validate_protected_header(request[4:84], request[84:])

        body = struct.pack("<II", 0, 3) + b"bag\0"
        header = aks.protect_header(self._identity(2), body)
        reply = struct.pack("<I", 0x50) + header + body
        self.assertEqual(aks.decode_copy_keybag_reply(reply, 2), b"bag")
        for changed in (
                reply[:-1],
                reply[:84] + struct.pack("<II", 1, 3) + b"bag\0",
                reply[:84] + struct.pack("<II", 0, 5) + b"bag\0",
                reply[:-1] + b"x"):
            with self.subTest(length=len(changed)):
                with self.assertRaises(aks.AKSTransportError):
                    aks.decode_copy_keybag_reply(changed, 2)
        with self.assertRaises(aks.AKSTransportError):
            aks.decode_copy_keybag_reply(reply, 2, max_blob_size=2)

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

    def test_verify_secret_metadata_has_no_defaults_or_truncation(self):
        handle = aks.derive_session_keybag_handle(0x1122334455667780, 8)
        selector = aks.derive_session_keybag_selector(10)
        self.assertEqual(aks.verify_secret_metadata(handle, selector),
                         aks.VerifySecretMetadata(
                             aks.SessionKeybagHandle(0x1122334455667788),
                             aks.SessionKeybagSelector(-10)))
        for handle, selector in (
                (-1, selector), (1 << 64, selector), (0, selector),
                (aks.SessionKeybagHandle(0), -(1 << 31) - 1),
                (aks.SessionKeybagHandle(0), aks.SessionKeybagSelector(
                    -(1 << 31) - 1)),
                (aks.SessionKeybagHandle(0), aks.SessionKeybagSelector(1 << 31)),
                (True, selector), (aks.SessionKeybagHandle(0), False)):
            with self.subTest(handle=handle, selector=selector):
                with self.assertRaises(aks.AKSTransportError):
                    aks.verify_secret_metadata(handle, selector)

    def test_session_keybag_handle_matches_random_base_plus_unique_id(self):
        self.assertEqual(
            aks.derive_session_keybag_handle(
                0x1122334455667788, 0x0102030405060708),
            aks.SessionKeybagHandle(0x122436485a6c7e90))
        self.assertEqual(
            aks.derive_session_keybag_handle(0xffffffffffffffff, 2),
            aks.SessionKeybagHandle(1))
        for nonce, unique_id in ((-1, 0), (1 << 64, 0), (0, -1),
                                 (0, 1 << 64), (True, 0), (0, False)):
            with self.subTest(nonce=nonce, unique_id=unique_id):
                with self.assertRaises(aks.AKSTransportError):
                    aks.derive_session_keybag_handle(nonce, unique_id)

    def test_session_keybag_selector_matches_apple_session_policy(self):
        self.assertEqual(aks.derive_session_keybag_selector(0),
                         aks.SessionKeybagSelector(-4))
        self.assertEqual(aks.derive_session_keybag_selector(10),
                         aks.SessionKeybagSelector(-10))
        self.assertEqual(aks.derive_session_keybag_selector(501),
                         aks.SessionKeybagSelector(-501))
        self.assertEqual(aks.derive_session_keybag_selector((1 << 31) - 2),
                         aks.SessionKeybagSelector(-((1 << 31) - 2)))
        for uid in (-1, 1, 9, (1 << 31) - 1, 1 << 32, True):
            with self.subTest(uid=uid):
                with self.assertRaises(aks.AKSTransportError):
                    aks.derive_session_keybag_selector(uid)

    def test_authorization_plan_requires_capabilities_before_verify(self):
        plan = aks.AuthorizationPlan()
        with self.assertRaises(aks.AKSTransportError):
            plan.plan_verify_secret(
                2, 12, keybag_handle=aks.SessionKeybagHandle(7),
                selector=aks.SessionKeybagSelector(-10))
        request_wire = plan.request_capabilities(1)
        self.assertEqual(aks.decode_envelope(request_wire),
                         aks.AKSEnvelope(0x4d, 1, 100, False))
        payload_body = struct.pack("<iQI", 0, 4, 0)
        payload_header = aks.protect_header(self._identity(), payload_body)
        payload = struct.pack("<I", 0x50) + payload_header + payload_body
        reply_wire = bytes.fromhex("07cd01000000640000000000")
        self.assertEqual(plan.accept_capabilities_transport(
            reply_wire, payload), 2)
        with self.assertRaises(aks.AKSTransportError):
            plan.plan_verify_secret(
                2, 12, keybag_handle=aks.SessionKeybagHandle(7),
                selector=aks.SessionKeybagSelector(-10))
        environment_wire = plan.request_startup_environment(2)
        self.assertEqual(aks.decode_envelope(environment_wire),
                         aks.AKSEnvelope(0x2a, 2, 0x470, False))
        environment_body = struct.pack("<i", 0)
        environment_header = aks.protect_header(
            self._identity(2), environment_body)
        environment_payload = (struct.pack("<I", 0x50) +
                               environment_header + environment_body)
        plan.accept_startup_environment(
            bytes.fromhex("07aa02000000580000000000"), environment_payload)
        verify_wire = plan.plan_verify_secret(
            3, 12, keybag_handle=aks.derive_session_keybag_handle(
                0x1122334455667780, 8),
            selector=aks.derive_session_keybag_selector(10))
        self.assertEqual(aks.decode_envelope(verify_wire),
                         aks.AKSEnvelope(0x21, 3, 144, False))
        self.assertEqual(plan.verify_metadata,
                         aks.VerifySecretMetadata(
                             aks.SessionKeybagHandle(0x1122334455667788),
                             aks.SessionKeybagSelector(-10)))
        with self.assertRaises(aks.AKSTransportError):
            plan.plan_verify_secret(
                3, 12, keybag_handle=aks.SessionKeybagHandle(7),
                selector=aks.SessionKeybagSelector(-10))

    def test_authorization_plan_rejects_uncorrelated_capabilities_reply(self):
        plan = aks.AuthorizationPlan()
        plan.request_capabilities(1)
        with self.assertRaises(aks.AKSTransportError):
            plan.accept_capabilities_transport(
                bytes.fromhex("07cd02000000640000000000"), bytes(100))

    def test_authorization_plan_rejects_bad_environment_sequence(self):
        plan = aks.AuthorizationPlan()
        with self.assertRaises(aks.AKSTransportError):
            plan.request_startup_environment(2)
        plan.header_version = 2
        request = plan.request_startup_environment(2)
        self.assertEqual(aks.decode_envelope(request).payload_length, 0x470)
        with self.assertRaises(aks.AKSTransportError):
            plan.request_startup_environment(3)
        body = struct.pack("<i", 0)
        payload = (struct.pack("<I", 0x50) +
                   aks.protect_header(self._identity(2), body) + body)
        with self.assertRaises(aks.AKSTransportError):
            plan.accept_startup_environment(
                bytes.fromhex("07aa03000000580000000000"), payload)
        plan.accept_startup_environment(
            bytes.fromhex("07aa02000000580000000000"), payload)
        with self.assertRaises(aks.AKSTransportError):
            plan.accept_startup_environment(
                bytes.fromhex("07aa02000000580000000000"), payload)


if __name__ == "__main__":
    unittest.main()
