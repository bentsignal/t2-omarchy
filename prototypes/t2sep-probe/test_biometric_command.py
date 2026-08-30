import importlib.util
from pathlib import Path
import sys
import struct
import unittest


SPEC = importlib.util.spec_from_file_location(
    "biometric_command", Path(__file__).with_name("biometric-command.py"))
command = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = command
SPEC.loader.exec_module(command)

BRIDGE_SPEC = importlib.util.spec_from_file_location(
    "bridge_protocol_for_command_test", Path(__file__).with_name("bridge-protocol.py"))
bridge = importlib.util.module_from_spec(BRIDGE_SPEC)
assert BRIDGE_SPEC.loader is not None
sys.modules[BRIDGE_SPEC.name] = bridge
BRIDGE_SPEC.loader.exec_module(bridge)


class OrdinaryMatchPayloadTests(unittest.TestCase):
    def test_current_sensor_initialization_command_shapes(self):
        self.assertEqual(command.sensor_readiness_fields(),
                         (0x53, 1, 0, b"", 1))
        self.assertEqual(command.provisioning_state_fields(),
                         (0x10, 1, 0, b"", 4))
        self.assertEqual(command.reset_sensor_fields(),
                         (0x02, 2, 0, b"", 0))
        self.assertEqual(command.sensor_info_fields(),
                         (0x35, 1, 0, b"", 12))
        self.assertEqual(command.bio_device_list_fields(),
                         (0x52, 1, 0, b"", 264))
        self.assertEqual(command.decode_sensor_readiness(b"\x01"), 1)
        self.assertEqual(command.decode_provisioning_state(
            struct.pack("<I", 5)), 5)
        self.assertEqual(command.decode_sensor_info(
            struct.pack("<3I", 1, 12, 7)), command.SensorInfo(1, 12, 7))
        record = command.BIO_DEVICE_RECORD.pack(
            1, bytes(16), 1, bytes(16), 6)
        self.assertEqual(command.decode_bio_device_list_summary(record),
                         command.BioDeviceListSummary(1, 1))

    def test_sensor_initialization_decoders_reject_wrong_shapes(self):
        for output in (b"", bytes(2), bytearray(b"\0")):
            with self.subTest(decoder="readiness", output=output):
                with self.assertRaises(command.BiometricCommandError):
                    command.decode_sensor_readiness(output)
        for output in (b"", bytes(3), bytes(5), bytearray(4)):
            with self.subTest(decoder="provisioning", output=output):
                with self.assertRaises(command.BiometricCommandError):
                    command.decode_provisioning_state(output)
        for output in (b"", bytes(11), bytes(13), bytearray(12),
                       struct.pack("<3I", 1, 11, 7)):
            with self.subTest(decoder="sensor_info", output=output):
                with self.assertRaises(command.BiometricCommandError):
                    command.decode_sensor_info(output)
        for output in (b"x", bytes(265), bytearray(44)):
            with self.subTest(decoder="bio_device", output_type=type(output)):
                with self.assertRaises(command.BiometricCommandError):
                    command.decode_bio_device_list_summary(output)

    def test_bio_device_summary_does_not_disclose_record_data(self):
        builtin = command.BIO_DEVICE_RECORD.pack(
            1, bytes(range(16)), 1, bytes(range(16, 32)), 6)
        external = command.BIO_DEVICE_RECORD.pack(
            2, b"a" * 16, 3, b"b" * 16, 9)
        summary = command.decode_bio_device_list_summary(builtin + external)
        self.assertEqual(summary, command.BioDeviceListSummary(2, 1))
        self.assertEqual(tuple(summary.__dict__),
                         ("record_count", "builtin_record_count"))

    def test_current_user_protected_config_getter_envelope(self):
        self.assertEqual(command.protected_config_fields(user_id=501),
                         (0x2e, 1, 0, b"\xf5\x01\0\0", 32))
        self.assertEqual(command.catacomb_uuid_fields(user_id=501),
                         (0x38, 0, 0, b"\xf5\x01\0\0", 16))

    def test_current_catacomb_save_and_load_codecs(self):
        context = struct.pack("<II16s", 501, 1, bytes(16))
        self.assertEqual(command.builtin_catacomb_save_context(user_id=501), context)
        self.assertEqual(command.prepare_save_catacomb_fields(user_id=501),
                         (0x3d, 2, 0, context, 4))
        self.assertEqual(command.decode_prepared_catacomb_size(
            struct.pack("<I", 4096)), 4096)
        self.assertEqual(command.complete_save_catacomb_fields(
            user_id=501, blob_size=4096), (0x3e, 2, 0, context, 4096))
        self.assertEqual(command.confirm_save_catacomb_fields(user_id=501),
                         (0x3f, 2, 0, context, 0))
        blob = bytearray(64)
        struct.pack_into("<I", blob, 8, 501)
        self.assertEqual(command.load_catacomb_fields(user_id=501, blob=bytes(blob)),
                         (0x40, 1, 0, bytes(blob), 0))
        self.assertEqual(command.current_catacomb_secure_data_fields(b"opaque"),
                         (0x40, 1, 0, b"opaque", 0))
        for invalid in (b"", bytes(command.MAX_CATACOMB_BLOB_SIZE + 1), bytearray(b"x")):
            with self.assertRaises(command.BiometricCommandError):
                command.current_catacomb_secure_data_fields(invalid)

    def test_catacomb_persistence_codecs_reject_unbounded_or_wrong_user_data(self):
        for output in (b"", b"123", struct.pack("<I", 32),
                       struct.pack("<I", command.MAX_CATACOMB_BLOB_SIZE + 1)):
            with self.assertRaises(command.BiometricCommandError):
                command.decode_prepared_catacomb_size(output)
        for size in (32, command.MAX_CATACOMB_BLOB_SIZE + 1, True):
            with self.assertRaises(command.BiometricCommandError):
                command.complete_save_catacomb_fields(user_id=501, blob_size=size)
        blob = bytearray(64)
        struct.pack_into("<I", blob, 8, 502)
        with self.assertRaises(command.BiometricCommandError):
            command.load_catacomb_fields(user_id=501, blob=bytes(blob))

    def test_authorized_user_policy_exact_layout_and_scrubbing(self):
        credential = bytearray(range(16))
        policy = command.UserProtectedPolicy(1, 1, 1, 0)
        request = command.consume_user_policy_credential(
            user_id=501, policy=policy, credential_set=credential)
        view = request.view()
        self.assertEqual(credential, bytearray(16))
        self.assertEqual(len(view), 60)
        self.assertEqual(struct.unpack_from("<7I", view), (501, 1, 1, 1, 0, 0, 16))
        self.assertEqual(view[28:44], bytes(range(16)))
        self.assertEqual(view[44:], bytes(16))
        self.assertNotIn("bytearray", repr(request))
        fields = command.authorized_user_policy_fields(request)
        self.assertEqual(fields[:3], (0x2f, 1, 0))
        self.assertEqual(fields[4], 0)
        request.close()
        self.assertEqual(bytes(view), bytes(60))
        with self.assertRaises(command.BiometricCommandError):
            command.authorized_user_policy_fields(request)

    def test_authorized_user_policy_rejects_partial_or_invalid_inputs(self):
        good = command.UserProtectedPolicy(1, 1, 1, 0)
        cases = ((-1, good, bytearray(16)),
                 (501, command.UserProtectedPolicy(-1, 1, 1, 0), bytearray(16)),
                 (501, command.UserProtectedPolicy(True, 1, 1, 0), bytearray(16)),
                 (501, good, bytearray(15)), (501, good, b"immutable"))
        for user_id, policy, credential in cases:
            with self.subTest(user_id=user_id, policy=policy, length=len(credential)):
                with self.assertRaises(command.BiometricCommandError):
                    command.consume_user_policy_credential(
                        user_id=user_id, policy=policy, credential_set=credential)
                if isinstance(credential, bytearray):
                    self.assertEqual(credential, bytearray(len(credential)))

    def test_exact_token_free_enrollment_payload(self):
        payload = command.encode_ordinary_enroll_payload(user_id=7)
        self.assertEqual(len(payload), 48)
        self.assertEqual(payload[:16].hex(), "00000000070000000000000000000000")
        self.assertEqual(payload[16:], bytes(32))
        self.assertEqual(
            command.decode_ordinary_enroll_payload(payload),
            command.OrdinaryEnrollPayload(0, 7, 0, 0),
        )

    def test_enrollment_decoder_rejects_privileged_variants(self):
        good = command.encode_ordinary_enroll_payload(user_id=7)
        variants = (
            (1).to_bytes(4, "little") + good[4:],
            good[:8] + (1).to_bytes(4, "little") + good[12:],
            good[:12] + (1).to_bytes(4, "little") + good[16:],
            good[:16] + b"x" + good[17:],
        )
        for bad in variants:
            with self.subTest(bad=bad[:20]):
                with self.assertRaises(command.BiometricCommandError):
                    command.decode_ordinary_enroll_payload(bad)

    def test_authorized_current_enrollment_consumes_and_scrubs_credential(self):
        credential = bytearray(range(16))
        request = command.consume_builtin_enrollment_credential(
            user_id=501, credential_set=credential)
        view = request.view()
        self.assertEqual(credential, bytearray(16))

        self.assertEqual(len(view), 68)
        self.assertEqual(struct.unpack_from("<IIII", view, 0),
                         (0, 501, 0, 16))
        self.assertEqual(view[16:32], bytes(range(16)))
        self.assertEqual(view[32:48], bytes(16))
        self.assertEqual(struct.unpack_from("<I", view, 48)[0], 1)
        self.assertEqual(view[52:68], bytes(16))
        self.assertNotIn("bytearray", repr(request))
        fields = command.authorized_enroll_fields(request)
        self.assertEqual(fields[:3], (3, 2, 0))
        self.assertEqual(len(fields[3]), 68)
        self.assertEqual(fields[3][16:32], bytes(range(16)))
        self.assertEqual(fields[4], 0)
        request.close()
        self.assertEqual(bytes(view), bytes(68))
        with self.assertRaises(command.BiometricCommandError):
            request.view()
        with self.assertRaises(command.BiometricCommandError):
            command.authorized_enroll_fields(request)

    def test_authorized_enrollment_rejects_and_scrubs_bad_inputs(self):
        for user_id, credential in ((-1, bytearray(range(16))),
                                    (501, bytearray(15)),
                                    (501, b"not mutable")):
            with self.subTest(user_id=user_id, length=len(credential)):
                with self.assertRaises(command.BiometricCommandError):
                    command.consume_builtin_enrollment_credential(
                        user_id=user_id, credential_set=credential)
                if isinstance(credential, bytearray):
                    self.assertEqual(credential, bytearray(len(credential)))

    def test_exact_default_payload(self):
        payload = command.encode_ordinary_match_payload()
        self.assertEqual(len(payload), 68)
        self.assertEqual(payload[:8].hex(), "00000000ffffffff")
        self.assertEqual(payload[8:], bytes(60))
        self.assertEqual(
            command.decode_ordinary_match_payload(payload),
            command.OrdinaryMatchPayload(0, 0xFFFFFFFF),
        )

    def test_explicit_user_id_is_little_endian(self):
        payload = command.encode_ordinary_match_payload(user_id=0x12345678)
        self.assertEqual(payload[:8].hex(), "0000000078563412")

    def test_rejects_invalid_user_ids(self):
        for value in (-1, 0x100000000, True, "1"):
            with self.subTest(value=value):
                with self.assertRaises(command.BiometricCommandError):
                    command.encode_ordinary_match_payload(user_id=value)

    def test_decoder_rejects_every_special_form(self):
        good = command.encode_ordinary_match_payload()
        for bad in (b"", good[:-1],
                    (1).to_bytes(4, "little") + good[4:],
                    good[:8] + b"\x01" + good[9:]):
            with self.subTest(bad=bad[:12]):
                with self.assertRaises(command.BiometricCommandError):
                    command.decode_ordinary_match_payload(bad)

    def test_exact_operation_fields(self):
        enroll = command.ordinary_enroll_fields(user_id=7)
        self.assertEqual(enroll[:3], (3, 1, 0))
        self.assertEqual(len(enroll[3]), 48)
        self.assertEqual(enroll[4], 0)
        match = command.ordinary_match_fields()
        self.assertEqual(match[:3], (4, 1, 0))
        self.assertEqual(len(match[3]), 68)
        self.assertEqual(match[4], 0)
        self.assertEqual(command.presence_detect_fields(), (0x26, 1, 0, b"", 0))
        self.assertEqual(command.cancel_fields(), (0x0C, 1, 0, b"", 0))

    def test_identity_queries_and_strict_decoders(self):
        self.assertEqual(command.max_identity_count_fields(), (0x0F, 1, 0, b"", 4))
        self.assertEqual(command.free_identity_count_fields(user_id=7),
                         (0x41, 1, 0, b"\x07\0\0\0", 4))
        self.assertEqual(command.identity_list_fields(user_id=7, max_identities=5),
                         (0x42, 1, 0, b"\x07\0\0\0", 100))
        self.assertEqual(command.decode_identity_count(b"\x05\0\0\0"), 5)
        first = command.BiometricIdentity(7, bytes(range(16)))
        second = command.BiometricIdentity(8, bytes(range(16, 32)))
        raw = command.IDENTITY.pack(first.user_id, first.uuid)
        raw += command.IDENTITY.pack(second.user_id, second.uuid)
        self.assertEqual(command.decode_identity_list(raw), (first, second))
        self.assertEqual(command.remove_identity_fields(first),
                         (0x0D, 1, 0, raw[:20], 0))

    def test_current_system_protected_config_codec(self):
        self.assertEqual(command.system_protected_config_fields(),
                         (0x43, 2, 0, b"", 36))
        words = (172800, 5, 5, 1, 1, 1, 1, 14400, 561600)
        decoded = command.decode_system_protected_config(struct.pack("<9I", *words))
        self.assertEqual(tuple(decoded.__dict__.values()), words)
        for bad in (b"", bytes(28), bytes(40)):
            with self.assertRaises(command.BiometricCommandError):
                command.decode_system_protected_config(bad)

    def test_identity_codecs_fail_closed(self):
        for maximum in (0, 65, True):
            with self.assertRaises(command.BiometricCommandError):
                command.identity_list_fields(user_id=7, max_identities=maximum)
        self.assertEqual(command.decode_identity_list(b""), ())
        for output in (b"", b"\x41\0\0\0", b"\0" * 5):
            with self.assertRaises(command.BiometricCommandError):
                command.decode_identity_count(output)
        with self.assertRaises(command.BiometricCommandError):
            command.decode_identity_list(b"x")
        duplicate = command.IDENTITY.pack(7, bytes(16)) * 2
        with self.assertRaises(command.BiometricCommandError):
            command.decode_identity_list(duplicate)
        with self.assertRaises(command.BiometricCommandError):
            command.remove_identity_fields(command.BiometricIdentity(7, b"short"))

    def test_enrollment_delta_requires_one_new_identity(self):
        old = command.BiometricIdentity(7, bytes(16))
        new = command.BiometricIdentity(7, bytes(range(16)))
        self.assertEqual(command.identify_enrollment_delta(
            (old,), (old, new), expected_user_id=7), new)
        bad_snapshots = (
            ((old,), (old,)),
            ((old,), (new,)),
            ((old,), (old, new, command.BiometricIdentity(7, b"x" * 16))),
            ((old,), (old, command.BiometricIdentity(8, bytes(range(16))))),
        )
        for before, after in bad_snapshots:
            with self.subTest(before=before, after=after):
                with self.assertRaises(command.BiometricCommandError):
                    command.identify_enrollment_delta(
                        before, after, expected_user_id=7)

    def test_composes_with_verified_bridge_envelope(self):
        request = bridge.biometric_perform_request(*command.ordinary_match_fields())
        self.assertEqual(request[0:2], (3, 0))
        self.assertEqual(request[2][:8].hex(), "424d040001000000")
        self.assertEqual(request[2][8:16].hex(), "00000000ffffffff")
        self.assertEqual(len(request[2]), 76)
        self.assertEqual(request[3], 0)

    def test_strict_catalina_match_identity_decoder(self):
        blob = bytearray(command.CATALINA_MATCH_RESULT_BASE_SIZE + 8)
        struct.pack_into("<I", blob, 0, 7)
        blob[4:20] = bytes(range(16))
        struct.pack_into("<I", blob, command.CATALINA_MATCH_RESULT_LOTL_COUNT_OFFSET, 2)
        struct.pack_into("<2I", blob, command.CATALINA_MATCH_RESULT_LOTL_OFFSET, 9, 11)
        result = command.decode_catalina_match_identity(bytes(blob))
        self.assertEqual(result.user_id, 7)
        self.assertEqual(result.uuid, bytes(range(16)))
        self.assertEqual(result.lotl_user_ids, (9, 11))

    def test_trusted_identity_offsets_disclose_only_locations(self):
        identity = command.BiometricIdentity(7, bytes(range(16)))
        record = command.IDENTITY.pack(identity.user_id, identity.uuid)
        self.assertEqual(command.trusted_identity_offsets(
            b"abc" + record + b"x" + record, (identity,)), ((3, 24),))
        self.assertEqual(command.trusted_identity_offsets(b"none", (identity,)), ((),))

    def test_match_identity_decoder_fails_closed(self):
        base = bytearray(command.CATALINA_MATCH_RESULT_BASE_SIZE)
        for bad in (b"", bytes(base) + b"x"):
            with self.assertRaises(command.BiometricCommandError):
                command.decode_catalina_match_identity(bad)
        struct.pack_into("<I", base, command.CATALINA_MATCH_RESULT_LOTL_COUNT_OFFSET,
                         command.MAX_LOTL_USER_IDS + 1)
        with self.assertRaises(command.BiometricCommandError):
            command.decode_catalina_match_identity(bytes(base))

    def test_exact_current_v2_match_identity_decoder(self):
        blob = bytearray(command.CURRENT_MATCH_RESULT_V2_SIZE)
        struct.pack_into("<I16s", blob, 0, 7, bytes(range(16)))
        result = command.decode_current_match_identity_v2(bytes(blob))
        self.assertEqual((result.user_id, result.uuid, result.lotl_user_ids),
                         (7, bytes(range(16)), ()))
        for bad in (bytes(blob[:-1]), bytes(blob) + b"x"):
            with self.assertRaises(command.BiometricCommandError):
                command.decode_current_match_identity_v2(bad)

    def test_terminal_service_events_are_bound_to_type_and_version(self):
        identity = command.BiometricIdentity(7, bytes(range(16)))
        raw_identity = command.IDENTITY.pack(identity.user_id, identity.uuid)
        self.assertEqual(command.decode_catalina_enroll_result_event(
            status=0xE3FF8003, version=1, data=raw_identity), identity)

        match = bytearray(command.CATALINA_MATCH_RESULT_BASE_SIZE)
        struct.pack_into("<I", match, 0, identity.user_id)
        match[4:20] = identity.uuid
        self.assertEqual(command.decode_catalina_match_result_event(
            status=0xE3FF8002, version=1, data=bytes(match)).user_id, 7)
        match_v2 = bytearray(command.CURRENT_MATCH_RESULT_V2_SIZE)
        struct.pack_into("<I16s", match_v2, 0, identity.user_id, identity.uuid)
        self.assertEqual(command.decode_catalina_match_result_event(
            status=0xE3FF8002, version=2, data=bytes(match_v2)).user_id, 7)

        for status, version, data in (
            (0xE3FF8002, 1, raw_identity),
            (0xE3FF8003, 2, raw_identity),
            (0xE3FF8003, 1, raw_identity + b"x"),
        ):
            with self.subTest(status=status, version=version):
                with self.assertRaises(command.BiometricCommandError):
                    command.decode_catalina_enroll_result_event(
                        status=status, version=version, data=data)

        self.assertEqual(command.decode_terminal_biometric_event(
            active_operation="enroll", status=0xE3FF8003, version=1,
            data=raw_identity), identity)
        for operation, status, data in (
            ("match", 0xE3FF8003, raw_identity),
            ("enroll", 0xE3FF8002, bytes(match)),
            ("", 0xE3FF8003, raw_identity),
        ):
            with self.subTest(operation=operation, status=status):
                with self.assertRaises(command.BiometricCommandError):
                    command.decode_terminal_biometric_event(
                        active_operation=operation, status=status,
                        version=1, data=data)

    def test_current_bridge_service_event_record(self):
        record = bytearray(43)
        struct.pack_into("<II", record, 8, 0xE3FF8002, 1)
        struct.pack_into("<Q", record, 24, 7)
        struct.pack_into("<Q", record, 32, 3)
        record[40:] = b"abc"
        decoded = command.decode_bridge_service_event(
            [9, 0xE3FF8000, bytes(record), 11, 12])
        self.assertEqual((decoded.status, decoded.version, decoded.ordinal,
                          decoded.data, decoded.reference_timestamp,
                          decoded.continuous_time_delta),
                         (0xE3FF8002, 1, 7, b"abc", 11, 12))
        for bad in (
            [8, 0xE3FF8000, bytes(record), 11, 12],
            [9, 0xE3FF8001, bytes(record), 11, 12],
            [9, 0xE3FF8000, bytes(record[:-1]), 11, 12],
        ):
            with self.assertRaises(command.BiometricCommandError):
                command.decode_bridge_service_event(bad)


if __name__ == "__main__":
    unittest.main()
