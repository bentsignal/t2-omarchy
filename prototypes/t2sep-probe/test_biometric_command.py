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

    def test_match_identity_decoder_fails_closed(self):
        base = bytearray(command.CATALINA_MATCH_RESULT_BASE_SIZE)
        for bad in (b"", bytes(base) + b"x"):
            with self.assertRaises(command.BiometricCommandError):
                command.decode_catalina_match_identity(bad)
        struct.pack_into("<I", base, command.CATALINA_MATCH_RESULT_LOTL_COUNT_OFFSET,
                         command.MAX_LOTL_USER_IDS + 1)
        with self.assertRaises(command.BiometricCommandError):
            command.decode_catalina_match_identity(bytes(base))


if __name__ == "__main__":
    unittest.main()
