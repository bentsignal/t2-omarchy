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
        match = command.ordinary_match_fields()
        self.assertEqual(match[:3], (4, 1, 0))
        self.assertEqual(len(match[3]), 68)
        self.assertEqual(match[4], 0)
        self.assertEqual(command.presence_detect_fields(), (0x26, 1, 0, b"", 0))
        self.assertEqual(command.cancel_fields(), (0x0C, 1, 0, b"", 0))

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
