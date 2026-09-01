import importlib.util
from pathlib import Path
import struct
import sys
import unittest


SPEC = importlib.util.spec_from_file_location(
    "macos_calibration_accessory_evidence",
    Path(__file__).with_name("macos-calibration-accessory-evidence.py"))
evidence = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = evidence
SPEC.loader.exec_module(evidence)


def fixture():
    header = struct.pack("<IIIIIIII", evidence.MH_MAGIC_64,
                         evidence.CPU_TYPE_X86_64, 3, 2, 0, 0, 0, 0)
    patterns = (evidence.EEPROM_METHOD, evidence.FDR_METHOD,
                evidence.BIO_DEVICE_LIST, evidence.ACCESSORY_INFO_INPUT,
                evidence.ACCESSORY_INFO_COMMAND, evidence.MATCH_BASE_INPUT,
                evidence.MATCH_SELECTION_APPEND,
                evidence.MATCH_SELECTION_DECODE,
                evidence.SYSTEM_SLEEP_STATE_COMMAND,
                evidence.BUILTIN_RECORD_PREFIX,
                evidence.BUILTIN_RECORD_GROUP, evidence.BUILTIN_RECORD_FLAGS,
                evidence.SENSOR_INFO, evidence.SENSOR_INFO_STORE,
                evidence.SENSOR_TYPE_GETTER)
    return header + b"".join(evidence.REQUIRED) + b"".join(patterns)


class CalibrationAccessoryEvidenceTests(unittest.TestCase):
    def test_accepts_exact_shapes(self):
        support = (evidence.SUPPORT_CACHE_PROLOGUE
                   + evidence.SUPPORT_RECORD_ALLOCATION
                   + evidence.SUPPORT_MATCH_DEFAULTS
                   + evidence.SUPPORT_MATCH_USER_FILTER
                   + evidence.SUPPORT_MATCH_FLAG_MAP)
        result = evidence.inspect(fixture(), support, evidence.SUPPORT_UUID)
        self.assertEqual(result["eeprom_method"], 5)
        self.assertEqual(result["fdr_method"], 11)
        self.assertEqual(result["bio_device_command"], 0x52)
        self.assertEqual(result["bio_device_record_size"], 44)
        self.assertEqual(result["accessory_info_command"], 0x54)
        self.assertEqual(result["accessory_info_input_size"], 20)
        self.assertEqual(result["accessory_info_output_size"], 83)
        self.assertEqual(result["match_command"], 4)
        self.assertEqual(result["match_base_input_size"], 68)
        self.assertEqual(result["match_processed_flags_clear_mask"], 0x80)
        self.assertEqual(result["match_selection_header_size"], 8)
        self.assertEqual(result["match_selection_record_size"], 20)
        self.assertEqual(result["match_default_processed_flags"], 0)
        self.assertEqual(result["match_default_user_id"], 0xFFFFFFFF)
        self.assertTrue(result["match_user_id_is_filter_derived"])
        self.assertEqual(result["match_for_unlock_flags"], 1)
        self.assertEqual(result["match_for_prearm_flags"], 0x100)
        self.assertEqual(result["match_selected_identity_flags"], 0x4000)
        self.assertEqual(result["system_sleep_state_command"], 0x57)

    def test_rejects_wrong_architecture_uuid_and_support(self):
        support = (evidence.SUPPORT_CACHE_PROLOGUE
                   + evidence.SUPPORT_RECORD_ALLOCATION
                   + evidence.SUPPORT_MATCH_DEFAULTS
                   + evidence.SUPPORT_MATCH_USER_FILTER
                   + evidence.SUPPORT_MATCH_FLAG_MAP)
        bad_arch = bytearray(fixture())
        struct.pack_into("<I", bad_arch, 4, 0x0100000C)
        with self.assertRaises(evidence.EvidenceError):
            evidence.inspect(bytes(bad_arch), support, evidence.SUPPORT_UUID)
        with self.assertRaises(evidence.EvidenceError):
            evidence.inspect(fixture(), support, "00000000-0000-0000-0000-000000000000")
        with self.assertRaises(evidence.EvidenceError):
            evidence.inspect(fixture(), b"wrong", evidence.SUPPORT_UUID)

    def test_rejects_each_daemon_pattern_mutation(self):
        support = (evidence.SUPPORT_CACHE_PROLOGUE
                   + evidence.SUPPORT_RECORD_ALLOCATION
                   + evidence.SUPPORT_MATCH_DEFAULTS
                   + evidence.SUPPORT_MATCH_FLAG_MAP)
        patterns = (evidence.EEPROM_METHOD, evidence.FDR_METHOD,
                    evidence.BIO_DEVICE_LIST, evidence.ACCESSORY_INFO_INPUT,
                    evidence.ACCESSORY_INFO_COMMAND, evidence.MATCH_BASE_INPUT,
                    evidence.MATCH_SELECTION_APPEND,
                    evidence.MATCH_SELECTION_DECODE,
                    evidence.SYSTEM_SLEEP_STATE_COMMAND,
                    evidence.BUILTIN_RECORD_PREFIX,
                    evidence.BUILTIN_RECORD_GROUP, evidence.BUILTIN_RECORD_FLAGS,
                    evidence.SENSOR_INFO, evidence.SENSOR_INFO_STORE,
                    evidence.SENSOR_TYPE_GETTER)
        for pattern in patterns:
            damaged = fixture().replace(pattern, bytes([pattern[0] ^ 1]) + pattern[1:], 1)
            with self.assertRaises(evidence.EvidenceError):
                evidence.inspect(damaged, support, evidence.SUPPORT_UUID)

    def test_rejects_each_support_pattern_mutation(self):
        patterns = (evidence.SUPPORT_CACHE_PROLOGUE,
                    evidence.SUPPORT_RECORD_ALLOCATION,
                    evidence.SUPPORT_MATCH_DEFAULTS,
                    evidence.SUPPORT_MATCH_USER_FILTER,
                    evidence.SUPPORT_MATCH_FLAG_MAP)
        support = b"".join(patterns)
        for pattern in patterns:
            damaged = support.replace(
                pattern, bytes([pattern[0] ^ 1]) + pattern[1:], 1)
            with self.assertRaises(evidence.EvidenceError):
                evidence.inspect(fixture(), damaged, evidence.SUPPORT_UUID)


if __name__ == "__main__":
    unittest.main()
