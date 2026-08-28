import importlib.util
from pathlib import Path
import struct
import sys
import unittest


SPEC = importlib.util.spec_from_file_location(
    "macos_biometric_command_evidence",
    Path(__file__).with_name("macos-biometric-command-evidence.py"))
evidence = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = evidence
SPEC.loader.exec_module(evidence)


def fixture(strings, patterns, *, cpu=evidence.CPU_TYPE_X86_64):
    header = struct.pack("<IIIIIIII", evidence.MH_MAGIC_64, cpu, 3, 2, 0, 0, 0, 0)
    return header + b"|".join((*strings, *patterns.values()))


class CommandEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.daemon = fixture(evidence.DAEMON_STRINGS, evidence.DAEMON_PATTERNS)
        self.support = fixture(evidence.SUPPORT_STRINGS, evidence.SUPPORT_PATTERNS)

    def test_recovers_exact_safe_command_facts(self):
        result = evidence.inspect(self.daemon, self.support)
        self.assertEqual(result["command_version"], 1)
        self.assertEqual(result["enroll_command"], 3)
        self.assertEqual(result["enroll_payload_size"], 48)
        self.assertEqual(result["match_command"], 4)
        self.assertEqual(result["match_payload_size"], 68)
        self.assertEqual(result["ordinary_processed_flags"], 0)
        self.assertEqual(result["default_user_id"], 0xFFFFFFFF)
        self.assertEqual(result["presence_command"], 0x26)
        self.assertEqual(result["cancel_command"], 0x0C)
        self.assertEqual(result["match_result_base_size"], 0xC70)
        self.assertEqual(result["match_result_lotl_count_offset"], 0xC6C)
        self.assertEqual(result["identity_list_command"], 0x42)
        self.assertEqual(result["identity_record_size"], 20)
        self.assertEqual(result["remove_identity_command"], 0x0D)
        self.assertEqual(result["max_identity_count_command"], 0x0F)
        self.assertEqual(result["free_identity_count_command"], 0x41)
        self.assertEqual(result["match_result_service_event"], 0xE3FF8002)
        self.assertEqual(result["enroll_result_service_event"], 0xE3FF8003)
        self.assertEqual(result["service_event_version"], 1)

    def test_rejects_wrong_architecture(self):
        bad = fixture(evidence.DAEMON_STRINGS, evidence.DAEMON_PATTERNS,
                      cpu=0x0100000C)
        with self.assertRaisesRegex(evidence.CommandEvidenceError, "x86_64"):
            evidence.inspect(bad, self.support)

    def test_rejects_each_missing_daemon_fact(self):
        facts = (*evidence.DAEMON_STRINGS, *evidence.DAEMON_PATTERNS.values())
        for fact in facts:
            with self.subTest(fact=fact[:32]):
                damaged = self.daemon.replace(fact, b"X" * len(fact), 1)
                with self.assertRaisesRegex(evidence.CommandEvidenceError,
                                            "daemon command"):
                    evidence.inspect(damaged, self.support)

    def test_rejects_each_missing_support_fact(self):
        facts = (*evidence.SUPPORT_STRINGS, *evidence.SUPPORT_PATTERNS.values())
        for fact in facts:
            with self.subTest(fact=fact[:32]):
                damaged = self.support.replace(fact, b"X" * len(fact), 1)
                with self.assertRaisesRegex(evidence.CommandEvidenceError,
                                            "operation default"):
                    evidence.inspect(self.daemon, damaged)

    def test_rejects_ambiguous_instruction_evidence(self):
        duplicate = self.daemon + evidence.DAEMON_PATTERNS[
            "match command 4 with 68-byte input"]
        with self.assertRaisesRegex(evidence.CommandEvidenceError, "ambiguous"):
            evidence.inspect(duplicate, self.support)


if __name__ == "__main__":
    unittest.main()
