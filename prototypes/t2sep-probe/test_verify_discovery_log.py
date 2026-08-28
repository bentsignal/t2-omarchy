import importlib.util
from pathlib import Path
import sys
import unittest


MODULE_PATH = Path(__file__).with_name("verify-discovery-log.py")
SPEC = importlib.util.spec_from_file_location("verify_discovery_log", MODULE_PATH)
verifier = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = verifier
SPEC.loader.exec_module(verifier)


PREFIX = "Aug 27 23:00:00 intelmac kernel: t2sep_probe 0000:04:00.2: "


def line(message):
    return PREFIX + message


def valid_log():
    return "\n".join((
        "unrelated service log",
        line("control NOP response passed strict validation"),
        line("discovery candidate 0: 080000fd 6f696273 00000000 00100100"),
        line("discovery identity: id=0x8 name=6f696273"),
        line("discovery candidate 1: 080100fd 4b014104 00000000 00100100"),
        line("discovery OOL: id=0x8 in=4..65 pages out=1..75 pages"),
        line("bounded discovery complete: records=2 identities=1 sbio=yes limits=yes result=0"),
        line("issued Apple CPU-stop value 5 at +0x8024; payload FIFOs accessed only by explicit bounded gates"),
    ))


class DiscoveryLogVerifierTests(unittest.TestCase):
    def test_accepts_one_complete_cursor_bounded_session(self):
        result = verifier.verify_log(valid_log())
        self.assertEqual(result, verifier.VerificationResult(2, 1, (4, 65, 1, 75)))

    def test_rejects_missing_or_duplicate_lifecycle_events(self):
        original = valid_log()
        cases = (
            original.replace(line("control NOP response passed strict validation") + "\n", ""),
            original.replace(line("control NOP response passed strict validation"),
                             line("control NOP response passed strict validation") + "\n"
                             + line("control NOP response passed strict validation")),
            original.replace(line("bounded discovery complete: records=2 identities=1 sbio=yes limits=yes result=0") + "\n", ""),
            original.replace(line("issued Apple CPU-stop value 5 at +0x8024; payload FIFOs accessed only by explicit bounded gates"), ""),
        )
        for text in cases:
            with self.subTest(text=text):
                with self.assertRaises(verifier.VerificationError):
                    verifier.verify_log(text)

    def test_rejects_reordered_truncated_and_disagreeing_records(self):
        original = valid_log()
        cases = (
            original.replace("candidate 0", "candidate 1"),
            original.replace(line("discovery identity: id=0x8 name=6f696273") + "\n", ""),
            original.replace("identity: id=0x8", "identity: id=0x9"),
            original.replace("out=1..75", "out=1..74"),
            original.replace("records=2 identities=1", "records=3 identities=1"),
            original.replace("sbio=yes limits=yes result=0", "sbio=no limits=yes result=0"),
            original.replace("result=0", "result=-71"),
        )
        for text in cases:
            with self.subTest(text=text):
                with self.assertRaises(verifier.VerificationError):
                    verifier.verify_log(text)

    def test_replays_candidate_bytes_and_requires_usable_sbio(self):
        malformed_transport = valid_log().replace(
            "080000fd 6f696273 00000000 00100100",
            "080000fd 6f696273 00000000 00140100",
        )
        with self.assertRaisesRegex(verifier.VerificationError, "offline replay"):
            verifier.verify_log(malformed_transport)

        xart = valid_log().replace("080000fd 6f696273", "130000fd 74726178")
        xart = xart.replace("id=0x8 name=6f696273", "id=0x13 name=74726178")
        xart = xart.replace("080100fd", "130100fd")
        xart = xart.replace("id=0x8 in=", "id=0x13 in=")
        with self.assertRaisesRegex(verifier.VerificationError, "usable sbio"):
            verifier.verify_log(xart)

    def test_rejects_failure_lines_and_mixed_stale_sessions(self):
        failure = valid_log().replace(
            line("bounded discovery complete"),
            line("discovery transport error") + "\n" + line("bounded discovery complete"),
        )
        with self.assertRaisesRegex(verifier.VerificationError, "failure"):
            verifier.verify_log(failure)
        with self.assertRaises(verifier.VerificationError):
            verifier.verify_log(valid_log() + "\n" + valid_log())

    def test_rejects_non_text(self):
        with self.assertRaises(verifier.VerificationError):
            verifier.verify_log(b"log")


if __name__ == "__main__":
    unittest.main()
