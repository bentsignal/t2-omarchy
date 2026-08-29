import importlib.util
from pathlib import Path
import sys
import unittest


SPEC = importlib.util.spec_from_file_location(
    "verify_control_nop_log", Path(__file__).with_name("verify-control-nop-log.py"))
verify = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = verify
SPEC.loader.exec_module(verify)

PREFIX = "Aug 28 01:00:00 intelmac kernel: t2sep_probe 0000:04:00.2: "


def line(value):
    return PREFIX + value


GOOD = "\n".join((
    line("temporarily enabled PCI memory decoding for this probe"),
    line("allocated MSI vectors 108 and 109"),
    line("control NOP response after 10 ms: 00010100 00000000 00000000 00100100"),
    line("control NOP response passed strict validation"),
    line("issued Apple CPU-stop value 5 at +0x8024; payload FIFOs accessed only by explicit bounded gates"),
    line("MSI observations: vector0=1 vector1=1"),
    line("restored PCI command word from 0x0002 to original 0x0006"),
    line("temporary PCI enable released before probe returned"),
    line("read-only probe removed"),
))


class VerifyControlNopLogTests(unittest.TestCase):
    def test_accepts_exact_complete_probe(self):
        self.assertEqual(verify.verify(GOOD), 10)

    def test_rejects_bad_response_failure_and_incomplete_lifecycle(self):
        cases = (
            GOOD.replace("00010100", "00000100"),
            GOOD.replace("00100100", "00140100"),
            GOOD.replace("after 10 ms", "after 5001 ms"),
            GOOD.replace("vector1=1", "vector1=0"),
            GOOD.replace(line("control NOP response passed strict validation"),
                         line("control NOP response failed strict validation")),
            GOOD.replace(
                line("issued Apple CPU-stop value 5 at +0x8024; payload FIFOs accessed only by explicit bounded gates"),
                line("OOL registration request: opcode=2 tag=2 words=07020200 00000100 00004000 00000000") + "\n" +
                line("issued Apple CPU-stop value 5 at +0x8024; payload FIFOs accessed only by explicit bounded gates")),
            GOOD.replace(line("read-only probe removed"), ""),
        )
        for transcript in cases:
            with self.subTest():
                with self.assertRaises(verify.VerificationError):
                    verify.verify(transcript)

    def test_ignores_unqualified_loader_warning_and_rejects_non_text(self):
        warning = ("Aug 28 01:00:00 intelmac kernel: t2sep_probe: module "
                   "verification failed: signature missing")
        self.assertEqual(verify.verify(warning + "\n" + GOOD), 10)
        with self.assertRaises(verify.VerificationError):
            verify.verify(b"")


if __name__ == "__main__":
    unittest.main()
