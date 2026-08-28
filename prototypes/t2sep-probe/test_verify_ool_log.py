import importlib.util
from pathlib import Path
import sys
import unittest


SPEC = importlib.util.spec_from_file_location(
    "verify_ool_log", Path(__file__).with_name("verify-ool-log.py"))
verify = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = verify
SPEC.loader.exec_module(verify)

PREFIX = "Aug 28 01:00:00 intelmac kernel: t2sep_probe 0000:04:00.2: "


def line(value):
    return PREFIX + value


GOOD = "\n".join((
    line("bounded discovery complete: records=2 identities=1 sbio=yes limits=yes result=0"),
    line("OOL registration request: opcode=2 tag=2 words=08020200 00000100 00004000 00000000"),
    line("OOL acknowledgement: request_opcode=2 tag=2 raw=08820200 00000000 12345678 00000000 decoded_endpoint=0 decoded_tag=2 decoded_opcode=130 decoded_target=8"),
    line("OOL registration request: opcode=3 tag=3 words=08030300 00000200 0004b000 00000000"),
    line("OOL acknowledgement: request_opcode=3 tag=3 raw=09830300 00000000 87654321 00000000 decoded_endpoint=0 decoded_tag=3 decoded_opcode=131 decoded_target=9"),
    line("issued Apple CPU-stop value 5 at +0x8024; payload FIFOs accessed only by explicit bounded gates"),
    line("OOL buffers scrubbed and released after CPU stop; result=0"),
))


class VerifyOolLogTests(unittest.TestCase):
    def test_emits_observed_profile_without_guessing(self):
        self.assertEqual(verify.verify(GOOD), ((130, 8), (131, 9)))

    def test_rejects_status_tag_order_and_cleanup_failures(self):
        mutations = (
            GOOD.replace("raw=08820200 00000000", "raw=08820200 00000001"),
            GOOD.replace("decoded_tag=2", "decoded_tag=4"),
            GOOD.replace("opcode=2 tag=2", "opcode=3 tag=2", 1),
            GOOD.replace(line("OOL buffers scrubbed and released after CPU stop; result=0"), ""),
        )
        for transcript in mutations:
            with self.subTest(transcript=transcript):
                with self.assertRaises(verify.VerificationError):
                    verify.verify(transcript)

    def test_rejects_raw_decode_disagreement_and_error_flags(self):
        with self.assertRaises(verify.VerificationError):
            verify.verify(GOOD.replace("decoded_opcode=130", "decoded_opcode=129"))
        with self.assertRaises(verify.VerificationError):
            verify.verify(GOOD.replace(
                "08820200 00000000 12345678 00000000",
                "08820200 00000000 12345678 00040000"))


if __name__ == "__main__":
    unittest.main()
