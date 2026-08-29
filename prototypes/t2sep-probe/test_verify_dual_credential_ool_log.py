import importlib.util
from pathlib import Path
import sys
import unittest


SPEC = importlib.util.spec_from_file_location(
    "verify_dual_credential_ool_log",
    Path(__file__).with_name("verify-dual-credential-ool-log.py"))
verify = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = verify
SPEC.loader.exec_module(verify)

PREFIX = "Aug 29 01:00:00 intelmac kernel: t2sep_probe 0000:04:00.2: "


def line(value):
    return PREFIX + value


GOOD = "\n".join((
    line("temporarily enabled PCI memory decoding for this probe"),
    line("allocated MSI vectors 108 and 109"),
    line("control NOP response passed strict validation"),
    line("pinned OOL buffers: target=7 in_dma=0x0000000000100000 in_size=16384 out_dma=0x0000000000200000 out_size=16384"),
    line("pinned OOL buffers: target=10 in_dma=0x0000000000300000 in_size=16384 out_dma=0x0000000000400000 out_size=16384"),
    line("OOL registration request: opcode=2 tag=2 words=07020200 00000100 00004000 00000000"),
    line("OOL acknowledgement: request_opcode=2 tag=2 raw=07010200 00000000 00000000 00101200 decoded_endpoint=0 decoded_tag=2 decoded_opcode=1 decoded_target=7"),
    line("OOL registration request: opcode=3 tag=3 words=07030300 00000200 00004000 00000000"),
    line("OOL acknowledgement: request_opcode=3 tag=3 raw=07010300 00000000 00000000 00102300 decoded_endpoint=0 decoded_tag=3 decoded_opcode=1 decoded_target=7"),
    line("OOL registration request: opcode=2 tag=4 words=0a020400 00000300 00004000 00000000"),
    line("OOL acknowledgement: request_opcode=2 tag=4 raw=0a010400 00000000 00000000 00103400 decoded_endpoint=0 decoded_tag=4 decoded_opcode=1 decoded_target=10"),
    line("OOL registration request: opcode=3 tag=5 words=0a030500 00000400 00004000 00000000"),
    line("OOL acknowledgement: request_opcode=3 tag=5 raw=0a010500 00000000 00000000 00104500 decoded_endpoint=0 decoded_tag=5 decoded_opcode=1 decoded_target=10"),
    line("issued Apple CPU-stop value 5 at +0x8024; payload FIFOs accessed only by explicit bounded gates"),
    line("OOL buffers scrubbed and released after CPU stop; result=0"),
    line("MSI observations: vector0=5 vector1=5"),
    line("restored PCI command word from 0x0002 to original 0x0006"),
    line("temporary PCI enable released before probe returned"),
    line("read-only probe removed"),
))


class VerifyDualCredentialOolLogTests(unittest.TestCase):
    def test_accepts_exact_simultaneous_profiles(self):
        self.assertEqual(verify.verify(GOOD),
                         ((7, 1, 7), (7, 1, 7),
                          (10, 1, 10), (10, 1, 10)))

    def test_rejects_overlap_profile_changes_order_and_incomplete_teardown(self):
        mutations = (
            GOOD.replace("in_dma=0x0000000000300000",
                         "in_dma=0x0000000000100000"),
            GOOD.replace("raw=0a010400", "raw=0a020400"),
            GOOD.replace("opcode=2 tag=4", "opcode=2 tag=6", 1),
            GOOD.replace(line("OOL buffers scrubbed and released after CPU stop; result=0"), ""),
            GOOD.replace(line("read-only probe removed"), ""),
        )
        for transcript in mutations:
            with self.subTest(transcript=transcript):
                with self.assertRaises(verify.VerificationError):
                    verify.verify(transcript)


if __name__ == "__main__":
    unittest.main()
