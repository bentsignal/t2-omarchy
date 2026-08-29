import importlib.util
from pathlib import Path
import sys
import unittest


SPEC = importlib.util.spec_from_file_location(
    "verify_credential_ool_log",
    Path(__file__).with_name("verify-credential-ool-log.py"))
verify = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = verify
SPEC.loader.exec_module(verify)

PREFIX = "Aug 28 01:00:00 intelmac kernel: t2sep_probe 0000:04:00.2: "


def line(value):
    return PREFIX + value


GOOD = "\n".join((
    line("temporarily enabled PCI memory decoding for this probe"),
    line("allocated MSI vectors 108 and 109"),
    line("control NOP response passed strict validation"),
    line("pinned OOL buffers: target=7 in_dma=0x0000000000100000 in_size=16384 out_dma=0x0000000000200000 out_size=16384"),
    line("OOL registration request: opcode=2 tag=2 words=07020200 00000100 00004000 00000000"),
    line("OOL acknowledgement: request_opcode=2 tag=2 raw=07010200 00000000 00000000 00101200 decoded_endpoint=0 decoded_tag=2 decoded_opcode=1 decoded_target=7"),
    line("OOL registration request: opcode=3 tag=3 words=07030300 00000200 00004000 00000000"),
    line("OOL acknowledgement: request_opcode=3 tag=3 raw=07010300 00000000 00000000 00102300 decoded_endpoint=0 decoded_tag=3 decoded_opcode=1 decoded_target=7"),
    line("issued Apple CPU-stop value 5 at +0x8024; payload FIFOs accessed only by explicit bounded gates"),
    line("OOL buffers scrubbed and released after CPU stop; result=0"),
    line("MSI observations: vector0=3 vector1=3"),
    line("restored PCI command word from 0x0002 to original 0x0006"),
    line("temporary PCI enable released before probe returned"),
    line("read-only probe removed"),
))


class VerifyCredentialOolLogTests(unittest.TestCase):
    def test_accepts_exact_aks_transcript(self):
        self.assertEqual(verify.verify(GOOD, 7), ((1, 7), (1, 7)))

    def test_ignores_unsigned_module_loader_warning(self):
        warning = ("Aug 28 01:00:00 intelmac kernel: t2sep_probe: module "
                   "verification failed: signature and/or required key missing")
        self.assertEqual(verify.verify(warning + "\n" + GOOD, 7),
                         ((1, 7), (1, 7)))

    def test_rejects_wrong_service_shape_status_and_order(self):
        mutations = (
            (GOOD, 10),
            (GOOD.replace("00004000", "0004b000", 1), 7),
            (GOOD.replace("raw=07010200 00000000", "raw=07010200 00000001"), 7),
            (GOOD.replace("raw=07010200 00000000 00000000",
                          "raw=07010200 00000000 00000001"), 7),
            (GOOD.replace("opcode=3 tag=3", "opcode=3 tag=2", 1), 7),
            (GOOD.replace("out_dma=0x0000000000200000",
                          "out_dma=0x0000000000100000"), 7),
            (GOOD.replace("vector0=3", "vector0=0"), 7),
            (GOOD.replace(line("control NOP response passed strict validation"), ""), 7),
            (GOOD.replace(line("OOL buffers scrubbed and released after CPU stop; result=0"), ""), 7),
            (GOOD.replace(line("read-only probe removed"), ""), 7),
        )
        for transcript, endpoint in mutations:
            with self.subTest(endpoint=endpoint):
                with self.assertRaises(verify.VerificationError):
                    verify.verify(transcript, endpoint)

    def test_rejects_unapproved_endpoint(self):
        with self.assertRaises(verify.VerificationError):
            verify.verify(GOOD, 8)


if __name__ == "__main__":
    unittest.main()
