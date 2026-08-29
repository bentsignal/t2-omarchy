import importlib.util
from pathlib import Path
import sys
import unittest


SPEC = importlib.util.spec_from_file_location(
    "verify_aks_capabilities_log",
    Path(__file__).with_name("verify-aks-capabilities-log.py"))
verify = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = verify
SPEC.loader.exec_module(verify)

PREFIX = "Aug 28 23:00:00 intelmac kernel: t2sep_probe 0000:04:00.2: "


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
    line("AKS capabilities request: endpoint=7 selector=0x4d tag=4 length=100 header_version=1"),
    line("AKS capabilities envelope: raw=0004cd07 00640000 00000000 00000000"),
    line("AKS capabilities reply passed strict validation: status=0 remote_header_version=2"),
    line("issued Apple CPU-stop value 5 at +0x8024; payload FIFOs accessed only by explicit bounded gates"),
    line("OOL buffers scrubbed and released after CPU stop; result=0"),
    line("MSI observations: vector0=3 vector1=3"),
    line("restored PCI command word from 0x0002 to original 0x0006"),
    line("temporary PCI enable released before probe returned"),
    line("read-only probe removed"),
))


class VerifyAksCapabilitiesLogTests(unittest.TestCase):
    def test_accepts_complete_strict_transcript(self):
        self.assertEqual(verify.verify(GOOD), 2)

    def test_rejects_changed_or_missing_capability_evidence(self):
        mutations = (
            GOOD.replace("selector=0x4d", "selector=0x4c"),
            GOOD.replace("raw=0004cd07", "raw=0005cd07"),
            GOOD.replace("status=0", "status=-1"),
            GOOD.replace("remote_header_version=2", "remote_header_version=0"),
            GOOD.replace(line("AKS capabilities envelope: raw=0004cd07 00640000 00000000 00000000"), ""),
            GOOD.replace(
                line("AKS capabilities request: endpoint=7 selector=0x4d tag=4 length=100 header_version=1") + "\n",
                "").replace(
                    line("issued Apple CPU-stop value 5 at +0x8024; payload FIFOs accessed only by explicit bounded gates"),
                    line("issued Apple CPU-stop value 5 at +0x8024; payload FIFOs accessed only by explicit bounded gates") + "\n" +
                    line("AKS capabilities request: endpoint=7 selector=0x4d tag=4 length=100 header_version=1")),
        )
        for transcript in mutations:
            with self.subTest():
                with self.assertRaises(verify.VerificationError):
                    verify.verify(transcript)

    def test_caps_newer_remote_version_like_apple(self):
        self.assertEqual(
            verify.verify(GOOD.replace("remote_header_version=2",
                                       "remote_header_version=99")), 99)


if __name__ == "__main__":
    unittest.main()
