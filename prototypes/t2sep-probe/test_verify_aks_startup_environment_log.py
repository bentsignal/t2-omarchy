import importlib.util
from pathlib import Path
import sys
import unittest


SPEC = importlib.util.spec_from_file_location(
    "verify_aks_startup_environment_log",
    Path(__file__).with_name("verify-aks-startup-environment-log.py"))
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
    line("OOL registration request: opcode=2 tag=2 words=07020200 00000100 00004000 00000000"),
    line("OOL acknowledgement: request_opcode=2 tag=2 raw=07010200 00000000 00000000 00101200 decoded_endpoint=0 decoded_tag=2 decoded_opcode=1 decoded_target=7"),
    line("OOL registration request: opcode=3 tag=3 words=07030300 00000200 00004000 00000000"),
    line("OOL acknowledgement: request_opcode=3 tag=3 raw=07010300 00000000 00000000 00102300 decoded_endpoint=0 decoded_tag=3 decoded_opcode=1 decoded_target=7"),
    line("AKS capabilities request: endpoint=7 selector=0x4d tag=1 length=100 header_version=1"),
    line("AKS capabilities envelope: raw=0001cd07 00640000 00000000 00000000"),
    line("AKS capabilities reply passed strict validation: status=0 remote_header_version=2"),
    line("AKS startup environment request: endpoint=7 selector=0x2a tag=2 length=1136 header_version=2 no_effaceable_storage=0 mode=4"),
    line("AKS startup environment envelope: raw=0002aa07 00580000 00000000 00000000"),
    line("AKS startup environment reply passed strict validation: status=0 header_version=2"),
    line("issued Apple CPU-stop value 5 at +0x8024; payload FIFOs accessed only by explicit bounded gates"),
    line("OOL buffers scrubbed and released after CPU stop; result=0"),
    line("MSI observations: vector0=3 vector1=3"),
    line("restored PCI command word from 0x0002 to original 0x0006"),
    line("temporary PCI enable released before probe returned"),
    line("read-only probe removed"),
))


class VerifyAksStartupEnvironmentLogTests(unittest.TestCase):
    def test_accepts_complete_strict_transcript(self):
        self.assertEqual(verify.verify(GOOD), 2)

    def test_caps_newer_version_is_capped_to_two(self):
        self.assertEqual(verify.verify(
            GOOD.replace("remote_header_version=2", "remote_header_version=99")), 2)

    def test_accepts_negotiated_version_one(self):
        version_one = GOOD.replace("remote_header_version=2",
                                   "remote_header_version=1").replace(
            "header_version=2", "header_version=1")
        self.assertEqual(verify.verify(version_one), 1)

    def test_accepts_apple_version_one_fallback(self):
        fallback = GOOD.replace(
            line("AKS capabilities envelope: raw=0001cd07 00640000 00000000 00000000") + "\n" +
            line("AKS capabilities reply passed strict validation: status=0 remote_header_version=2"),
            line("AKS capabilities negotiation unavailable: result=-110; applying Apple header-version-1 fallback"),
        ).replace("header_version=2", "header_version=1")
        self.assertEqual(verify.verify(fallback), 1)

    def test_rejects_changed_reordered_or_failed_environment(self):
        mutations = (
            GOOD.replace("selector=0x2a", "selector=0x2b"),
            GOOD.replace("no_effaceable_storage=0", "no_effaceable_storage=1"),
            GOOD.replace("raw=0002aa07", "raw=0006aa07"),
            GOOD.replace("raw=0002aa07 00580000", "raw=0002aa07 00590000"),
            GOOD.replace("status=0 header_version=2", "status=-1 header_version=2"),
            GOOD.replace("status=0 header_version=2", "status=0 header_version=1"),
            GOOD.replace(line("AKS startup environment envelope: raw=0002aa07 00580000 00000000 00000000"), ""),
        )
        for transcript in mutations:
            with self.subTest():
                with self.assertRaises(verify.VerificationError):
                    verify.verify(transcript)


if __name__ == "__main__":
    unittest.main()
