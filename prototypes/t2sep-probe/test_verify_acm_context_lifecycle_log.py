import importlib.util
from pathlib import Path
import sys
import unittest


SPEC = importlib.util.spec_from_file_location(
    "verify_acm_context_lifecycle_log",
    Path(__file__).with_name("verify-acm-context-lifecycle-log.py"))
verify = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = verify
SPEC.loader.exec_module(verify)

PREFIX = "Aug 28 23:50:00 intelmac kernel: t2sep_probe 0000:04:00.2: "


def line(value):
    return PREFIX + value


GOOD = "\n".join((
    line("temporarily enabled PCI memory decoding for this probe"),
    line("allocated MSI vectors 108 and 109"),
    line("control NOP response passed strict validation"),
    line("pinned OOL buffers: target=10 in_dma=0x0000000000100000 in_size=16384 out_dma=0x0000000000200000 out_size=16384"),
    line("OOL registration request: opcode=2 tag=2 words=0a020200 00000100 00004000 00000000"),
    line("OOL acknowledgement: request_opcode=2 tag=2 raw=0a010200 00000000 00000000 00101200 decoded_endpoint=0 decoded_tag=2 decoded_opcode=1 decoded_target=10"),
    line("OOL registration request: opcode=3 tag=3 words=0a030300 00000200 00004000 00000000"),
    line("OOL acknowledgement: request_opcode=3 tag=3 raw=0a010300 00000000 00000000 00102300 decoded_endpoint=0 decoded_tag=3 decoded_opcode=1 decoded_target=10"),
    line("ACM SCRD initialization request: endpoint=10 message_type=1 length=8 version=0x28"),
    line("ACM SCRD-initialization envelope request: raw=0008010a 00000000 00000000 00000000"),
    line("ACM SCRD-initialization envelope reply: raw=0000010a 00000000 00000000 00103400"),
    line("ACM SCRD initialization reply passed strict validation: status=0 length=0"),
    line("ACM ping request: endpoint=10 message_type=1 selector=29 length=8 expected_reply=0"),
    line("ACM ping-1d envelope request: raw=0008010a 00000000 00000000 00000000"),
    line("ACM ping-1d envelope reply: raw=0000010a 00000000 00000000 00103400"),
    line("ACM ping reply passed strict validation: status=0 length=0"),
    line("ACM context-create request: endpoint=10 message_type=1 selector=36 length=12 domain=0 expected_reply=21"),
    line("ACM context-create-24 envelope request: raw=000c010a 00000000 00000000 00000000"),
    line("ACM context-create-24 envelope reply: raw=0015010a 00000000 00000000 00104500"),
    line("ACM context-create reply passed strict validation: status=0 length=21 context_bytes=not-logged"),
    line("ACM context-delete request: endpoint=10 message_type=1 selector=2 length=24 context_length=16 context_bytes=not-logged"),
    line("ACM context-delete envelope request: raw=0018010a 00000000 00000000 00000000"),
    line("ACM context-delete envelope reply: raw=0000010a 00000000 00000000 00105600"),
    line("ACM context-delete reply passed strict validation: status=0 length=0"),
    line("issued Apple CPU-stop value 5 at +0x8024; payload FIFOs accessed only by explicit bounded gates"),
    line("OOL buffers scrubbed and released after CPU stop; result=0"),
    line("MSI observations: vector0=3 vector1=3"),
    line("restored PCI command word from 0x0002 to original 0x0006"),
    line("temporary PCI enable released before probe returned"),
    line("read-only probe removed"),
))


class VerifyAcmContextLifecycleLogTests(unittest.TestCase):
    def test_accepts_complete_secret_free_lifecycle(self):
        self.assertIsNone(verify.verify(GOOD))

    def test_accepts_exact_apple_minus_three_fallback(self):
        fallback = GOOD.replace(
            line("ACM context-create-24 envelope reply: raw=0015010a 00000000 00000000 00104500") + "\n" +
            line("ACM context-create reply passed strict validation: status=0 length=21 context_bytes=not-logged"),
            line("ACM context-create-24 envelope reply: raw=0000010a fffffffd 00000000 00104500") + "\n" +
            line("ACM current context-create returned -3; applying Apple legacy fallback") + "\n" +
            line("ACM context-create fallback request: endpoint=10 message_type=1 selector=1 length=12 domain=0 expected_reply=17") + "\n" +
            line("ACM context-create-01 envelope request: raw=000c010a 00000000 00000000 00000000") + "\n" +
            line("ACM context-create-01 envelope reply: raw=0011010a 00000000 00000000 00104500") + "\n" +
            line("ACM context-create reply passed strict validation: status=0 length=17 context_bytes=not-logged"))
        self.assertIsNone(verify.verify(fallback))

    def test_rejects_changed_reordered_or_secret_evidence(self):
        mutations = (
            GOOD.replace("version=0x28", "version=0x27"),
            GOOD.replace("raw=0015010a", "raw=0014010a"),
            GOOD.replace("raw=0000010a 00000000 00000000 00105600",
                         "raw=0000010a 00000001 00000000 00105600"),
            GOOD.replace("00105600", "00145600"),
            GOOD.replace("context_bytes=not-logged", "context=0xdeadbeef", 1),
            GOOD.replace(
                line("ACM context-delete request: endpoint=10 message_type=1 selector=2 length=24 context_length=16 context_bytes=not-logged") + "\n",
                "").replace(
                    line("ACM context-create request: endpoint=10 message_type=1 selector=36 length=12 domain=0 expected_reply=21"),
                    line("ACM context-create request: endpoint=10 message_type=1 selector=36 length=12 domain=0 expected_reply=21") + "\n" +
                    line("ACM context-delete request: endpoint=10 message_type=1 selector=2 length=24 context_length=16 context_bytes=not-logged")),
        )
        for transcript in mutations:
            with self.subTest():
                with self.assertRaises(verify.VerificationError):
                    verify.verify(transcript)


if __name__ == "__main__":
    unittest.main()
