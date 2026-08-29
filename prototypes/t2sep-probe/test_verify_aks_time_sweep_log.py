import importlib.util
from pathlib import Path
import sys
import unittest


SPEC = importlib.util.spec_from_file_location(
    "verify_aks_time_sweep_log",
    Path(__file__).with_name("verify-aks-time-sweep-log.py"))
verify = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = verify
SPEC.loader.exec_module(verify)

PREFIX = "Aug 29 09:00:00 intelmac kernel: t2sep_probe 0000:04:00.2: "


def line(value):
    return PREFIX + value


def transcript(success=None):
    values = [
        line("temporarily enabled PCI memory decoding for this probe"),
        line("allocated MSI vectors 108 and 109"),
        line("control NOP response passed strict validation"),
        line("pinned OOL buffers: target=7 in_dma=0x0000000000100000 in_size=16384 out_dma=0x0000000000200000 out_size=16384"),
        line("OOL registration request: opcode=2 tag=2 words=07020200 00000100 00004000 00000000"),
        line("OOL acknowledgement: request_opcode=2 tag=2 raw=07010200 00000000 00000000 00101200 decoded_endpoint=0 decoded_tag=2 decoded_opcode=1 decoded_target=7"),
        line("OOL registration request: opcode=3 tag=3 words=07030300 00000200 00004000 00000000"),
        line("OOL acknowledgement: request_opcode=3 tag=3 raw=07010300 00000000 00000000 00102300 decoded_endpoint=0 decoded_tag=3 decoded_opcode=1 decoded_target=7"),
    ]
    for index, name in enumerate(verify.CLASSES, 1):
        values.append(line(f"AKS time candidate request: class={name} endpoint=7 selector=0x4d tag={index} length=100 header_version=1"))
        if name == success:
            values.extend((
                line(f"AKS time candidate envelope: class={name} raw={7 | 0xcd << 8 | index << 16:08x} 005c0000 00000000 00000000"),
                line(f"AKS time candidate reply passed strict validation: class={name} status=0 remote_header_version=2 reply_size=92"),
                line(f"AKS time sweep accepted class={name} negotiated_header_version=2 attempts={index}"),
            ))
            break
        values.append(line(f"AKS time candidate produced no reply: class={name}"))
    if success is None:
        values.append(line("AKS time sweep completed without accepted candidate: attempts=5 result=-110"))
    values.extend((
        line("issued Apple CPU-stop value 5 at +0x8024; payload FIFOs accessed only by explicit bounded gates"),
        line("OOL buffers scrubbed and released after CPU stop; result=0" if success else
             "OOL buffers scrubbed and released after CPU stop; result=-110"),
        line("MSI observations: vector0=3 vector1=3"),
        line("restored PCI command word from 0x0002 to original 0x0006"),
        line("temporary PCI enable released before probe returned"),
        line("read-only probe removed"),
    ))
    return "\n".join(values)


class VerifyAksTimeSweepLogTests(unittest.TestCase):
    def test_accepts_strict_success_and_exhaustion(self):
        self.assertEqual(verify.verify(transcript("monotonic")), "monotonic")
        self.assertIsNone(verify.verify(transcript()))

    def test_rejects_changed_order_tag_or_teardown(self):
        good = transcript()
        mutations = (
            good.replace("class=zero endpoint=7", "class=raw endpoint=7", 1),
            good.replace("class=zero endpoint=7 selector=0x4d tag=1",
                         "class=zero endpoint=7 selector=0x4d tag=2", 1),
            good.replace(line("read-only probe removed"), ""),
            good.replace("attempts=5 result=-110", "attempts=4 result=-110"),
        )
        for changed in mutations:
            with self.subTest():
                with self.assertRaises(verify.VerificationError):
                    verify.verify(changed)


if __name__ == "__main__":
    unittest.main()
