#!/usr/bin/env python3
"""Source-level regression checks for the privileged OOL capture boundary."""

from pathlib import Path
import unittest


SOURCE = Path(__file__).with_name("t2sep_probe.c").read_text()


class KernelOolSafetyTests(unittest.TestCase):
    def test_capture_requires_discovery_and_confirmation(self) -> None:
        self.assertIn(
            "if (apple_capture_ool_acks &&\n"
            "\t    (!apple_collect_discovery ||\n"
            "\t     ool_ack_confirmation != T2SEP_OOL_CONFIRMATION))",
            SOURCE,
        )

    def test_registration_is_bounded_and_tag_correlated(self) -> None:
        self.assertIn("for (i = 0; i < 500; i++)", SOURCE)
        self.assertIn("((response[0] >> 8) & 0xff) != tag", SOURCE)
        self.assertIn("response[1] != 0", SOURCE)
        self.assertIn("pdev, bar4, ool_target, 2, 2, in_dma, in_size", SOURCE)
        self.assertIn("pdev, bar4, ool_target, 3, 3, out_dma, out_size", SOURCE)

    def test_credential_capture_is_default_off_and_triply_gated(self) -> None:
        self.assertIn("static bool apple_capture_credential_ool_acks;", SOURCE)
        self.assertIn(
            "credential_ool_confirmation != T2SEP_CREDENTIAL_OOL_CONFIRMATION",
            SOURCE,
        )
        self.assertIn(
            "(credential_endpoint != T2SEP_AKS_ENDPOINT &&\n"
            "\t      credential_endpoint != T2SEP_ACM_ENDPOINT)",
            SOURCE,
        )
        self.assertIn("credential OOL capture skipped because NOP did not validate", SOURCE)
        self.assertIn(
            "SBIO, credential OOL, and AKS capabilities modes are mutually exclusive",
            SOURCE)

    def test_aks_capabilities_is_separately_gated_and_nonsecret(self) -> None:
        self.assertIn("static bool apple_probe_aks_capabilities;", SOURCE)
        self.assertIn(
            "aks_capabilities_confirmation != T2SEP_AKS_CAPABILITIES_CONFIRMATION",
            SOURCE)
        self.assertIn("response[0] != 0x0004cd07", SOURCE)
        self.assertIn("crypto_memneq(receive + 4, reply_digest, 16)", SOURCE)
        self.assertIn("ktime_get_boottime_ns() / NSEC_PER_USEC", SOURCE)
        self.assertIn(
            "put_unaligned_le64(1, send + T2SEP_AKS_SERIALIZED_HEADER_SIZE + 4)",
            SOURCE)
        self.assertNotIn("ktime_get_mono_fast_ns", SOURCE)
        self.assertNotIn("password", SOURCE.lower())

    def test_credential_capture_sends_no_service_envelope(self) -> None:
        self.assertNotIn("VERIFY_SECRET", SOURCE)
        self.assertNotIn("ACMContextCreate", SOURCE)
        self.assertIn("T2SEP_CREDENTIAL_OOL_SIZE (4 * PAGE_SIZE)", SOURCE)

    def test_stop_precedes_scrub_and_free(self) -> None:
        function = SOURCE.index("static int t2sep_apple_start_cpu_probe")
        stop = SOURCE.index("iowrite32(5, bar4 + T2SEP_INTEL_CPU_STOP)", function)
        scrub = SOURCE.index("memzero_explicit(in_buffer", stop)
        free = SOURCE.index("dma_free_coherent", scrub)
        self.assertLess(stop, scrub)
        self.assertLess(scrub, free)


if __name__ == "__main__":
    unittest.main()
