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
            "SBIO, single/dual credential OOL, AKS capabilities/startup, and ACM context modes are mutually exclusive",
            SOURCE)

    def test_dual_credential_capture_is_separately_gated_and_nonsecret(self):
        self.assertIn("static bool apple_capture_dual_credential_ool_acks;", SOURCE)
        self.assertIn(
            "dual_credential_ool_confirmation !=\n"
            "\t\tT2SEP_DUAL_CREDENTIAL_OOL_CONFIRMATION", SOURCE)
        for fragment in (
                "pdev, bar4, T2SEP_AKS_ENDPOINT, 2, 2",
                "pdev, bar4, T2SEP_AKS_ENDPOINT, 3, 3",
                "pdev, bar4, T2SEP_ACM_ENDPOINT, 2, 4",
                "pdev, bar4, T2SEP_ACM_ENDPOINT, 3, 5"):
            self.assertIn(fragment, SOURCE)
        self.assertIn("second_in_buffer", SOURCE)
        self.assertIn("second_out_buffer", SOURCE)
        self.assertNotIn("VERIFY_SECRET", SOURCE)

    def test_aks_capabilities_is_separately_gated_and_nonsecret(self) -> None:
        self.assertIn("static bool apple_probe_aks_capabilities;", SOURCE)
        self.assertIn(
            "aks_capabilities_confirmation != T2SEP_AKS_CAPABILITIES_CONFIRMATION",
            SOURCE)
        self.assertIn("response[0] != 0x0004cd07", SOURCE)
        self.assertIn("crypto_memneq(received_digest, digest", SOURCE)
        self.assertIn("ktime_get_boottime_ns() / NSEC_PER_USEC", SOURCE)
        self.assertIn(
            "put_unaligned_le64(1, send + T2SEP_AKS_SERIALIZED_HEADER_SIZE + 4)",
            SOURCE)
        self.assertIn(
            "sha256_update(&context, wire + 4 + 0x10, header_tail)",
            SOURCE)
        self.assertIn(
            "sha256_update(&context, wire + T2SEP_AKS_SERIALIZED_HEADER_SIZE",
            SOURCE)
        self.assertNotIn("ktime_get_mono_fast_ns", SOURCE)
        self.assertNotIn("password", SOURCE.lower())

    def test_aks_startup_environment_is_separately_gated_and_nonsecret(self):
        self.assertIn("static bool apple_probe_aks_startup_environment;", SOURCE)
        self.assertIn(
            "aks_startup_environment_confirmation !=\n"
            "\t\tT2SEP_AKS_STARTUP_ENV_CONFIRMATION", SOURCE)
        self.assertIn("u32 request[3] = { 0x00052a07, 0x04700000, 0 };", SOURCE)
        self.assertIn("response[0] != 0x0005aa07", SOURCE)
        self.assertIn("response[1] != 0x00580000", SOURCE)
        self.assertIn("min_t(u64, remote_version, 2)", SOURCE)
        self.assertIn("put_unaligned_le64(ktime_get_real_seconds()", SOURCE)
        self.assertIn("T2SEP_AKS_STARTUP_ENV_BLOB_SIZE", SOURCE)
        self.assertNotIn("VERIFY_SECRET", SOURCE)

    def test_credential_capture_sends_no_service_envelope(self) -> None:
        self.assertNotIn("VERIFY_SECRET", SOURCE)
        self.assertNotIn("ACMContextCreate", SOURCE)
        self.assertIn("T2SEP_CREDENTIAL_OOL_SIZE (4 * PAGE_SIZE)", SOURCE)

    def test_acm_lifecycle_is_separately_gated_and_secret_free(self) -> None:
        self.assertIn("static bool apple_probe_acm_context_lifecycle;", SOURCE)
        self.assertIn(
            "acm_context_confirmation != T2SEP_ACM_CONTEXT_CONFIRMATION",
            SOURCE)
        self.assertIn('memcpy(send, "DRCS\\n", 5)', SOURCE)
        self.assertIn("send[5] = 0x28", SOURCE)
        self.assertIn("send[4] = 1", SOURCE)
        self.assertIn("send[4] = 2", SOURCE)
        self.assertIn("memcpy(send + 8, receive, T2SEP_ACM_CONTEXT_SIZE)", SOURCE)
        self.assertIn("context_bytes=not-logged", SOURCE)
        self.assertNotIn("context=%", SOURCE)
        self.assertNotIn("password", SOURCE.lower())

    def test_stop_precedes_scrub_and_free(self) -> None:
        function = SOURCE.index("static int t2sep_apple_start_cpu_probe")
        stop = SOURCE.index("iowrite32(5, bar4 + T2SEP_INTEL_CPU_STOP)", function)
        scrub = SOURCE.index("memzero_explicit(in_buffer", stop)
        free = SOURCE.index("dma_free_coherent", scrub)
        self.assertLess(stop, scrub)
        self.assertLess(scrub, free)


if __name__ == "__main__":
    unittest.main()
