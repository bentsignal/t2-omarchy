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
            "SBIO, single/dual credential OOL, AKS capabilities/time/startup, ACM context, combined startup, and password verification modes are mutually exclusive",
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
        self.assertIn("response[0] != (T2SEP_AKS_ENDPOINT | 0xcd << 8 | (u32)tag << 16)", SOURCE)
        self.assertIn("applying Apple header-version-1 fallback", SOURCE)
        self.assertIn("response[0] != 0x0002aa07", SOURCE)
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
        start = SOURCE.index("static int t2sep_probe_aks_capabilities_at")
        end = SOURCE.index("static int t2sep_probe_aks_capabilities(", start)
        self.assertNotIn("password", SOURCE[start:end].lower())

    def test_aks_time_sweep_is_bounded_separately_gated_and_nonsecret(self):
        self.assertIn("static bool apple_probe_aks_time_sweep;", SOURCE)
        self.assertIn(
            "aks_time_sweep_confirmation != T2SEP_AKS_TIME_SWEEP_CONFIRMATION",
            SOURCE)
        for name in ("zero", "sep-start-relative", "monotonic", "raw", "boottime"):
            self.assertIn(f'"{name}"', SOURCE)
        self.assertIn("i < ARRAY_SIZE(candidates)", SOURCE)
        self.assertIn("if (ret != -ETIMEDOUT)", SOURCE)
        self.assertNotIn("continuous_usec=%", SOURCE)

    def test_aks_startup_environment_is_separately_gated_and_nonsecret(self):
        self.assertIn("static bool apple_probe_aks_startup_environment;", SOURCE)
        self.assertIn(
            "aks_startup_environment_confirmation !=\n"
            "\t\tT2SEP_AKS_STARTUP_ENV_CONFIRMATION", SOURCE)
        self.assertIn("u32 request[3] = { 0x00022a07, 0x04700000, 0 };", SOURCE)
        self.assertIn("response[0] != 0x0002aa07", SOURCE)
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
        self.assertIn("send[4] = 0x24", SOURCE)
        self.assertIn("allow_minus_three_fallback", SOURCE)
        self.assertIn("T2SEP_ACM_CURRENT_CONTEXT_RESPONSE_SIZE 21", SOURCE)
        self.assertIn("send[4] = 1", SOURCE)
        self.assertIn("send[4] = 2", SOURCE)
        self.assertIn("memcpy(context, receive, T2SEP_ACM_CONTEXT_SIZE)", SOURCE)
        self.assertIn("memcpy(send + 8, context, T2SEP_ACM_CONTEXT_SIZE)", SOURCE)
        self.assertIn("memzero_explicit(context, sizeof(context))", SOURCE)
        self.assertIn("context_bytes=not-logged", SOURCE)
        self.assertNotIn("context=%", SOURCE)
        start = SOURCE.index("static int t2sep_probe_acm_context_create")
        end = SOURCE.index("static void t2sep_revoke_password_key", start)
        self.assertNotIn("password", SOURCE[start:end].lower())

    def test_combined_credential_startup_is_dual_bounded_and_gated(self):
        self.assertIn("static bool apple_probe_credential_startup;", SOURCE)
        self.assertIn(
            "credential_startup_confirmation !=\n"
            "\t\tT2SEP_CREDENTIAL_STARTUP_CONFIRMATION", SOURCE)
        self.assertIn(
            "bool dual_credential_ool = apple_capture_dual_credential_ool_acks ||\n"
            "\t\t\t\t   apple_probe_credential_startup ||\n"
            "\t\t\t\t   apple_probe_password_verification;", SOURCE)
        self.assertIn(
            "pdev, bar4, second_in_buffer, second_out_buffer", SOURCE)

    def test_password_verification_consumes_one_key_and_scrubs(self):
        for fragment in (
                "static bool apple_probe_password_verification;",
                "password_verification_confirmation !=\n"
                "\t\tT2SEP_PASSWORD_VERIFICATION_CONFIRMATION",
                "key->type != &key_type_user", "payload->datalen",
                "payload->datalen > T2SEP_AKS_MAX_PASSWORD_SIZE",
                "key_revoke(key)", "memzero_explicit(&keybag_handle",
                "if (reply_received)",
                "memzero_explicit(send, T2SEP_CREDENTIAL_OOL_SIZE)",
                "password_bytes=not-logged", "device_state=not-logged"):
            self.assertIn(fragment, SOURCE)
        revoke = SOURCE.index("key_revoke(key)",
                              SOURCE.index("t2sep_probe_aks_verify_password"))
        send = SOURCE.index("t2sep_send_intel_message(bar4, request)", revoke)
        self.assertLess(revoke, send)

    def test_stop_precedes_scrub_and_free(self) -> None:
        function = SOURCE.index("static int t2sep_apple_start_cpu_probe")
        stop = SOURCE.index("iowrite32(5, bar4 + T2SEP_INTEL_CPU_STOP)", function)
        scrub = SOURCE.index("memzero_explicit(in_buffer", stop)
        free = SOURCE.index("dma_free_coherent", scrub)
        self.assertLess(stop, scrub)
        self.assertLess(scrub, free)


if __name__ == "__main__":
    unittest.main()
