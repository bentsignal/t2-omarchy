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
            "SBIO, single/dual credential OOL, AKS capabilities/time/startup, ACM context, combined startup, password verification, and ephemeral keybag modes are mutually exclusive",
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
            "\t\t\t\t   apple_probe_password_verification ||\n"
            "\t\t\t\t   apple_probe_ephemeral_keybag_authorization ||\n"
            "\t\t\t\t   apple_probe_authorized_enrollment_handoff;", SOURCE)
        self.assertIn(
            "pdev, bar4, second_in_buffer, second_out_buffer", SOURCE)

    def test_password_verification_consumes_one_key_and_scrubs(self):
        for fragment in (
                "static bool apple_probe_password_verification;",
                "password_verification_confirmation !=\n"
                "\t\tT2SEP_PASSWORD_VERIFICATION_CONFIRMATION",
                "key->type != &key_type_user", "payload->datalen",
                "payload->datalen > T2SEP_AKS_MAX_PASSWORD_SIZE",
                "key_revoke(key)",
                "if (reply_received)",
                "memzero_explicit(send, T2SEP_CREDENTIAL_OOL_SIZE)",
                "password_bytes=not-logged", "device_state=not-logged",
                "AKS verify-secret service rejection:",
                "A service rejection is not evidence that the password was wrong"):
            self.assertIn(fragment, SOURCE)
        revoke = SOURCE.index("key_revoke(key)",
                              SOURCE.index("t2sep_probe_aks_verify_password"))
        send = SOURCE.index("t2sep_send_intel_message(bar4, request)", revoke)
        self.assertLess(revoke, send)

    def test_ephemeral_keybag_gate_has_bounded_lifecycle(self):
        for fragment in (
                "static bool apple_probe_ephemeral_keybag_authorization;",
                "T2SEP_EPHEMERAL_KEYBAG_CONFIRMATION",
                "t2sep_probe_aks_create_device_keybag(",
                "t2sep_probe_aks_copy_keybag_blob(",
                "t2sep_probe_aks_load_keybag_blob(",
                "blob_bytes=not-logged",
                "s32 requested_selector = -1;",
                "store_type=0 secret_bytes=not-logged",
                "t2sep_probe_aks_make_system_keybag(",
                "selector=0x0d tag=4",
                "s32 system_selector = -(s32)macos_session_uid",
                "t2sep_probe_aks_verify_password(",
                "t2sep_wait_aks_make_system_reply(",
                "notification_opcodes[] = { 0x00, 0x04 }",
                "t2sep_wait_aks_system_unload_reply(",
                "service_status == -13",
                "t2sep_probe_aks_ensure_keybag_absent(",
                'keybag_handle, system_selector, "system"',
                'keybag_handle, runtime_selector, "source"',
                "status=%d absent=yes",
                "independent absence check still required",
                "get_unaligned_le32(receive) != T2SEP_AKS_HEADER_SIZE"):
            self.assertIn(fragment, SOURCE)
        create = SOURCE.index("t2sep_probe_aks_create_device_keybag(",
                              SOURCE.index("static int t2sep_probe_ephemeral"))
        copy = SOURCE.index("t2sep_probe_aks_copy_keybag_blob(", create)
        preload_unload = SOURCE.index("0x05, 5,", copy)
        preload_absence = SOURCE.index("0x02, 6,", preload_unload)
        load = SOURCE.index("t2sep_probe_aks_load_keybag_blob(", preload_absence)
        promote = SOURCE.index("t2sep_probe_aks_make_system_keybag(", load)
        verify = SOURCE.index("t2sep_probe_aks_verify_password(", promote)
        system_absence = SOURCE.index(
            "t2sep_probe_aks_ensure_keybag_absent(", verify)
        source_absence = SOURCE.index(
            "t2sep_probe_aks_ensure_keybag_absent(", system_absence + 1)
        delete = SOURCE.index("t2sep_probe_acm_context_delete(", source_absence)
        self.assertLess(create, promote)
        self.assertLess(create, copy)
        self.assertLess(copy, preload_unload)
        self.assertLess(preload_unload, preload_absence)
        self.assertLess(preload_absence, load)
        self.assertLess(load, promote)
        self.assertLess(promote, verify)
        self.assertLess(verify, system_absence)
        self.assertLess(system_absence, source_absence)
        self.assertLess(source_absence, delete)

    def test_authorized_enrollment_handoff_is_read_once_and_bounded(self):
        for fragment in (
                "static bool apple_probe_authorized_enrollment_handoff;",
                "T2SEP_AUTHORIZED_ENROLLMENT_CONFIRMATION",
                "module_param_cb(enrollment_credential",
                "module_param_cb(enrollment_done",
                "NULL, 0400", "NULL, 0200",
                "t2sep_enrollment_consumed = true",
                "memzero_explicit(t2sep_enrollment_credential",
                "wait_for_completion_timeout(&t2sep_enrollment_credential_read",
                "wait_for_completion_timeout(&t2sep_enrollment_finished",
                "credential_bytes=not-logged"):
            self.assertIn(fragment, SOURCE)
        publish = SOURCE.index("memcpy(t2sep_enrollment_credential, context")
        wait = SOURCE.index("wait_for_completion_timeout", publish)
        unload = SOURCE.index("t2sep_probe_aks_ensure_keybag_absent(", wait)
        self.assertLess(publish, wait)
        self.assertLess(wait, unload)

    def test_stop_precedes_scrub_and_free(self) -> None:
        function = SOURCE.index("static int t2sep_apple_start_cpu_probe")
        stop = SOURCE.index("iowrite32(5, bar4 + T2SEP_INTEL_CPU_STOP)", function)
        scrub = SOURCE.index("memzero_explicit(in_buffer", stop)
        free = SOURCE.index("dma_free_coherent", scrub)
        self.assertLess(stop, scrub)
        self.assertLess(scrub, free)

    def test_stale_inbox_is_bounded_and_only_drained_while_stopped(self):
        for fragment in (
                "t2sep_drain_stopped_stale_inbox(",
                "T2SEP_INTEL_CPU_CONTROL) != 0x7f",
                "count < 16",
                "stopped-CPU stale inbox drain completed",
                "return -EOVERFLOW;"):
            self.assertIn(fragment, SOURCE)
        function = SOURCE.index("static int t2sep_apple_start_cpu_probe")
        drain = SOURCE.index("t2sep_drain_stopped_stale_inbox", function)
        start = SOURCE.index("iowrite32(1, bar4 + T2SEP_INTEL_CPU_START)",
                             function)
        self.assertLess(drain, start)


if __name__ == "__main__":
    unittest.main()
