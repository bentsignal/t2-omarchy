from pathlib import Path
import unittest


SOURCE = Path(__file__).with_name("run-authorized-enrollment-probe.sh").read_text()
CLIENT = Path(__file__).with_name("authorized-enrollment-client.py").read_text()
LOAD_CLIENT = Path(__file__).with_name("authorized-catacomb-load-client.py").read_text()
SKS_CLIENT = Path(__file__).with_name("authorized-sks-lock-state-client.py").read_text()


class AuthorizedEnrollmentRunnerSafetyTests(unittest.TestCase):
    def test_credential_uses_stdin_not_argument_or_log(self):
        self.assertIn('sudo -n cat "$credential_path" |', SOURCE)
        self.assertNotIn("--credential", SOURCE)
        self.assertIn("sys.stdin.buffer.readline(34)", CLIENT)
        self.assertNotIn("print(credential", CLIENT)
        self.assertIn("line[:] = bytes(len(line))", CLIENT)

    def test_cleanup_acknowledges_then_waits_and_unloads(self):
        ack = SOURCE.index("sudo -n tee \"$done_path\"")
        wait = SOURCE.index('wait "$insmod_pid"', ack)
        unload = SOURCE.index("sudo -n rmmod t2sep_probe", wait)
        self.assertLess(ack, wait)
        self.assertLess(wait, unload)
        self.assertIn("trap cleanup EXIT", SOURCE)
        self.assertIn('keyctl revoke "$serial"', SOURCE)

    def test_distinct_confirmation_and_independent_verifier(self):
        self.assertIn("I_UNDERSTAND_THIS_CREATES_ONE_FINGERPRINT_IDENTITY", SOURCE)
        self.assertIn("authorized_enrollment_confirmation=0x41555448454e5231", SOURCE)
        self.assertIn("verify-authorized-enrollment-handoff-log.py", SOURCE)

    def test_transactional_enrollment_has_distinct_confirmation_and_root_store(self):
        self.assertIn(
            "I_UNDERSTAND_THIS_TRANSACTIONALLY_CREATES_ONE_FINGERPRINT_IDENTITY",
            SOURCE,
        )
        self.assertIn("transactional-enrollment-client.py", SOURCE)
        self.assertIn("--state-root /var/lib/t2-touchid", SOURCE)
        self.assertIn('if (( transactional )); then', SOURCE)

    def test_policy_bootstrap_requires_a_distinct_explicit_confirmation(self):
        self.assertIn(
            "I_UNDERSTAND_THIS_CREATES_ONE_USER_POLICY_AND_FINGERPRINT_IDENTITY",
            SOURCE)
        self.assertIn("authorized-policy-enrollment-client.py", SOURCE)
        self.assertIn('authorize_policy=1', SOURCE)
        self.assertIn('apple_authorize_enrollment_policy="$authorize_policy"', SOURCE)
        self.assertIn('--require-enrollment-policy', SOURCE)

    def test_policy_authorization_has_a_no_touch_diagnostic(self):
        self.assertIn(
            "I_UNDERSTAND_THIS_AUTHORIZES_ENROLLMENT_POLICY_WITHOUT_TOUCH",
            SOURCE)
        self.assertIn("policy-authorization-no-touch-client.py", SOURCE)

    def test_authorized_catacomb_load_is_distinct_and_scrubs_handoff(self):
        self.assertIn(
            "I_UNDERSTAND_THIS_LOADS_RETAINED_MACOS_CATACOMBS_WITH_AN_AUTHORIZED_BAG",
            SOURCE)
        self.assertIn("authorized-catacomb-load-client.py", SOURCE)
        self.assertIn("sys.stdin.buffer.readline(34)", LOAD_CLIENT)
        self.assertIn("credential[:] = bytes(len(credential))", LOAD_CLIENT)
        self.assertNotIn("print(credential", LOAD_CLIENT)

    def test_read_only_bridge_preflight_precedes_password_prompt(self):
        preflight = SOURCE.index("biometric-connectivity-preflight.py")
        prompt = SOURCE.index("prompt_dir=$(mktemp -d)")
        self.assertLess(preflight, prompt)
        self.assertIn("password was not requested", SOURCE)

    def test_authorized_sks_comparison_cannot_enroll(self):
        self.assertIn(
            "I_UNDERSTAND_THIS_ONLY_READS_SKS_LOCK_STATE_WITH_AN_AUTHORIZED_BAG",
            SOURCE)
        self.assertIn("authorized-sks-lock-state-client.py", SOURCE)
        self.assertIn("sks-lock-state-probe.py", SKS_CLIENT)
        self.assertNotIn("authorized_enroll_fields", SKS_CLIENT)
        self.assertIn("credential[:] = bytes(len(credential))", SKS_CLIENT)
        sks_case = SOURCE[SOURCE.index(
            "I_UNDERSTAND_THIS_ONLY_READS_SKS_LOCK_STATE_WITH_AN_AUTHORIZED_BAG"):
            SOURCE.index(
                "I_UNDERSTAND_THIS_AUTHORIZES_ENROLLMENT_POLICY_WITHOUT_TOUCH")]
        self.assertNotIn("authorize_policy=1", sks_case)


if __name__ == "__main__":
    unittest.main()
