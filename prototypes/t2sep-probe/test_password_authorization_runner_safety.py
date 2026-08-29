from pathlib import Path
import unittest


SOURCE = Path(__file__).with_name("run-password-authorization-probe.sh").read_text()


class PasswordAuthorizationRunnerSafetyTests(unittest.TestCase):
    def test_password_never_enters_shell_variable_or_argv(self):
        self.assertIn("systemd-ask-password --no-tty --echo=no", SOURCE)
        self.assertIn("set +x", SOURCE)
        self.assertIn("|\n  keyctl padd user", SOURCE)
        self.assertNotIn("password=$(", SOURCE)
        self.assertNotIn("password=\"$", SOURCE)
        self.assertIn('password_key_serial="$serial"', SOURCE)

    def test_key_is_revoked_unlinked_and_module_unloaded(self):
        for fragment in ("trap cleanup EXIT", 'keyctl revoke "$serial"',
                         'keyctl unlink "$serial" @s', "rmmod t2sep_probe",
                         "verify-password-authorization-log.py"):
            self.assertIn(fragment, SOURCE)

    def test_runner_has_exact_gate_and_preflight(self):
        for fragment in ("I_UNDERSTAND_ONE_PASSWORD_ATTEMPT", "MacBookPro16,1",
                         "0x106b", "0x1802", "module is stale",
                         "password_verification_confirmation=0x5041535356455249"):
            self.assertIn(fragment, SOURCE)


if __name__ == "__main__":
    unittest.main()
