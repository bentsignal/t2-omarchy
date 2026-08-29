from pathlib import Path
import unittest


SOURCE = Path(__file__).with_name("run-authorized-enrollment-probe.sh").read_text()
CLIENT = Path(__file__).with_name("authorized-enrollment-client.py").read_text()


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


if __name__ == "__main__":
    unittest.main()
