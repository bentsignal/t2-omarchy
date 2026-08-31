from pathlib import Path
import unittest


SOURCE = Path(__file__).with_name("policy-authorization-no-touch-client.py").read_text()
RUNNER = Path(__file__).with_name("run-authorized-enrollment-probe.sh").read_text()


class PolicyAuthorizationNoTouchTests(unittest.TestCase):
    def test_client_has_no_biometric_or_transport_capability(self):
        self.assertNotIn("import socket", SOURCE)
        self.assertNotIn("biometric-command", SOURCE)
        self.assertNotIn("BridgeSession", SOURCE)
        self.assertNotIn("authorized_enroll_fields", SOURCE)
        self.assertIn("context[:] = bytes(len(context))", SOURCE)
        self.assertIn("line[:] = bytes(len(line))", SOURCE)

    def test_runner_enables_policy_but_uses_no_touch_client(self):
        start = RUNNER.index(
            "I_UNDERSTAND_THIS_AUTHORIZES_ENROLLMENT_POLICY_WITHOUT_TOUCH")
        end = RUNNER.index(
            "I_UNDERSTAND_THIS_CREATES_ONE_FINGERPRINT_IDENTITY", start)
        branch = RUNNER[start:end]
        self.assertIn("policy-authorization-no-touch-client.py", branch)
        self.assertIn("authorize_policy=1", branch)


if __name__ == "__main__":
    unittest.main()
