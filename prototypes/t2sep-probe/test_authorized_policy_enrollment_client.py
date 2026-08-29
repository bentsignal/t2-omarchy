import importlib.util
from pathlib import Path
import sys
import unittest


PATH = Path(__file__).with_name("authorized-policy-enrollment-client.py")
SPEC = importlib.util.spec_from_file_location("policy_client_tested", PATH)
module = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = module
SPEC.loader.exec_module(module)


class AuthorizedPolicyEnrollmentClientTests(unittest.TestCase):
    def test_live_gate_remains_closed_on_import(self):
        self.assertFalse(module.enrollment.LIVE_ENROLLMENT_ENABLED)

    def test_source_never_logs_credential_or_enables_apple_pay(self):
        source = PATH.read_text()
        self.assertIn("UserProtectedPolicy(1, 1, 1, 0)", source)
        self.assertNotIn("print(credential", source)
        self.assertIn("credential[:] = bytes(len(credential))", source)
        self.assertIn("policy_credential[:] = bytes(len(policy_credential))", source)
        self.assertIn("catacomb_sink=lambda blob: store.save(", source)


if __name__ == "__main__":
    unittest.main()
