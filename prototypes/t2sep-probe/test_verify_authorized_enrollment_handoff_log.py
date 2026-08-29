import importlib.util
from pathlib import Path
import sys
import unittest


PATH = Path(__file__).with_name("verify-authorized-enrollment-handoff-log.py")
SPEC = importlib.util.spec_from_file_location("authorized_handoff_log_tested", PATH)
assert SPEC and SPEC.loader
verifier = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = verifier
SPEC.loader.exec_module(verifier)


class AuthorizedEnrollmentHandoffLogTests(unittest.TestCase):
    def fixture(self):
        lines = list(verifier.base.ORDERED)
        position = lines.index(
            "AKS verify-secret reply passed strict validation: authorized=yes") + 1
        lines[position:position] = verifier.HANDOFF
        return "\n".join(lines)

    def test_requires_handoff_between_authorization_and_unload(self):
        verifier.verify(self.fixture())
        for marker in verifier.HANDOFF:
            with self.subTest(marker=marker):
                with self.assertRaises(ValueError):
                    verifier.verify(self.fixture().replace(marker, "missing"))

    def test_rejects_timeout_or_credential_logging(self):
        for marker in verifier.FORBIDDEN:
            with self.subTest(marker=marker):
                with self.assertRaises(ValueError):
                    verifier.verify(self.fixture() + "\n" + marker)


if __name__ == "__main__":
    unittest.main()
