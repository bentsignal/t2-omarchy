import contextlib
import importlib.util
import io
from pathlib import Path
import sys
import unittest


PATH = Path(__file__).with_name("authorized-enrollment-client.py")
SPEC = importlib.util.spec_from_file_location("authorized_enrollment_client_tested", PATH)
assert SPEC and SPEC.loader
client = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = client
SPEC.loader.exec_module(client)


class AuthorizedEnrollmentClientTests(unittest.TestCase):
    def instruction(self, status):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            client.progress_instruction((status, 1, 12))
        return output.getvalue()

    def test_ready_and_progress_have_short_physical_instructions(self):
        self.assertIn("TOUCH NOW", self.instruction(client.enrollment.READY_STATUS))
        for status in client.enrollment.PROGRESS_MINIMUMS:
            with self.subTest(status=status):
                self.assertIn("LIFT, reposition", self.instruction(status))

    def test_terminal_event_has_no_false_touch_instruction(self):
        output = self.instruction(client.enrollment.biometric.SERVICE_EVENT_ENROLL_RESULT)
        self.assertNotIn("TOUCH NOW", output)
        self.assertNotIn("LIFT", output)


if __name__ == "__main__":
    unittest.main()
