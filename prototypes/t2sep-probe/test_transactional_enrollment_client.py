import contextlib
import importlib.util
import io
from pathlib import Path
import sys
import unittest


PATH = Path(__file__).with_name("transactional-enrollment-client.py")
SPEC = importlib.util.spec_from_file_location("transactional_enrollment_client_tested", PATH)
client = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = client
SPEC.loader.exec_module(client)


class TransactionalEnrollmentClientTests(unittest.TestCase):
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

    def test_credential_is_stdin_only_and_scrubbed(self):
        source = PATH.read_text()
        self.assertIn("sys.stdin.buffer.readline(34)", source)
        self.assertIn("line[:] = bytes(len(line))", source)
        self.assertNotIn("print(credential", source)
        self.assertNotIn("terminal_identity_uuid", source)


if __name__ == "__main__":
    unittest.main()
