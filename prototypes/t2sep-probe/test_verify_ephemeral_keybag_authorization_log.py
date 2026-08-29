import importlib.util
from pathlib import Path
import sys
import unittest


MODULE = Path(__file__).with_name(
    "verify-ephemeral-keybag-authorization-log.py")
SPEC = importlib.util.spec_from_file_location("ephemeral_log", MODULE)
assert SPEC and SPEC.loader
verifier = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = verifier
SPEC.loader.exec_module(verifier)


class EphemeralKeybagLogTests(unittest.TestCase):
    def test_success_requires_complete_ordered_teardown(self):
        log = "\n".join(f"kernel: {marker}" for marker in verifier.ORDERED)
        verifier.verify(log)
        for index in range(len(verifier.ORDERED)):
            with self.subTest(index=index):
                lines = log.splitlines()
                del lines[index]
                with self.assertRaises(ValueError):
                    verifier.verify("\n".join(lines))

    def test_rejects_duplicate_or_forbidden_content(self):
        log = "\n".join(verifier.ORDERED)
        with self.assertRaises(ValueError):
            verifier.verify(log + "\n" + verifier.ORDERED[3])
        for marker in verifier.FORBIDDEN:
            with self.subTest(marker=marker):
                with self.assertRaises(ValueError):
                    verifier.verify(log + "\n" + marker)


if __name__ == "__main__":
    unittest.main()
