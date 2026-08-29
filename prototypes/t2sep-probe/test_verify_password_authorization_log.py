import importlib.util
from pathlib import Path
import sys
import unittest


HERE = Path(__file__).parent


def load(filename, name):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


verify = load("verify-password-authorization-log.py", "verify_password_authorization_log")
combined = load("test_verify_credential_startup_log.py", "password_combined_fixture")


lines = combined.GOOD.splitlines()
delete_index = next(index for index, value in enumerate(lines)
                    if "ACM context-delete request:" in value)
stop_index = next(index for index, value in enumerate(lines)
                  if "issued Apple CPU-stop value 5" in value)
prefix = lines[0].split("temporarily enabled", 1)[0]
VERIFY_LINES = [
    prefix + "AKS verify-secret request: endpoint=7 selector=0x21 tag=3 length=144 variant=1 password_bytes=not-logged context_bytes=not-logged",
    prefix + "AKS verify-secret envelope: raw=0003a107 00600000 00000000 00000000",
    prefix + "AKS verify-secret reply passed strict validation: authorized=yes device_state=not-logged",
]
SUMMARY = prefix + "credential authorization completed: authorized=yes result=0 secret_bytes=not-logged context_bytes=not-logged"
GOOD = "\n".join(lines[:delete_index] + VERIFY_LINES +
                 lines[delete_index:stop_index] + [SUMMARY] +
                 lines[stop_index:])


class VerifyPasswordAuthorizationLogTests(unittest.TestCase):
    def test_accepts_complete_scrubbed_authorization(self):
        self.assertEqual(verify.verify(GOOD), 2)

    def test_rejects_correlation_order_secret_and_cleanup_changes(self):
        mutations = (
            GOOD.replace("raw=0003a107", "raw=0004a107"),
            GOOD.replace("00600000", "00610000", 1),
            GOOD.replace("length=144", "length=145"),
            GOOD.replace("password_bytes=not-logged", "password=hunter2", 1),
            GOOD.replace("authorized=yes", "authorized=no", 1),
            GOOD.replace(VERIFY_LINES[2] + "\n", ""),
            GOOD.replace(next(line for line in GOOD.splitlines()
                              if "ACM context-delete request:" in line), ""),
            GOOD.replace(next(line for line in GOOD.splitlines()
                              if "read-only probe removed" in line), ""),
        )
        for changed in mutations:
            with self.subTest():
                with self.assertRaises(verify.VerificationError):
                    verify.verify(changed)


if __name__ == "__main__":
    unittest.main()
