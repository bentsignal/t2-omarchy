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


verify = load("verify-credential-startup-log.py", "verify_credential_startup_log")
dual_fixture = load("test_verify_dual_credential_ool_log.py", "combined_dual_fixture")
aks_fixture = load("test_verify_aks_startup_environment_log.py", "combined_aks_fixture")
acm_fixture = load("test_verify_acm_context_lifecycle_log.py", "combined_acm_fixture")


def service_lines(text, prefix):
    return [line for line in text.splitlines()
            if f"t2sep_probe 0000:04:00.2: {prefix}" in line]


dual_lines = dual_fixture.GOOD.splitlines()
stop_index = next(index for index, value in enumerate(dual_lines)
                  if "issued Apple CPU-stop value 5" in value)
GOOD = "\n".join(
    dual_lines[:stop_index] +
    service_lines(aks_fixture.GOOD, "AKS ") +
    service_lines(acm_fixture.GOOD, "ACM ") +
    dual_lines[stop_index:])


class VerifyCredentialStartupLogTests(unittest.TestCase):
    def test_accepts_complete_combined_lifetime(self):
        self.assertEqual(verify.verify(GOOD), 2)

    def test_accepts_observed_compact_capabilities_reply(self):
        compact = GOOD.replace(
            "AKS capabilities envelope: raw=0001cd07 00640000",
            "AKS capabilities envelope: raw=0001cd07 005c0000").replace(
                "AKS capabilities reply passed strict validation: status=0 remote_header_version=2",
                "AKS capabilities reply passed strict validation: status=0 remote_header_version=2 reply_size=92")
        self.assertEqual(verify.verify(compact), 2)

    def test_rejects_order_missing_endpoint_secret_and_teardown(self):
        aks_lines = service_lines(aks_fixture.GOOD, "AKS ")
        acm_lines = service_lines(acm_fixture.GOOD, "ACM ")
        reordered = "\n".join(
            dual_lines[:stop_index] + acm_lines + aks_lines +
            dual_lines[stop_index:])
        mutations = (
            reordered,
            GOOD.replace("pinned OOL buffers: target=10",
                         "pinned OOL buffers: target=11", 1),
            GOOD.replace("context_bytes=not-logged", "context=0xdeadbeef", 1),
            GOOD.replace(next(line for line in GOOD.splitlines()
                              if "AKS startup environment reply passed" in line), ""),
            GOOD.replace(next(line for line in GOOD.splitlines()
                              if "read-only probe removed" in line), ""),
        )
        for changed in mutations:
            with self.subTest():
                with self.assertRaises(verify.VerificationError):
                    verify.verify(changed)


if __name__ == "__main__":
    unittest.main()
