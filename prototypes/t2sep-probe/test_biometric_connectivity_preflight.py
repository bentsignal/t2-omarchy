import importlib.util
from pathlib import Path
import sys
import unittest
from unittest import mock


PATH = Path(__file__).with_name("biometric-connectivity-preflight.py")
SPEC = importlib.util.spec_from_file_location("biometric_preflight_tested", PATH)
assert SPEC and SPEC.loader
preflight = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = preflight
SPEC.loader.exec_module(preflight)


class BiometricConnectivityPreflightTests(unittest.TestCase):
    def test_exact_reply_passes_and_gate_is_restored(self):
        preflight.coupled.LIVE_COUPLED_QUERY_ENABLED = False
        with mock.patch.object(preflight.coupled, "live_query",
                               return_value=(0, 3)) as query:
            self.assertEqual(preflight.verify("t2test"), (0, 3))
        query.assert_called_once_with("t2test", 5.0)
        self.assertFalse(preflight.coupled.LIVE_COUPLED_QUERY_ENABLED)

    def test_transport_and_wrong_reply_fail_closed(self):
        for result in (OSError("down"), (0, 4), (-3, 3)):
            with self.subTest(result=result):
                side_effect = result if isinstance(result, Exception) else None
                return_value = None if side_effect else result
                with mock.patch.object(preflight.coupled, "live_query",
                                       side_effect=side_effect,
                                       return_value=return_value):
                    with self.assertRaises(preflight.PreflightError):
                        preflight.verify("t2test")


if __name__ == "__main__":
    unittest.main()
