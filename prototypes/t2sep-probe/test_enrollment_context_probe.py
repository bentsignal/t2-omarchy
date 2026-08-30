import importlib.util
from pathlib import Path
import sys
import unittest


PATH = Path(__file__).with_name("enrollment-context-probe.py")
SPEC = importlib.util.spec_from_file_location("enrollment_context_probe_tested", PATH)
assert SPEC and SPEC.loader
probe = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = probe
SPEC.loader.exec_module(probe)


class EnrollmentContextProbeTests(unittest.TestCase):
    def test_live_gate_is_closed(self):
        self.assertFalse(probe.LIVE_CONTEXT_ENABLED)
        with self.assertRaisesRegex(probe.EnrollmentContextError, "disabled"):
            probe.live_probe()

    def test_probe_initializes_then_establishes_without_enrollment(self):
        calls = []
        original_session = probe.enrollment.coupled.bridge_query.BridgeSession
        original_initialize = probe.enrollment._initialize_current_bridge
        original_establish = probe.enrollment._establish_enrollment_sensor_context
        session = object()
        probe.enrollment.coupled.bridge_query.BridgeSession = lambda sock: session
        probe.enrollment._initialize_current_bridge = (
            lambda value: calls.append(("initialize", value)))
        probe.enrollment._establish_enrollment_sensor_context = (
            lambda value: calls.append(("context", value)))
        try:
            probe.probe_socket(object())
        finally:
            probe.enrollment.coupled.bridge_query.BridgeSession = original_session
            probe.enrollment._initialize_current_bridge = original_initialize
            probe.enrollment._establish_enrollment_sensor_context = original_establish
        self.assertEqual(calls, [("initialize", session), ("context", session)])


if __name__ == "__main__":
    unittest.main()
