import importlib.util
from pathlib import Path
import plistlib
import sys
import unittest


SPEC = importlib.util.spec_from_file_location(
    "discovered_bridge_plan", Path(__file__).with_name("discovered-bridge-plan.py"))
plan = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = plan
SPEC.loader.exec_module(plan)


class DiscoveredBridgePlanTests(unittest.TestCase):
    def test_uses_current_rsd_address_and_advertised_port(self):
        result = plan.build_plan(49152, 7)
        self.assertEqual(result.endpoint, ("fe80::aede:48ff:fe00:11dd", 49152, 0, 7))
        self.assertNotEqual(result.endpoint[0], plan.bridge.T2_LINK_LOCAL_ADDRESS)
        header_size = plan.bridge.BRIDGE_FRAME_HEADER.size
        self.assertEqual(plistlib.loads(result.bridge_version_query[header_size:]), [0])
        self.assertEqual(plistlib.loads(result.service_opened_query[header_size:]), [1])
        self.assertEqual(plan.bridge.decode_frame_header(
            result.helo[:header_size], max_body=65536).kind,
            plan.bridge.FRAME_HELO)

    def test_rejects_unvalidated_endpoint_values(self):
        for port in (0, 65536, -1, True, "52032"):
            with self.subTest(port=port):
                with self.assertRaises(plan.PlanError):
                    plan.build_plan(port, 1)
        for index in (0, 1 << 32, -1, True, "1"):
            with self.subTest(index=index):
                with self.assertRaises(plan.PlanError):
                    plan.build_plan(52032, index)

    def test_bridge_validation_is_preserved(self):
        for kwargs in ({"max_body": 0}, {"os_build": ""},
                       {"process_name": "bad\0name"},
                       {"bridge_version": float("nan")}):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(plan.PlanError):
                    plan.build_plan(52032, 1, **kwargs)


if __name__ == "__main__":
    unittest.main()
