import importlib.util
import sys
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "endpoint_lifecycle", Path(__file__).with_name("endpoint-lifecycle.py"))
life = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = life
SPEC.loader.exec_module(life)


class EndpointLifecycleTests(unittest.TestCase):
    def ready_endpoint(self):
        endpoint = life.EndpointLifecycle(8)
        endpoint.enable()
        endpoint.commit_registration("send", "send-a", control_succeeded=True)
        endpoint.commit_registration("receive", "recv-a", control_succeeded=True)
        return endpoint

    def test_registration_commits_only_after_control_success(self):
        endpoint = life.EndpointLifecycle(8)
        endpoint.enable()
        endpoint.commit_registration("send", "failed", control_succeeded=False)
        self.assertEqual(endpoint.mappings, ())
        endpoint.commit_registration("send", "send-a", control_succeeded=True)
        self.assertFalse(endpoint.ready)
        endpoint.commit_registration("receive", "recv-a", control_succeeded=True)
        self.assertTrue(endpoint.ready)

    def test_replacement_keeps_old_mapping_retained(self):
        endpoint = self.ready_endpoint()
        endpoint.commit_registration("send", "send-b", control_succeeded=True)
        by_id = {mapping.identifier: mapping for mapping in endpoint.mappings}
        self.assertFalse(by_id["send-a"].current)
        self.assertTrue(by_id["send-b"].current)
        self.assertEqual(len(endpoint.mappings), 3)

    def test_operations_and_sleep_hold_are_balanced(self):
        endpoint = self.ready_endpoint()
        endpoint.begin_operation()
        with self.assertRaisesRegex(life.LifecycleError, "drain"):
            endpoint.hold_for_sleep()
        endpoint.end_operation()
        with self.assertRaisesRegex(life.LifecycleError, "underflow"):
            endpoint.end_operation()
        endpoint.hold_for_sleep()
        with self.assertRaises(life.LifecycleError):
            endpoint.begin_operation()
        endpoint.resume()
        endpoint.begin_operation()
        endpoint.end_operation()

    def test_release_requires_stop_and_scrub_for_every_retained_mapping(self):
        endpoint = self.ready_endpoint()
        endpoint.commit_registration("send", "send-b", control_succeeded=True)
        with self.assertRaisesRegex(life.LifecycleError, "before transport stop"):
            endpoint.release("send-a")
        endpoint.stop_transport()
        with self.assertRaisesRegex(life.LifecycleError, "scrubbed"):
            endpoint.release("send-a")
        for mapping in tuple(endpoint.mappings):
            endpoint.scrub(mapping.identifier)
            endpoint.release(mapping.identifier)
        self.assertEqual(endpoint.mappings, ())

    def test_stop_rejects_active_operations_and_is_terminal(self):
        endpoint = self.ready_endpoint()
        endpoint.begin_operation()
        with self.assertRaisesRegex(life.LifecycleError, "drain"):
            endpoint.stop_transport()
        endpoint.end_operation()
        endpoint.stop_transport()
        self.assertFalse(endpoint.ready)
        with self.assertRaises(life.LifecycleError):
            endpoint.enable()
        with self.assertRaises(life.LifecycleError):
            endpoint.begin_operation()

    def test_strict_inputs(self):
        for endpoint_id in (True, 0, 0xFD, None):
            with self.assertRaises(life.LifecycleError):
                life.EndpointLifecycle(endpoint_id)
        endpoint = life.EndpointLifecycle(8)
        with self.assertRaises(life.LifecycleError):
            endpoint.commit_registration("send", "x", control_succeeded=True)
        endpoint.enable()
        for direction, identifier, result in (
                ("bad", "x", True), ("send", "", True),
                ("send", "x", 1)):
            with self.assertRaises(life.LifecycleError):
                endpoint.commit_registration(direction, identifier,
                                             control_succeeded=result)


if __name__ == "__main__":
    unittest.main()
