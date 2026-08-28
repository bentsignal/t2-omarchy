import importlib.util
import sys
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "endpoint_router", Path(__file__).with_name("endpoint-router.py"))
router = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = router
SPEC.loader.exec_module(router)


class EndpointRouterTests(unittest.TestCase):
    def test_routes_only_first_three_words_to_registered_endpoint(self):
        demux = router.EndpointRouter()
        queue = demux.register(8)
        queue.enable()
        self.assertEqual(demux.route([0x12340008, 2, 3, 0x80000000]), "queued")
        message = queue.dispatch_one()
        self.assertEqual(message.words, (0x12340008, 2, 3))
        self.assertEqual(message.endpoint, 8)

    def test_unroutable_and_unknown_endpoints_are_dropped(self):
        demux = router.EndpointRouter()
        self.assertEqual(demux.route([8, 0, 0, 0]), "dropped-unregistered")
        demux.register(8)
        self.assertEqual(demux.route([0xFD, 0, 0, 0]), "dropped-unroutable")
        self.assertEqual(demux.route([32, 0, 0, 0]), "dropped-unroutable")

    def test_disabled_queue_retains_messages_without_dispatch(self):
        demux = router.EndpointRouter()
        queue = demux.register(8)
        demux.route([8, 1, 2, 0])
        self.assertEqual(queue.pending, 1)
        self.assertIsNone(queue.dispatch_one())
        queue.enable()
        self.assertEqual(queue.dispatch_one().words, (8, 1, 2))

    def test_ring_has_31_usable_slots_and_never_overwrites(self):
        demux = router.EndpointRouter()
        queue = demux.register(8)
        for sequence in range(31):
            demux.route([8, sequence, 0, 0])
        self.assertEqual(queue.pending, 31)
        with self.assertRaises(router.QueueFull):
            demux.route([8, 31, 0, 0])
        queue.enable()
        self.assertEqual([queue.dispatch_one().words[1] for _ in range(31)],
                         list(range(31)))

    def test_transport_errors_and_malformed_records_fail_closed(self):
        demux = router.EndpointRouter()
        demux.register(8)
        for flag in (1 << 18, 1 << 19):
            with self.assertRaisesRegex(router.RouterError, "transport"):
                demux.route([8, 0, 0, flag])
        for record in (None, [0] * 3, [0] * 5, [0, 0, 0, True]):
            with self.assertRaises(router.RouterError):
                demux.route(record)

    def test_registration_and_queue_state_are_strict(self):
        demux = router.EndpointRouter()
        for endpoint in (True, -1, 32, None):
            with self.assertRaises(router.RouterError):
                demux.register(endpoint)
        queue = demux.register(8)
        with self.assertRaises(router.RouterError):
            demux.register(8)
        queue.enable()
        with self.assertRaises(router.RouterError):
            queue.enable()
        queue.disable()
        with self.assertRaises(router.RouterError):
            queue.disable()


if __name__ == "__main__":
    unittest.main()
