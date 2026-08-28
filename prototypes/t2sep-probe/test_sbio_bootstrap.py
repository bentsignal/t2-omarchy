import importlib.util
from pathlib import Path
import sys
import unittest


SPEC = importlib.util.spec_from_file_location(
    "sbio_bootstrap", Path(__file__).with_name("sbio-bootstrap.py"))
sbio = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = sbio
SPEC.loader.exec_module(sbio)


IDENTITY = [0x080000FD, 0x6F696273, 0, 0]
LIMITS = [0x080100FD, 0x4B014104, 0, 0]


class SbioBootstrapTests(unittest.TestCase):
    def ready_bootstrap(self):
        bootstrap = sbio.SbioBootstrap()
        bootstrap.accept_discovery(IDENTITY)
        bootstrap.accept_discovery(LIMITS)
        bootstrap.finalize_discovery()
        send, receive = bootstrap.registration_requests(
            0x100000, 0x200000, send_tag=2, receive_tag=3)
        return bootstrap, send, receive

    def test_exact_ordered_bootstrap(self):
        bootstrap, send, receive = self.ready_bootstrap()
        self.assertEqual(send, [0x08020200, 0x100, 0x4000, 0])
        self.assertEqual(receive, [0x08030300, 0x200, 0x4B000, 0])
        profile = sbio.ReplyProfile(0x82, 8, 0x83, 8)
        bootstrap.accept_registration_replies(
            [0x08820200, 0, 0, 0], [0x08830300, 0, 0, 0], profile)
        first = bootstrap.initialization_session(initial_sequence=7).start()
        self.assertEqual(first.notification_word, 0x000700000073FC00)
        self.assertEqual(first.packet.hex(),
                         "0100000004000000000000000000000000000000730000000400000003000000")

    def test_rejects_skipped_or_repeated_phases(self):
        bootstrap = sbio.SbioBootstrap()
        with self.assertRaisesRegex(sbio.BootstrapError, "finalized discovery"):
            bootstrap.registration_requests(0x100000, 0x200000,
                                            send_tag=2, receive_tag=3)
        bootstrap.accept_discovery(IDENTITY)
        bootstrap.accept_discovery(LIMITS)
        bootstrap.finalize_discovery()
        with self.assertRaisesRegex(sbio.BootstrapError, "already finalized"):
            bootstrap.finalize_discovery()
        bootstrap.registration_requests(0x100000, 0x200000,
                                        send_tag=2, receive_tag=3)
        with self.assertRaisesRegex(sbio.BootstrapError, "already prepared"):
            bootstrap.registration_requests(0x300000, 0x400000,
                                            send_tag=4, receive_tag=5)

    def test_requires_distinct_tags_and_observed_reply_profile(self):
        bootstrap = sbio.SbioBootstrap()
        bootstrap.accept_discovery(IDENTITY)
        bootstrap.accept_discovery(LIMITS)
        bootstrap.finalize_discovery()
        with self.assertRaisesRegex(sbio.BootstrapError, "distinct tags"):
            bootstrap.registration_requests(0x100000, 0x200000,
                                            send_tag=2, receive_tag=2)
        _, send, receive = self.ready_bootstrap()
        with self.assertRaisesRegex(sbio.BootstrapError, "reply profile"):
            _.accept_registration_replies(send, receive, None)

    def test_failed_ack_never_makes_endpoint_ready(self):
        bootstrap, _, _ = self.ready_bootstrap()
        profile = sbio.ReplyProfile(0x82, 8, 0x83, 8)
        with self.assertRaises(sbio.BootstrapError):
            bootstrap.accept_registration_replies(
                [0x08820200, 1, 0, 0], [0x08830300, 0, 0, 0], profile)
        self.assertFalse(bootstrap.ownership.ready)
        with self.assertRaisesRegex(sbio.BootstrapError, "both committed"):
            bootstrap.initialization_session()


if __name__ == "__main__":
    unittest.main()
