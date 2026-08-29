import importlib.util
from pathlib import Path
import sys
import unittest


MODULE = Path(__file__).with_name("credential-services-bootstrap.py")
SPEC = importlib.util.spec_from_file_location("credential_services_bootstrap", MODULE)
assert SPEC and SPEC.loader
bootstrap = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = bootstrap
SPEC.loader.exec_module(bootstrap)


def reply(request, opcode, target):
    return [((request[0] & 0xff00) | opcode << 16 | target << 24), 0, 0, 0]


class CredentialServicesBootstrapTests(unittest.TestCase):
    def test_both_fixed_services_use_two_16k_mappings(self):
        for service in (bootstrap.ACM, bootstrap.AKS):
            with self.subTest(service=service.name):
                state = bootstrap.CredentialServiceBootstrap(service)
                send, receive = state.registration_requests(
                    0x100000, 0x200000, send_tag=4, receive_tag=5)
                self.assertEqual(send, [service.endpoint << 24 | 2 << 16 | 4 << 8,
                                        0x100, 0x4000, 0])
                self.assertEqual(receive,
                                 [service.endpoint << 24 | 3 << 16 | 5 << 8,
                                  0x200, 0x4000, 0])

    def test_registration_requires_exact_independent_reply_profile(self):
        for service, profile in (
                (bootstrap.AKS, bootstrap.AKS_REPLY_PROFILE),
                (bootstrap.ACM, bootstrap.ACM_REPLY_PROFILE)):
            with self.subTest(service=service.name):
                state = bootstrap.CredentialServiceBootstrap(service)
                send, receive = state.registration_requests(
                    0x100000, 0x200000, send_tag=4, receive_tag=5)
                state.accept_registration_replies(
                    reply(send, 1, service.endpoint),
                    reply(receive, 1, service.endpoint), profile)
                self.assertTrue(state.ready)
                self.assertEqual(
                    state.stop_and_release(),
                    (f"{service.name}-receive", f"{service.name}-send"))

    def test_failure_never_commits_partial_ownership(self):
        state = bootstrap.CredentialServiceBootstrap(bootstrap.ACM)
        send, receive = state.registration_requests(
            0x100000, 0x200000, send_tag=4, receive_tag=5)
        profile = bootstrap.ReplyProfile(0x82, 10, 0x83, 10)
        with self.assertRaises(bootstrap.CredentialBootstrapError):
            state.accept_registration_replies(reply(send, 0x82, 10),
                                              reply(receive, 0x83, 7), profile)
        self.assertFalse(state.ready)
        self.assertEqual(state.ownership.mappings, ())

    def test_rejects_unknown_service_duplicate_tags_and_reuse(self):
        with self.assertRaises(bootstrap.CredentialBootstrapError):
            bootstrap.CredentialServiceBootstrap(
                bootstrap.ServiceProfile("guess", 9))
        state = bootstrap.CredentialServiceBootstrap(bootstrap.ACM)
        with self.assertRaises(bootstrap.CredentialBootstrapError):
            state.registration_requests(0x100000, 0x200000,
                                        send_tag=1, receive_tag=1)
        state.registration_requests(0x100000, 0x200000,
                                    send_tag=1, receive_tag=2)
        with self.assertRaises(bootstrap.CredentialBootstrapError):
            state.registration_requests(0x300000, 0x400000,
                                        send_tag=3, receive_tag=4)

    def test_dual_bootstrap_uses_four_global_tags_and_becomes_ready_atomically(self):
        state = bootstrap.DualCredentialBootstrap()
        requests = state.registration_requests(
            0x100000, 0x200000, 0x300000, 0x400000)
        self.assertEqual(
            requests,
            ([bootstrap.AKS.endpoint << 24 | 2 << 16 | 2 << 8,
              0x100, 0x4000, 0],
             [bootstrap.AKS.endpoint << 24 | 3 << 16 | 3 << 8,
              0x200, 0x4000, 0],
             [bootstrap.ACM.endpoint << 24 | 2 << 16 | 4 << 8,
              0x300, 0x4000, 0],
             [bootstrap.ACM.endpoint << 24 | 3 << 16 | 5 << 8,
              0x400, 0x4000, 0]))
        self.assertFalse(state.ready)
        state.accept_registration_replies(
            *(reply(request, 1, target) for request, target in zip(
                requests, (bootstrap.AKS.endpoint, bootstrap.AKS.endpoint,
                           bootstrap.ACM.endpoint, bootstrap.ACM.endpoint))))
        self.assertTrue(state.ready)
        self.assertEqual(
            state.stop_and_release(),
            ("acm-receive", "acm-send", "aks-receive", "aks-send"))
        self.assertTrue(state.aks.ownership.transport_stopped)
        self.assertTrue(state.acm.ownership.transport_stopped)
        self.assertEqual(state.aks.ownership.mappings, ())
        self.assertEqual(state.acm.ownership.mappings, ())

    def test_dual_bad_final_reply_commits_neither_endpoint(self):
        state = bootstrap.DualCredentialBootstrap()
        requests = state.registration_requests(
            0x100000, 0x200000, 0x300000, 0x400000)
        replies = [reply(request, 1, target) for request, target in zip(
            requests, (bootstrap.AKS.endpoint, bootstrap.AKS.endpoint,
                       bootstrap.ACM.endpoint, bootstrap.ACM.endpoint))]
        replies[-1][1] = 1
        with self.assertRaises(bootstrap.CredentialBootstrapError):
            state.accept_registration_replies(*replies)
        self.assertEqual(state.aks.ownership.mappings, ())
        self.assertEqual(state.acm.ownership.mappings, ())

    def test_dual_rejects_invalid_global_layout_or_tag_range(self):
        invalid = (
            ((0x100000, 0x100000, 0x300000, 0x400000), 2),
            ((0x100001, 0x200000, 0x300000, 0x400000), 2),
            ((0x100000, 0x200000, 0x300000, 0x400000), 0),
            ((0x100000, 0x200000, 0x300000, 0x400000), 0xfd),
            ((0x100000, 0x200000, 0x300000, 0x400000), True),
            ((True, 0x200000, 0x300000, 0x400000), 2),
            (((1 << 44) - 0x2000, 0x200000, 0x300000, 0x400000), 2),
        )
        for addresses, first_tag in invalid:
            with self.subTest(addresses=addresses, first_tag=first_tag):
                with self.assertRaises(bootstrap.CredentialBootstrapError):
                    bootstrap.DualCredentialBootstrap().registration_requests(
                        *addresses, first_tag=first_tag)

    def test_dual_stop_preflights_both_endpoints(self):
        state = bootstrap.DualCredentialBootstrap()
        with self.assertRaises(bootstrap.CredentialBootstrapError):
            state.stop_and_release()
        requests = state.registration_requests(
            0x100000, 0x200000, 0x300000, 0x400000)
        state.accept_registration_replies(
            *(reply(request, 1, target) for request, target in zip(
                requests, (bootstrap.AKS.endpoint, bootstrap.AKS.endpoint,
                           bootstrap.ACM.endpoint, bootstrap.ACM.endpoint))))
        state.acm.ownership.begin_operation()
        with self.assertRaises(bootstrap.CredentialBootstrapError):
            state.stop_and_release()
        self.assertFalse(state.aks.ownership.transport_stopped)
        self.assertFalse(state.acm.ownership.transport_stopped)


if __name__ == "__main__":
    unittest.main()
