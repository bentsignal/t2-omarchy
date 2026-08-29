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
        state = bootstrap.CredentialServiceBootstrap(bootstrap.AKS)
        send, receive = state.registration_requests(
            0x100000, 0x200000, send_tag=4, receive_tag=5)
        profile = bootstrap.AKS_REPLY_PROFILE
        state.accept_registration_replies(reply(send, 1, 7),
                                          reply(receive, 1, 7), profile)
        self.assertTrue(state.ready)
        self.assertEqual(state.stop_and_release(), ("aks-receive", "aks-send"))

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


if __name__ == "__main__":
    unittest.main()
