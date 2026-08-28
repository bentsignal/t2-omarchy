import importlib.util
from pathlib import Path
import struct
import sys
import unittest


SPEC = importlib.util.spec_from_file_location(
    "authentication_result", Path(__file__).with_name("authentication-result.py"))
auth = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = auth
SPEC.loader.exec_module(auth)


def event(user_id, uuid=bytes(range(16)), *, lotl=()):
    blob = bytearray(auth.biometric.CATALINA_MATCH_RESULT_BASE_SIZE + 4 * len(lotl))
    struct.pack_into("<I16s", blob, 0, user_id, uuid)
    struct.pack_into("<I", blob,
                     auth.biometric.CATALINA_MATCH_RESULT_LOTL_COUNT_OFFSET,
                     len(lotl))
    if lotl:
        struct.pack_into(f"<{len(lotl)}I", blob,
                         auth.biometric.CATALINA_MATCH_RESULT_LOTL_OFFSET, *lotl)
    return bytes(blob)


class MatchAuthenticationTests(unittest.TestCase):
    def setUp(self):
        self.identity = auth.biometric.BiometricIdentity(501, bytes(range(16)))

    def operation(self):
        return auth.MatchAuthentication(
            expected_user_id=501, trusted_identities=(self.identity,))

    def test_authorizes_only_exact_trusted_identity(self):
        operation = self.operation()
        decision = operation.accept_terminal(
            status=auth.biometric.SERVICE_EVENT_MATCH_RESULT,
            version=auth.biometric.SERVICE_EVENT_VERSION, data=event(501))
        self.assertTrue(decision.matched)
        self.assertEqual(decision.identity, self.identity)
        self.assertEqual(operation.finish(), decision)
        with self.assertRaisesRegex(auth.AuthenticationResultError, "complete"):
            operation.accept_terminal(
                status=auth.biometric.SERVICE_EVENT_MATCH_RESULT,
                version=1, data=event(501))

    def test_uint32_max_is_terminal_no_match(self):
        operation = self.operation()
        decision = operation.accept_terminal(
            status=auth.biometric.SERVICE_EVENT_MATCH_RESULT,
            version=1, data=event(0xFFFFFFFF, bytes([0xAA]) * 16))
        self.assertFalse(decision.matched)
        self.assertIsNone(decision.identity)
        self.assertEqual(operation.finish(), decision)

    def test_rejects_unknown_wrong_user_and_wrong_event(self):
        for data, pattern in ((event(501, bytes(16)), "trusted"),
                              (event(502), "different user")):
            with self.subTest(pattern=pattern):
                operation = self.operation()
                with self.assertRaisesRegex(auth.AuthenticationResultError, pattern):
                    operation.accept_terminal(
                        status=auth.biometric.SERVICE_EVENT_MATCH_RESULT,
                        version=1, data=data)
                with self.assertRaisesRegex(auth.AuthenticationResultError, "failed"):
                    operation.accept_terminal(
                        status=auth.biometric.SERVICE_EVENT_MATCH_RESULT,
                        version=1, data=event(501))
        with self.assertRaisesRegex(auth.AuthenticationResultError, "invalid"):
            operation = self.operation()
            operation.accept_terminal(
                status=auth.biometric.SERVICE_EVENT_MATCH_ACTIVITY,
                version=1, data=event(501))
        with self.assertRaisesRegex(auth.AuthenticationResultError, "failed"):
            operation.finish()

    def test_rejects_bad_snapshot_and_incomplete_operation(self):
        with self.assertRaises(auth.AuthenticationResultError):
            auth.MatchAuthentication(expected_user_id=501, trusted_identities=())
        wrong = auth.biometric.BiometricIdentity(502, bytes(16))
        with self.assertRaisesRegex(auth.AuthenticationResultError, "different user"):
            auth.MatchAuthentication(expected_user_id=501,
                                     trusted_identities=(wrong,))
        with self.assertRaisesRegex(auth.AuthenticationResultError, "no terminal"):
            self.operation().finish()

    def test_abort_permanently_fails_operation(self):
        operation = self.operation()
        operation.abort()
        with self.assertRaisesRegex(auth.AuthenticationResultError, "failed"):
            operation.finish()
        with self.assertRaisesRegex(auth.AuthenticationResultError, "failed"):
            operation.accept_terminal(
                status=auth.biometric.SERVICE_EVENT_MATCH_RESULT,
                version=1, data=event(501))


if __name__ == "__main__":
    unittest.main()
