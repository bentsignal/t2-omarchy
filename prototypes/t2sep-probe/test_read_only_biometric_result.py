import importlib.util
from pathlib import Path
import plistlib
import struct
import sys
import unittest


SPEC = importlib.util.spec_from_file_location(
    "read_only_biometric_result",
    Path(__file__).with_name("read-only-biometric-result.py"))
result = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = result
SPEC.loader.exec_module(result)


def reply(status, output):
    return plistlib.dumps([status, output], fmt=plistlib.FMT_BINARY)


class ReadOnlyBiometricResultTests(unittest.TestCase):
    def test_correlates_complete_identity_snapshot(self):
        identity = struct.pack("<I16s", 501, bytes(range(16)))
        replies = result.IdentityQueryReplies(user_id=501)
        self.assertIsNone(replies.accept(reply(0, struct.pack("<I", 5))))
        self.assertIsNone(replies.accept(reply(0, struct.pack("<I", 4))))
        snapshot = replies.accept(reply(0, identity))
        self.assertEqual(snapshot.maximum_count, 5)
        self.assertEqual(snapshot.free_count, 4)
        self.assertEqual(snapshot.identities[0].user_id, 501)
        self.assertEqual(replies.finish(), snapshot)
        with self.assertRaisesRegex(result.ReadOnlyResultError, "complete"):
            replies.accept(reply(0, identity))

    def test_rejects_incomplete_nonzero_missing_and_bad_counts(self):
        with self.assertRaises(result.ReadOnlyResultError):
            result.IdentityQueryReplies(user_id=-1)
        replies = result.IdentityQueryReplies(user_id=501)
        with self.assertRaisesRegex(result.ReadOnlyResultError, "incomplete"):
            replies.finish()
        with self.assertRaisesRegex(result.ReadOnlyResultError, "nonzero"):
            replies.accept(reply(-1, b"\0" * 4))
        replies = result.IdentityQueryReplies(user_id=501)
        with self.assertRaisesRegex(result.ReadOnlyResultError, "no output"):
            replies.accept(reply(0, None))
        replies = result.IdentityQueryReplies(user_id=501)
        replies.accept(reply(0, struct.pack("<I", 2)))
        with self.assertRaisesRegex(result.ReadOnlyResultError, "exceeds"):
            replies.accept(reply(0, struct.pack("<I", 3)))

    def test_rejects_wrong_user_and_more_listed_than_occupied(self):
        wrong_user = struct.pack("<I16s", 502, bytes(16))
        replies = result.IdentityQueryReplies(user_id=501)
        replies.accept(reply(0, struct.pack("<I", 2)))
        replies.accept(reply(0, struct.pack("<I", 1)))
        with self.assertRaisesRegex(result.ReadOnlyResultError, "unexpected user"):
            replies.accept(reply(0, wrong_user))

        two = (struct.pack("<I16s", 501, bytes(16))
               + struct.pack("<I16s", 501, bytes([1]) * 16))
        replies = result.IdentityQueryReplies(user_id=501)
        replies.accept(reply(0, struct.pack("<I", 2)))
        replies.accept(reply(0, struct.pack("<I", 1)))
        with self.assertRaisesRegex(result.ReadOnlyResultError, "occupied"):
            replies.accept(reply(0, two))


if __name__ == "__main__":
    unittest.main()
