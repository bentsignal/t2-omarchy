import importlib.util
from pathlib import Path
import struct
import sys
import tempfile
import unittest


SPEC = importlib.util.spec_from_file_location(
    "catacomb_store_tested", Path(__file__).with_name("catacomb-store.py"))
store = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = store
SPEC.loader.exec_module(store)


class CatacombStoreTests(unittest.TestCase):
    def blob(self, uid=501):
        result = bytearray(128)
        struct.pack_into("<I", result, 8, uid)
        return bytes(result)

    def test_round_trip_and_atomic_file_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / "nested" / "501.catacomb"
            store.save(path, user_id=501, blob=self.blob())
            self.assertEqual(store.load(path, expected_user_id=501), self.blob())
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)

    def test_corruption_or_user_substitution_fails_closed(self):
        record = store.encode_record(user_id=501, blob=self.blob())
        altered = record[:-1] + bytes((record[-1] ^ 1,))
        with self.assertRaises(store.CatacombStoreError):
            store.decode_record(altered, expected_user_id=501)
        with self.assertRaises(store.CatacombStoreError):
            store.decode_record(record, expected_user_id=502)
        with self.assertRaises(store.CatacombStoreError):
            store.encode_record(user_id=501, blob=self.blob(502))


if __name__ == "__main__":
    unittest.main()
