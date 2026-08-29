import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


MODULE = Path(__file__).with_name("verify-bridgeos-keybag-store-types.py")
SPEC = importlib.util.spec_from_file_location("keybag_store_evidence", MODULE)
assert SPEC and SPEC.loader
evidence = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = evidence
SPEC.loader.exec_module(evidence)


class KeybagStoreEvidenceTests(unittest.TestCase):
    def test_exact_call_site_is_required(self):
        label, base, address, expected = evidence.EVIDENCE[0]
        data = bytearray(address - base + len(expected))
        data[address - base:address - base + len(expected)] = expected
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "keybagd"
            path.write_bytes(data)
            import hashlib
            digest = hashlib.sha256(data).hexdigest()
            evidence.verify(path, digest, ((label, base, address, expected),))
            data[address - base] ^= 1
            path.write_bytes(data)
            with mock.patch.object(evidence.hashlib, "sha256") as sha:
                sha.return_value.hexdigest.return_value = digest
                with self.assertRaisesRegex(ValueError, "call site mismatch"):
                    evidence.verify(path, digest,
                                    ((label, base, address, expected),))

    def test_hash_mismatch_fails_before_instruction_check(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "binary"
            path.write_bytes(b"not the pinned image")
            with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                evidence.verify(path, "0" * 64, ())


if __name__ == "__main__":
    unittest.main()
