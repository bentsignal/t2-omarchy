import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest


PATH = Path(__file__).with_name("xnu-intcoproc-evidence.py")
SPEC = importlib.util.spec_from_file_location("xnu_intcoproc_evidence", PATH)
evidence = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = evidence
SPEC.loader.exec_module(evidence)


class XnuIntcoprocEvidenceTests(unittest.TestCase):
    def fixture(self, root):
        for label, relative in evidence.FILES.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("\n".join(evidence.REQUIRED[label]))

    def test_verifies_local_access_control_semantics(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.fixture(root)
            result = evidence.inspect(root)
        self.assertEqual(result["option_value"], 0x1118)
        self.assertEqual(result["pcb_effect"], "INP2_INTCOPROC_ALLOWED")
        self.assertFalse(result["peer_visible_signal"])
        self.assertFalse(result["linux_equivalent_required"])
        self.assertEqual(len(result["source_sha256"]), 5)

    def test_rejects_missing_semantic_link(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.fixture(root)
            path = root / evidence.FILES["socket"]
            path.write_text(path.read_text().replace(
                "PRIV_NET_RESTRICTED_INTCOPROC", "missing"))
            with self.assertRaisesRegex(evidence.EvidenceError, "lacks required"):
                evidence.inspect(root)

    def test_rejects_symlinked_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.fixture(root)
            path = root / evidence.FILES["tcp"]
            target = root / "tcp-copy.c"
            target.write_bytes(path.read_bytes())
            path.unlink()
            path.symlink_to(target)
            with self.assertRaisesRegex(evidence.EvidenceError, "regular source"):
                evidence.inspect(root)


if __name__ == "__main__":
    unittest.main()
