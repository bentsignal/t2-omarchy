#!/usr/bin/env python3
import importlib.util
import io
import os
import plistlib
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


SCRIPT = Path(__file__).with_name("import-current-catacomb.py")
SPEC = importlib.util.spec_from_file_location("current_catacomb_import", SCRIPT)
importer = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = importer
SPEC.loader.exec_module(importer)

FIXTURES = Path(__file__).with_name("test_validate_current_macos_catacomb.py")
FIXTURE_SPEC = importlib.util.spec_from_file_location("current_catacomb_fixtures", FIXTURES)
fixtures = importlib.util.module_from_spec(FIXTURE_SPEC)
assert FIXTURE_SPEC and FIXTURE_SPEC.loader
sys.modules[FIXTURE_SPEC.name] = fixtures
FIXTURE_SPEC.loader.exec_module(fixtures)


def make_archive(directory: Path, *, empty=False) -> tuple[Path, dict[str, bytes]]:
    user = plistlib.loads(fixtures.user_fixture())
    if empty:
        user["$objects"][3]["NS.objects"] = []
        user = plistlib.dumps(user, fmt=plistlib.FMT_BINARY, sort_keys=False)
    else:
        user = fixtures.user_fixture()
    components = {
        "master.cat": fixtures.master_fixture(),
        "user_000001f5.cat": user,
        "biolockout.cat": fixtures.biolockout_fixture(),
    }
    archive_path = directory / "current.tar.gz"
    with tarfile.open(archive_path, "w:gz") as archive:
        for name, data in components.items():
            metadata = tarfile.TarInfo(f"Catacomb/{name}")
            metadata.size = len(data)
            archive.addfile(metadata, io.BytesIO(data))
    archive_path.chmod(0o600)
    return archive_path, components


def make_old_store(root: Path, *, extra=False) -> dict[str, bytes]:
    store = root / "catacomb"
    store.mkdir(mode=0o700)
    values = {
        "master.cat": b"old-master",
        "user_000001f5.cat": b"old-user",
        "biolockout.cat": b"old-biolockout",
    }
    for name, data in values.items():
        path = store / name
        path.write_bytes(data)
        path.chmod(0o600)
    if extra:
        extra_path = store / "unexpected"
        extra_path.write_bytes(b"unsafe")
        extra_path.chmod(0o600)
    return values


class CurrentCatacombImportTests(unittest.TestCase):
    def test_import_is_atomic_and_preserves_previous_store(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            old = make_old_store(root)
            archive, current = make_archive(root)
            result = importer.install_archive(archive, root, 501)
            self.assertTrue(result.identity_nonzero)
            self.assertTrue(result.previous_store_preserved)
            self.assertTrue(result.import_committed)
            for name, data in current.items():
                self.assertEqual((root / "catacomb" / name).read_bytes(), data)
                self.assertEqual(stat_mode(root / "catacomb" / name), 0o600)
            for name, data in old.items():
                self.assertEqual(
                    (root / "catacomb-zero-identity-backup" / name).read_bytes(),
                    data,
                )

    def test_empty_identity_archive_is_rejected_before_store_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            old = make_old_store(root)
            archive, components = make_archive(root)
            empty = SimpleNamespace(identity_count=0, components=components)
            with patch.object(
                importer.validator, "load_validated_archive", return_value=empty
            ), self.assertRaisesRegex(importer.ImportError, "no enrolled identity"):
                importer.install_archive(archive, root, 501)
            self.assertFalse((root / "catacomb-zero-identity-backup").exists())
            for name, data in old.items():
                self.assertEqual((root / "catacomb" / name).read_bytes(), data)

    def test_unexpected_existing_entry_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            make_old_store(root, extra=True)
            archive, _ = make_archive(root)
            with self.assertRaisesRegex(importer.ImportError, "exact component set"):
                importer.install_archive(archive, root, 501)

    def test_failure_after_backup_rolls_previous_store_back(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            old = make_old_store(root)
            archive, _ = make_archive(root)

            def fail(milestone):
                if milestone == "previous_store_preserved":
                    raise RuntimeError("injected failure")

            with self.assertRaisesRegex(RuntimeError, "injected failure"):
                importer.install_archive(archive, root, 501, failure_hook=fail)
            self.assertFalse((root / "catacomb-zero-identity-backup").exists())
            for name, data in old.items():
                self.assertEqual((root / "catacomb" / name).read_bytes(), data)


def stat_mode(path: Path) -> int:
    return os.stat(path, follow_symlinks=False).st_mode & 0o777


if __name__ == "__main__":
    unittest.main()
