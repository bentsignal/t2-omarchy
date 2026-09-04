import importlib.util
from pathlib import Path
import plistlib
import sys
import tempfile
import unittest
import uuid


SCRIPT = Path(__file__).with_name("enrollment-transaction.py")
SPEC = importlib.util.spec_from_file_location("enrollment_transaction", SCRIPT)
transaction = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = transaction
SPEC.loader.exec_module(transaction)

FIXTURES = Path(__file__).resolve().parents[2] / "tools/research/test_validate_current_macos_catacomb.py"
FIXTURE_SPEC = importlib.util.spec_from_file_location("transaction_fixtures", FIXTURES)
fixtures = importlib.util.module_from_spec(FIXTURE_SPEC)
assert FIXTURE_SPEC and FIXTURE_SPEC.loader
sys.modules[FIXTURE_SPEC.name] = fixtures
FIXTURE_SPEC.loader.exec_module(fixtures)


def make_root(directory: str):
    root = Path(directory)
    root.chmod(0o700)
    (root / "mutations").mkdir(mode=0o700)
    store = root / "catacomb"
    store.mkdir(mode=0o700)
    components = {
        "master.cat": fixtures.master_fixture(),
        "user_000001f5.cat": fixtures.user_fixture(),
        "biolockout.cat": fixtures.biolockout_fixture(),
    }
    for name, data in components.items():
        path = store / name
        path.write_bytes(data)
        path.chmod(0o600)
    return root, components


def staged_values():
    return {
        "user_000001f5.cat": b"LTFC" + b"x" * 28,
        "master.cat": b"LTFC" + b"y" * 28,
        "biolockout.cat": b"HRLB" + b"z" * 28,
    }


def begin(value):
    value.begin(
        live_identity_count=2,
        maximum_identity_count=5,
        free_identity_count=2,
    )


class EnrollmentTransactionTests(unittest.TestCase):
    def test_validated_commit_preserves_rollback_and_removes_private_stage(self):
        with tempfile.TemporaryDirectory() as directory:
            root, before_components = make_root(directory)
            baseline = transaction.validator.validate_components(
                before_components, 501, plistlib.loads
            )
            operation_id = str(uuid.uuid4())
            value = transaction.EnrollmentTransaction(
                root, apple_user_id=501, operation_id=operation_id
            )
            begin(value)
            value.record_terminal_identity(b"n" * 16)
            for name, data in staged_values().items():
                value.stage_secure_component(name, data)
            value.commit(identity_name="Linux Finger 2", apple_time=800_000_000.0)
            summary = value.safe_summary()
            self.assertEqual(summary["phase"], "committed")
            self.assertTrue(summary["identifiers_redacted"])
            self.assertFalse(value.identity_path.exists())
            self.assertFalse(value.secure.exists())
            backup = root / f"catacomb-pre-enrollment-{operation_id}-backup"
            for name, data in before_components.items():
                self.assertEqual((backup / name).read_bytes(), data)
            installed = {
                path.name: path.read_bytes() for path in (root / "catacomb").iterdir()
            }
            validated = transaction.validator.validate_components(
                installed, 501, plistlib.loads
            )
            self.assertEqual(validated.identity_count, baseline.identity_count + 1)
            self.assertEqual(
                validated.identity_entity_count, baseline.identity_entity_count + 1
            )
            self.assertEqual(
                validated.master_enrollment_count,
                baseline.master_enrollment_count + 1,
            )

    def test_failure_after_baseline_move_rolls_back(self):
        with tempfile.TemporaryDirectory() as directory:
            root, before_components = make_root(directory)

            def fail(stage):
                if stage == "baseline-preserved":
                    raise RuntimeError("injected failure")

            value = transaction.EnrollmentTransaction(
                root,
                apple_user_id=501,
                operation_id=str(uuid.uuid4()),
                failure_hook=fail,
            )
            begin(value)
            value.record_terminal_identity(b"n" * 16)
            for name, data in staged_values().items():
                value.stage_secure_component(name, data)
            with self.assertRaisesRegex(RuntimeError, "injected failure"):
                value.commit(identity_name="Linux Finger 2", apple_time=800_000_000.0)
            for name, data in before_components.items():
                self.assertEqual((root / "catacomb" / name).read_bytes(), data)

    def test_commit_rejects_changed_baseline(self):
        with tempfile.TemporaryDirectory() as directory:
            root, _ = make_root(directory)
            value = transaction.EnrollmentTransaction(
                root, apple_user_id=501, operation_id=str(uuid.uuid4())
            )
            begin(value)
            value.record_terminal_identity(b"n" * 16)
            for name, data in staged_values().items():
                value.stage_secure_component(name, data)
            path = root / "catacomb/master.cat"
            path.write_bytes(path.read_bytes() + b"changed")
            with self.assertRaisesRegex(
                transaction.EnrollmentTransactionError, "changed during enrollment"
            ):
                value.commit(identity_name="Linux Finger 2", apple_time=800_000_000.0)

    def test_staging_rejects_duplicate_and_wrong_magic(self):
        with tempfile.TemporaryDirectory() as directory:
            root, _ = make_root(directory)
            value = transaction.EnrollmentTransaction(
                root, apple_user_id=501, operation_id=str(uuid.uuid4())
            )
            begin(value)
            value.record_terminal_identity(b"n" * 16)
            with self.assertRaisesRegex(
                transaction.EnrollmentTransactionError, "payload is invalid"
            ):
                value.stage_secure_component("master.cat", b"HRLB" + bytes(12))
            value.stage_secure_component("master.cat", b"LTFC" + b"y" * 28)
            with self.assertRaisesRegex(
                transaction.EnrollmentTransactionError, "already staged"
            ):
                value.stage_secure_component("master.cat", b"LTFC" + b"q" * 28)

    def test_journal_never_contains_private_identity_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root, _ = make_root(directory)
            value = transaction.EnrollmentTransaction(
                root, apple_user_id=501, operation_id=str(uuid.uuid4())
            )
            begin(value)
            private = bytes(range(16))
            value.record_terminal_identity(private)
            journal = value.journal_path.read_bytes()
            self.assertNotIn(private, journal)
            self.assertNotIn(private.hex().encode(), journal)
            self.assertTrue(value.safe_summary()["identifiers_redacted"])


if __name__ == "__main__":
    unittest.main()
