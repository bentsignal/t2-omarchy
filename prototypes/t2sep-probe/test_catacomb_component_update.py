import importlib.util
from pathlib import Path
import plistlib
import sys
import unittest


SCRIPT = Path(__file__).with_name("catacomb-component-update.py")
SPEC = importlib.util.spec_from_file_location("catacomb_component_update", SCRIPT)
update = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = update
SPEC.loader.exec_module(update)

FIXTURES = Path(__file__).resolve().parents[2] / "tools/research/test_validate_current_macos_catacomb.py"
FIXTURE_SPEC = importlib.util.spec_from_file_location("component_update_fixtures", FIXTURES)
fixtures = importlib.util.module_from_spec(FIXTURE_SPEC)
assert FIXTURE_SPEC and FIXTURE_SPEC.loader
sys.modules[FIXTURE_SPEC.name] = fixtures
FIXTURE_SPEC.loader.exec_module(fixtures)


def source_components():
    return {
        "master.cat": fixtures.master_fixture(),
        "user_000001f5.cat": fixtures.user_fixture(),
        "biolockout.cat": fixtures.biolockout_fixture(),
    }


class CatacombComponentUpdateTests(unittest.TestCase):
    def test_builds_one_identity_three_secure_payload_update(self):
        before = update.validator.validate_components(source_components(), 501, plistlib.loads)
        result = update.build_enrollment_update(
            source_components(),
            apple_user_id=501,
            terminal_identity_uuid=b"n" * 16,
            user_secure_data=b"LTFC" + b"x" * 28,
            master_secure_data=b"LTFC" + b"y" * 28,
            biolockout_secure_data=b"HRLB" + b"z" * 28,
            identity_name="Linux Finger 2",
            apple_time=800_000_000.0,
        )
        after = update.validator.validate_components(result, 501, plistlib.loads)
        self.assertEqual(after.identity_count, before.identity_count + 1)
        self.assertEqual(after.identity_entity_count, before.identity_entity_count + 1)
        self.assertEqual(after.master_enrollment_count, before.master_enrollment_count + 1)
        self.assertEqual(after.user_secure_data, b"LTFC" + b"x" * 28)
        self.assertEqual(after.master_secure_data, b"LTFC" + b"y" * 28)
        self.assertEqual(after.biolockout_secure_data, b"HRLB" + b"z" * 28)
        self.assertEqual(before.identity_uuid_delta_counts(after), (1, 0))

    def test_rejects_unchanged_required_secure_payload(self):
        before = update.validator.validate_components(source_components(), 501, plistlib.loads)
        with self.assertRaisesRegex(
            update.CatacombComponentUpdateError, "every required secure payload"
        ):
            update.build_enrollment_update(
                source_components(),
                apple_user_id=501,
                terminal_identity_uuid=b"n" * 16,
                user_secure_data=before.user_secure_data,
                master_secure_data=b"LTFC" + b"y" * 28,
                biolockout_secure_data=b"HRLB" + b"z" * 28,
                identity_name="Linux Finger 2",
                apple_time=800_000_000.0,
            )

    def test_rejects_duplicate_or_malformed_identity(self):
        components = source_components()
        graph = update.validator.KeyedArchive(
            components["user_000001f5.cat"], plistlib.loads
        )
        references = graph.classed(
            graph.top["CatacombIdentityList"], "NSMutableArray", {"NS.objects"}
        )["NS.objects"]
        identity = graph.classed(
            references[0], "BiometricKitIdentity", update.IDENTITY_KEYS
        )
        existing = graph.raw_uuid(identity["BKIdentityUUID"])
        with self.assertRaisesRegex(
            update.CatacombComponentUpdateError, "already present"
        ):
            update.build_enrollment_update(
                components,
                apple_user_id=501,
                terminal_identity_uuid=existing,
                user_secure_data=b"LTFC" + b"x" * 28,
                master_secure_data=b"LTFC" + b"y" * 28,
                biolockout_secure_data=b"HRLB" + b"z" * 28,
                identity_name="Linux Finger 2",
                apple_time=800_000_000.0,
            )
        with self.assertRaisesRegex(
            update.CatacombComponentUpdateError, "UUID is invalid"
        ):
            update.build_enrollment_update(
                components,
                apple_user_id=501,
                terminal_identity_uuid=b"short",
                user_secure_data=b"LTFC" + b"x" * 28,
                master_secure_data=b"LTFC" + b"y" * 28,
                biolockout_secure_data=b"HRLB" + b"z" * 28,
                identity_name="Linux Finger 2",
                apple_time=800_000_000.0,
            )

    def test_source_never_prints_private_values(self):
        source = SCRIPT.read_text()
        self.assertNotIn("print(", source)
        self.assertNotIn(".hex()", source)


if __name__ == "__main__":
    unittest.main()
