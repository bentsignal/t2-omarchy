#!/usr/bin/env python3
import importlib.util
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace


SCRIPT = Path(__file__).with_name("catacomb-identity-shape-delta.py")
SPEC = importlib.util.spec_from_file_location("catacomb_identity_shape_delta", SCRIPT)
delta = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = delta
SPEC.loader.exec_module(delta)


class CatacombIdentityShapeDeltaTests(unittest.TestCase):
    def test_two_record_one_entity_addition_is_reported_without_identifiers(self):
        before = SimpleNamespace(
            identity_count=0,
            identity_entity_count=0,
            identity_entity_group_sizes=(),
            master_enrollment_count=1,
            components={
                "master.cat": b"before-master",
                "user_000001f5.cat": b"before-user",
                "biolockout.cat": b"before-lockout",
            },
            identity_uuid_delta_counts=lambda later: (2, 0),
        )
        after = SimpleNamespace(
            identity_count=2,
            identity_entity_count=1,
            identity_entity_group_sizes=(2,),
            master_enrollment_count=3,
            components={
                "master.cat": b"after-master",
                "user_000001f5.cat": b"after-user",
                "biolockout.cat": b"after-lockout",
            },
        )
        result = delta.compare_validated(before, after)
        self.assertTrue(result.two_record_one_entity_addition_observed)
        self.assertEqual(result.identity_records_added, 2)
        self.assertEqual(result.entity_number_count_delta, 1)
        self.assertEqual(result.master_enrollment_count_delta, 2)
        self.assertTrue(result.all_components_changed)
        self.assertFalse(result.logical_finger_count_inferred)
        self.assertTrue(result.identifiers_redacted)
        self.assertFalse(result.mutation_performed)

    def test_removal_or_replacement_is_not_misclassified_as_addition(self):
        before = SimpleNamespace(
            identity_count=2,
            identity_entity_count=1,
            identity_entity_group_sizes=(2,),
            master_enrollment_count=3,
            components={
                "master.cat": b"same-master",
                "user_000001f5.cat": b"same-user",
                "biolockout.cat": b"same-lockout",
            },
            identity_uuid_delta_counts=lambda later: (2, 2),
        )
        after = SimpleNamespace(
            identity_count=2,
            identity_entity_count=1,
            identity_entity_group_sizes=(2,),
            master_enrollment_count=3,
            components={
                "master.cat": b"same-master",
                "user_000001f5.cat": b"same-user",
                "biolockout.cat": b"same-lockout",
            },
        )
        result = delta.compare_validated(before, after)
        self.assertFalse(result.two_record_one_entity_addition_observed)

    def test_source_never_prints_or_serializes_private_identity_values(self):
        source = SCRIPT.read_text()
        self.assertNotIn("_identity_uuids", source)
        self.assertNotIn("BKIdentityUUID", source)
        self.assertNotIn(".hex()", source)


if __name__ == "__main__":
    unittest.main()
