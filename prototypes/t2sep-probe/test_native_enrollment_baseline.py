import importlib.util
import struct
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


SCRIPT = Path(__file__).with_name("native-enrollment-baseline.py")
SPEC = importlib.util.spec_from_file_location("native_enrollment_baseline", SCRIPT)
baseline = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = baseline
SPEC.loader.exec_module(baseline)


class FakeSession:
    def __init__(self, _sock):
        self.calls = []


class NativeEnrollmentBaselineTests(unittest.TestCase):
    @staticmethod
    def validated(*, matches=True):
        return SimpleNamespace(
            identity_count=2,
            identity_entity_count=1,
            identity_entity_group_sizes=(2,),
            master_enrollment_count=3,
            matches_identity_uuids=lambda values: matches and len(values) == 2,
        )

    @staticmethod
    def identities():
        identity_type = baseline.restore.state.biometric.BiometricIdentity
        return (
            identity_type(501, bytes(range(16))),
            identity_type(501, bytes(range(1, 17))),
        )

    def test_builds_redacted_non_mutating_baseline(self):
        policy = struct.pack("<8I", *((1, 1, 1, 0) * 2))
        session = FakeSession(object())
        replies = [
            (0, policy),
            (0, struct.pack("<I", 5)),
            (0, struct.pack("<I", 1)),
            (-536870206, bytes(16)),
            (-536870206, bytes(2048)),
            (-536870206, bytes(3584)),
        ]
        with (
            patch.object(
                baseline.restore, "read_current_store", return_value=self.validated()
            ),
            patch.object(
                baseline.restore.state.coupled.bridge_query,
                "BridgeSession",
                return_value=session,
            ),
            patch.object(baseline.restore.state, "_initialize"),
            patch.object(
                baseline.restore,
                "_stable_identity_inventory",
                return_value=self.identities(),
            ),
            patch.object(
                baseline.restore.state, "_perform", side_effect=replies
            ) as perform,
        ):
            result = baseline.probe_socket(
                object(), apple_user_id=501, store_path=Path("/private/store")
            )
        commands = [item.args[1][0] for item in perform.call_args_list]
        self.assertEqual(commands, [0x2E, 0x0F, 0x41, 0x38, 0x3C, 0x50])
        self.assertTrue(result.identity_inventory_matches_archive)
        self.assertEqual(result.archive_entity_group_sizes, (2,))
        self.assertEqual(result.archive_master_enrollment_count, 3)
        self.assertTrue(result.reported_capacity_available)
        self.assertFalse(result.capacity_semantics_proven)
        self.assertFalse(result.persistence_path_ready)
        self.assertFalse(result.safe_for_mutation)
        self.assertFalse(result.mutation_performed)
        self.assertTrue(result.identifiers_redacted)

    def test_archive_and_live_identity_mismatch_fails_before_other_queries(self):
        with (
            patch.object(
                baseline.restore,
                "read_current_store",
                return_value=self.validated(matches=False),
            ),
            patch.object(
                baseline.restore.state.coupled.bridge_query,
                "BridgeSession",
                return_value=FakeSession(object()),
            ),
            patch.object(baseline.restore.state, "_initialize"),
            patch.object(
                baseline.restore,
                "_stable_identity_inventory",
                return_value=self.identities(),
            ),
            patch.object(baseline.restore.state, "_perform") as perform,
        ):
            with self.assertRaisesRegex(
                baseline.NativeEnrollmentBaselineError, "inventories disagree"
            ):
                baseline.probe_socket(
                    object(), apple_user_id=501, store_path=Path("/private/store")
                )
        perform.assert_not_called()

    def test_nonexact_policy_fails_closed(self):
        policy = struct.pack("<8I", *((1, 1, 1, 0) + (1, 1, 0, 0)))
        with (
            patch.object(
                baseline.restore, "read_current_store", return_value=self.validated()
            ),
            patch.object(
                baseline.restore.state.coupled.bridge_query,
                "BridgeSession",
                return_value=FakeSession(object()),
            ),
            patch.object(baseline.restore.state, "_initialize"),
            patch.object(
                baseline.restore,
                "_stable_identity_inventory",
                return_value=self.identities(),
            ),
            patch.object(baseline.restore.state, "_perform", return_value=(0, policy)),
        ):
            with self.assertRaisesRegex(
                baseline.NativeEnrollmentBaselineError, "exact proven policy"
            ):
                baseline.probe_socket(
                    object(), apple_user_id=501, store_path=Path("/private/store")
                )

    def test_source_does_not_reference_mutating_helpers_or_identifiers(self):
        source = SCRIPT.read_text()
        for forbidden in (
            "cancel_fields",
            "load_fdr_calibration_fields",
            "current_catacomb_component_fields",
            "reset_sensor_fields",
            "no_catacomb_fields",
            "ordinary_enroll_fields",
            "authorized_enroll_fields",
            "remove_identity_fields",
            "identity.uuid.hex",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
