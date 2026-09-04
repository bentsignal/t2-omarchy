import importlib.util
import plistlib
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch


SCRIPT = Path(__file__).with_name("cold-catacomb-restore.py")
SPEC = importlib.util.spec_from_file_location("cold_catacomb_restore", SCRIPT)
restore = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = restore
SPEC.loader.exec_module(restore)


def ltfc(user_id: int, label: bytes) -> bytes:
    return restore.state.biometric.CATACOMB_FILE_HEADER.pack(
        0x4346544C, 10, user_id, bytes(20)
    ) + label


class FakeSession:
    def __init__(self, _sock):
        self.calls = []

    def call(self, message):
        self.calls.append(message)
        return [b"FDR calibration"]


class ColdCatacombRestoreTests(unittest.TestCase):
    def validated(self):
        return SimpleNamespace(
            identity_count=2,
            master_secure_data=ltfc(-1, b"master"),
            user_secure_data=ltfc(501, b"user"),
            biolockout_secure_data=b"HRLB" + bytes(12),
        )

    def test_private_archive_source_uses_strict_validator(self):
        validated = self.validated()
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "clean.tar.gz"
            archive.write_bytes(b"bounded private archive")
            archive.chmod(0o600)
            with patch.object(
                restore.validator, "load_validated_archive", return_value=validated
            ) as load:
                result = restore.read_current_store(archive, 501)
        self.assertIs(result, validated)
        load.assert_called_once_with(archive, 501, plistlib.loads)

    def test_exact_restore_order_and_stable_nonempty_readback(self):
        identity = struct.pack("<I16s", 501, bytes(range(16)))
        replies = [
            (0, b""),
            (0, b""),
            (0, None),
            (0, None),
            (0, None),
            (0, None),
            (0, None),
            (0, bytes(32)),
            (0, identity),
            (0, identity),
        ]
        session = FakeSession(object())
        with (
            patch.object(restore, "read_current_store", return_value=self.validated()),
            patch.object(
                restore.state.coupled.bridge_query,
                "BridgeSession",
                return_value=session,
            ),
            patch.object(restore.state, "_initialize") as initialize,
            patch.object(restore.state, "_perform", side_effect=replies) as perform,
        ):
            result = restore.probe_socket(
                object(), apple_user_id=501, store_path=Path("/private/store")
            )
        initialize.assert_called_once_with(session)
        self.assertEqual(
            session.calls,
            [[restore.state.coupled.bridge_query.protocol.CALIBRATION_DATA_FROM_FDR]],
        )
        commands = [item.args[1][0] for item in perform.call_args_list]
        self.assertEqual(
            commands,
            [0x42, 0x42, 0x0C, 0x20, 0x40, 0x40, 0x4B, 0x2E, 0x42, 0x42],
        )
        self.assertTrue(result.completed)
        self.assertTrue(result.restoration_required)
        self.assertTrue(result.identity_readback_stable)
        self.assertEqual(result.identity_count, 1)

    def test_stable_preexisting_inventory_skips_every_mutation(self):
        identity = struct.pack("<I16s", 501, bytes(range(16)))
        session = FakeSession(object())
        with (
            patch.object(restore, "read_current_store", return_value=self.validated()),
            patch.object(
                restore.state.coupled.bridge_query,
                "BridgeSession",
                return_value=session,
            ),
            patch.object(restore.state, "_initialize"),
            patch.object(
                restore.state,
                "_perform",
                side_effect=[(0, identity), (0, identity), (0, bytes(32))],
            ) as perform,
        ):
            result = restore.probe_socket(
                object(), apple_user_id=501, store_path=Path("/private/store")
            )
        self.assertEqual(session.calls, [])
        commands = [item.args[1][0] for item in perform.call_args_list]
        self.assertEqual(commands, [0x42, 0x42, 0x2E])
        self.assertFalse(result.restoration_required)
        self.assertEqual(result.component_count, 0)
        self.assertEqual(result.identity_count, 1)
        self.assertIsNone(result.calibration_status)

    def test_restore_stops_on_first_rejected_component(self):
        replies = [(0, None), (0, None), (0, None), (0, None), (22, None)]
        with (
            patch.object(restore, "read_current_store", return_value=self.validated()),
            patch.object(restore.state.coupled.bridge_query, "BridgeSession", FakeSession),
            patch.object(restore.state, "_initialize"),
            patch.object(restore.state, "_perform", side_effect=replies) as perform,
        ):
            with self.assertRaisesRegex(restore.ColdRestoreError, "master Catacomb"):
                restore.probe_socket(
                    object(), apple_user_id=501, store_path=Path("/private/store")
                )
        self.assertEqual(perform.call_count, 5)

    def test_restore_rejects_unstable_identity_readback(self):
        first = struct.pack("<I16s", 501, bytes(range(16)))
        second = struct.pack("<I16s", 501, bytes(range(1, 17)))
        replies = [(0, b""), (0, b"")] + [(0, None)] * 5 + [
            (0, bytes(32)),
            (0, first),
            (0, second),
        ]
        with (
            patch.object(restore, "read_current_store", return_value=self.validated()),
            patch.object(restore.state.coupled.bridge_query, "BridgeSession", FakeSession),
            patch.object(restore.state, "_initialize"),
            patch.object(restore.state, "_perform", side_effect=replies),
        ):
            with self.assertRaisesRegex(restore.ColdRestoreError, "unstable"):
                restore.probe_socket(
                    object(), apple_user_id=501, store_path=Path("/private/store")
                )

    def test_source_has_no_sensor_reset_or_secret_output(self):
        source = SCRIPT.read_text()
        self.assertNotIn("reset_sensor_fields", source)
        self.assertNotIn("secure_data.hex", source)
        self.assertNotIn("identity.uuid", source)
        self.assertIn("identity_readback_stable", source)


if __name__ == "__main__":
    unittest.main()
