# SPDX-License-Identifier: MIT
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch
import t2_touchid_status as status


class StatusTests(unittest.TestCase):
    def test_record_has_only_public_state(self):
        record = status.status_record("scan", "ready")
        self.assertEqual(set(record), {"schema_version", "channel", "state", "updated_at"})

    def test_invalid_states_rejected(self):
        for channel, state in (("scan", "authenticated"), ("../scan", "ready"), ("transport", "ready")):
            with self.assertRaises(ValueError):
                status.status_record(channel, state)

    def test_nonroot_does_not_write(self):
        with patch.object(status.os, "geteuid", return_value=1000), patch.object(status.tempfile, "mkstemp") as create:
            status.publish("scan", "ready")
            create.assert_not_called()

    def test_atomic_private_owner_public_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            info = MagicMock(st_mode=0o40755, st_uid=0)
            with patch.object(status, "DIRECTORY", directory), patch.object(status.os, "geteuid", return_value=0), patch.object(status.Path, "lstat", return_value=info):
                status.publish("scan", "ready")
                status.publish("scan", "idle")
            self.assertEqual(json.loads((directory / "scan.json").read_text())["state"], "idle")
            self.assertEqual((directory / "scan.json").stat().st_mode & 0o777, 0o644)
            self.assertEqual(len(list(directory.iterdir())), 1)

    def test_ui_failure_does_not_raise(self):
        with patch.object(status.os, "geteuid", return_value=0), patch.object(status.Path, "lstat", side_effect=OSError("missing")):
            status.publish("scan", "ready")
