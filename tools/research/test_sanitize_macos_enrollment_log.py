import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest


MODULE_PATH = Path(__file__).with_name("sanitize-macos-enrollment-log.py")
SPEC = importlib.util.spec_from_file_location(
    "sanitize_macos_enrollment_log", MODULE_PATH
)
sanitizer = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(sanitizer)


def record(template, message, thread=7, process="/usr/libexec/biometrickitd"):
    return json.dumps(
        {
            "processImagePath": process,
            "threadID": thread,
            "formatString": template,
            "eventMessage": message,
        }
    )


def command_entry(command, version, value, input_length, thread=7):
    template = sanitizer.ENTRY_TEMPLATE
    message = (
        "performCommand:version:inValue:inData:inSize:outData:outSize: "
        f"{command}, {version}, {value}, 0x1234, {input_length}, 0x5678, 0x9abc"
    )
    return record(template, message, thread)


def command_exit(status, thread=7):
    template = sanitizer.EXIT_TEMPLATE
    message = (
        "performCommand:version:inValue:inData:inSize:outData:outSize: "
        f"-> err:0x{status:x}"
    )
    return record(template, message, thread)


class EnrollmentLogSanitizerTests(unittest.TestCase):
    def write_private(self, root, lines):
        path = Path(root) / "unified-log.ndjson"
        path.write_text("\n".join(lines) + "\n")
        path.chmod(0o600)
        return path

    def test_extracts_public_sequence_without_private_values(self):
        secret = "DO-NOT-LEAK-CREDENTIAL"
        private_uuid = "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"
        private_path = "/Users/example/private-biometric-data"
        lines = [
            record(
                sanitizer.ENROLL_TEMPLATE,
                "enroll:forUser:withOptions:withClient: 1, 501, "
                f"{{credential={secret}; uuid={private_uuid}; path={private_path};}}, "
                "<BKClient: 0x1111>",
            ),
            command_entry(0x52, 1, 0, 0),
            command_exit(0),
            command_entry(0x54, 1, 0, 20),
            command_exit(0),
            command_entry(0x0C, 1, 0, 0),
            command_exit(0),
            command_entry(0x03, 2, 0, 68),
            command_exit(0),
            command_entry(0x04, 1, 1, 112),
            command_exit(0),
            record(sanitizer.ENROLL_EXIT_TEMPLATE,
                   "enroll:forUser:withOptions:withClient: -> err:0x0"),
        ]
        with tempfile.TemporaryDirectory() as temporary:
            result = sanitizer.sanitize(self.write_private(temporary, lines))
        self.assertEqual(result["total_commands"], 5)
        self.assertEqual(
            [item["command"] for item in result["command_3_windows"][0]["commands"]],
            ["0x52", "0x54", "0x0c", "0x03", "0x04"],
        )
        self.assertEqual(result["command_4_windows"][0]["command_4_index"], 4)
        self.assertEqual(
            result["command_4_windows"][0]["commands"][-1],
            {
                "relative_index": 0,
                "command": "0x04",
                "version": 1,
                "value": 1,
                "input_length": 112,
                "status": 0,
            },
        )
        self.assertEqual(result["enrollment_calls"], [
            {"mode": 1, "user_id": 501, "status": 0}
        ])
        rendered = json.dumps(result)
        for private_value in (secret, private_uuid, private_path, "0x1234"):
            self.assertNotIn(private_value, rendered)

    def test_ignores_other_process_and_unrecognized_template(self):
        lines = [
            command_entry(3, 2, 0, 68).replace(
                "/usr/libexec/biometrickitd", "/usr/libexec/not-biometrickitd"
            ),
            record("private %@", "credential DO-NOT-LEAK"),
        ]
        with tempfile.TemporaryDirectory() as temporary:
            result = sanitizer.sanitize(self.write_private(temporary, lines))
        self.assertEqual(result["total_commands"], 0)
        self.assertEqual(result["command_3_windows"], [])
        self.assertEqual(result["command_4_windows"], [])

    def test_rejects_symlink_and_exposed_permissions(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            private = self.write_private(root, [command_entry(3, 2, 0, 68)])
            alias = root / "alias.ndjson"
            alias.symlink_to(private)
            with self.assertRaises(sanitizer.LogSanitizerError):
                sanitizer.sanitize(alias)
            private.chmod(0o644)
            with self.assertRaisesRegex(sanitizer.LogSanitizerError, "owner-only"):
                sanitizer.sanitize(private)


if __name__ == "__main__":
    unittest.main()
