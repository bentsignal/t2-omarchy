#!/usr/bin/env python3
import importlib.util
import io
import plistlib
import sys
import tarfile
import tempfile
import unittest
import uuid
from pathlib import Path


SCRIPT = Path(__file__).with_name("validate-current-macos-catacomb.py")
SPEC = importlib.util.spec_from_file_location("current_catacomb_validator", SCRIPT)
validator = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = validator
SPEC.loader.exec_module(validator)


def descriptor(name, *parents):
    return {"$classname": name, "$classes": [name, *parents]}


def user_fixture(user_id=501):
    objects = [
        "$null",
        {"NS.data": b"LTFC" + b"u" * 28, "$class": plistlib.UID(2)},
        descriptor("NSMutableData", "NSData", "NSObject"),
        {"NS.objects": [plistlib.UID(4), plistlib.UID(18)], "$class": plistlib.UID(14)},
        {
            "BKIdentityMatchCount": 0,
            "BKIdentityCreationTime": plistlib.UID(6),
            "BKIdentityEntityNumber": 0,
            "BKIdentityUUID": uuid.UUID(int=1).bytes,
            "BKIdentityFlags": 0,
            "BKIdentityMatchCountContinuous": 0,
            "BKIdentityName": plistlib.UID(5),
            "BKIdentityType": 1,
            "BKIdentityAccessory": plistlib.UID(8),
            "BKIdentityUpdateCount": 1,
            "BKIdentityUserID": user_id,
            "BKIdentityAttribute": 0,
            "$class": plistlib.UID(12),
        },
        "First finger",
        {"NS.time": 700000000.0, "$class": plistlib.UID(7)},
        descriptor("NSDate", "NSObject"),
        {
            "BKAccessoryUUID": bytes(16),
            "BKAccessoryFlags": 6,
            "BKAccessoryName": plistlib.UID(9),
            "BKAccessoryType": 1,
            "BKAccessoryGroup": plistlib.UID(10),
            "$class": plistlib.UID(11),
        },
        "Builtin",
        {
            "BKAccessoryGroupName": plistlib.UID(9),
            "BKAccessoryGroupType": 1,
            "BKAccessoryGroupUUID": bytes(16),
            "$class": plistlib.UID(13),
        },
        descriptor("BiometricKitAccessory", "NSObject"),
        descriptor("BiometricKitIdentity", "NSObject"),
        descriptor("BiometricKitAccessoryGroup", "NSObject"),
        descriptor("NSMutableArray", "NSArray", "NSObject"),
        {"NS.uuidbytes": uuid.UUID(int=2).bytes, "$class": plistlib.UID(16)},
        descriptor("NSUUID", "NSObject"),
        {"NS.uuidbytes": uuid.UUID(int=3).bytes, "$class": plistlib.UID(16)},
        {
            "BKIdentityMatchCount": 0,
            "BKIdentityCreationTime": plistlib.UID(20),
            "BKIdentityEntityNumber": 0,
            "BKIdentityUUID": uuid.UUID(int=4).bytes,
            "BKIdentityFlags": 0,
            "BKIdentityMatchCountContinuous": 0,
            "BKIdentityName": plistlib.UID(19),
            "BKIdentityType": 1,
            "BKIdentityAccessory": plistlib.UID(8),
            "BKIdentityUpdateCount": 1,
            "BKIdentityUserID": user_id,
            "BKIdentityAttribute": 0,
            "$class": plistlib.UID(12),
        },
        "Second finger",
        {"NS.time": 710000000.0, "$class": plistlib.UID(7)},
    ]
    return plistlib.dumps(
        {
            "$version": 100000,
            "$archiver": "NSKeyedArchiver",
            "$top": {
                "CatacombVersion": 0x30000,
                "CatacombSecureData": plistlib.UID(1),
                "CatacombUserKeybagUUID": plistlib.UID(17),
                "CatacombUserID": user_id,
                "CatacombIdentityList": plistlib.UID(3),
                "CatacombUserUUID": plistlib.UID(15),
            },
            "$objects": objects,
        },
        fmt=plistlib.FMT_BINARY,
        sort_keys=False,
    )


def master_fixture():
    return plistlib.dumps(
        {
            "$version": 100000,
            "$archiver": "NSKeyedArchiver",
            "$top": {
                "CatacombVersion": 0x30000,
                "CatacombSecureData": plistlib.UID(1),
                "CatacombCurrentDate": plistlib.UID(3),
                "CatacombUserID": -1,
                "CatacombEnrollmentCount": 2,
            },
            "$objects": [
                "$null",
                {"NS.data": b"LTFC" + b"m" * 28, "$class": plistlib.UID(2)},
                descriptor("NSMutableData", "NSData", "NSObject"),
                {"NS.time": 710000000.0, "$class": plistlib.UID(4)},
                descriptor("NSDate", "NSObject"),
            ],
        },
        fmt=plistlib.FMT_BINARY,
        sort_keys=False,
    )


def biolockout_fixture():
    return plistlib.dumps(
        {
            "$version": 100000,
            "$archiver": "NSKeyedArchiver",
            "$top": {
                "BioLockoutRecordSecureData": plistlib.UID(1),
                "BioLockoutRecordVersion": 0x10000,
            },
            "$objects": [
                "$null",
                {"NS.data": b"HRLB" + b"b" * 28, "$class": plistlib.UID(2)},
                descriptor("NSMutableData", "NSData", "NSObject"),
            ],
        },
        fmt=plistlib.FMT_BINARY,
        sort_keys=False,
    )


class CurrentMacOSCatacombValidatorTests(unittest.TestCase):
    def archive(self, directory, *, user=None, duplicate=False):
        path = Path(directory) / "private.tar.gz"
        components = {
            "master.cat": master_fixture(),
            "user_000001f5.cat": user or user_fixture(),
            "biolockout.cat": biolockout_fixture(),
        }
        with tarfile.open(path, "w:gz") as archive:
            for name, data in components.items():
                occurrences = 2 if duplicate and name == "master.cat" else 1
                for occurrence in range(occurrences):
                    info = tarfile.TarInfo(f"Catacomb/{occurrence}/{name}")
                    info.size = len(data)
                    archive.addfile(info, io.BytesIO(data))
        path.chmod(0o600)
        return path

    @staticmethod
    def python_loader(data):
        return plistlib.loads(data)

    def test_two_identities_may_share_one_entity_number(self):
        with tempfile.TemporaryDirectory() as directory:
            result = validator.validate_archive(
                self.archive(directory), 501, self.python_loader
            )
        self.assertEqual(result["identity_count"], 2)
        self.assertTrue(result["semantic_round_trip_equal"])
        self.assertTrue(result["identifiers_redacted"])
        self.assertNotIn("uuid", result)

    def test_duplicate_identity_uuid_is_rejected(self):
        root = plistlib.loads(user_fixture())
        root["$objects"][18]["BKIdentityUUID"] = root["$objects"][4]["BKIdentityUUID"]
        user = plistlib.dumps(root, fmt=plistlib.FMT_BINARY, sort_keys=False)
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(validator.ValidationError):
                validator.validate_archive(
                    self.archive(directory, user=user), 501, self.python_loader
                )

    def test_foreign_user_identity_is_rejected(self):
        root = plistlib.loads(user_fixture())
        root["$objects"][18]["BKIdentityUserID"] = 502
        user = plistlib.dumps(root, fmt=plistlib.FMT_BINARY, sort_keys=False)
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(validator.ValidationError):
                validator.validate_archive(
                    self.archive(directory, user=user), 501, self.python_loader
                )

    def test_unknown_identity_schema_is_rejected(self):
        root = plistlib.loads(user_fixture())
        root["$objects"][18]["Unexpected"] = 1
        user = plistlib.dumps(root, fmt=plistlib.FMT_BINARY, sort_keys=False)
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(validator.ValidationError):
                validator.validate_archive(
                    self.archive(directory, user=user), 501, self.python_loader
                )

    def test_duplicate_archive_component_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(validator.ValidationError):
                validator.validate_archive(
                    self.archive(directory, duplicate=True), 501, self.python_loader
                )

    def test_archive_must_be_private(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.archive(directory)
            path.chmod(0o644)
            with self.assertRaises(validator.ValidationError):
                validator.validate_archive(path, 501, self.python_loader)

    def test_independent_reader_disagreement_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(validator.ValidationError):
                validator.validate_archive(self.archive(directory), 501, lambda _data: {})

    @unittest.skipUnless(Path("/usr/bin/plutil").is_file(), "requires macOS plutil")
    def test_foundation_reader_accepts_synthetic_archive(self):
        with tempfile.TemporaryDirectory() as directory:
            result = validator.validate_archive(self.archive(directory), 501)
        self.assertTrue(result["foundation_readback"])


if __name__ == "__main__":
    unittest.main()
