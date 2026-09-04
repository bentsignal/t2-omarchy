#!/usr/bin/env python3
"""Validate a private macOS Catacomb archive without exposing identifiers."""

from __future__ import annotations

import argparse
from collections import Counter
import json
import math
import os
import plistlib
import stat
import subprocess
import tarfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Callable


MAX_ARCHIVE_BYTES = 32 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 256
MAX_COMPONENT_BYTES = 1024 * 1024
MAX_OBJECTS = 256
MAX_IDENTITIES = 10
MAX_STRING_BYTES = 1024

CLASS_CHAINS = {
    "NSMutableData": ["NSMutableData", "NSData", "NSObject"],
    "NSMutableArray": ["NSMutableArray", "NSArray", "NSObject"],
    "BiometricKitIdentity": ["BiometricKitIdentity", "NSObject"],
    "NSDate": ["NSDate", "NSObject"],
    "BiometricKitAccessory": ["BiometricKitAccessory", "NSObject"],
    "BiometricKitAccessoryGroup": ["BiometricKitAccessoryGroup", "NSObject"],
    "NSUUID": ["NSUUID", "NSObject"],
}


class ValidationError(ValueError):
    pass


@dataclass(frozen=True, repr=False)
class ValidatedCatacomb:
    """Private validated material for trusted import/restore callers."""

    components: dict[str, bytes]
    master_secure_data: bytes
    user_secure_data: bytes
    biolockout_secure_data: bytes
    identity_count: int
    identity_entity_count: int
    identity_entity_group_sizes: tuple[int, ...]
    master_enrollment_count: int
    _identity_uuids: frozenset[bytes] = field(repr=False, compare=False)

    def __repr__(self) -> str:
        return (
            "ValidatedCatacomb(component_count=3, "
            f"identity_nonzero={self.identity_count > 0}, "
            f"entity_reuse={self.identity_entity_count < self.identity_count}, "
            "data=<redacted>)"
        )

    def matches_identity_uuids(self, identity_uuids: object) -> bool:
        """Compare a trusted live UUID set without returning archive identifiers."""
        if not isinstance(identity_uuids, (tuple, list, set, frozenset)):
            return False
        values: list[bytes] = []
        for value in identity_uuids:
            if not isinstance(value, bytes) or len(value) != 16:
                return False
            values.append(value)
        return len(values) == len(set(values)) and frozenset(values) == self._identity_uuids

    def identity_uuid_delta_counts(self, later: object) -> tuple[int, int]:
        """Return only added/removed counts for another validated archive."""
        if not isinstance(later, ValidatedCatacomb):
            raise TypeError("later Catacomb must be independently validated")
        return (
            len(later._identity_uuids - self._identity_uuids),
            len(self._identity_uuids - later._identity_uuids),
        )


def _caller_uid() -> int:
    sudo_uid = os.environ.get("SUDO_UID", "")
    if os.geteuid() == 0 and sudo_uid.isdecimal() and int(sudo_uid) > 0:
        return int(sudo_uid)
    return os.geteuid()


def _normalize_plist(value: Any) -> Any:
    if isinstance(value, plistlib.UID):
        return ("uid", value.data)
    if isinstance(value, dict):
        if set(value) == {"CF$UID"} and isinstance(value["CF$UID"], int):
            return ("uid", value["CF$UID"])
        return {key: _normalize_plist(child) for key, child in value.items()}
    if isinstance(value, list):
        return [_normalize_plist(child) for child in value]
    return value


def _foundation_load(data: bytes) -> Any:
    result = subprocess.run(
        ["/usr/bin/plutil", "-convert", "xml1", "-o", "-", "--", "-"],
        input=data,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        raise ValidationError("Foundation rejected a Catacomb property list")
    try:
        return plistlib.loads(result.stdout)
    except (plistlib.InvalidFileException, ValueError, OverflowError) as error:
        raise ValidationError("Foundation emitted an unreadable property list") from error


def _read_components(path: Path, apple_user_id: int) -> dict[str, bytes]:
    expected = {
        "master.cat",
        "biolockout.cat",
        f"user_{apple_user_id:08x}.cat",
    }
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ValidationError("cannot safely open the private archive") from error
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid not in {0, _caller_uid()}
            or metadata.st_mode & 0o077
            or not 0 < metadata.st_size <= MAX_ARCHIVE_BYTES
        ):
            raise ValidationError("private archive metadata is unsafe")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            try:
                archive = tarfile.open(fileobj=stream, mode="r:*")
            except tarfile.TarError as error:
                raise ValidationError("private archive is unreadable") from error
            components: dict[str, bytes] = {}
            try:
                with archive:
                    for index, member in enumerate(archive):
                        if index >= MAX_ARCHIVE_MEMBERS:
                            raise ValidationError("private archive has too many members")
                        member_path = PurePosixPath(member.name)
                        name = member_path.name
                        if name not in expected:
                            continue
                        if member_path.is_absolute() or ".." in member_path.parts:
                            raise ValidationError("Catacomb member path is unsafe")
                        if (
                            name in components
                            or not member.isfile()
                            or not 0 < member.size <= MAX_COMPONENT_BYTES
                        ):
                            raise ValidationError("Catacomb component member is unsafe")
                        extracted = archive.extractfile(member)
                        if extracted is None:
                            raise ValidationError("Catacomb component cannot be read")
                        data = extracted.read(MAX_COMPONENT_BYTES + 1)
                        if len(data) != member.size:
                            raise ValidationError("Catacomb component length is inconsistent")
                        components[name] = data
            except tarfile.TarError as error:
                raise ValidationError("private archive is malformed") from error
    finally:
        os.close(descriptor)
    if set(components) != expected:
        raise ValidationError("archive lacks the selected Catacomb component set")
    return components


class KeyedArchive:
    def __init__(self, data: bytes, foundation_loader: Callable[[bytes], Any]) -> None:
        if not isinstance(data, bytes) or not 0 < len(data) <= MAX_COMPONENT_BYTES:
            raise ValidationError("Catacomb component size is outside policy")
        if not data.startswith(b"bplist00"):
            raise ValidationError("Catacomb component is not a binary property list")
        try:
            root = plistlib.loads(data)
        except (plistlib.InvalidFileException, ValueError, OverflowError) as error:
            raise ValidationError("Catacomb component property list is invalid") from error
        foundation_root = foundation_loader(data)
        if _normalize_plist(root) != _normalize_plist(foundation_root):
            raise ValidationError("independent property-list readers disagree")
        if not isinstance(root, dict) or set(root) != {"$version", "$archiver", "$top", "$objects"}:
            raise ValidationError("keyed archive root is unknown")
        if root["$version"] != 100000 or root["$archiver"] != "NSKeyedArchiver":
            raise ValidationError("keyed archive version is unsupported")
        if not isinstance(root["$top"], dict):
            raise ValidationError("keyed archive top object is malformed")
        if not isinstance(root["$objects"], list) or not 1 <= len(root["$objects"]) <= MAX_OBJECTS:
            raise ValidationError("keyed archive object count is outside policy")
        self.root = root
        self.top = root["$top"]
        self.objects = root["$objects"]
        self._validate_objects()
        self._validate_reachability()

    def _index(self, reference: Any) -> int:
        if not isinstance(reference, plistlib.UID) or not 0 <= reference.data < len(self.objects):
            raise ValidationError("keyed archive reference is invalid")
        return reference.data

    def _object(self, reference: Any) -> Any:
        return self.objects[self._index(reference)]

    def _class_name(self, value: dict[str, Any]) -> str:
        descriptor = self._object(value.get("$class"))
        if (
            not isinstance(descriptor, dict)
            or set(descriptor) != {"$classname", "$classes"}
            or not isinstance(descriptor.get("$classname"), str)
        ):
            raise ValidationError("keyed archive class descriptor is malformed")
        name = descriptor["$classname"]
        if descriptor["$classes"] != CLASS_CHAINS.get(name):
            raise ValidationError("keyed archive class chain is unsupported")
        return name

    def _validate_objects(self) -> None:
        if self.objects[0] != "$null":
            raise ValidationError("keyed archive null sentinel is absent")
        aggregate = 0
        for value in self.objects:
            if isinstance(value, str):
                size = len(value.encode("utf-8"))
                aggregate += size
                if size > MAX_STRING_BYTES:
                    raise ValidationError("keyed archive string exceeds policy")
            elif isinstance(value, bytes):
                aggregate += len(value)
            elif isinstance(value, dict):
                if "$class" in value:
                    self._class_name(value)
                elif set(value) != {"$classname", "$classes"}:
                    raise ValidationError("keyed archive dictionary is unknown")
            elif not isinstance(value, (int, float, bool)):
                raise ValidationError("keyed archive primitive is unsupported")
        if aggregate > MAX_COMPONENT_BYTES:
            raise ValidationError("decoded Catacomb data exceeds policy")

    def _validate_reachability(self) -> None:
        reached: set[int] = set()
        active: set[int] = set()

        def visit(value: Any) -> None:
            if isinstance(value, plistlib.UID):
                index = self._index(value)
                if index == 0:
                    return
                if index in active:
                    raise ValidationError("keyed archive object graph contains a cycle")
                if index in reached:
                    return
                active.add(index)
                visit(self.objects[index])
                active.remove(index)
                reached.add(index)
            elif isinstance(value, dict):
                for child in value.values():
                    visit(child)
            elif isinstance(value, list):
                for child in value:
                    visit(child)

        visit(self.top)
        if reached != set(range(1, len(self.objects))):
            raise ValidationError("keyed archive contains unreachable objects")

    def classed(self, reference: Any, name: str, keys: set[str]) -> dict[str, Any]:
        value = self._object(reference)
        if not isinstance(value, dict) or set(value) != keys | {"$class"}:
            raise ValidationError("keyed archive object schema is unknown")
        if self._class_name(value) != name:
            raise ValidationError("keyed archive object class is unexpected")
        return value

    def integer(self, value: Any) -> int:
        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 0xFFFFFFFF:
            raise ValidationError("Catacomb integer is outside uint32 policy")
        return value

    def text(self, reference: Any) -> str:
        value = self._object(reference)
        if not isinstance(value, str) or len(value.encode("utf-8")) > MAX_STRING_BYTES:
            raise ValidationError("Catacomb string is malformed")
        return value

    def date(self, reference: Any) -> float:
        value = self.classed(reference, "NSDate", {"NS.time"})["NS.time"]
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
            raise ValidationError("Catacomb date is malformed")
        return float(value)

    def data(self, reference: Any, magic: bytes) -> bytes:
        value = self.classed(reference, "NSMutableData", {"NS.data"})["NS.data"]
        if not isinstance(value, bytes) or not 16 <= len(value) <= MAX_COMPONENT_BYTES:
            raise ValidationError("Catacomb secure data is malformed")
        if not value.startswith(magic):
            raise ValidationError("Catacomb secure data type is unexpected")
        return value

    def archived_uuid(self, reference: Any) -> bytes:
        value = self.classed(reference, "NSUUID", {"NS.uuidbytes"})["NS.uuidbytes"]
        return self.raw_uuid(value)

    @staticmethod
    def raw_uuid(value: Any) -> bytes:
        if not isinstance(value, bytes) or len(value) != 16:
            raise ValidationError("Catacomb UUID is malformed")
        return value


def _validate_accessory(graph: KeyedArchive, reference: Any) -> None:
    accessory = graph.classed(
        reference,
        "BiometricKitAccessory",
        {"BKAccessoryUUID", "BKAccessoryFlags", "BKAccessoryName", "BKAccessoryType", "BKAccessoryGroup"},
    )
    group = graph.classed(
        accessory["BKAccessoryGroup"],
        "BiometricKitAccessoryGroup",
        {"BKAccessoryGroupName", "BKAccessoryGroupType", "BKAccessoryGroupUUID"},
    )
    if not (
        graph.raw_uuid(accessory["BKAccessoryUUID"]) == bytes(16)
        and graph.integer(accessory["BKAccessoryFlags"]) == 6
        and graph.text(accessory["BKAccessoryName"]) == "Builtin"
        and graph.integer(accessory["BKAccessoryType"]) == 1
        and graph.raw_uuid(group["BKAccessoryGroupUUID"]) == bytes(16)
        and graph.text(group["BKAccessoryGroupName"]) == "Builtin"
        and graph.integer(group["BKAccessoryGroupType"]) == 1
    ):
        raise ValidationError("Catacomb accessory is not the built-in sensor")


def _validate_user(graph: KeyedArchive, apple_user_id: int) -> tuple[Any, ...]:
    expected_top = {
        "CatacombVersion",
        "CatacombSecureData",
        "CatacombUserKeybagUUID",
        "CatacombUserID",
        "CatacombIdentityList",
        "CatacombUserUUID",
    }
    if set(graph.top) != expected_top or graph.top["CatacombVersion"] != 0x30000:
        raise ValidationError("user Catacomb top schema is unsupported")
    if graph.top["CatacombUserID"] != apple_user_id:
        raise ValidationError("user Catacomb belongs to another user")
    secure_data = graph.data(graph.top["CatacombSecureData"], b"LTFC")
    account_uuid = graph.archived_uuid(graph.top["CatacombUserUUID"])
    keybag_uuid = graph.archived_uuid(graph.top["CatacombUserKeybagUUID"])
    identity_array = graph.classed(graph.top["CatacombIdentityList"], "NSMutableArray", {"NS.objects"})
    references = identity_array["NS.objects"]
    if not isinstance(references, list) or len(references) > MAX_IDENTITIES:
        raise ValidationError("user Catacomb identity list is malformed")
    identities = []
    for reference in references:
        identity = graph.classed(
            reference,
            "BiometricKitIdentity",
            {
                "BKIdentityMatchCount",
                "BKIdentityCreationTime",
                "BKIdentityEntityNumber",
                "BKIdentityUUID",
                "BKIdentityFlags",
                "BKIdentityMatchCountContinuous",
                "BKIdentityName",
                "BKIdentityType",
                "BKIdentityAccessory",
                "BKIdentityUpdateCount",
                "BKIdentityUserID",
                "BKIdentityAttribute",
            },
        )
        if graph.integer(identity["BKIdentityUserID"]) != apple_user_id:
            raise ValidationError("identity belongs to another user")
        _validate_accessory(graph, identity["BKIdentityAccessory"])
        identities.append(
            (
                graph.raw_uuid(identity["BKIdentityUUID"]),
                graph.integer(identity["BKIdentityEntityNumber"]),
                graph.text(identity["BKIdentityName"]),
                graph.integer(identity["BKIdentityType"]),
                graph.integer(identity["BKIdentityFlags"]),
                graph.integer(identity["BKIdentityAttribute"]),
                graph.integer(identity["BKIdentityMatchCount"]),
                graph.integer(identity["BKIdentityMatchCountContinuous"]),
                graph.integer(identity["BKIdentityUpdateCount"]),
                graph.date(identity["BKIdentityCreationTime"]),
            )
        )
    if len({identity[0] for identity in identities}) != len(identities):
        raise ValidationError("identity UUIDs are not unique")
    return secure_data, account_uuid, keybag_uuid, tuple(identities)


def _validate_master(graph: KeyedArchive) -> tuple[Any, ...]:
    expected_top = {
        "CatacombVersion",
        "CatacombSecureData",
        "CatacombCurrentDate",
        "CatacombUserID",
        "CatacombEnrollmentCount",
    }
    if set(graph.top) != expected_top or graph.top["CatacombVersion"] != 0x30000:
        raise ValidationError("master Catacomb top schema is unsupported")
    if graph.top["CatacombUserID"] != -1:
        raise ValidationError("master Catacomb user scope is invalid")
    return (
        graph.data(graph.top["CatacombSecureData"], b"LTFC"),
        graph.integer(graph.top["CatacombEnrollmentCount"]),
        graph.date(graph.top["CatacombCurrentDate"]),
    )


def _validate_biolockout(graph: KeyedArchive) -> tuple[Any, ...]:
    if set(graph.top) != {"BioLockoutRecordSecureData", "BioLockoutRecordVersion"}:
        raise ValidationError("bio-lockout Catacomb top schema is unsupported")
    if graph.top["BioLockoutRecordVersion"] != 0x10000:
        raise ValidationError("bio-lockout Catacomb version is unsupported")
    return (graph.data(graph.top["BioLockoutRecordSecureData"], b"HRLB"),)


def _validate_component(
    data: bytes,
    validator: Callable[[KeyedArchive], tuple[Any, ...]],
    foundation_loader: Callable[[bytes], Any],
) -> tuple[Any, ...]:
    graph = KeyedArchive(data, foundation_loader)
    model = validator(graph)
    reencoded = plistlib.dumps(graph.root, fmt=plistlib.FMT_BINARY, sort_keys=False)
    round_trip = validator(KeyedArchive(reencoded, foundation_loader))
    if round_trip != model:
        raise ValidationError("Catacomb semantic round trip changed")
    return model


def validate_components(
    components: dict[str, bytes],
    apple_user_id: int,
    foundation_loader: Callable[[bytes], Any] = _foundation_load,
) -> ValidatedCatacomb:
    if isinstance(apple_user_id, bool) or not isinstance(apple_user_id, int):
        raise ValidationError("Apple user ID is invalid")
    if not 0 <= apple_user_id <= 0xFFFFFFFF:
        raise ValidationError("Apple user ID is outside uint32 policy")
    user_name = f"user_{apple_user_id:08x}.cat"
    if set(components) != {"master.cat", "biolockout.cat", user_name}:
        raise ValidationError("component set does not match the selected user")
    user = _validate_component(
        components[user_name],
        lambda graph: _validate_user(graph, apple_user_id),
        foundation_loader,
    )
    master = _validate_component(
        components["master.cat"], _validate_master, foundation_loader
    )
    biolockout = _validate_component(
        components["biolockout.cat"], _validate_biolockout, foundation_loader
    )
    identities = user[3]
    entity_counts = Counter(identity[1] for identity in identities)
    return ValidatedCatacomb(
        components=dict(components),
        master_secure_data=master[0],
        user_secure_data=user[0],
        biolockout_secure_data=biolockout[0],
        identity_count=len(identities),
        identity_entity_count=len(entity_counts),
        identity_entity_group_sizes=tuple(sorted(entity_counts.values())),
        master_enrollment_count=master[1],
        _identity_uuids=frozenset(identity[0] for identity in identities),
    )


def load_validated_archive(
    path: Path,
    apple_user_id: int,
    foundation_loader: Callable[[bytes], Any] = _foundation_load,
) -> ValidatedCatacomb:
    return validate_components(
        _read_components(path, apple_user_id), apple_user_id, foundation_loader
    )


def validate_archive(
    path: Path,
    apple_user_id: int,
    foundation_loader: Callable[[bytes], Any] = _foundation_load,
) -> dict[str, object]:
    validated = load_validated_archive(path, apple_user_id, foundation_loader)
    return {
        "schema_version": 1,
        "component_count": 3,
        "identity_count": validated.identity_count,
        "identity_entity_count": validated.identity_entity_count,
        "identity_entity_group_sizes": list(validated.identity_entity_group_sizes),
        "identity_entity_reuse_present": (
            validated.identity_entity_count < validated.identity_count
        ),
        "master_enrollment_count": validated.master_enrollment_count,
        "logical_finger_count_inferred": False,
        "schemas_valid": True,
        "foundation_readback": True,
        "semantic_round_trip_equal": True,
        "secure_envelopes_valid": True,
        "account_and_keybag_bindings_present": True,
        "identifiers_redacted": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("archive", type=Path)
    parser.add_argument("--apple-user-id", type=int, required=True)
    args = parser.parse_args()
    try:
        result = validate_archive(args.archive, args.apple_user_id)
    except (OSError, ValidationError, ValueError) as error:
        parser.error("current Catacomb validation failed")
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
