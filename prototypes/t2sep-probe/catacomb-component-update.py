#!/usr/bin/env python3
"""Build a strictly validated three-component Catacomb enrollment update.

This module is offline-only.  It accepts already captured opaque SEP payloads,
updates the host-side NSKeyedArchive metadata, and returns no public identity
values.  Transport, journaling, and durable installation belong to callers.
"""

from __future__ import annotations

import copy
import importlib.util
import math
from pathlib import Path
import plistlib
import sys


def _load_validator():
    path = Path(__file__).resolve().parents[2] / "tools/research/validate-current-macos-catacomb.py"
    spec = importlib.util.spec_from_file_location("catacomb_component_validator", path)
    if spec is None or spec.loader is None:
        raise ImportError("Catacomb validator is unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


validator = _load_validator()

IDENTITY_KEYS = {
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
}


class CatacombComponentUpdateError(ValueError):
    pass


def _bounded_secure_data(value: bytes, magic: bytes, label: str) -> bytes:
    if (
        not isinstance(value, bytes)
        or not value.startswith(magic)
        or not 16 <= len(value) <= validator.MAX_COMPONENT_BYTES
    ):
        raise CatacombComponentUpdateError(f"{label} secure data is invalid")
    return value


def _graph(data: bytes):
    return validator.KeyedArchive(data, plistlib.loads)


def _encode(root: dict) -> bytes:
    try:
        return plistlib.dumps(root, fmt=plistlib.FMT_BINARY, sort_keys=False)
    except (TypeError, ValueError, OverflowError) as error:
        raise CatacombComponentUpdateError("Catacomb encoding failed") from error


def _replace_data(graph, root: dict, top_key: str, value: bytes) -> None:
    index = graph._index(graph.top[top_key])
    target = root["$objects"][index]
    if not isinstance(target, dict) or set(target) != {"NS.data", "$class"}:
        raise CatacombComponentUpdateError("secure-data object changed after validation")
    target["NS.data"] = value


def _update_user(
    source: bytes,
    *,
    apple_user_id: int,
    identity_uuid: bytes,
    secure_data: bytes,
    identity_name: str,
    apple_time: float,
) -> bytes:
    graph = _graph(source)
    identities = graph.classed(
        graph.top["CatacombIdentityList"], "NSMutableArray", {"NS.objects"}
    )["NS.objects"]
    if not isinstance(identities, list) or not identities:
        raise CatacombComponentUpdateError(
            "a populated built-in identity prototype is required"
        )
    if len(identities) >= validator.MAX_IDENTITIES:
        raise CatacombComponentUpdateError("identity capacity policy reached")

    existing_entities: set[int] = set()
    existing_uuids: set[bytes] = set()
    for reference in identities:
        identity = graph.classed(reference, "BiometricKitIdentity", IDENTITY_KEYS)
        existing_entities.add(graph.integer(identity["BKIdentityEntityNumber"]))
        existing_uuids.add(graph.raw_uuid(identity["BKIdentityUUID"]))
    if identity_uuid in existing_uuids:
        raise CatacombComponentUpdateError("terminal identity is already present")
    entity = next(
        (candidate for candidate in range(validator.MAX_IDENTITIES) if candidate not in existing_entities),
        None,
    )
    if entity is None:
        raise CatacombComponentUpdateError("no unused identity entity remains")

    root = copy.deepcopy(graph.root)
    objects = root["$objects"]
    prototype_index = graph._index(identities[0])
    prototype = copy.deepcopy(objects[prototype_index])
    creation_index = graph._index(prototype["BKIdentityCreationTime"])
    creation = objects[creation_index]
    if not isinstance(creation, dict) or set(creation) != {"NS.time", "$class"}:
        raise CatacombComponentUpdateError("identity date prototype changed")

    name_index = len(objects)
    objects.append(identity_name)
    date_index = len(objects)
    objects.append({"NS.time": apple_time, "$class": creation["$class"]})
    prototype.update(
        {
            "BKIdentityMatchCount": 0,
            "BKIdentityCreationTime": plistlib.UID(date_index),
            "BKIdentityEntityNumber": entity,
            "BKIdentityUUID": identity_uuid,
            "BKIdentityMatchCountContinuous": 0,
            "BKIdentityName": plistlib.UID(name_index),
            "BKIdentityUpdateCount": 1,
            "BKIdentityUserID": apple_user_id,
        }
    )
    identity_index = len(objects)
    objects.append(prototype)
    array_index = graph._index(graph.top["CatacombIdentityList"])
    root["$objects"][array_index]["NS.objects"].append(plistlib.UID(identity_index))
    _replace_data(graph, root, "CatacombSecureData", secure_data)
    return _encode(root)


def _update_master(
    source: bytes, *, secure_data: bytes, enrollment_count: int, apple_time: float
) -> bytes:
    graph = _graph(source)
    root = copy.deepcopy(graph.root)
    root["$top"]["CatacombEnrollmentCount"] = enrollment_count
    date_index = graph._index(graph.top["CatacombCurrentDate"])
    date = root["$objects"][date_index]
    if not isinstance(date, dict) or set(date) != {"NS.time", "$class"}:
        raise CatacombComponentUpdateError("master date object changed")
    date["NS.time"] = apple_time
    _replace_data(graph, root, "CatacombSecureData", secure_data)
    return _encode(root)


def _update_biolockout(source: bytes, *, secure_data: bytes) -> bytes:
    graph = _graph(source)
    root = copy.deepcopy(graph.root)
    _replace_data(graph, root, "BioLockoutRecordSecureData", secure_data)
    return _encode(root)


def build_enrollment_update(
    components: dict[str, bytes],
    *,
    apple_user_id: int,
    terminal_identity_uuid: bytes,
    user_secure_data: bytes,
    master_secure_data: bytes,
    biolockout_secure_data: bytes,
    identity_name: str,
    apple_time: float,
) -> dict[str, bytes]:
    """Return a validated one-identity, one-entity, three-payload update."""
    if (
        isinstance(apple_user_id, bool)
        or not isinstance(apple_user_id, int)
        or not 0 <= apple_user_id <= 0xFFFFFFFF
    ):
        raise CatacombComponentUpdateError("Apple user ID is invalid")
    if not isinstance(terminal_identity_uuid, bytes) or len(terminal_identity_uuid) != 16:
        raise CatacombComponentUpdateError("terminal identity UUID is invalid")
    if (
        not isinstance(identity_name, str)
        or not identity_name
        or len(identity_name.encode("utf-8")) > validator.MAX_STRING_BYTES
    ):
        raise CatacombComponentUpdateError("identity name is invalid")
    if isinstance(apple_time, bool) or not isinstance(apple_time, (int, float)) or not math.isfinite(apple_time):
        raise CatacombComponentUpdateError("Apple timestamp is invalid")

    user_secure_data = _bounded_secure_data(user_secure_data, b"LTFC", "user")
    master_secure_data = _bounded_secure_data(master_secure_data, b"LTFC", "master")
    biolockout_secure_data = _bounded_secure_data(
        biolockout_secure_data, b"HRLB", "bio-lockout"
    )
    user_name = f"user_{apple_user_id:08x}.cat"
    try:
        before = validator.validate_components(components, apple_user_id, plistlib.loads)
    except (TypeError, ValueError, validator.ValidationError) as error:
        raise CatacombComponentUpdateError("source Catacomb validation failed") from error
    if before.identity_count <= 0:
        raise CatacombComponentUpdateError("source Catacomb must contain an identity")
    if (
        user_secure_data == before.user_secure_data
        or master_secure_data == before.master_secure_data
        or biolockout_secure_data == before.biolockout_secure_data
    ):
        raise CatacombComponentUpdateError(
            "enrollment did not change every required secure payload"
        )

    output = {
        user_name: _update_user(
            components[user_name],
            apple_user_id=apple_user_id,
            identity_uuid=terminal_identity_uuid,
            secure_data=user_secure_data,
            identity_name=identity_name,
            apple_time=float(apple_time),
        ),
        "master.cat": _update_master(
            components["master.cat"],
            secure_data=master_secure_data,
            enrollment_count=before.master_enrollment_count + 1,
            apple_time=float(apple_time),
        ),
        "biolockout.cat": _update_biolockout(
            components["biolockout.cat"], secure_data=biolockout_secure_data
        ),
    }
    try:
        after = validator.validate_components(output, apple_user_id, plistlib.loads)
    except (TypeError, ValueError, validator.ValidationError) as error:
        raise CatacombComponentUpdateError("updated Catacomb validation failed") from error
    added, removed = before.identity_uuid_delta_counts(after)
    if not (
        after.identity_count == before.identity_count + 1
        and after.identity_entity_count == before.identity_entity_count + 1
        and after.master_enrollment_count == before.master_enrollment_count + 1
        and added == 1
        and removed == 0
        and after.user_secure_data == user_secure_data
        and after.master_secure_data == master_secure_data
        and after.biolockout_secure_data == biolockout_secure_data
    ):
        raise CatacombComponentUpdateError("updated Catacomb invariant failed")
    return output
