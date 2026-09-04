#!/usr/bin/env python3
"""Compare two private Catacomb stores while redacting every identifier."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import plistlib
import stat
import sys
from dataclasses import asdict, dataclass
from pathlib import Path


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {path.name}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


HERE = Path(__file__).resolve().parent
validator = _load(
    "catacomb_identity_shape_validator",
    HERE / "validate-current-macos-catacomb.py",
)


class CatacombShapeDeltaError(RuntimeError):
    pass


@dataclass(frozen=True)
class CatacombShapeDelta:
    before_identity_record_count: int
    after_identity_record_count: int
    identity_record_count_delta: int
    identity_records_added: int
    identity_records_removed: int
    before_entity_number_count: int
    after_entity_number_count: int
    entity_number_count_delta: int
    after_entity_group_sizes: tuple[int, ...]
    before_master_enrollment_count: int
    after_master_enrollment_count: int
    master_enrollment_count_delta: int
    master_component_changed: bool
    user_component_changed: bool
    biolockout_component_changed: bool
    all_components_changed: bool
    two_record_one_entity_addition_observed: bool
    logical_finger_count_inferred: bool
    identifiers_redacted: bool
    mutation_performed: bool


def _private_component(path: Path) -> bytes:
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_nlink != 1
        or metadata.st_mode & 0o077
        or not 0 < metadata.st_size <= validator.MAX_COMPONENT_BYTES
    ):
        raise CatacombShapeDeltaError("private Catacomb component metadata is unsafe")
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        data = os.read(descriptor, validator.MAX_COMPONENT_BYTES + 1)
        if len(data) != metadata.st_size:
            raise CatacombShapeDeltaError("private Catacomb component changed while reading")
        return data
    finally:
        os.close(descriptor)


def load_private_source(path: Path, apple_user_id: int):
    if not path.is_absolute():
        raise CatacombShapeDeltaError("private Catacomb source path must be absolute")
    metadata = path.lstat()
    foundation_loader = (
        validator._foundation_load
        if Path("/usr/bin/plutil").is_file()
        else plistlib.loads
    )
    if stat.S_ISREG(metadata.st_mode):
        try:
            return validator.load_validated_archive(
                path, apple_user_id, foundation_loader
            )
        except (OSError, ValueError, validator.ValidationError) as error:
            raise CatacombShapeDeltaError(
                "private Catacomb archive validation failed"
            ) from error
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_mode & 0o077
    ):
        raise CatacombShapeDeltaError("private Catacomb store directory is unsafe")
    expected = {
        "master.cat",
        "biolockout.cat",
        f"user_{apple_user_id:08x}.cat",
    }
    with os.scandir(path) as entries:
        actual = {entry.name for entry in entries}
    if actual != expected:
        raise CatacombShapeDeltaError("private store lacks the exact component set")
    components = {name: _private_component(path / name) for name in expected}
    try:
        return validator.validate_components(
            components, apple_user_id, foundation_loader
        )
    except (OSError, ValueError, validator.ValidationError) as error:
        raise CatacombShapeDeltaError("private Catacomb store validation failed") from error


def compare_validated(before, after) -> CatacombShapeDelta:
    added, removed = before.identity_uuid_delta_counts(after)
    record_delta = after.identity_count - before.identity_count
    entity_delta = after.identity_entity_count - before.identity_entity_count
    master_delta = after.master_enrollment_count - before.master_enrollment_count
    master_changed = before.components["master.cat"] != after.components["master.cat"]
    user_name = next(name for name in before.components if name.startswith("user_"))
    user_changed = before.components[user_name] != after.components[user_name]
    biolockout_changed = (
        before.components["biolockout.cat"] != after.components["biolockout.cat"]
    )
    two_record_one_entity = (
        record_delta == 2
        and added == 2
        and removed == 0
        and entity_delta == 1
        and master_delta == 2
        and 2 in after.identity_entity_group_sizes
    )
    return CatacombShapeDelta(
        before_identity_record_count=before.identity_count,
        after_identity_record_count=after.identity_count,
        identity_record_count_delta=record_delta,
        identity_records_added=added,
        identity_records_removed=removed,
        before_entity_number_count=before.identity_entity_count,
        after_entity_number_count=after.identity_entity_count,
        entity_number_count_delta=entity_delta,
        after_entity_group_sizes=after.identity_entity_group_sizes,
        before_master_enrollment_count=before.master_enrollment_count,
        after_master_enrollment_count=after.master_enrollment_count,
        master_enrollment_count_delta=master_delta,
        master_component_changed=master_changed,
        user_component_changed=user_changed,
        biolockout_component_changed=biolockout_changed,
        all_components_changed=master_changed and user_changed and biolockout_changed,
        two_record_one_entity_addition_observed=two_record_one_entity,
        # Entity grouping is structural evidence, not a general UI mapping.
        logical_finger_count_inferred=False,
        identifiers_redacted=True,
        mutation_performed=False,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("before", type=Path)
    parser.add_argument("after", type=Path)
    parser.add_argument("--apple-user-id", type=int, required=True)
    args = parser.parse_args()
    try:
        before = load_private_source(args.before, args.apple_user_id)
        after = load_private_source(args.after, args.apple_user_id)
        result = compare_validated(before, after)
    except (CatacombShapeDeltaError, OSError, ValueError, TypeError):
        parser.error("Catacomb identity-shape comparison failed safely")
    print(json.dumps(asdict(result), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
