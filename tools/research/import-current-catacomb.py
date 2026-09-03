#!/usr/bin/env python3
"""Atomically import one validated nonempty macOS Catacomb on Linux."""

from __future__ import annotations

import argparse
import importlib.util
import os
import plistlib
import stat
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable


SCRIPT_DIR = Path(__file__).resolve().parent
VALIDATOR_PATH = SCRIPT_DIR / "validate-current-macos-catacomb.py"
CONFIRMATION = "I_UNDERSTAND_THIS_REPLACES_THE_LINUX_CATACOMB_STORE"
DEFAULT_STATE_ROOT = Path("/var/lib/t2-touchid")


def _load_validator():
    spec = importlib.util.spec_from_file_location(
        "current_catacomb_import_validator", VALIDATOR_PATH
    )
    if spec is None or spec.loader is None:
        raise ImportError("current Catacomb validator is unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


validator = _load_validator()


class ImportError(RuntimeError):
    pass


@dataclass(frozen=True)
class ImportResult:
    component_count: int
    identity_nonzero: bool
    previous_store_preserved: bool
    import_committed: bool


def _require_private_directory(path: Path) -> None:
    metadata = path.stat(follow_symlinks=False)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_mode & 0o077
    ):
        raise ImportError("Catacomb state directory is not private and caller-owned")


def _sync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_private(path: Path, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        offset = 0
        while offset < len(data):
            written = os.write(descriptor, data[offset:])
            if written <= 0:
                raise ImportError("Catacomb component write made no progress")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _require_replaceable_store(path: Path, expected: set[str]) -> None:
    _require_private_directory(path)
    with os.scandir(path) as entries:
        actual = {entry.name for entry in entries}
    if actual != expected:
        raise ImportError("existing Catacomb store is not the exact component set")
    for name in expected:
        metadata = (path / name).stat(follow_symlinks=False)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
            or metadata.st_mode & 0o077
            or not 0 < metadata.st_size <= validator.MAX_COMPONENT_BYTES
        ):
            raise ImportError("existing Catacomb component is unsafe")


def install_archive(
    archive: Path,
    state_root: Path,
    apple_user_id: int,
    *,
    foundation_loader=plistlib.loads,
    failure_hook: Callable[[str], None] | None = None,
) -> ImportResult:
    if not state_root.is_absolute():
        raise ImportError("Catacomb state root must be absolute")
    _require_private_directory(state_root)
    try:
        validated = validator.load_validated_archive(
            archive, apple_user_id, foundation_loader
        )
    except (OSError, ValueError, validator.ValidationError) as error:
        raise ImportError("current Catacomb archive validation failed") from error
    if validated.identity_count <= 0:
        raise ImportError("current Catacomb archive has no enrolled identity")

    expected = {
        "master.cat",
        "biolockout.cat",
        f"user_{apple_user_id:08x}.cat",
    }
    if set(validated.components) != expected:
        raise ImportError("validated Catacomb component set changed")
    target = state_root / "catacomb"
    backup = state_root / "catacomb-zero-identity-backup"
    if os.path.lexists(backup):
        raise ImportError("Catacomb rollback directory already exists")
    if os.path.lexists(target):
        _require_replaceable_store(target, expected)

    staging = Path(tempfile.mkdtemp(prefix=".catacomb-current.", dir=state_root))
    staging.chmod(0o700)
    target_moved = False
    committed = False
    try:
        for name in sorted(expected):
            _write_private(staging / name, validated.components[name])
        _sync_directory(staging)
        if failure_hook:
            failure_hook("staging_synced")
        if target.exists():
            os.rename(target, backup)
            target_moved = True
            _sync_directory(state_root)
            if failure_hook:
                failure_hook("previous_store_preserved")
        os.rename(staging, target)
        committed = True
        _sync_directory(state_root)
        if failure_hook:
            failure_hook("current_store_committed")
    except BaseException:
        if target_moved and not committed and not os.path.lexists(target):
            os.rename(backup, target)
            _sync_directory(state_root)
        raise
    finally:
        if not committed and staging.exists():
            for child in staging.iterdir():
                child.unlink()
            staging.rmdir()
    return ImportResult(3, True, target_moved, True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("archive", type=Path)
    parser.add_argument("--apple-user-id", type=int, default=501)
    parser.add_argument("--confirm", required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("current Catacomb import requires root")
    if args.confirm != CONFIRMATION:
        parser.error(f"import requires --confirm={CONFIRMATION}")
    try:
        result = install_archive(
            args.archive, DEFAULT_STATE_ROOT, args.apple_user_id
        )
    except (OSError, ImportError) as error:
        parser.error(str(error))
    print(
        "current Catacomb imported: "
        f"components={result.component_count} "
        f"identity_nonzero={'yes' if result.identity_nonzero else 'no'} "
        f"previous_store_preserved={'yes' if result.previous_store_preserved else 'no'} "
        f"committed={'yes' if result.import_committed else 'no'}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
