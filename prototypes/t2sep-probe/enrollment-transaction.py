#!/usr/bin/env python3
"""Crash-safe host transaction for one T2 native enrollment.

The journal contains only counts, lengths, and digests.  Private identity and
SEP payload bytes live only in root-owned mode-0600 staging files and are
removed after a successful validated commit.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import re
import stat
import sys
import uuid
from typing import Callable


def _load(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {filename}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


component_update = _load("enrollment_transaction_component_update", "catacomb-component-update.py")
validator = component_update.validator

COMPONENT_NAMES = ("master.cat", "biolockout.cat")
APPLE_EPOCH_OFFSET = 978_307_200


class EnrollmentTransactionError(RuntimeError):
    pass


def _sync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_new(path: Path, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        offset = 0
        while offset < len(data):
            written = os.write(descriptor, data[offset:])
            if written <= 0:
                raise EnrollmentTransactionError("private write made no progress")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _read_private(path: Path, maximum: int) -> bytes:
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_nlink != 1
        or metadata.st_mode & 0o077
        or not 0 < metadata.st_size <= maximum
    ):
        raise EnrollmentTransactionError("private staged file metadata is unsafe")
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        data = os.read(descriptor, maximum + 1)
    finally:
        os.close(descriptor)
    if len(data) != metadata.st_size:
        raise EnrollmentTransactionError("private staged file changed while reading")
    return data


def _private_directory(path: Path) -> None:
    metadata = path.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_mode & 0o077
    ):
        raise EnrollmentTransactionError("state directory is not private and caller-owned")


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class EnrollmentTransaction:
    def __init__(
        self,
        state_root: Path,
        *,
        apple_user_id: int,
        operation_id: str,
        failure_hook: Callable[[str], None] | None = None,
    ) -> None:
        if not state_root.is_absolute():
            raise EnrollmentTransactionError("state root must be absolute")
        _private_directory(state_root)
        try:
            canonical = str(uuid.UUID(operation_id))
        except (ValueError, AttributeError, TypeError) as error:
            raise EnrollmentTransactionError("operation ID must be a UUID") from error
        if canonical != operation_id:
            raise EnrollmentTransactionError("operation ID is not canonical")
        if isinstance(apple_user_id, bool) or not isinstance(apple_user_id, int) or not 0 <= apple_user_id <= 0xFFFFFFFF:
            raise EnrollmentTransactionError("Apple user ID is invalid")
        self.state_root = state_root
        self.apple_user_id = apple_user_id
        self.operation_id = operation_id
        self.user_name = f"user_{apple_user_id:08x}.cat"
        self.expected_names = {self.user_name, *COMPONENT_NAMES}
        self.operation = state_root / "mutations" / f"enrollment-{operation_id}"
        self.secure = self.operation / "secure"
        self.journal_path = self.operation / "journal.json"
        self.identity_path = self.operation / "identity.private"
        self.failure_hook = failure_hook

    def _components(self, path: Path) -> dict[str, bytes]:
        _private_directory(path)
        with os.scandir(path) as entries:
            names = {entry.name for entry in entries}
        if names != self.expected_names:
            raise EnrollmentTransactionError("Catacomb store has the wrong component set")
        return {
            name: _read_private(path / name, validator.MAX_COMPONENT_BYTES)
            for name in self.expected_names
        }

    def _write_journal(self, value: dict[str, object]) -> None:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        temporary = self.operation / ".journal.new"
        if temporary.exists():
            temporary.unlink()
        _write_new(temporary, encoded)
        os.replace(temporary, self.journal_path)
        _sync_directory(self.operation)

    def _journal(self) -> dict[str, object]:
        try:
            value = json.loads(_read_private(self.journal_path, 64 * 1024))
        except (json.JSONDecodeError, OSError, ValueError) as error:
            raise EnrollmentTransactionError("enrollment journal is invalid") from error
        if not isinstance(value, dict) or value.get("operation_id") != self.operation_id:
            raise EnrollmentTransactionError("enrollment journal belongs to another operation")
        return value

    def begin(
        self,
        *,
        live_identity_count: int,
        maximum_identity_count: int,
        free_identity_count: int,
    ) -> None:
        if any(
            isinstance(value, bool) or not isinstance(value, int) or value < 0
            for value in (
                live_identity_count,
                maximum_identity_count,
                free_identity_count,
            )
        ):
            raise EnrollmentTransactionError("live identity capacity is invalid")
        if free_identity_count < 1 or live_identity_count >= maximum_identity_count:
            raise EnrollmentTransactionError("live identity capacity is exhausted")
        mutations = self.state_root / "mutations"
        if not mutations.exists():
            mutations.mkdir(mode=0o700)
            _sync_directory(self.state_root)
        _private_directory(mutations)
        if os.path.lexists(self.operation):
            raise EnrollmentTransactionError("enrollment operation already exists")
        self.operation.mkdir(mode=0o700)
        self.secure.mkdir(mode=0o700)
        _sync_directory(self.operation)
        components = self._components(self.state_root / "catacomb")
        try:
            baseline = validator.validate_components(
                components, self.apple_user_id, plistlib.loads
            )
        except (ValueError, validator.ValidationError) as error:
            raise EnrollmentTransactionError("baseline Catacomb validation failed") from error
        if not 0 < baseline.identity_count < validator.MAX_IDENTITIES:
            raise EnrollmentTransactionError("baseline identity capacity is unsafe")
        if baseline.identity_count != live_identity_count:
            raise EnrollmentTransactionError("host and live identity counts disagree")
        self._write_journal(
            {
                "schema": 1,
                "operation_id": self.operation_id,
                "phase": "prepared",
                "apple_user_id": self.apple_user_id,
                "baseline_identity_count": baseline.identity_count,
                "maximum_identity_count": maximum_identity_count,
                "free_identity_count": free_identity_count,
                "baseline_entity_count": baseline.identity_entity_count,
                "baseline_master_count": baseline.master_enrollment_count,
                "baseline_components": {
                    name: {"sha256": _digest(data), "length": len(data)}
                    for name, data in sorted(components.items())
                },
                "staged_secure": {},
                "identifiers_redacted": True,
            }
        )
        _sync_directory(mutations)

    def record_terminal_identity(self, identity_uuid: bytes) -> None:
        journal = self._journal()
        if journal.get("phase") != "prepared":
            raise EnrollmentTransactionError("terminal identity is out of order")
        if not isinstance(identity_uuid, bytes) or len(identity_uuid) != 16:
            raise EnrollmentTransactionError("terminal identity is invalid")
        _write_new(self.identity_path, identity_uuid)
        _sync_directory(self.operation)
        journal["terminal_identity_sha256"] = _digest(identity_uuid)
        journal["phase"] = "terminal-identity"
        self._write_journal(journal)

    def stage_secure_component(self, name: str, data: bytes) -> None:
        journal = self._journal()
        if journal.get("phase") not in {"terminal-identity", "secure-staging"}:
            raise EnrollmentTransactionError("secure component is out of order")
        if name not in self.expected_names:
            raise EnrollmentTransactionError("secure component name is invalid")
        magic = b"HRLB" if name == "biolockout.cat" else b"LTFC"
        if (
            not isinstance(data, bytes)
            or not data.startswith(magic)
            or not 16 <= len(data) <= validator.MAX_COMPONENT_BYTES
        ):
            raise EnrollmentTransactionError("secure component payload is invalid")
        staged = journal.get("staged_secure")
        if not isinstance(staged, dict) or name in staged:
            raise EnrollmentTransactionError("secure component was already staged")
        _write_new(self.secure / name, data)
        _sync_directory(self.secure)
        staged[name] = {"sha256": _digest(data), "length": len(data)}
        journal["phase"] = "secure-staging"
        self._write_journal(journal)

    def commit(self, *, identity_name: str, apple_time: float) -> None:
        journal = self._journal()
        staged = journal.get("staged_secure")
        if journal.get("phase") != "secure-staging" or not isinstance(staged, dict) or set(staged) != self.expected_names:
            raise EnrollmentTransactionError("all secure components must be staged")
        current = self._components(self.state_root / "catacomb")
        baseline = journal.get("baseline_components")
        observed = {
            name: {"sha256": _digest(data), "length": len(data)}
            for name, data in sorted(current.items())
        }
        if baseline != observed:
            raise EnrollmentTransactionError("host Catacomb changed during enrollment")
        identity_uuid = _read_private(self.identity_path, 16)
        if _digest(identity_uuid) != journal.get("terminal_identity_sha256"):
            raise EnrollmentTransactionError("terminal identity staging is inconsistent")
        secure = {
            name: _read_private(self.secure / name, validator.MAX_COMPONENT_BYTES)
            for name in self.expected_names
        }
        for name, data in secure.items():
            if staged.get(name) != {"sha256": _digest(data), "length": len(data)}:
                raise EnrollmentTransactionError("secure component staging is inconsistent")
        try:
            candidate = component_update.build_enrollment_update(
                current,
                apple_user_id=self.apple_user_id,
                terminal_identity_uuid=identity_uuid,
                user_secure_data=secure[self.user_name],
                master_secure_data=secure["master.cat"],
                biolockout_secure_data=secure["biolockout.cat"],
                identity_name=identity_name,
                apple_time=apple_time,
            )
        except component_update.CatacombComponentUpdateError as error:
            raise EnrollmentTransactionError("candidate Catacomb construction failed") from error

        candidate_path = self.operation / "candidate"
        candidate_path.mkdir(mode=0o700)
        for name in sorted(self.expected_names):
            _write_new(candidate_path / name, candidate[name])
        _sync_directory(candidate_path)
        if self.failure_hook:
            self.failure_hook("candidate-synced")
        journal["candidate_components"] = {
            name: {"sha256": _digest(data), "length": len(data)}
            for name, data in sorted(candidate.items())
        }
        journal["phase"] = "candidate-synced"
        self._write_journal(journal)

        target = self.state_root / "catacomb"
        backup = self.state_root / f"catacomb-pre-enrollment-{self.operation_id}-backup"
        if os.path.lexists(backup):
            raise EnrollmentTransactionError("enrollment rollback directory already exists")
        moved = False
        committed = False
        try:
            os.rename(target, backup)
            moved = True
            _sync_directory(self.state_root)
            if self.failure_hook:
                self.failure_hook("baseline-preserved")
            os.rename(candidate_path, target)
            committed = True
            _sync_directory(self.state_root)
        except BaseException:
            if moved and not committed and not os.path.lexists(target):
                os.rename(backup, target)
                _sync_directory(self.state_root)
            raise
        journal["phase"] = "committed"
        journal["rollback_preserved"] = True
        self._write_journal(journal)
        for path in (self.identity_path, *(self.secure / name for name in self.expected_names)):
            path.unlink()
        self.secure.rmdir()
        _sync_directory(self.operation)

    def safe_summary(self) -> dict[str, object]:
        journal = self._journal()
        return {
            "operation_id": self.operation_id,
            "phase": journal.get("phase"),
            "baseline_identity_count": journal.get("baseline_identity_count"),
            "staged_component_count": len(journal.get("staged_secure", {})),
            "identifiers_redacted": True,
        }
