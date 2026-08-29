#!/usr/bin/env python3
"""Fail-closed local storage envelope for opaque SEP catacomb blobs."""

from __future__ import annotations

import hashlib
import hmac
import os
from pathlib import Path
import struct


MAGIC = b"T2CATDB\0"
VERSION = 1
HEADER = struct.Struct("<8sIII32s")
MINIMUM_BLOB_SIZE = 33
MAXIMUM_BLOB_SIZE = 64 * 1024 * 1024


class CatacombStoreError(ValueError):
    pass


def _uid(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 0xffffffff:
        raise CatacombStoreError("user ID does not fit in 32 bits")
    return value


def encode_record(*, user_id: int, blob: bytes) -> bytes:
    user_id = _uid(user_id)
    if (not isinstance(blob, bytes)
            or not MINIMUM_BLOB_SIZE <= len(blob) <= MAXIMUM_BLOB_SIZE):
        raise CatacombStoreError("catacomb blob is outside safe bounds")
    if struct.unpack_from("<I", blob, 8)[0] != user_id:
        raise CatacombStoreError("catacomb blob belongs to a different user")
    digest = hashlib.sha256(blob).digest()
    return HEADER.pack(MAGIC, VERSION, user_id, len(blob), digest) + blob


def decode_record(record: bytes, *, expected_user_id: int) -> bytes:
    expected_user_id = _uid(expected_user_id)
    if not isinstance(record, bytes) or len(record) < HEADER.size + MINIMUM_BLOB_SIZE:
        raise CatacombStoreError("catacomb record is truncated")
    magic, version, user_id, size, digest = HEADER.unpack_from(record)
    blob = record[HEADER.size:]
    if magic != MAGIC or version != VERSION or user_id != expected_user_id:
        raise CatacombStoreError("catacomb record identity is invalid")
    if size != len(blob) or size > MAXIMUM_BLOB_SIZE:
        raise CatacombStoreError("catacomb record length is invalid")
    if not hmac.compare_digest(digest, hashlib.sha256(blob).digest()):
        raise CatacombStoreError("catacomb record integrity check failed")
    if struct.unpack_from("<I", blob, 8)[0] != expected_user_id:
        raise CatacombStoreError("catacomb payload user does not match its envelope")
    return blob


def save(path: Path, *, user_id: int, blob: bytes) -> None:
    """Atomically replace one root-owned record and fsync file plus directory."""
    if not isinstance(path, Path) or not path.is_absolute():
        raise CatacombStoreError("catacomb path must be absolute")
    record = encode_record(user_id=user_id, blob=blob)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    descriptor = None
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        view = memoryview(record)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise CatacombStoreError("catacomb record write made no progress")
            view = view[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def load(path: Path, *, expected_user_id: int) -> bytes:
    if not isinstance(path, Path) or not path.is_absolute():
        raise CatacombStoreError("catacomb path must be absolute")
    metadata = path.stat()
    if metadata.st_mode & 0o077:
        raise CatacombStoreError("catacomb record permissions are too broad")
    if metadata.st_size > HEADER.size + MAXIMUM_BLOB_SIZE:
        raise CatacombStoreError("catacomb record exceeds its size cap")
    return decode_record(path.read_bytes(), expected_user_id=expected_user_id)
