#!/usr/bin/env python3
"""Build a mutation-free, identifier-redacted native-enrollment baseline."""

from __future__ import annotations

import argparse
import fcntl
import importlib.util
import json
import os
import stat
import struct
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
restore = _load("native_enrollment_cold_restore", HERE / "cold-catacomb-restore.py")

CONFIRMATION = "I_UNDERSTAND_THIS_ONLY_READS_NATIVE_ENROLLMENT_BASELINE"
OPERATION_LOCK = Path("/run/t2-touchid/operation.lock")
EXPECTED_POLICY = (1, 1, 1, 0)
LIVE_BASELINE_ENABLED = False


class NativeEnrollmentBaselineError(RuntimeError):
    pass


@dataclass(frozen=True)
class NativeEnrollmentBaseline:
    archive_identity_record_count: int
    archive_entity_number_count: int
    archive_entity_group_sizes: tuple[int, ...]
    archive_master_enrollment_count: int
    live_identity_record_count: int
    identity_inventory_matches_archive: bool
    identity_readback_stable: bool
    protected_policy_exact: bool
    maximum_identity_count: int
    reported_free_identity_count: int
    reported_capacity_available: bool
    capacity_semantics_proven: bool
    catacomb_uuid_query_status: int
    catacomb_state_query_status: int
    catacomb_group_query_status: int
    persistence_path_ready: bool
    safe_for_mutation: bool
    identifiers_redacted: bool
    mutation_performed: bool


def _perform(session, fields, label: str):
    try:
        return restore.state._perform(session, fields)
    except (
        ValueError,
        restore.state.biometric.BiometricCommandError,
    ) as error:
        raise NativeEnrollmentBaselineError(f"{label} reply shape is invalid") from error


def _identity_capacity(session, fields, label: str) -> int:
    status, output = _perform(session, fields, label)
    if status != 0:
        raise NativeEnrollmentBaselineError(f"{label} failed with status {status}")
    try:
        return restore.state.biometric.decode_identity_count(output or b"")
    except restore.state.biometric.BiometricCommandError as error:
        raise NativeEnrollmentBaselineError(f"{label} is malformed") from error


def _optional_catacomb_query(session, fields, *, record_size: int | None, label: str) -> int:
    status, output = _perform(session, fields, label)
    if status != 0:
        # This Bridge generation returns the caller-sized zero-filled output
        # allocation even when the SEP rejects these optional queries. Its
        # contents have no meaning on failure and are never retained.
        if output is not None and (
            not isinstance(output, bytes) or len(output) not in {0, fields[4]}
        ):
            raise NativeEnrollmentBaselineError(f"rejected {label} returned unexpected data")
        return status
    if record_size is None:
        if not isinstance(output, bytes) or len(output) != 16:
            raise NativeEnrollmentBaselineError(f"successful {label} is malformed")
        return status
    try:
        restore.state.biometric.validate_opaque_record_array(
            output or b"",
            record_size=record_size,
            maximum_records=(
                restore.state.biometric.MAX_CATACOMB_STATE_RECORDS
                if record_size == restore.state.biometric.CATACOMB_STATE_RECORD_SIZE
                else restore.state.biometric.MAX_CATACOMB_GROUP_STATE_RECORDS
            ),
        )
    except restore.state.biometric.BiometricCommandError as error:
        raise NativeEnrollmentBaselineError(f"successful {label} is malformed") from error
    return status


def probe_socket(sock, *, apple_user_id: int, store_path: Path) -> NativeEnrollmentBaseline:
    validated = restore.read_current_store(store_path, apple_user_id)
    session = restore.state.coupled.bridge_query.BridgeSession(sock)
    restore.state._initialize(session)

    identities = restore._stable_identity_inventory(
        session, apple_user_id, "native-enrollment identity inventory"
    )
    if not identities:
        raise NativeEnrollmentBaselineError("native-enrollment identity inventory is empty")
    inventory_matches = validated.matches_identity_uuids(
        tuple(identity.uuid for identity in identities)
    )
    if not inventory_matches:
        raise NativeEnrollmentBaselineError(
            "live SEP and validated host identity inventories disagree"
        )

    status, protected = _perform(
        session,
        restore.state.biometric.protected_config_fields(user_id=apple_user_id),
        "protected policy",
    )
    if (
        status != 0
        or not isinstance(protected, bytes)
        or len(protected) != restore.state.biometric.PROTECTED_CONFIG_SIZE
    ):
        raise NativeEnrollmentBaselineError(f"protected policy failed with status {status}")
    policy_words = struct.unpack("<8I", protected)
    if policy_words[:4] != EXPECTED_POLICY or policy_words[4:] != EXPECTED_POLICY:
        raise NativeEnrollmentBaselineError("protected policy is not the exact proven policy")

    maximum = _identity_capacity(
        session, restore.state.biometric.max_identity_count_fields(), "maximum identity count"
    )
    free = _identity_capacity(
        session,
        restore.state.biometric.free_identity_count_fields(user_id=apple_user_id),
        "free identity count",
    )
    if maximum < len(identities) or free > maximum:
        raise NativeEnrollmentBaselineError("identity capacity counters are inconsistent")

    uuid_status = _optional_catacomb_query(
        session,
        restore.state.biometric.catacomb_uuid_fields(user_id=apple_user_id),
        record_size=None,
        label="Catacomb UUID query",
    )
    state_status = _optional_catacomb_query(
        session,
        restore.state.biometric.catacomb_state_fields(),
        record_size=restore.state.biometric.CATACOMB_STATE_RECORD_SIZE,
        label="Catacomb state query",
    )
    group_status = _optional_catacomb_query(
        session,
        restore.state.biometric.catacomb_group_state_fields(),
        record_size=restore.state.biometric.CATACOMB_GROUP_STATE_RECORD_SIZE,
        label="Catacomb group query",
    )

    return NativeEnrollmentBaseline(
        archive_identity_record_count=validated.identity_count,
        archive_entity_number_count=validated.identity_entity_count,
        archive_entity_group_sizes=validated.identity_entity_group_sizes,
        archive_master_enrollment_count=validated.master_enrollment_count,
        live_identity_record_count=len(identities),
        identity_inventory_matches_archive=inventory_matches,
        identity_readback_stable=True,
        protected_policy_exact=True,
        maximum_identity_count=maximum,
        reported_free_identity_count=free,
        reported_capacity_available=free > 0,
        # The observed counters are not interchangeable with record, entity,
        # or user-visible fingerprint counts on this firmware.
        capacity_semantics_proven=False,
        catacomb_uuid_query_status=uuid_status,
        catacomb_state_query_status=state_status,
        catacomb_group_query_status=group_status,
        # A validator is not a transactionally durable enrollment finalizer.
        persistence_path_ready=False,
        safe_for_mutation=False,
        identifiers_redacted=True,
        mutation_performed=False,
    )


def live_probe(
    *, apple_user_id: int, store_path: Path, interface: str, timeout: float = 5.0
) -> NativeEnrollmentBaseline:
    if not LIVE_BASELINE_ENABLED:
        raise NativeEnrollmentBaselineError("live native-enrollment baseline is disabled")
    result = None

    def run(sock):
        nonlocal result
        result = probe_socket(sock, apple_user_id=apple_user_id, store_path=store_path)
        return result

    original = restore.state.coupled.bridge_query.query_connected_socket
    original_gate = restore.state.coupled.LIVE_COUPLED_QUERY_ENABLED
    try:
        restore.state.coupled.bridge_query.query_connected_socket = run
        restore.state.coupled.LIVE_COUPLED_QUERY_ENABLED = True
        restore.state.coupled.live_query(interface, timeout)
    finally:
        restore.state.coupled.bridge_query.query_connected_socket = original
        restore.state.coupled.LIVE_COUPLED_QUERY_ENABLED = original_gate
    if result is None:
        raise NativeEnrollmentBaselineError("live native-enrollment baseline produced no result")
    return result


def _lock_operation():
    flags = os.O_RDWR | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(OPERATION_LOCK, flags)
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_mode & 0o077
    ):
        os.close(descriptor)
        raise NativeEnrollmentBaselineError("operation lock is unsafe")
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live", action="store_true")
    parser.add_argument("--apple-user-id", type=int, default=501)
    parser.add_argument("--store", type=Path, default=Path("/var/lib/t2-touchid/catacomb"))
    parser.add_argument("--interface", default="enp4s0f1u1")
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--confirm", default="")
    args = parser.parse_args()
    if not args.live:
        print("offline only: live mode performs read-only enrollment baseline queries")
        return 0
    if os.geteuid() != 0:
        parser.error("live mode requires root")
    if args.confirm != CONFIRMATION:
        parser.error(f"live mode requires --confirm={CONFIRMATION}")

    descriptor = _lock_operation()
    global LIVE_BASELINE_ENABLED
    LIVE_BASELINE_ENABLED = True
    try:
        result = live_probe(
            apple_user_id=args.apple_user_id,
            store_path=args.store,
            interface=args.interface,
            timeout=args.timeout,
        )
    except (
        NativeEnrollmentBaselineError,
        OSError,
        ValueError,
        restore.ColdRestoreError,
    ) as error:
        parser.error("native-enrollment baseline failed safely")
    finally:
        LIVE_BASELINE_ENABLED = False
        os.close(descriptor)
    print(json.dumps(asdict(result), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
