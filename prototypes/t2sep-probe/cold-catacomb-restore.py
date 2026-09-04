#!/usr/bin/env python3
"""Fail-closed cold-boot restore of one validated current macOS Catacomb."""

from __future__ import annotations

import argparse
import importlib.util
import os
import plistlib
import stat
import sys
from dataclasses import dataclass
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
state = _load("cold_restore_state", HERE / "user-state-probe.py")
VALIDATOR_PATH = HERE / "validate-current-macos-catacomb.py"
if not VALIDATOR_PATH.is_file():
    VALIDATOR_PATH = HERE.parents[1] / "tools/research/validate-current-macos-catacomb.py"
validator = _load(
    "cold_restore_validator",
    VALIDATOR_PATH,
)
CONFIRMATION = "I_UNDERSTAND_THIS_RESTORES_THE_CURRENT_T2_CATACOMB"
LIVE_COLD_RESTORE_ENABLED = False
MAX_FDR_BYTES = 1024 * 1024


class ColdRestoreError(RuntimeError):
    pass


@dataclass(frozen=True)
class ColdRestoreResult:
    component_count: int
    source_identity_nonzero: bool
    restoration_required: bool
    calibration_status: int | None
    master_status: int | None
    user_status: int | None
    biolockout_status: int | None
    protected_config_length: int
    identity_count: int
    identity_readback_stable: bool
    completed: bool


def _private_component(path: Path) -> bytes:
    metadata = path.stat(follow_symlinks=False)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_nlink != 1
        or metadata.st_mode & 0o077
        or not 0 < metadata.st_size <= validator.MAX_COMPONENT_BYTES
    ):
        raise ColdRestoreError("local Catacomb component metadata is unsafe")
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        data = os.read(descriptor, validator.MAX_COMPONENT_BYTES + 1)
        if len(data) != metadata.st_size:
            raise ColdRestoreError("local Catacomb component changed while reading")
        return data
    finally:
        os.close(descriptor)


def read_current_store(path: Path, apple_user_id: int):
    if not path.is_absolute():
        raise ColdRestoreError("local Catacomb path must be absolute")
    metadata = path.stat(follow_symlinks=False)
    if stat.S_ISREG(metadata.st_mode):
        try:
            validated = validator.load_validated_archive(
                path, apple_user_id, plistlib.loads
            )
        except (OSError, ValueError, validator.ValidationError) as error:
            raise ColdRestoreError("local Catacomb archive validation failed") from error
        if validated.identity_count <= 0:
            raise ColdRestoreError("local Catacomb contains no enrolled identity")
        return validated
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_mode & 0o077
    ):
        raise ColdRestoreError("local Catacomb directory is unsafe")
    expected = {
        "master.cat",
        "biolockout.cat",
        f"user_{apple_user_id:08x}.cat",
    }
    with os.scandir(path) as entries:
        actual = {entry.name for entry in entries}
    if actual != expected:
        raise ColdRestoreError("local Catacomb does not contain the exact component set")
    components = {name: _private_component(path / name) for name in expected}
    try:
        validated = validator.validate_components(
            components, apple_user_id, plistlib.loads
        )
    except (OSError, ValueError, validator.ValidationError) as error:
        raise ColdRestoreError("local Catacomb validation failed") from error
    if validated.identity_count <= 0:
        raise ColdRestoreError("local Catacomb contains no enrolled identity")
    return validated


def _perform_zero_output(session, fields, label: str) -> int:
    try:
        status, output = state._perform(session, fields)
    except (ValueError, state.biometric.BiometricCommandError) as error:
        raise ColdRestoreError(f"{label} reply shape is invalid") from error
    if status != 0 or output is not None:
        raise ColdRestoreError(f"{label} failed with status {status}")
    return status


def _stable_identity_inventory(session, apple_user_id: int, label: str):
    outputs = []
    identities = ()
    for _ in range(2):
        status, output = state._perform(
            session, state.biometric.identity_list_fields(user_id=apple_user_id)
        )
        if status != 0 or (output is not None and not isinstance(output, bytes)):
            raise ColdRestoreError(f"{label} failed with status {status}")
        try:
            decoded = state.biometric.decode_identity_list(output or b"")
        except state.biometric.BiometricCommandError as error:
            raise ColdRestoreError(f"{label} is malformed") from error
        if any(item.user_id != apple_user_id for item in decoded):
            raise ColdRestoreError(f"{label} contains a foreign user")
        outputs.append(output)
        identities = decoded
    if outputs[0] != outputs[1]:
        raise ColdRestoreError(f"{label} is unstable")
    return identities


def _protected_config_length(session, apple_user_id: int, label: str) -> int:
    status, protected = state._perform(
        session, state.biometric.protected_config_fields(user_id=apple_user_id)
    )
    if (
        status != 0
        or not isinstance(protected, bytes)
        or len(protected) != state.biometric.PROTECTED_CONFIG_SIZE
    ):
        raise ColdRestoreError(f"{label} is invalid with status {status}")
    return len(protected)


def probe_socket(sock, *, apple_user_id: int, store_path: Path) -> ColdRestoreResult:
    validated = read_current_store(store_path, apple_user_id)
    session = state.coupled.bridge_query.BridgeSession(sock)
    state._initialize(session)

    preexisting = _stable_identity_inventory(
        session, apple_user_id, "pre-restore identity inventory"
    )
    if preexisting:
        protected_length = _protected_config_length(
            session, apple_user_id, "pre-restore protected policy"
        )
        return ColdRestoreResult(
            component_count=0,
            source_identity_nonzero=True,
            restoration_required=False,
            calibration_status=None,
            master_status=None,
            user_status=None,
            biolockout_status=None,
            protected_config_length=protected_length,
            identity_count=len(preexisting),
            identity_readback_stable=True,
            completed=True,
        )

    _perform_zero_output(session, state.biometric.cancel_fields(), "initial cancellation")
    reply = session.call([state.coupled.bridge_query.protocol.CALIBRATION_DATA_FROM_FDR])
    if (
        not isinstance(reply, list)
        or len(reply) != 1
        or not isinstance(reply[0], bytes)
        or not 0 < len(reply[0]) <= MAX_FDR_BYTES
    ):
        raise ColdRestoreError("bridgeOS returned invalid FDR calibration data")
    calibration_status = _perform_zero_output(
        session,
        state.biometric.load_fdr_calibration_fields(reply[0]),
        "FDR calibration load",
    )
    master_status = _perform_zero_output(
        session,
        state.biometric.current_catacomb_component_fields(
            user_id=-1, blob=validated.master_secure_data
        ),
        "master Catacomb load",
    )
    user_status = _perform_zero_output(
        session,
        state.biometric.current_catacomb_component_fields(
            user_id=apple_user_id, blob=validated.user_secure_data
        ),
        "selected-user Catacomb load",
    )
    biolockout_status = _perform_zero_output(
        session,
        state.biometric.load_biolockout_fields(validated.biolockout_secure_data),
        "bio-lockout load",
    )

    protected_length = _protected_config_length(
        session, apple_user_id, "restored protected policy"
    )
    identities = _stable_identity_inventory(
        session, apple_user_id, "restored identity readback"
    )
    if not identities:
        raise ColdRestoreError("restored identity readback is empty")
    return ColdRestoreResult(
        component_count=3,
        source_identity_nonzero=True,
        restoration_required=True,
        calibration_status=calibration_status,
        master_status=master_status,
        user_status=user_status,
        biolockout_status=biolockout_status,
        protected_config_length=protected_length,
        identity_count=len(identities),
        identity_readback_stable=True,
        completed=True,
    )


def live_restore(
    *,
    apple_user_id: int,
    store_path: Path,
    interface: str,
    timeout: float = 5.0,
) -> ColdRestoreResult:
    if not LIVE_COLD_RESTORE_ENABLED:
        raise ColdRestoreError("live cold restore is disabled in source")
    result = None

    def run(sock):
        nonlocal result
        result = probe_socket(
            sock, apple_user_id=apple_user_id, store_path=store_path
        )
        return result

    original = state.coupled.bridge_query.query_connected_socket
    original_gate = state.coupled.LIVE_COUPLED_QUERY_ENABLED
    try:
        state.coupled.bridge_query.query_connected_socket = run
        state.coupled.LIVE_COUPLED_QUERY_ENABLED = True
        state.coupled.live_query(interface, timeout)
    finally:
        state.coupled.bridge_query.query_connected_socket = original
        state.coupled.LIVE_COUPLED_QUERY_ENABLED = original_gate
    if result is None:
        raise ColdRestoreError("cold restore produced no result")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live", action="store_true")
    parser.add_argument(
        "--apple-user-id",
        type=int,
        default=int(os.environ.get("T2_TOUCHID_MACOS_USER_ID", "501")),
    )
    parser.add_argument(
        "--store", type=Path, default=Path("/var/lib/t2-touchid/catacomb")
    )
    parser.add_argument(
        "--interface", default=os.environ.get("T2_TOUCHID_INTERFACE", "enp4s0f1u1")
    )
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--confirm", default="")
    args = parser.parse_args()
    if args.confirm and args.confirm != CONFIRMATION:
        parser.error(f"restore requires --confirm={CONFIRMATION}")
    if not args.live:
        validated = read_current_store(args.store, args.apple_user_id)
        print(
            "current Catacomb offline validation passed: components=3 "
            f"identity_nonzero={'yes' if validated.identity_count > 0 else 'no'}"
        )
        return 0
    if os.geteuid() != 0:
        parser.error("live cold restore requires root")
    if args.confirm != CONFIRMATION:
        parser.error(f"live restore requires --confirm={CONFIRMATION}")
    global LIVE_COLD_RESTORE_ENABLED
    LIVE_COLD_RESTORE_ENABLED = True
    try:
        result = live_restore(
            apple_user_id=args.apple_user_id,
            store_path=args.store,
            interface=args.interface,
            timeout=args.timeout,
        )
    finally:
        LIVE_COLD_RESTORE_ENABLED = False
    print(
        "current Catacomb cold restore decision complete: "
        f"restoration_required={'yes' if result.restoration_required else 'no'} "
        f"components_loaded={result.component_count} "
        f"source_identity_nonzero={'yes' if result.source_identity_nonzero else 'no'} "
        f"calibration_status={result.calibration_status} "
        f"master_status={result.master_status} user_status={result.user_status} "
        f"biolockout_status={result.biolockout_status} "
        f"protected_config_length={result.protected_config_length} "
        f"identity_nonzero={'yes' if result.identity_count > 0 else 'no'} "
        f"identity_readback_stable={'yes' if result.identity_readback_stable else 'no'}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
