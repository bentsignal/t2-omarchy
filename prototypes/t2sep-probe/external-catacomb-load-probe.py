#!/usr/bin/env python3
"""One-shot load of decoded current-macOS CatacombSecureData; reports no data."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import importlib.util
from pathlib import Path
import sys


def _load(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


state = _load("external_catacomb_state", "user-state-probe.py")
CONFIRMATION = "I_UNDERSTAND_THIS_LOADS_ONE_LOCAL_MACOS_CATACOMB"
LIVE_LOAD_ENABLED = False


class ExternalCatacombLoadError(RuntimeError):
    pass


@dataclass(frozen=True)
class ExternalCatacombLoadResult:
    load_status: int
    protected_length: int
    identity_count: int


def read_secure_data(path: Path) -> bytes:
    if not isinstance(path, Path) or not path.is_absolute():
        raise ExternalCatacombLoadError("secure-data path must be absolute")
    metadata = path.stat()
    if metadata.st_mode & 0o077:
        raise ExternalCatacombLoadError("secure-data permissions are too broad")
    if not 0 < metadata.st_size <= state.biometric.MAX_CATACOMB_BLOB_SIZE:
        raise ExternalCatacombLoadError("secure-data file is outside safe bounds")
    data = path.read_bytes()
    if len(data) != metadata.st_size:
        raise ExternalCatacombLoadError("secure-data file changed while reading")
    return data


def probe_socket(sock, *, user_id: int, secure_data: bytes) -> ExternalCatacombLoadResult:
    session = state.coupled.bridge_query.BridgeSession(sock)
    state._initialize(session)
    load_status, output = state._perform(
        session, state.biometric.current_catacomb_secure_data_fields(secure_data))
    if load_status != 0 or output is not None:
        raise ExternalCatacombLoadError(f"catacomb load failed with status {load_status}")
    protected_status, protected = state._perform(
        session, state.biometric.protected_config_fields(user_id=user_id))
    if protected_status != 0 or not isinstance(protected, bytes) or len(protected) != 32:
        raise ExternalCatacombLoadError(
            f"protected policy did not load with status {protected_status}")
    identity_status, identities = state._perform(
        session, state.biometric.identity_list_fields(user_id=user_id))
    if identity_status != 0:
        raise ExternalCatacombLoadError(f"identity readback failed with status {identity_status}")
    decoded = state.biometric.decode_identity_list(identities or b"")
    if any(identity.user_id != user_id for identity in decoded):
        raise ExternalCatacombLoadError("loaded catacomb returned a foreign user identity")
    return ExternalCatacombLoadResult(load_status, len(protected), len(decoded))


def live_probe(*, user_id: int, path: Path, interface: str = "enp4s0f1u1",
               timeout: float = 5.0) -> ExternalCatacombLoadResult:
    if not LIVE_LOAD_ENABLED:
        raise ExternalCatacombLoadError("live external catacomb load is disabled")
    secure_data = read_secure_data(path)
    result = None

    def run(sock):
        nonlocal result
        result = probe_socket(sock, user_id=user_id, secure_data=secure_data)
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
        raise ExternalCatacombLoadError("external catacomb load produced no result")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live", action="store_true")
    parser.add_argument("--user-id", type=int, required=True)
    parser.add_argument("--path", type=Path, required=True)
    parser.add_argument("--interface", default="enp4s0f1u1")
    parser.add_argument("--confirm", default="")
    args = parser.parse_args()
    if not args.live:
        print("offline only: one-shot current-macOS secure-data load plan")
        return
    if args.confirm != CONFIRMATION:
        parser.error(f"live load requires --confirm={CONFIRMATION}")
    global LIVE_LOAD_ENABLED
    LIVE_LOAD_ENABLED = True
    try:
        result = live_probe(user_id=args.user_id, path=args.path,
                            interface=args.interface)
    finally:
        LIVE_LOAD_ENABLED = False
    print("external catacomb loaded: "
          f"status={result.load_status} protected_length={result.protected_length} "
          f"identity_count={result.identity_count}")


if __name__ == "__main__":
    main()
