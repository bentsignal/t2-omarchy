#!/usr/bin/env python3
"""Correlate bounded replies for the offline read-only identity-query plan."""

from __future__ import annotations

from dataclasses import dataclass
import importlib.util
from pathlib import Path
import sys


def _load(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(
        name, Path(__file__).with_name(filename))
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


bridge = _load("read_only_result_bridge", "bridge-protocol.py")
biometric = _load("read_only_result_biometric", "biometric-command.py")

BODY_CAP = 64 * 1024


class ReadOnlyResultError(ValueError):
    pass


@dataclass(frozen=True)
class IdentitySnapshot:
    maximum_count: int
    free_count: int
    identities: tuple[biometric.BiometricIdentity, ...]


class IdentityQueryReplies:
    """Accept exactly max-count, free-count, then identity-list replies."""

    def __init__(self, *, user_id: int):
        try:
            biometric.free_identity_count_fields(user_id=user_id)
        except biometric.BiometricCommandError as error:
            raise ReadOnlyResultError("invalid expected user ID") from error
        self.user_id = user_id
        self._phase = 0
        self._maximum: int | None = None
        self._free: int | None = None
        self._snapshot: IdentitySnapshot | None = None

    def accept(self, body: bytes) -> IdentitySnapshot | None:
        if self._phase >= 3:
            raise ReadOnlyResultError("identity reply sequence is already complete")
        output_cap = (4, 4, biometric.IDENTITY.size * biometric.MAX_IDENTITIES)[
            self._phase]
        try:
            status, output = bridge.decode_perform_command_reply_body(
                body, max_body=BODY_CAP, max_output=output_cap)
        except bridge.BridgeProtocolError as error:
            raise ReadOnlyResultError("identity reply failed BridgeXPC decoding") from error
        if status != 0:
            raise ReadOnlyResultError("identity query returned a nonzero status")
        if output is None:
            raise ReadOnlyResultError("identity query returned no output data")
        try:
            if self._phase == 0:
                self._maximum = biometric.decode_identity_count(output)
            elif self._phase == 1:
                self._free = biometric.decode_identity_count(output)
                if self._maximum is None or self._free > self._maximum:
                    raise ReadOnlyResultError(
                        "free identity count exceeds the maximum")
            else:
                identities = biometric.decode_identity_list(output)
                if self._maximum is None or self._free is None:
                    raise ReadOnlyResultError("identity reply state is incomplete")
                if any(item.user_id != self.user_id for item in identities):
                    raise ReadOnlyResultError(
                        "identity list contains an unexpected user ID")
                if len(identities) > self._maximum - self._free:
                    raise ReadOnlyResultError(
                        "identity list exceeds the occupied sensor slots")
                self._snapshot = IdentitySnapshot(
                    self._maximum, self._free, identities)
        except biometric.BiometricCommandError as error:
            raise ReadOnlyResultError("identity reply payload is invalid") from error
        self._phase += 1
        return self._snapshot

    def finish(self) -> IdentitySnapshot:
        if self._phase != 3 or self._snapshot is None:
            raise ReadOnlyResultError("identity reply sequence is incomplete")
        return self._snapshot
