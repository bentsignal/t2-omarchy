#!/usr/bin/env python3
"""Fail-closed offline authorization from a correlated Touch ID match event."""

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


biometric = _load("authentication_result_biometric", "biometric-command.py")


class AuthenticationResultError(ValueError):
    pass


@dataclass(frozen=True)
class AuthenticationDecision:
    matched: bool
    identity: biometric.BiometricIdentity | None


class MatchAuthentication:
    """Authorize one match operation against a prior trusted identity snapshot.

    Construction arms exactly one operation. Only Catalina's correlated
    terminal match event can complete it. A non-``UINT32_MAX`` result must
    exactly match a separately enumerated identity for the expected Unix user;
    an unknown identity is an error, never a successful new principal.
    """

    def __init__(self, *, expected_user_id: int,
                 trusted_identities: tuple[biometric.BiometricIdentity, ...]):
        try:
            biometric.encode_ordinary_match_payload(user_id=expected_user_id)
        except biometric.BiometricCommandError as error:
            raise AuthenticationResultError("expected user ID is invalid") from error
        if not isinstance(trusted_identities, tuple) or not trusted_identities:
            raise AuthenticationResultError("trusted identity snapshot is empty or invalid")
        if any(not isinstance(item, biometric.BiometricIdentity)
               for item in trusted_identities):
            raise AuthenticationResultError("trusted identity snapshot has an invalid record")
        if len(set(trusted_identities)) != len(trusted_identities):
            raise AuthenticationResultError("trusted identity snapshot has duplicates")
        for item in trusted_identities:
            if item.user_id != expected_user_id:
                raise AuthenticationResultError(
                    "trusted identity belongs to a different user")
            if not isinstance(item.uuid, bytes) or len(item.uuid) != 16:
                raise AuthenticationResultError("trusted identity UUID is invalid")
        self.expected_user_id = expected_user_id
        self.trusted_identities = frozenset(trusted_identities)
        self._decision: AuthenticationDecision | None = None
        self._failed = False

    def accept_terminal(self, *, status: int, version: int,
                        data: bytes) -> AuthenticationDecision:
        if self._decision is not None:
            raise AuthenticationResultError("match operation is already complete")
        if self._failed:
            raise AuthenticationResultError("match operation has failed")
        try:
            result = biometric.decode_terminal_biometric_event(
                active_operation="match", status=status, version=version,
                data=data)
        except biometric.BiometricCommandError as error:
            self._failed = True
            raise AuthenticationResultError("terminal match event is invalid") from error
        if not isinstance(result, biometric.CatalinaMatchIdentity):
            self._failed = True
            raise AuthenticationResultError("terminal event is not a match result")
        if result.user_id == biometric.DEFAULT_USER_ID:
            self._decision = AuthenticationDecision(False, None)
            return self._decision
        identity = biometric.BiometricIdentity(result.user_id, result.uuid)
        if result.user_id != self.expected_user_id:
            self._failed = True
            raise AuthenticationResultError("matched identity belongs to a different user")
        if identity not in self.trusted_identities:
            self._failed = True
            raise AuthenticationResultError("matched identity is not in the trusted snapshot")
        self._decision = AuthenticationDecision(True, identity)
        return self._decision

    def abort(self) -> None:
        """Permanently fail an operation after timeout, cancellation, or I/O loss."""
        if self._decision is not None:
            raise AuthenticationResultError("match operation is already complete")
        if self._failed:
            raise AuthenticationResultError("match operation has failed")
        self._failed = True

    def finish(self) -> AuthenticationDecision:
        if self._failed:
            raise AuthenticationResultError("match operation has failed")
        if self._decision is None:
            raise AuthenticationResultError("match operation has no terminal result")
        return self._decision
