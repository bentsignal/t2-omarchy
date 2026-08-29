#!/usr/bin/env python3
"""Socket-free protocol/state model for a future root-owned Touch ID broker.

This module does not create sockets, inspect PAM, access hardware, or grant an
authentication.  It defines the narrow boundary through which a root PAM
helper could request one fresh match from a long-lived hardware-owning daemon.
"""

from __future__ import annotations

from dataclasses import dataclass
import importlib.util
from pathlib import Path
import struct
import sys


def _load(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(
        name, Path(__file__).with_name(filename))
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


authentication = _load("linux_auth_broker_result", "authentication-result.py")

MAGIC = b"T2AU"
VERSION = 1
OP_VERIFY = 1
REPLY_BIT = 0x80
REQUEST = struct.Struct("<4sBBHQII")
RESPONSE = struct.Struct("<4sBBHQiI")
STATUS_MATCH = 0
STATUS_NO_MATCH = 1
STATUS_ERROR = -1
MAX_TIMEOUT_MS = 60_000
UINT32_MAX = 0xFFFFFFFF


class BrokerProtocolError(ValueError):
    pass


@dataclass(frozen=True)
class PeerCredentials:
    pid: int
    uid: int
    gid: int


@dataclass(frozen=True)
class VerifyRequest:
    request_id: int
    user_id: int
    timeout_ms: int


@dataclass(frozen=True)
class VerifyResponse:
    request_id: int
    status: int

    @property
    def authenticated(self) -> bool:
        return self.status == STATUS_MATCH


def _u64(value: int, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < 1 << 64:
        raise BrokerProtocolError(f"{field} is not an unsigned 64-bit integer")
    return value


def encode_verify_request(*, request_id: int, user_id: int,
                          timeout_ms: int) -> bytes:
    request_id = _u64(request_id, "request ID")
    if not request_id:
        raise BrokerProtocolError("request ID must be nonzero")
    if (isinstance(user_id, bool) or not isinstance(user_id, int)
            or not 0 <= user_id < UINT32_MAX):
        raise BrokerProtocolError("target user ID is invalid")
    if (isinstance(timeout_ms, bool) or not isinstance(timeout_ms, int)
            or not 1 <= timeout_ms <= MAX_TIMEOUT_MS):
        raise BrokerProtocolError("timeout is outside the bounded range")
    return REQUEST.pack(MAGIC, VERSION, OP_VERIFY, 0, request_id,
                        user_id, timeout_ms)


def decode_verify_request(raw: bytes) -> VerifyRequest:
    if not isinstance(raw, bytes) or len(raw) != REQUEST.size:
        raise BrokerProtocolError("verify request has the wrong size")
    magic, version, opcode, reserved, request_id, user_id, timeout_ms = REQUEST.unpack(raw)
    if magic != MAGIC or version != VERSION or opcode != OP_VERIFY or reserved:
        raise BrokerProtocolError("verify request header is invalid")
    # Reuse the encoder as the canonical scalar validator.
    encode_verify_request(request_id=request_id, user_id=user_id,
                          timeout_ms=timeout_ms)
    return VerifyRequest(request_id, user_id, timeout_ms)


def encode_verify_response(*, request_id: int, status: int) -> bytes:
    request_id = _u64(request_id, "request ID")
    if not request_id:
        raise BrokerProtocolError("request ID must be nonzero")
    if status not in (STATUS_MATCH, STATUS_NO_MATCH, STATUS_ERROR):
        raise BrokerProtocolError("broker status is unsupported")
    return RESPONSE.pack(MAGIC, VERSION, OP_VERIFY | REPLY_BIT, 0,
                         request_id, status, 0)


def decode_verify_response(raw: bytes, *, expected_request_id: int) -> VerifyResponse:
    expected_request_id = _u64(expected_request_id, "expected request ID")
    if not isinstance(raw, bytes) or len(raw) != RESPONSE.size:
        raise BrokerProtocolError("verify response has the wrong size")
    magic, version, opcode, flags, request_id, status, reserved = RESPONSE.unpack(raw)
    if (magic != MAGIC or version != VERSION or
            opcode != OP_VERIFY | REPLY_BIT or flags or reserved):
        raise BrokerProtocolError("verify response header is invalid")
    if request_id != expected_request_id or not request_id:
        raise BrokerProtocolError("verify response correlation failed")
    if status not in (STATUS_MATCH, STATUS_NO_MATCH, STATUS_ERROR):
        raise BrokerProtocolError("verify response status is unsupported")
    return VerifyResponse(request_id, status)


class BrokerAuthorization:
    """Bind one root peer, target UID, deadline, and trusted match decision."""

    def __init__(self) -> None:
        self._request: VerifyRequest | None = None
        self._deadline_ns: int | None = None
        self._complete = False
        self._failed = False

    def begin(self, raw: bytes, *, peer: PeerCredentials,
              now_ns: int) -> VerifyRequest:
        if self._request is not None or self._complete or self._failed:
            raise BrokerProtocolError("broker authorization is not reusable")
        if (not isinstance(peer, PeerCredentials) or
                any(isinstance(value, bool) or not isinstance(value, int)
                    for value in (peer.pid, peer.uid, peer.gid)) or
                peer.pid <= 0 or peer.uid != 0 or peer.gid < 0):
            self._failed = True
            raise BrokerProtocolError("only a kernel-authenticated root peer is accepted")
        now_ns = _u64(now_ns, "monotonic time")
        try:
            request = decode_verify_request(raw)
        except BrokerProtocolError:
            self._failed = True
            raise
        deadline = now_ns + request.timeout_ms * 1_000_000
        if deadline >= 1 << 64:
            self._failed = True
            raise BrokerProtocolError("authorization deadline would overflow")
        self._request = request
        self._deadline_ns = deadline
        return request

    def complete(self, *, request_id: int,
                 decision: authentication.AuthenticationDecision,
                 now_ns: int) -> bytes:
        if self._request is None or self._deadline_ns is None:
            raise BrokerProtocolError("broker authorization was not started")
        if self._complete or self._failed:
            raise BrokerProtocolError("broker authorization cannot complete")
        now_ns = _u64(now_ns, "monotonic time")
        if request_id != self._request.request_id:
            self._failed = True
            raise BrokerProtocolError("match decision correlation failed")
        if now_ns > self._deadline_ns:
            self._failed = True
            raise BrokerProtocolError("match decision arrived after its deadline")
        if not isinstance(decision, authentication.AuthenticationDecision):
            self._failed = True
            raise BrokerProtocolError("untrusted match decision type")
        if decision.matched:
            if (not isinstance(
                    decision.identity,
                    authentication.biometric.BiometricIdentity) or
                    decision.identity.user_id != self._request.user_id or
                    not isinstance(decision.identity.uuid, bytes) or
                    len(decision.identity.uuid) != 16):
                self._failed = True
                raise BrokerProtocolError("match decision targets another user")
            status = STATUS_MATCH
        else:
            if decision.identity is not None:
                self._failed = True
                raise BrokerProtocolError("no-match decision unexpectedly has an identity")
            status = STATUS_NO_MATCH
        self._complete = True
        return encode_verify_response(request_id=request_id, status=status)

    def abort(self) -> bytes:
        if self._request is None or self._complete or self._failed:
            raise BrokerProtocolError("broker authorization cannot be aborted")
        self._failed = True
        return encode_verify_response(
            request_id=self._request.request_id, status=STATUS_ERROR)
