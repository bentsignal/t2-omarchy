#!/usr/bin/env python3
"""One-connection Unix seqpacket boundary for the T2 auth broker.

This module deliberately does not bind a pathname, daemonize, enable PAM, or
open biometric hardware.  A future root service supplies one fresh trusted
match callback and owns the listening socket lifecycle.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
import socket
import struct
import sys
import time
from typing import Callable


def _load():
    path = Path(__file__).with_name("linux-auth-broker.py")
    spec = importlib.util.spec_from_file_location("broker_server_protocol", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


broker = _load()
UCRED = struct.Struct("3i")


class BrokerServerError(RuntimeError):
    pass


def _peer_credentials(connection) -> broker.PeerCredentials:
    try:
        raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                                    UCRED.size)
    except OSError as error:
        raise BrokerServerError("kernel peer credentials are unavailable") from error
    if not isinstance(raw, bytes) or len(raw) != UCRED.size:
        raise BrokerServerError("kernel peer credentials have the wrong size")
    return broker.PeerCredentials(*UCRED.unpack(raw))


def serve_connection(
        connection,
        matcher: Callable[[broker.VerifyRequest],
                          broker.authentication.AuthenticationDecision],
        *, now_ns: Callable[[], int] = time.monotonic_ns) -> int:
    """Serve exactly one datagram and return the emitted broker status."""
    if not callable(matcher) or not callable(now_ns):
        raise BrokerServerError("broker callbacks are invalid")
    operation = broker.BrokerAuthorization()
    request = None
    try:
        raw, _ancillary, flags, _address = connection.recvmsg(
            broker.REQUEST.size, 0, socket.MSG_TRUNC)
        if flags & socket.MSG_TRUNC or len(raw) != broker.REQUEST.size:
            raise BrokerServerError("broker request was truncated or oversized")
        request = operation.begin(
            raw, peer=_peer_credentials(connection), now_ns=now_ns())
        connection.settimeout(request.timeout_ms / 1000)
        decision = matcher(request)
        response = operation.complete(
            request_id=request.request_id, decision=decision, now_ns=now_ns())
        status = broker.decode_verify_response(
            response, expected_request_id=request.request_id).status
    except Exception as error:
        # A correlated error is possible only after a valid request was begun.
        if request is None:
            if isinstance(error, BrokerServerError):
                raise
            raise BrokerServerError("broker request failed before correlation") from error
        # complete() deliberately poisons its state on a bad or late matcher
        # decision.  The request ID was already authenticated and decoded, so
        # emit a fail-closed correlated reply without trying to reuse that
        # terminal authorization object.
        response = broker.encode_verify_response(
            request_id=request.request_id, status=broker.STATUS_ERROR)
        status = broker.STATUS_ERROR
    try:
        connection.sendall(response)
    except OSError as error:
        raise BrokerServerError("broker response could not be sent") from error
    return status
