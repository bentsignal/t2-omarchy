#!/usr/bin/env python3
"""Offline composition of dual OOL ownership and credential authorization.

There is deliberately no device, DMA allocator, password prompt, or live-send
path here.  The coordinator makes transport readiness and operation lifetime
prerequisites of the already strict ACM/AKS authorization model.
"""

from __future__ import annotations

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


bootstrap = _load("credential_session_bootstrap", "credential-services-bootstrap.py")
authorization = _load("credential_session_authorization", "credential-authorization.py")


class CredentialSessionError(RuntimeError):
    pass


class CredentialSession:
    """Own one dual-endpoint transport and one authorization lifecycle."""

    def __init__(self) -> None:
        self.bootstrap = bootstrap.DualCredentialBootstrap()
        self._authorization = authorization.CredentialAuthorizationPlan()
        self._pending: tuple[str, str] | None = None
        self._context_live = False
        self.closed = False

    def __repr__(self) -> str:
        return ("CredentialSession("
                f"ready={self.bootstrap.ready}, pending={self._pending is not None}, "
                f"authorized={self._authorization.authorized}, "
                f"failed={self._authorization.failed}, closed={self.closed})")

    @property
    def authorized(self) -> bool:
        return self._authorization.authorized

    @property
    def failed(self) -> bool:
        return self._authorization.failed

    def registration_requests(self, *addresses: int, first_tag: int = 2):
        if self.closed:
            raise CredentialSessionError("credential session is closed")
        try:
            return self.bootstrap.registration_requests(
                *addresses, first_tag=first_tag)
        except bootstrap.CredentialBootstrapError as error:
            raise CredentialSessionError("credential registration was rejected") from error

    def accept_registration_replies(self, *replies: list[int]) -> None:
        if self.closed:
            raise CredentialSessionError("credential session is closed")
        try:
            self.bootstrap.accept_registration_replies(*replies)
        except bootstrap.CredentialBootstrapError as error:
            raise CredentialSessionError("credential registration failed") from error

    def _begin(self, service: str, phase: str) -> None:
        if self.closed or not self.bootstrap.ready or self._pending is not None:
            raise CredentialSessionError("credential transport is unavailable")
        owner = getattr(self.bootstrap, service).ownership
        try:
            owner.begin_operation()
        except bootstrap.lifecycle.LifecycleError as error:
            raise CredentialSessionError("credential operation could not begin") from error
        self._pending = (service, phase)

    def _require_available(self) -> None:
        if self.closed or not self.bootstrap.ready or self._pending is not None:
            raise CredentialSessionError("credential transport is unavailable")

    def _finish(self, service: str, phase: str) -> None:
        if self._pending != (service, phase):
            raise CredentialSessionError("credential reply is out of order")
        owner = getattr(self.bootstrap, service).ownership
        try:
            owner.end_operation()
        except bootstrap.lifecycle.LifecycleError as error:
            raise CredentialSessionError("credential operation could not finish") from error
        self._pending = None

    def initialize_acm(self):
        self._require_available()
        request = self._authorization.initialize_acm()
        self._begin("acm", "initialize")
        return request

    def accept_acm_initialization(self, envelope: bytes, payload: bytes) -> None:
        self._finish("acm", "initialize")
        self._authorization.accept_acm_initialization(envelope, payload)

    def create_context(self):
        self._require_available()
        request = self._authorization.create_context()
        self._begin("acm", "create")
        return request

    def accept_context(self, envelope: bytes, payload: bytearray) -> None:
        self._finish("acm", "create")
        self._authorization.accept_context(envelope, payload)
        self._context_live = True

    def request_aks_capabilities(self, tag: int) -> bytes:
        self._require_available()
        request = self._authorization.request_aks_capabilities(tag)
        self._begin("aks", "capabilities")
        return request

    def accept_aks_capabilities(self, envelope: bytes, payload: bytes) -> int:
        self._finish("aks", "capabilities")
        return self._authorization.accept_aks_capabilities(envelope, payload)

    def request_aks_environment(self, tag: int) -> bytes:
        self._require_available()
        request = self._authorization.request_aks_environment(tag)
        self._begin("aks", "environment")
        return request

    def accept_aks_environment(self, envelope: bytes, payload: bytes) -> None:
        self._finish("aks", "environment")
        self._authorization.accept_aks_environment(envelope, payload)

    def plan_verification(self, *args, **kwargs) -> bytes:
        self._require_available()
        return self._authorization.plan_verification(*args, **kwargs)

    def consume_verification_secrets(self, *args, **kwargs):
        self._require_available()
        request = self._authorization.consume_verification_secrets(*args, **kwargs)
        try:
            self._begin("aks", "verify")
        except CredentialSessionError:
            request.close()
            self._authorization.abort()
            raise
        return request

    def accept_verification(self, envelope: bytes, payload: bytes):
        self._finish("aks", "verify")
        return self._authorization.accept_verification(envelope, payload)

    def prepare_context_delete(self):
        self._require_available()
        request = self._authorization.prepare_context_delete()
        self._begin("acm", "delete")
        return request

    def accept_context_delete(self, envelope: bytes, payload: bytes) -> None:
        self._finish("acm", "delete")
        self._authorization.accept_context_delete(envelope, payload)
        self._context_live = False

    def shutdown(self) -> tuple[str, ...]:
        """Stop both endpoints, then scrub local state; never while active."""
        if self.closed:
            raise CredentialSessionError("credential session is closed")
        if self._pending is not None:
            raise CredentialSessionError("credential operation is still active")
        if self._context_live:
            raise CredentialSessionError(
                "live SEP context must be deleted before normal shutdown")
        try:
            tokens = self.bootstrap.stop_and_release()
        except bootstrap.CredentialBootstrapError as error:
            raise CredentialSessionError("credential transport shutdown failed") from error
        self._authorization.scrub_after_transport_stop()
        self.closed = True
        return tokens

    def abort_and_shutdown(self) -> tuple[str, ...]:
        """Stop both endpoints before locally scrubbing an undeleted context."""
        if self.closed:
            raise CredentialSessionError("credential session is closed")
        if self._pending is not None:
            raise CredentialSessionError("active operation has not drained")
        try:
            tokens = self.bootstrap.stop_and_release()
        except bootstrap.CredentialBootstrapError as error:
            raise CredentialSessionError("credential transport shutdown failed") from error
        self._authorization.scrub_after_transport_stop()
        self.closed = True
        self._context_live = False
        return tokens
