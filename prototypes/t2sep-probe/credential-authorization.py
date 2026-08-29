#!/usr/bin/env python3
"""Offline composition of one fail-closed ACM/AKS authorization lifecycle.

This module has no device, socket, PAM, or password-prompt API.  It only joins
the independently recovered codecs and keeps teardown possible after failure.
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


acm = _load("credential_authorization_acm", "acm-transport.py")
aks = _load("credential_authorization_aks", "aks-transport.py")
biometric = _load("credential_authorization_biometric", "biometric-command.py")


class CredentialAuthorizationError(RuntimeError):
    pass


class CredentialAuthorizationPlan:
    """Own one ephemeral context from creation through mandatory teardown."""

    def __init__(self) -> None:
        self.acm = acm.CurrentContextCreatePlan()
        self.aks = aks.AuthorizationPlan()
        self._context_response: bytearray | None = None
        self._verify_request: aks.VerifySecretRequest | None = None
        self._enrollment_request: biometric.AuthorizedEnrollRequest | None = None
        self._delete_command: bytearray | None = None
        self.authorized = False
        self.failed = False
        self.closed = False

    def __repr__(self) -> str:
        return ("CredentialAuthorizationPlan("
                f"context_created={self._context_response is not None}, "
                f"authorized={self.authorized}, failed={self.failed}, "
                f"closed={self.closed})")

    def __del__(self) -> None:
        # Local best-effort fallback; it cannot replace SEP delete/CPU stop.
        if not getattr(self, "closed", True):
            self._scrub_and_close()

    def _active(self) -> None:
        if self.closed:
            raise CredentialAuthorizationError("authorization lifecycle is closed")
        if self.failed:
            raise CredentialAuthorizationError(
                "authorization lifecycle failed; only teardown is allowed")

    def _fail(self, error: Exception) -> None:
        self.failed = True
        if self._verify_request is not None:
            self._verify_request.close()
        if self._enrollment_request is not None:
            self._enrollment_request.close()
        raise CredentialAuthorizationError("authorization lifecycle rejected input") from error

    def initialize_acm(self) -> tuple[bytes, bytes]:
        self._active()
        try:
            return self.acm.initialize()
        except acm.ACMTransportError as error:
            self._fail(error)

    def accept_acm_initialization(self, envelope: bytes, payload: bytes) -> None:
        self._active()
        try:
            self.acm.accept_initialization_reply(envelope, payload)
        except acm.ACMTransportError as error:
            self._fail(error)

    def create_context(self) -> tuple[bytes, bytes]:
        self._active()
        try:
            return self.acm.context_request()
        except acm.ACMTransportError as error:
            self._fail(error)

    def accept_context(self, envelope: bytes, payload: bytearray) -> None:
        self._active()
        if self._context_response is not None:
            if isinstance(payload, bytearray):
                payload[:] = bytes(len(payload))
            self._fail(CredentialAuthorizationError("context ownership duplicated"))
        try:
            if not self.acm.accept_context_response(envelope, payload):
                raise acm.ACMTransportError(
                    "live authorization requires the verified current context ABI")
        except acm.ACMTransportError as error:
            if isinstance(payload, bytearray):
                payload[:] = bytes(len(payload))
            self._fail(error)
        self._context_response = payload

    def request_aks_capabilities(self, tag: int) -> bytes:
        self._active()
        try:
            return self.aks.request_capabilities(tag)
        except aks.AKSTransportError as error:
            self._fail(error)

    def accept_aks_capabilities(self, envelope: bytes, payload: bytes) -> int:
        self._active()
        try:
            return self.aks.accept_capabilities_transport(envelope, payload)
        except aks.AKSTransportError as error:
            self._fail(error)

    def request_aks_environment(self, tag: int) -> bytes:
        self._active()
        try:
            return self.aks.request_startup_environment(tag)
        except aks.AKSTransportError as error:
            self._fail(error)

    def accept_aks_environment(self, envelope: bytes, payload: bytes) -> None:
        self._active()
        try:
            self.aks.accept_startup_environment(envelope, payload)
        except aks.AKSTransportError as error:
            self._fail(error)

    def plan_verification(self, tag: int, password_length: int, *,
                          keybag_handle: aks.SessionKeybagHandle,
                          selector: aks.SessionKeybagSelector) -> bytes:
        self._active()
        if self._context_response is None:
            self._fail(CredentialAuthorizationError("no ACM context exists"))
        try:
            return self.aks.plan_verify_secret(
                tag, password_length, keybag_handle=keybag_handle,
                selector=selector)
        except aks.AKSTransportError as error:
            self._fail(error)

    def consume_verification_secrets(
            self, identity_header: bytes, password: bytearray, *,
            device_state_active: bool) -> aks.VerifySecretRequest:
        self._active()
        if self._context_response is None or self._verify_request is not None:
            self._fail(CredentialAuthorizationError(
                "verification secret ownership is out of order"))
        context_copy = acm.context_external_form_for_authorization(
            self._context_response)
        try:
            request = self.aks.consume_verify_secret_payload(
                identity_header, password, context_copy,
                device_state_active=device_state_active)
        except aks.AKSTransportError as error:
            context_copy[:] = bytes(len(context_copy))
            self._fail(error)
        context_copy[:] = bytes(len(context_copy))
        self._verify_request = request
        return request

    def accept_verification(self, envelope: bytes,
                            payload: bytes) -> aks.VerifySecretReply:
        self._active()
        if self._verify_request is None:
            self._fail(CredentialAuthorizationError(
                "no owned verification request exists"))
        self._verify_request.close()
        try:
            reply = self.aks.accept_verify_secret_success(envelope, payload)
        except aks.AKSTransportError as error:
            self._fail(error)
        self.authorized = True
        return reply

    def build_builtin_enrollment_request(
            self, user_id: int) -> biometric.AuthorizedEnrollRequest:
        """Copy the authorized context directly into a scrub-owned request."""
        self._active()
        if not self.authorized or self._context_response is None:
            self._fail(CredentialAuthorizationError(
                "ACM context is not authorized for enrollment"))
        if self._enrollment_request is not None:
            self._fail(CredentialAuthorizationError(
                "enrollment credential ownership is duplicated"))
        context_copy = acm.context_external_form_for_authorization(
            self._context_response)
        try:
            request = biometric.consume_builtin_enrollment_credential(
                user_id=user_id, credential_set=context_copy)
        except biometric.BiometricCommandError as error:
            context_copy[:] = bytes(len(context_copy))
            self._fail(error)
        self._enrollment_request = request
        return request

    def finish_builtin_enrollment_request(
            self, request: biometric.AuthorizedEnrollRequest) -> None:
        self._active()
        if request is not self._enrollment_request:
            raise CredentialAuthorizationError(
                "enrollment credential is not owned by this lifecycle")
        request.close()
        self._enrollment_request = None

    def abort(self) -> None:
        """Fail authorization while preserving enough context for deletion."""
        if self.closed:
            raise CredentialAuthorizationError("authorization lifecycle is closed")
        self.failed = True
        if self._verify_request is not None:
            self._verify_request.close()
        if self._enrollment_request is not None:
            self._enrollment_request.close()

    def prepare_context_delete(self) -> tuple[bytes, memoryview]:
        """Build deletion even after failure; caller must attempt the exchange."""
        if self.closed or self._context_response is None:
            raise CredentialAuthorizationError("no live context can be deleted")
        if self._delete_command is not None:
            raise CredentialAuthorizationError("context deletion is already prepared")
        if not self.authorized:
            self.failed = True
            if self._verify_request is not None:
                self._verify_request.close()
        if self._enrollment_request is not None:
            self._enrollment_request.close()
            self._enrollment_request = None
        command = bytearray(acm.CONTEXT_DELETE_COMMAND_SIZE)
        try:
            envelope = self.acm.delete_request(self._context_response, command)
        except acm.ACMTransportError as error:
            command[:] = bytes(len(command))
            self.failed = True
            raise CredentialAuthorizationError("context deletion could not be built") from error
        self._delete_command = command
        return envelope, memoryview(command)

    def accept_context_delete(self, envelope: bytes, payload: bytes) -> None:
        if self.closed or self._context_response is None or self._delete_command is None:
            raise CredentialAuthorizationError("context deletion reply is out of order")
        try:
            self.acm.accept_delete_response(envelope, payload)
        except acm.ACMTransportError as error:
            self.failed = True
            raise CredentialAuthorizationError("context deletion failed") from error
        self._scrub_and_close()

    def scrub_after_transport_stop(self) -> None:
        """Close locally only after the caller has stopped the SEP transport."""
        if self.closed:
            return
        self.failed = True
        self._scrub_and_close()

    def _scrub_and_close(self) -> None:
        if self._verify_request is not None:
            self._verify_request.close()
        if self._enrollment_request is not None:
            self._enrollment_request.close()
        if self._context_response is not None:
            self._context_response[:] = bytes(len(self._context_response))
        if self._delete_command is not None:
            self._delete_command[:] = bytes(len(self._delete_command))
        self.closed = True
