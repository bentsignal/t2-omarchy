#!/usr/bin/env python3
"""Offline OOL bootstrap for the fixed Intel T2 ACM and AKS endpoints."""

from __future__ import annotations

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


control = _load("credential_services_control", "decode-message.py")
lifecycle = _load("credential_services_lifecycle", "endpoint-lifecycle.py")

OOL_SIZE = 0x4000


class CredentialBootstrapError(ValueError):
    pass


@dataclass(frozen=True)
class ServiceProfile:
    name: str
    endpoint: int


ACM = ServiceProfile("acm", 0x0A)
AKS = ServiceProfile("aks", 0x07)


@dataclass(frozen=True)
class ReplyProfile:
    send_opcode: int
    send_target: int
    receive_opcode: int
    receive_target: int


# Observed on the MacBookPro16,1 T2 in separate supervised runs on 2026-08-28
# and accepted by verify-credential-ool-log.py from cursor-bounded transcripts.
AKS_REPLY_PROFILE = ReplyProfile(1, AKS.endpoint, 1, AKS.endpoint)
ACM_REPLY_PROFILE = ReplyProfile(1, ACM.endpoint, 1, ACM.endpoint)


class CredentialServiceBootstrap:
    """Plan registration and ownership without allocating or touching DMA."""

    def __init__(self, profile: ServiceProfile) -> None:
        if profile not in (ACM, AKS):
            raise CredentialBootstrapError("unsupported fixed credential service")
        self.profile = profile
        self.ownership = lifecycle.EndpointLifecycle(profile.endpoint)
        self.ownership.enable()
        self._requests: dict[str, list[int]] = {}

    def registration_requests(self, send_dma: int, receive_dma: int,
                              *, send_tag: int, receive_tag: int
                              ) -> tuple[list[int], list[int]]:
        if self._requests:
            raise CredentialBootstrapError("registration requests were already prepared")
        if send_tag == receive_tag:
            raise CredentialBootstrapError("registration tags must be distinct")
        try:
            send = control.tag_control_request(control.encode_ool_registration(
                self.profile.endpoint, send_dma, OOL_SIZE,
                incoming_to_sep=True), send_tag)
            receive = control.tag_control_request(control.encode_ool_registration(
                self.profile.endpoint, receive_dma, OOL_SIZE,
                incoming_to_sep=False), receive_tag)
        except control.ControlMessageError as error:
            raise CredentialBootstrapError(str(error)) from error
        self._requests = {"send": send, "receive": receive}
        return list(send), list(receive)

    def accept_registration_replies(self, send_reply: list[int],
                                    receive_reply: list[int],
                                    profile: ReplyProfile) -> None:
        if set(self._requests) != {"send", "receive"}:
            raise CredentialBootstrapError("registration requests are incomplete")
        if not isinstance(profile, ReplyProfile):
            raise CredentialBootstrapError("independently observed reply profile required")
        try:
            control.validate_control_reply(
                self._requests["send"], send_reply,
                expected_opcode=profile.send_opcode,
                expected_target=profile.send_target)
            control.validate_control_reply(
                self._requests["receive"], receive_reply,
                expected_opcode=profile.receive_opcode,
                expected_target=profile.receive_target)
            self.ownership.commit_registration(
                "send", f"{self.profile.name}-send", control_succeeded=True)
            self.ownership.commit_registration(
                "receive", f"{self.profile.name}-receive", control_succeeded=True)
        except (control.ControlMessageError, lifecycle.LifecycleError) as error:
            raise CredentialBootstrapError(str(error)) from error

    @property
    def ready(self) -> bool:
        return self.ownership.ready

    def stop_and_release(self) -> tuple[str, ...]:
        try:
            self.ownership.stop_transport()
            tokens = tuple(sorted(mapping.identifier
                                  for mapping in self.ownership.mappings))
            for token in tokens:
                self.ownership.scrub(token)
                self.ownership.release(token)
            return tokens
        except lifecycle.LifecycleError as error:
            raise CredentialBootstrapError(str(error)) from error
