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
        self.validate_registration_replies(send_reply, receive_reply, profile)
        try:
            self.ownership.commit_registration(
                "send", f"{self.profile.name}-send", control_succeeded=True)
            self.ownership.commit_registration(
                "receive", f"{self.profile.name}-receive", control_succeeded=True)
        except lifecycle.LifecycleError as error:
            raise CredentialBootstrapError(str(error)) from error

    def validate_registration_replies(self, send_reply: list[int],
                                      receive_reply: list[int],
                                      profile: ReplyProfile) -> None:
        """Validate both acknowledgements without changing mapping ownership."""
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
        except control.ControlMessageError as error:
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


class DualCredentialBootstrap:
    """Atomically plan both fixed services under one SEP transport lifetime."""

    def __init__(self) -> None:
        self.aks = CredentialServiceBootstrap(AKS)
        self.acm = CredentialServiceBootstrap(ACM)
        self._requests: tuple[list[int], ...] | None = None

    @staticmethod
    def _validate_mappings(addresses: tuple[int, int, int, int]) -> None:
        if any(isinstance(value, bool) or not isinstance(value, int)
               for value in addresses):
            raise CredentialBootstrapError("DMA addresses must be integers")
        ranges = sorted((address, address + OOL_SIZE) for address in addresses)
        if any(start < 0 or end > (1 << 44) for start, end in ranges):
            # 32-bit page-frame field covers byte addresses through 2**44 - 1.
            raise CredentialBootstrapError("DMA mapping exceeds the control field")
        if any(ranges[index][1] > ranges[index + 1][0]
               for index in range(len(ranges) - 1)):
            raise CredentialBootstrapError("credential DMA mappings overlap")

    def registration_requests(
            self, aks_send_dma: int, aks_receive_dma: int,
            acm_send_dma: int, acm_receive_dma: int, *,
            first_tag: int = 2) -> tuple[list[int], list[int], list[int], list[int]]:
        if self._requests is not None:
            raise CredentialBootstrapError("dual registration was already prepared")
        if (isinstance(first_tag, bool) or not isinstance(first_tag, int)
                or not 1 <= first_tag <= 0xfc):
            raise CredentialBootstrapError("four nonzero control tags must fit in one byte")
        addresses = (aks_send_dma, aks_receive_dma, acm_send_dma, acm_receive_dma)
        self._validate_mappings(addresses)
        aks_requests = self.aks.registration_requests(
            aks_send_dma, aks_receive_dma, send_tag=first_tag,
            receive_tag=first_tag + 1)
        acm_requests = self.acm.registration_requests(
            acm_send_dma, acm_receive_dma, send_tag=first_tag + 2,
            receive_tag=first_tag + 3)
        self._requests = (*aks_requests, *acm_requests)
        return tuple(list(request) for request in self._requests)

    def accept_registration_replies(
            self, aks_send_reply: list[int], aks_receive_reply: list[int],
            acm_send_reply: list[int], acm_receive_reply: list[int]) -> None:
        if self._requests is None:
            raise CredentialBootstrapError("dual registration was not prepared")
        # Validate every wire acknowledgement before committing either endpoint.
        self.aks.validate_registration_replies(
            aks_send_reply, aks_receive_reply, AKS_REPLY_PROFILE)
        self.acm.validate_registration_replies(
            acm_send_reply, acm_receive_reply, ACM_REPLY_PROFILE)
        try:
            for service in (self.aks, self.acm):
                service.ownership.commit_registration(
                    "send", f"{service.profile.name}-send",
                    control_succeeded=True)
                service.ownership.commit_registration(
                    "receive", f"{service.profile.name}-receive",
                    control_succeeded=True)
        except lifecycle.LifecycleError as error:
            raise CredentialBootstrapError(str(error)) from error

    @property
    def ready(self) -> bool:
        return self.aks.ready and self.acm.ready

    def stop_and_release(self) -> tuple[str, ...]:
        """Model one global CPU stop before any of the four mappings is freed."""
        if not self.ready:
            raise CredentialBootstrapError("dual credential endpoints are not ready")
        try:
            services = (self.aks, self.acm)
            # Preflight both lifecycles so one cannot stop while the other still
            # has an operation in flight.
            if any(service.ownership.operations
                   or service.ownership.transport_stopped
                   for service in services):
                raise CredentialBootstrapError(
                    "both credential endpoints must be idle and running")
            for service in services:
                service.ownership.stop_transport()
            tokens = tuple(sorted(
                mapping.identifier
                for service in services
                for mapping in service.ownership.mappings))
            for service in services:
                for mapping in tuple(service.ownership.mappings):
                    service.ownership.scrub(mapping.identifier)
                    service.ownership.release(mapping.identifier)
            return tokens
        except lifecycle.LifecycleError as error:
            raise CredentialBootstrapError(str(error)) from error
