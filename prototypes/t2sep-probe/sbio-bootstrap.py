#!/usr/bin/env python3
"""Offline fail-closed composition of the recovered Intel ``sbio`` bootstrap."""

from __future__ import annotations

from dataclasses import dataclass
import importlib.util
from pathlib import Path
import sys


def _load(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


control = _load("sbio_bootstrap_control", "decode-message.py")
lifecycle = _load("sbio_bootstrap_lifecycle", "endpoint-lifecycle.py")
transfer = _load("sbio_bootstrap_transfer", "generic-transfer.py")

SEND_SIZE = 0x4000
RECEIVE_SIZE = 0x4B000


class BootstrapError(ValueError):
    pass


@dataclass(frozen=True)
class ReplyProfile:
    """Independently observed reply fields; intentionally has no defaults."""

    in_opcode: int
    in_target: int
    out_opcode: int
    out_target: int


class SbioBootstrap:
    """Plan and validate bootstrap messages without allocating or touching DMA."""

    def __init__(self) -> None:
        self.discovery = control.DiscoveryTable()
        self.endpoint = None
        self.ownership = lifecycle.EndpointLifecycle(0x08)
        self._requests: dict[str, list[int]] = {}

    def accept_discovery(self, words: list[int]):
        if self.endpoint is not None:
            raise BootstrapError("discovery is already finalized")
        return self.discovery.accept(words)

    def finalize_discovery(self):
        if self.endpoint is not None:
            raise BootstrapError("discovery is already finalized")
        try:
            self.endpoint = self.discovery.finalize_sbio(
                send_size=SEND_SIZE, receive_size=RECEIVE_SIZE)
            self.ownership.enable()
        except (control.DiscoveryError, lifecycle.LifecycleError) as error:
            raise BootstrapError(str(error)) from error
        return self.endpoint

    def registration_requests(self, send_dma: int, receive_dma: int,
                              *, send_tag: int, receive_tag: int
                              ) -> tuple[list[int], list[int]]:
        if self.endpoint is None:
            raise BootstrapError("registration requires finalized discovery")
        if self._requests:
            raise BootstrapError("registration requests were already prepared")
        if send_tag == receive_tag:
            raise BootstrapError("simultaneous control requests require distinct tags")
        try:
            send = control.tag_control_request(control.encode_ool_registration(
                self.endpoint.endpoint_id, send_dma, SEND_SIZE, incoming_to_sep=True), send_tag)
            receive = control.tag_control_request(control.encode_ool_registration(
                self.endpoint.endpoint_id, receive_dma, RECEIVE_SIZE,
                incoming_to_sep=False), receive_tag)
        except control.ControlMessageError as error:
            raise BootstrapError(str(error)) from error
        self._requests = {"send": send, "receive": receive}
        return list(send), list(receive)

    def accept_registration_replies(self, send_reply: list[int], receive_reply: list[int],
                                    profile: ReplyProfile) -> None:
        if set(self._requests) != {"send", "receive"}:
            raise BootstrapError("registration replies require both prepared requests")
        if not isinstance(profile, ReplyProfile):
            raise BootstrapError("registration requires an independently observed reply profile")
        try:
            control.validate_control_reply(
                self._requests["send"], send_reply,
                expected_opcode=profile.in_opcode, expected_target=profile.in_target)
            control.validate_control_reply(
                self._requests["receive"], receive_reply,
                expected_opcode=profile.out_opcode, expected_target=profile.out_target)
            self.ownership.commit_registration("send", "sbio-send",
                                               control_succeeded=True)
            self.ownership.commit_registration("receive", "sbio-receive",
                                               control_succeeded=True)
        except (control.ControlMessageError, lifecycle.LifecycleError) as error:
            raise BootstrapError(str(error)) from error

    def initialization_session(self, *, initial_sequence: int = 0):
        if not self.ownership.ready:
            raise BootstrapError("sbio initialization requires both committed OOL mappings")
        return transfer.sbio_initialization_session(initial_sequence=initial_sequence)
