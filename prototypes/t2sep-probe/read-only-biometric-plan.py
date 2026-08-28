#!/usr/bin/env python3
"""Compose the bounded read-only BridgeXPC/biometric query sequence offline.

This module has no socket API. It cannot enroll, match, remove an identity,
cancel an operation, or perform presence detection.
"""

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


discovery = _load("read_only_biometric_discovery", "discovered-bridge-plan.py")
bridge = discovery.bridge
biometric = _load("read_only_biometric_commands", "biometric-command.py")

BODY_CAP = 64 * 1024


class ReadOnlyPlanError(ValueError):
    pass


@dataclass(frozen=True)
class ReadOnlyBiometricPlan:
    endpoint: tuple[str, int, int, int]
    helo: bytes
    bridge_version: bytes
    service_opened: bytes
    maximum_identity_count: bytes
    free_identity_count: bytes
    identity_list: bytes


def _frame(fields: tuple[int, int, int, bytes, int]) -> bytes:
    command, version, value, payload, capacity = fields
    try:
        request = bridge.biometric_perform_request(
            command, version, value, payload, capacity)
        return bridge.encode_perform_command_frame(request, max_body=BODY_CAP)
    except bridge.BridgeProtocolError as error:
        raise ReadOnlyPlanError("read-only biometric frame composition failed") from error


def build_from_rsd_transcript(transcript: bytes, interface_index: int, *,
                              user_id: int,
                              os_build: str = "Linux",
                              bridge_version: int | float = 39,
                              process_name: str = "t2-read-only-biometric",
                              max_identities: int = biometric.MAX_IDENTITIES,
                              ) -> ReadOnlyBiometricPlan:
    """Build only methods 0/1 and Catalina identity-query commands."""
    try:
        base = discovery.build_plan_from_rsd_transcript(
            transcript, interface_index, os_build=os_build,
            bridge_version=bridge_version, process_name=process_name,
            max_body=BODY_CAP)
        maximum = biometric.max_identity_count_fields()
        free = biometric.free_identity_count_fields(user_id=user_id)
        identities = biometric.identity_list_fields(
            user_id=user_id, max_identities=max_identities)
    except (discovery.PlanError, biometric.BiometricCommandError) as error:
        raise ReadOnlyPlanError("invalid read-only biometric plan input") from error
    return ReadOnlyBiometricPlan(
        endpoint=base.endpoint,
        helo=base.helo,
        bridge_version=base.bridge_version_query,
        service_opened=base.service_opened_query,
        maximum_identity_count=_frame(maximum),
        free_identity_count=_frame(free),
        identity_list=_frame(identities),
    )
