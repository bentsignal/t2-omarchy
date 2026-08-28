#!/usr/bin/env python3
"""Compose an offline BridgeXPC plan from a validated RSD transcript.

This module has no socket API and performs no I/O.  It is the fail-closed
handoff between the modern RSD directory decoder and the current BridgeXPC
codec.  The preferred entry point does not expose a caller-controlled port.
"""

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


bridge = _load("discovered_bridge_protocol", "bridge-protocol.py")
rsd = _load("discovered_rsd_protocol", "rsd-protocol.py")


class PlanError(ValueError):
    pass


@dataclass(frozen=True)
class DiscoveredBridgePlan:
    endpoint: tuple[str, int, int, int]
    helo: bytes
    bridge_version_query: bytes
    service_opened_query: bytes


BIOMETRIC_SERVICE = "com.apple.eos.BiometricKit"
RSD_FRAME_CAP = 64 * 1024
RSD_FRAME_LIMIT = 16
RSD_TOTAL_CAP = 256 * 1024


def build_plan(advertised_port: int, interface_index: int, *,
               os_build: str = "Linux", bridge_version: int | float = 39,
               process_name: str = "t2-discovered-bridge",
               max_body: int = 64 * 1024) -> DiscoveredBridgePlan:
    """Build bounded bytes for methods 0 and 1 without opening an endpoint."""
    if isinstance(advertised_port, bool) or not isinstance(advertised_port, int):
        raise PlanError("advertised port must be an integer")
    if not 1 <= advertised_port <= 65535:
        raise PlanError("advertised port is out of range")
    if isinstance(interface_index, bool) or not isinstance(interface_index, int):
        raise PlanError("interface index must be an integer")
    if not 1 <= interface_index < 1 << 32:
        raise PlanError("interface index is out of range")
    try:
        helo = bridge.encode_helo_frame(os_build, bridge_version, process_name,
                                        max_body=max_body)
        version_query = bridge.encode_bridge_version_query_frame(max_body=max_body)
        opened_query = bridge.encode_service_opened_query_frame(max_body=max_body)
    except bridge.BridgeProtocolError as error:
        raise PlanError("invalid BridgeXPC plan input") from error
    endpoint = (rsd.T2_LINK_LOCAL_ADDRESS_CANDIDATE, advertised_port, 0,
                interface_index)
    return DiscoveredBridgePlan(endpoint, helo, version_query, opened_query)


def build_plan_from_rsd_transcript(transcript: bytes, interface_index: int, **kwargs
                                   ) -> DiscoveredBridgePlan:
    """Strictly decode one passive RSD transcript and compose its bridge plan."""
    if not isinstance(transcript, bytes):
        raise PlanError("RSD transcript must be bytes")
    try:
        parser = rsd.PassiveRSDTranscript(
            wanted_service=BIOMETRIC_SERVICE,
            max_frame=RSD_FRAME_CAP,
            max_frames=RSD_FRAME_LIMIT,
            max_total=RSD_TOTAL_CAP,
            max_xpc_body=RSD_FRAME_CAP,
        )
        parser.feed(transcript)
        advertised_port = parser.finish()
    except rsd.RSDProtocolError as error:
        raise PlanError("RSD transcript did not prove a BiometricKit endpoint") from error
    return build_plan(advertised_port, interface_index, **kwargs)
