#!/usr/bin/env python3
"""Socket-factory-free handoff from T2 DNS-SD evidence to passive RSD."""

from __future__ import annotations

from contextlib import AbstractContextManager
from dataclasses import dataclass
import importlib.util
from pathlib import Path
import sys
from typing import Callable, Protocol
import uuid


def _load(name: str, filename: str):
    specification = importlib.util.spec_from_file_location(
        name, Path(__file__).with_name(filename))
    assert specification and specification.loader
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


mdns_query = _load("rsd_mdns_query_composed", "rsd-mdns-query.py")
rsd_query = _load("rsd_query_composed", "rsd-query.py")


class ConnectedSocket(Protocol):
    def sendall(self, data: bytes) -> None: ...
    def recv(self, size: int) -> bytes: ...


class CompositionError(RuntimeError):
    pass


@dataclass(frozen=True)
class DiscoveredDirectoryCapture:
    discovery: object
    directory: object


def capture_discovered_directory(
        mdns_socket,
        connector: Callable[[tuple[str, int, int, int]],
                            AbstractContextManager[ConnectedSocket]],
        interface_index: int,
        client_uuid: uuid.UUID) -> DiscoveredDirectoryCapture:
    """Discover, connect, and passively read RSD without a port parameter."""
    if not isinstance(client_uuid, uuid.UUID):
        raise CompositionError("client UUID must be a UUID")
    if not callable(connector):
        raise CompositionError("connector must be callable")
    try:
        discovery = mdns_query.capture_socket(mdns_socket, interface_index)
    except mdns_query.QueryError as error:
        raise CompositionError("T2 RSD discovery failed") from error
    try:
        context = connector(discovery.endpoint)
        with context as rsd_socket:
            directory = rsd_query.capture_connected_socket(rsd_socket, client_uuid)
    except (OSError, rsd_query.QueryError) as error:
        raise CompositionError("passive T2 RSD directory capture failed") from error
    return DiscoveredDirectoryCapture(discovery, directory)


if __name__ == "__main__":
    print("offline composition only; no socket constructor is present")
