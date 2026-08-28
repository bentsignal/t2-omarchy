#!/usr/bin/env python3
"""Gated method-0 query while its Multiverse directory session stays open.

The live path can send only the existing RSD directory handshake, BridgeXPC
HELO, and method 0.  It contains no method-3 or SBIO encoder/call site.
"""

from __future__ import annotations

import argparse
from contextlib import AbstractContextManager
import importlib.util
import math
from pathlib import Path
import select
import socket
import sys
from typing import Callable, Protocol
import uuid


def _load(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


rsd_query = _load("coupled_rsd_query", "rsd-query.py")
bridge_query = _load("coupled_bridge_query_impl", "bridge-query.py")

CONFIRMATION = "I_UNDERSTAND_THIS_ONLY_QUERIES_THE_T2_BRIDGE_VERSION"
LIVE_COUPLED_QUERY_ENABLED = False


class ConnectedSocket(Protocol):
    def sendall(self, data: bytes) -> None: ...
    def recv(self, size: int) -> bytes: ...


class CoupledQueryError(RuntimeError):
    pass


def connect_multiverse_socket(interface: str, endpoint: tuple[str, int, int, int],
                              timeout: float) -> socket.socket:
    """Mirror the portable parts of Apple's MultiverseSupport socket setup."""
    sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    try:
        # Darwin's SO_INTCOPROC_ALLOW has no Linux equivalent.  Binding the
        # socket to the T2 USB network interface is the closest portable
        # expression of its routing intent; the sockaddr scope ID remains set.
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE,
                        interface.encode() + b"\0")
        sock.setblocking(False)
        result = sock.connect_ex(endpoint)
        if result not in (0, getattr(socket, "EINPROGRESS", 115)):
            raise OSError(result, "Multiverse socket connect failed")
        if result:
            _, writable, exceptional = select.select([], [sock], [sock], timeout)
            if exceptional or not writable:
                raise TimeoutError("Multiverse socket connect timed out")
            error = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
            if error:
                raise OSError(error, "Multiverse socket connect failed")
        sock.settimeout(timeout)
        return sock
    except BaseException:
        sock.close()
        raise


def query_with_open_directory(
        directory_socket: ConnectedSocket,
        service_connector: Callable[[tuple[str, int, int, int]],
                                    AbstractContextManager[ConnectedSocket]],
        interface_index: int,
        client_uuid: uuid.UUID) -> tuple[int, int]:
    """Discover a dynamic port and issue method 0 before directory teardown."""
    if not callable(service_connector):
        raise CoupledQueryError("service connector must be callable")
    if (not isinstance(interface_index, int) or isinstance(interface_index, bool)
            or interface_index <= 0):
        raise CoupledQueryError("interface index must be positive")
    if not isinstance(client_uuid, uuid.UUID):
        raise CoupledQueryError("client UUID must be a UUID")
    try:
        capture = rsd_query.capture_connected_socket(directory_socket, client_uuid)
        endpoint = rsd_query.protocol.observed_rsd_sockaddr(
            interface_index, capture.advertised_port)
        with service_connector(endpoint) as service_socket:
            return bridge_query.query_connected_socket(service_socket)
    except (OSError, rsd_query.QueryError, bridge_query.QueryError) as error:
        raise CoupledQueryError("coupled directory/BridgeXPC query failed") from error


def live_query(interface: str, timeout: float,
               client_uuid: uuid.UUID | None = None) -> tuple[int, int]:
    if not LIVE_COUPLED_QUERY_ENABLED:
        raise CoupledQueryError("live coupled query is disabled in source")
    if (isinstance(timeout, bool) or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout) or not 0 < timeout <= 5):
        raise CoupledQueryError("timeout must be finite, positive, and at most five seconds")
    if client_uuid is None:
        client_uuid = uuid.uuid4()
    if not isinstance(client_uuid, uuid.UUID):
        raise CoupledQueryError("client UUID must be a UUID")
    ifindex = rsd_query.verify_t2_interface(interface)
    directory_port = rsd_query.SAME_BOOT_DIRECTORY_PORT_VERIFICATION[0]
    directory_target = rsd_query.protocol.observed_rsd_sockaddr(ifindex, directory_port)

    class Connector:
        def __init__(self, endpoint):
            self.endpoint = endpoint
            self.sock = None

        def __enter__(self):
            self.sock = connect_multiverse_socket(interface, self.endpoint, timeout)
            return self.sock

        def __exit__(self, *_):
            if self.sock is not None:
                self.sock.close()

    with connect_multiverse_socket(interface, directory_target, timeout) as directory_socket:
        return query_with_open_directory(directory_socket, Connector, ifindex, client_uuid)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live", action="store_true")
    parser.add_argument("--interface", default="enp4s0f1u1")
    parser.add_argument("--timeout", type=float, default=3.0)
    parser.add_argument("--client-uuid", type=uuid.UUID)
    parser.add_argument("--confirm", default="")
    args = parser.parse_args()
    if not args.live:
        print("offline only: coupled RSD directory + BridgeXPC method-0 plan")
        return
    if args.confirm != CONFIRMATION:
        parser.error(f"live mode requires --confirm={CONFIRMATION}")
    status, version = live_query(args.interface, args.timeout, args.client_uuid)
    print(f"bridge status={status} version={version}")


if __name__ == "__main__":
    main()
