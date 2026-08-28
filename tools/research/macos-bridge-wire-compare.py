#!/usr/bin/env python3
"""Compare private macOS BridgeXPC writes with the Linux reconstruction.

The input files remain local. Output contains only sizes, SHA-256 digests,
decoded non-private HELO fields, and the first differing byte offset.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import itertools
import json
from pathlib import Path
import plistlib
import sys


PROTOCOL_PATH = (Path(__file__).parents[2] / "prototypes" / "t2sep-probe"
                 / "bridge-protocol.py")
SPEC = importlib.util.spec_from_file_location("wire_compare_bridge_protocol",
                                              PROTOCOL_PATH)
assert SPEC and SPEC.loader
bridge = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = bridge
SPEC.loader.exec_module(bridge)

CAP = 64 * 1024


class CompareError(ValueError):
    pass


def _read_private(path: Path) -> bytes:
    if not isinstance(path, Path) or path.is_symlink() or not path.is_file():
        raise CompareError("input must be one regular non-symlink file")
    if path.stat().st_mode & 0o077:
        raise CompareError("private wire input permissions expose group/world access")
    data = path.read_bytes()
    if not data or len(data) > CAP:
        raise CompareError("private wire input size is invalid")
    return data


def _frame(data: bytes, expected_kind: int) -> bytes:
    if len(data) < bridge.BRIDGE_FRAME_HEADER.size:
        raise CompareError("wire input lacks a complete BridgeXPC header")
    try:
        header = bridge.decode_frame_header(
            data[:bridge.BRIDGE_FRAME_HEADER.size], max_body=CAP)
    except bridge.BridgeProtocolError as error:
        raise CompareError("wire input has an invalid BridgeXPC header") from error
    if header.kind != expected_kind:
        raise CompareError("wire input has the wrong BridgeXPC frame kind")
    if len(data) != bridge.BRIDGE_FRAME_HEADER.size + header.body_size:
        raise CompareError("wire input is not exactly one complete BridgeXPC frame")
    return data[bridge.BRIDGE_FRAME_HEADER.size:]


def _first_difference(left: bytes, right: bytes) -> int | None:
    for offset, (a, b) in enumerate(zip(left, right)):
        if a != b:
            return offset
    return None if len(left) == len(right) else min(len(left), len(right))


def _native_helo_order_variants(fields: dict[str, object]) -> set[bytes]:
    """Return compact JSON frames for every Foundation dictionary key order."""
    items = tuple(fields.items())
    result = set()
    for ordering in itertools.permutations(items):
        body = json.dumps(dict(ordering), separators=(",", ":")).encode("utf-8")
        result.add(bridge.encode_frame_header(bridge.FRAME_HELO, len(body)) + body)
    return result


def compare(helo_wire: bytes, query_wire: bytes, *, os_build: str,
            version: int | float, process_name: str) -> dict[str, object]:
    helo_body = _frame(helo_wire, bridge.FRAME_HELO)
    query_body = _frame(query_wire, bridge.FRAME_MESSAGE)
    try:
        decoded_helo = bridge.decode_helo_body(helo_body, max_body=CAP)
        decoded_query = plistlib.loads(query_body)
    except (bridge.BridgeProtocolError, plistlib.InvalidFileException,
            ValueError, TypeError) as error:
        raise CompareError("wire input body failed strict decoding") from error
    if decoded_query != [bridge.GET_BRIDGE_VERSION]:
        raise CompareError("message input is not exactly method-zero array [0]")
    expected_helo = bridge.encode_helo_frame(
        os_build, version, process_name, max_body=CAP)
    expected_query = bridge.encode_bridge_version_query_frame(max_body=CAP)
    expected_fields = bridge.decode_helo_body(
        expected_helo[bridge.BRIDGE_FRAME_HEADER.size:], max_body=CAP)
    native_order_variants = _native_helo_order_variants(expected_fields)
    return {
        "helo_size": len(helo_wire),
        "helo_sha256": hashlib.sha256(helo_wire).hexdigest(),
        "helo_fields": decoded_helo,
        "helo_exact": helo_wire == expected_helo,
        "helo_fields_exact": decoded_helo == expected_fields,
        "helo_native_order_variant": helo_wire in native_order_variants,
        "helo_native_order_variant_count": len(native_order_variants),
        "helo_first_difference": _first_difference(helo_wire, expected_helo),
        "query_size": len(query_wire),
        "query_sha256": hashlib.sha256(query_wire).hexdigest(),
        "query_exact": query_wire == expected_query,
        "query_first_difference": _first_difference(query_wire, expected_query),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("client_helo", type=Path)
    parser.add_argument("method_zero", type=Path)
    parser.add_argument("--os-build", required=True)
    parser.add_argument("--bridge-version", type=float, required=True)
    parser.add_argument("--process-name", default="biometrickitd")
    args = parser.parse_args()
    result = compare(_read_private(args.client_helo),
                     _read_private(args.method_zero),
                     os_build=args.os_build, version=args.bridge_version,
                     process_name=args.process_name)
    for key, value in result.items():
        print(f"{key}={value}")


if __name__ == "__main__":
    main()
