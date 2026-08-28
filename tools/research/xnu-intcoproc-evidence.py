#!/usr/bin/env python3
"""Verify XNU's local-only SO_INTCOPROC_ALLOW access-control path."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


class EvidenceError(ValueError):
    pass


FILES = {
    "socket_private": "bsd/sys/socket_private.h",
    "socket": "bsd/kern/uipc_socket.c",
    "pcb": "bsd/netinet/in_pcb.c",
    "tcp": "bsd/netinet/tcp_output.c",
    "ipv6": "bsd/netinet6/ip6_output.c",
}
MAX_FILE_SIZE = 8 * 1024 * 1024

REQUIRED = {
    "socket_private": (
        "#define SO_INTCOPROC_ALLOW              0x1118",
        "Try to use internal co-processor interfaces.",
    ),
    "socket": (
        "case SO_INTCOPROC_ALLOW:",
        "PRIV_NET_RESTRICTED_INTCOPROC",
        "inp_set_intcoproc_allowed",
        "inp_clear_intcoproc_allowed",
    ),
    "pcb": (
        "INP2_INTCOPROC_ALLOWED",
        "IFNET_IS_INTCOPROC(ifp) && !INP_INTCOPROC_ALLOWED(inp)",
        "return TRUE;",
    ),
    "tcp": (
        "INP_INTCOPROC_ALLOWED(inp) && isipv6",
        "IP6OAF_INTCOPROC_ALLOWED",
    ),
    "ipv6": (
        "ip6oa->ip6oa_flags & IP6OAF_INTCOPROC_ALLOWED",
        "necp_packet_should_skip_filters(m)",
    ),
}


def _read_regular(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise EvidenceError(f"not a regular source file: {path}")
    size = path.stat().st_size
    if size <= 0 or size > MAX_FILE_SIZE:
        raise EvidenceError(f"source file size is invalid: {path}")
    return path.read_bytes()


def inspect(source_root: Path) -> dict[str, object]:
    if source_root.is_symlink() or not source_root.is_dir():
        raise EvidenceError("XNU source root is not a regular directory")

    hashes: dict[str, str] = {}
    for label, relative in FILES.items():
        data = _read_regular(source_root / relative)
        try:
            source = data.decode("utf-8")
        except UnicodeDecodeError as error:
            raise EvidenceError(f"source file is not UTF-8: {relative}") from error
        missing = [value for value in REQUIRED[label] if value not in source]
        if missing:
            raise EvidenceError(
                f"{relative} lacks required INTCOPROC evidence: {missing[0]}")
        hashes[relative] = hashlib.sha256(data).hexdigest()

    return {
        "socket_option": "SO_INTCOPROC_ALLOW",
        "option_value": 0x1118,
        "credential_gate": "PRIV_NET_RESTRICTED_INTCOPROC",
        "pcb_effect": "INP2_INTCOPROC_ALLOWED",
        "send_receive_effect": "allow-otherwise-restricted-intcoproc-interface",
        "peer_visible_signal": False,
        "linux_equivalent_required": False,
        "source_sha256": hashes,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("xnu_source_root", type=Path)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    try:
        result = inspect(args.xnu_source_root)
    except EvidenceError as error:
        raise SystemExit(str(error)) from error
    if args.json:
        print(json.dumps(result, sort_keys=True, indent=2))
    else:
        print("verified XNU SO_INTCOPROC_ALLOW: entitlement-gated local "
              "interface access; no peer-visible signal")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
