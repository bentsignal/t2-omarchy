#!/usr/bin/env python3
"""Fail-closed verifier for one successful ephemeral AKS authorization run."""

import sys


ORDERED = (
    "AKS startup environment reply passed strict validation",
    "ACM context-create reply passed strict validation",
    "AKS create-device-keybag request:",
    "AKS create-device-keybag reply passed strict validation:",
    "AKS make-system-keybag request:",
    "AKS make-system-keybag notification passed strict validation: ordinal=1 opcode=0x00",
    "AKS make-system-keybag notification passed strict validation: ordinal=2 opcode=0x04",
    "AKS make-system-keybag reply passed strict validation: promoted=yes",
    "AKS verify-secret reply passed strict validation: authorized=yes",
    "AKS copy-keybag confirms presence: role=system",
    "AKS system-unload notification passed strict validation: opcode=0x01",
    "AKS unload-keybag reply passed strict validation: role=system",
    "AKS copy-keybag confirms teardown: role=system",
    "AKS copy-keybag confirms teardown: role=source",
    "ACM context-delete reply passed strict validation",
    "ephemeral keybag authorization completed: created=yes promoted=yes promote=0 authorized=yes system_absent_proof=0 source_absent_proof=0 context_delete=0",
    "issued Apple CPU-stop value 5",
    "OOL buffers scrubbed and released after CPU stop; result=0",
    "read-only probe removed",
)

FORBIDDEN = (
    "bounded Apple transport probe failed",
    "service rejection",
    "did not prove absence",
    "transport error",
    "password=",
    "context=",
)


def verify(log: str) -> None:
    cursor = 0
    for marker in ORDERED:
        found = log.find(marker, cursor)
        if found < 0:
            raise ValueError(f"missing or out-of-order marker: {marker}")
        if log.find(marker, found + 1) >= 0:
            raise ValueError(f"duplicate marker: {marker}")
        cursor = found + len(marker)
    for marker in FORBIDDEN:
        if marker in log:
            raise ValueError(f"forbidden transcript content: {marker}")


def main() -> int:
    try:
        verify(sys.stdin.read())
    except ValueError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print("ephemeral keybag authorization transcript passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
