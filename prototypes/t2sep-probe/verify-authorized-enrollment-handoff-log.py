#!/usr/bin/env python3
"""Fail-closed verifier for the live ACM-to-BiometricKit handoff."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys


def _load_base():
    path = Path(__file__).with_name("verify-ephemeral-keybag-authorization-log.py")
    spec = importlib.util.spec_from_file_location("handoff_base_verifier", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


base = _load_base()
HANDOFF = (
    "authorized enrollment handoff ready: credential_bytes=not-logged",
    "authorized enrollment handoff completed without logging credential bytes",
)
FORBIDDEN = (
    "handoff timed out", "credential=", "enrollment_credential=",
)


def verify(log: str) -> None:
    base.verify(log)
    verify_marker = log.index(
        "AKS verify-secret reply passed strict validation: authorized=yes")
    unload_marker = log.index("AKS unload-keybag reply passed strict validation")
    cursor = verify_marker
    for marker in HANDOFF:
        found = log.find(marker, cursor, unload_marker)
        if found < 0 or log.find(marker, found + 1) >= 0:
            raise ValueError(f"missing, duplicated, or out-of-order marker: {marker}")
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
    print("authorized enrollment handoff transcript passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
