#!/usr/bin/env python3
"""Verify one bounded, non-secret AKS capabilities transcript from stdin."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import re
import sys


class VerificationError(ValueError):
    pass


def _load_ool_verifier():
    path = Path(__file__).with_name("verify-credential-ool-log.py")
    spec = importlib.util.spec_from_file_location("aks_capabilities_ool_verifier", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


ool = _load_ool_verifier()
ENVELOPE = re.compile(
    r"AKS capabilities envelope: raw=([0-9a-fA-F]{8}) "
    r"([0-9a-fA-F]{8}) ([0-9a-fA-F]{8}) ([0-9a-fA-F]{8})")
SUCCESS = re.compile(
    r"AKS capabilities reply passed strict validation: status=(-?\d+) "
    r"remote_header_version=(\d+)")


def verify(text: str) -> int:
    if not isinstance(text, str):
        raise VerificationError("AKS capabilities transcript must be text")
    try:
        if ool.verify(text, 7) != ((1, 7), (1, 7)):
            raise VerificationError("AKS OOL profile changed")
    except ool.VerificationError as error:
        raise VerificationError(str(error)) from error

    state = 0
    remote_version = None
    for line in text.splitlines():
        if "t2sep_probe 0000:04:00.2:" not in line:
            continue
        if "AKS capabilities request:" in line:
            if state != 0 or not all(value in line for value in (
                    "endpoint=7", "selector=0x4d", "tag=4", "length=100",
                    "header_version=1")):
                raise VerificationError("AKS capabilities request is malformed or reordered")
            state = 1
            continue
        match = ENVELOPE.search(line)
        if match:
            if state != 1:
                raise VerificationError("AKS capabilities envelope is reordered")
            words = tuple(int(value, 16) for value in match.groups())
            if words[:3] != (0x0004cd07, 0x00640000, 0) or words[3] & 0xc0000:
                raise VerificationError("AKS capabilities envelope failed correlation")
            state = 2
            continue
        match = SUCCESS.search(line)
        if match:
            if state != 2 or int(match[1]) != 0:
                raise VerificationError("AKS capabilities result is reordered or unsuccessful")
            remote_version = int(match[2])
            if remote_version < 1:
                raise VerificationError("AKS capabilities version is unsupported")
            state = 3
    if state != 3 or remote_version is None:
        raise VerificationError("AKS capabilities transcript is incomplete")
    return remote_version


def main() -> None:
    try:
        version = verify(sys.stdin.read())
    except (ValueError, VerificationError) as error:
        print(f"AKS capabilities verification failed: {error}", file=sys.stderr)
        raise SystemExit(1)
    print(f"verified AKS capabilities reply: remote_header_version={version}")


if __name__ == "__main__":
    main()
