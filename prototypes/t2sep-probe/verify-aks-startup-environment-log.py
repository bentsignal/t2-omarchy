#!/usr/bin/env python3
"""Verify one bounded, non-secret AKS startup-environment transcript."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import re
import sys


class VerificationError(ValueError):
    pass


def _load_ool_verifier():
    path = Path(__file__).with_name("verify-credential-ool-log.py")
    spec = importlib.util.spec_from_file_location("aks_startup_ool_verifier", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


ool = _load_ool_verifier()
CAPS_ENVELOPE = re.compile(
    r"AKS capabilities envelope: raw=([0-9a-fA-F]{8}) "
    r"([0-9a-fA-F]{8}) ([0-9a-fA-F]{8}) ([0-9a-fA-F]{8})")
CAPS_SUCCESS = re.compile(
    r"AKS capabilities reply passed strict validation: status=(-?\d+) "
    r"remote_header_version=(\d+)")
CAPS_FALLBACK = re.compile(
    r"AKS capabilities negotiation unavailable: result=(-?\d+); "
    r"applying Apple header-version-1 fallback")
ENV_REQUEST = re.compile(
    r"AKS startup environment request: endpoint=7 selector=0x2a tag=2 "
    r"length=1136 header_version=(\d+) no_effaceable_storage=0 mode=4")
ENV_ENVELOPE = re.compile(
    r"AKS startup environment envelope: raw=([0-9a-fA-F]{8}) "
    r"([0-9a-fA-F]{8}) ([0-9a-fA-F]{8}) ([0-9a-fA-F]{8})")
ENV_SUCCESS = re.compile(
    r"AKS startup environment reply passed strict validation: status=(-?\d+) "
    r"header_version=(\d+)")


def verify(text: str) -> int:
    if not isinstance(text, str):
        raise VerificationError("AKS startup transcript must be text")
    # The generic OOL verifier correctly rejects negative results.  The one
    # exception here is Apple's explicitly modelled capabilities fallback,
    # which this verifier validates in the ordered AKS state machine below.
    ool_text = "\n".join(
        line for line in text.splitlines()
        if not CAPS_FALLBACK.search(line)
    )
    try:
        if ool.verify(ool_text, 7) != ((1, 7), (1, 7)):
            raise VerificationError("AKS OOL profile changed")
    except ool.VerificationError as error:
        raise VerificationError(str(error)) from error

    state = 0
    negotiated = None
    for line in text.splitlines():
        if "t2sep_probe 0000:04:00.2:" not in line:
            continue
        if "AKS capabilities request:" in line:
            required = ("endpoint=7", "selector=0x4d", "tag=1",
                        "length=100", "header_version=1")
            if state != 0 or not all(value in line for value in required):
                raise VerificationError("capabilities request is malformed or reordered")
            state = 1
            continue
        match = CAPS_ENVELOPE.search(line)
        if match:
            words = tuple(int(value, 16) for value in match.groups())
            if (state != 1 or words[0] != 0x0001cd07 or
                    words[1] not in (0x005c0000, 0x00640000) or words[2] != 0):
                raise VerificationError("capabilities envelope failed correlation")
            if words[3] & 0xc0000:
                raise VerificationError("capabilities envelope reports transport error")
            state = 2
            continue
        match = CAPS_SUCCESS.search(line)
        if match:
            remote = int(match[2])
            if state != 2 or int(match[1]) != 0 or remote < 1:
                raise VerificationError("capabilities result is unsuccessful")
            negotiated = min(remote, 2)
            state = 3
            continue
        match = CAPS_FALLBACK.search(line)
        if match:
            if state != 1 or int(match[1]) == 0:
                raise VerificationError("capabilities fallback is malformed or reordered")
            negotiated = 1
            state = 3
            continue
        match = ENV_REQUEST.search(line)
        if match:
            if state != 3 or int(match[1]) != negotiated:
                raise VerificationError("environment request version/order changed")
            state = 4
            continue
        match = ENV_ENVELOPE.search(line)
        if match:
            words = tuple(int(value, 16) for value in match.groups())
            if state != 4 or words[:3] != (0x0002aa07, 0x00580000, 0):
                raise VerificationError("environment envelope failed correlation")
            if words[3] & 0xc0000:
                raise VerificationError("environment envelope reports transport error")
            state = 5
            continue
        match = ENV_SUCCESS.search(line)
        if match:
            if (state != 5 or int(match[1]) != 0 or
                    int(match[2]) != negotiated):
                raise VerificationError("environment result is unsuccessful")
            state = 6
            continue
        if "issued Apple CPU-stop value 5" in line:
            if state != 6:
                raise VerificationError("startup sequence did not finish before CPU stop")
            state = 7
    if state != 7 or negotiated is None:
        raise VerificationError("AKS startup transcript is incomplete")
    return negotiated


def main() -> None:
    try:
        version = verify(sys.stdin.read())
    except (ValueError, VerificationError) as error:
        print(f"AKS startup verification failed: {error}", file=sys.stderr)
        raise SystemExit(1)
    print(f"verified AKS startup environment: header_version={version}")


if __name__ == "__main__":
    main()
