#!/usr/bin/env python3
"""Verify one successful, scrubbed AKS password authorization transcript."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import re
import sys


class VerificationError(ValueError):
    pass


def _load():
    path = Path(__file__).with_name("verify-credential-startup-log.py")
    spec = importlib.util.spec_from_file_location("password_auth_startup", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


startup = _load()
REQUEST = re.compile(
    r"AKS verify-secret request: endpoint=7 selector=0x21 tag=3 "
    r"length=(\d+) variant=1 options=0x200 password_bytes=not-logged "
    r"context_bytes=not-logged")
ENVELOPE = re.compile(
    r"AKS verify-secret envelope: raw=([0-9a-fA-F]{8}) "
    r"([0-9a-fA-F]{8}) ([0-9a-fA-F]{8}) ([0-9a-fA-F]{8})")


def verify(text: str) -> int:
    if not isinstance(text, str):
        raise VerificationError("password authorization transcript must be text")
    try:
        version = startup.verify(text)
    except startup.VerificationError as error:
        raise VerificationError(str(error)) from error

    state = 0
    request_size = None
    for line in text.splitlines():
        if "t2sep_probe 0000:04:00.2:" not in line:
            continue
        lowered = line.lower()
        if (("password=" in lowered or "context=0x" in lowered or
             "device_state=0x" in lowered) and
                "password_bytes=not-logged" not in line):
            raise VerificationError("transcript appears to expose secret material")
        if "ACM context-create reply passed strict validation:" in line:
            if state != 0:
                raise VerificationError("context creation is duplicated or reordered")
            state = 1
            continue
        match = REQUEST.search(line)
        if match:
            request_size = int(match[1])
            if (state != 1 or request_size < 136 or request_size > 388 or
                    request_size % 4):
                raise VerificationError("verify-secret request is malformed or reordered")
            state = 2
            continue
        match = ENVELOPE.search(line)
        if match:
            words = tuple(int(value, 16) for value in match.groups())
            if (state != 2 or words[:3] != (0x0003A107, 0x00600000, 0) or
                    words[3] & 0xc0000):
                raise VerificationError("verify-secret reply failed correlation")
            state = 3
            continue
        if "AKS verify-secret reply passed strict validation:" in line:
            if (state != 3 or "authorized=yes" not in line or
                    "device_state=not-logged" not in line):
                raise VerificationError("verify-secret success is malformed")
            state = 4
            continue
        if "ACM context-delete request:" in line:
            if state != 4:
                raise VerificationError("context delete preceded authorization")
            state = 5
            continue
        if "credential authorization completed:" in line:
            if (state != 5 or "authorized=yes" not in line or "result=0" not in line or
                    "secret_bytes=not-logged" not in line or
                    "context_bytes=not-logged" not in line):
                raise VerificationError("authorization summary is malformed")
            state = 6
            continue
        if "issued Apple CPU-stop value 5" in line:
            if state != 6:
                raise VerificationError("authorization did not finish before CPU stop")
            state = 7
    if state != 7 or request_size is None:
        raise VerificationError("password authorization transcript is incomplete")
    return version


def main() -> None:
    try:
        version = verify(sys.stdin.read())
    except (ValueError, VerificationError) as error:
        print(f"password authorization verification failed: {error}", file=sys.stderr)
        raise SystemExit(1)
    print(f"verified scrubbed password authorization: header_version={version}")


if __name__ == "__main__":
    main()
