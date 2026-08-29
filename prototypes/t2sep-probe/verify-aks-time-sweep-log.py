#!/usr/bin/env python3
"""Verify one bounded, non-secret AKS continuous-time sweep transcript."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import re
import sys


class VerificationError(ValueError):
    pass


def _load_ool_verifier():
    path = Path(__file__).with_name("verify-credential-ool-log.py")
    spec = importlib.util.spec_from_file_location("aks_time_ool_verifier", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


ool = _load_ool_verifier()
CLASSES = ("zero", "sep-start-relative", "monotonic", "raw", "boottime")
REQUEST = re.compile(
    r"AKS time candidate request: class=([a-z-]+) endpoint=7 "
    r"selector=0x4d tag=(\d+) length=100 header_version=1")
ENVELOPE = re.compile(
    r"AKS time candidate envelope: class=([a-z-]+) raw="
    r"([0-9a-fA-F]{8}) ([0-9a-fA-F]{8}) ([0-9a-fA-F]{8}) ([0-9a-fA-F]{8})")
SUCCESS = re.compile(
    r"AKS time candidate reply passed strict validation: class=([a-z-]+) "
    r"status=(-?\d+) remote_header_version=(\d+) reply_size=(92|100)")
NO_REPLY = re.compile(r"AKS time candidate produced no reply: class=([a-z-]+)")
ACCEPTED = re.compile(
    r"AKS time sweep accepted class=([a-z-]+) "
    r"negotiated_header_version=(\d+) attempts=(\d+)")
EXHAUSTED = re.compile(
    r"AKS time sweep completed without accepted candidate: attempts=(\d+) result=(-?\d+)")


def verify(text: str) -> str | None:
    if not isinstance(text, str):
        raise VerificationError("AKS time-sweep transcript must be text")
    attempted: list[str] = []
    pending: str | None = None
    pending_reply_size: int | None = None
    accepted: str | None = None
    terminal = False
    sanitized: list[str] = []

    for line in text.splitlines():
        bound = "t2sep_probe 0000:04:00.2:" in line
        if not bound:
            sanitized.append(line)
            continue
        match = REQUEST.search(line)
        if match:
            name, tag = match[1], int(match[2])
            index = len(attempted)
            if terminal or pending or index >= len(CLASSES) or name != CLASSES[index] or tag != index + 1:
                raise VerificationError("time candidate request changed order or correlation")
            attempted.append(name)
            pending = name
            sanitized.append(line)
            continue
        match = ENVELOPE.search(line)
        if match:
            name = match[1]
            words = tuple(int(value, 16) for value in match.groups()[1:])
            tag = len(attempted)
            reply_size = words[1] >> 16
            if (pending != name or words[0] != (7 | 0xcd << 8 | tag << 16) or
                    reply_size not in (92, 100) or words[1] & 0xffff or
                    words[2] != 0 or words[3] & 0xc0000):
                raise VerificationError("time candidate reply envelope failed correlation")
            pending_reply_size = reply_size
            sanitized.append(line)
            continue
        match = SUCCESS.search(line)
        if match:
            name, status, version = match[1], int(match[2]), int(match[3])
            if (pending != name or status != 0 or version < 1 or
                    int(match[4]) != pending_reply_size):
                raise VerificationError("time candidate strict result is invalid")
            accepted = name
            pending = None
            pending_reply_size = None
            sanitized.append(line)
            continue
        match = NO_REPLY.search(line)
        if match:
            if pending != match[1]:
                raise VerificationError("time candidate timeout lacks its request")
            pending = None
            pending_reply_size = None
            sanitized.append(line)
            continue
        match = ACCEPTED.search(line)
        if match:
            if (terminal or pending or accepted != match[1] or
                    int(match[2]) < 1 or int(match[3]) != len(attempted)):
                raise VerificationError("accepted time candidate summary is invalid")
            terminal = True
            sanitized.append(line)
            continue
        match = EXHAUSTED.search(line)
        if match:
            if (terminal or pending or accepted is not None or attempted != list(CLASSES) or
                    int(match[1]) != len(CLASSES) or int(match[2]) != -110):
                raise VerificationError("exhausted time sweep summary is invalid")
            terminal = True
            continue
        if "OOL buffers scrubbed and released after CPU stop; result=-110" in line:
            if not terminal or accepted is not None:
                raise VerificationError("negative cleanup is out of order")
            sanitized.append(line.replace("result=-110", "result=0"))
            continue
        if ("bounded Apple transport probe failed: -110" in line or
                "probe with driver t2sep_probe failed with error -110" in line):
            if not terminal or accepted is not None:
                raise VerificationError("unexpected bounded-probe failure")
            continue
        if any(marker in line for marker in ("timed out", "failed:", "result=-")):
            raise VerificationError("transcript contains an unexpected failure marker")
        sanitized.append(line)

    if not terminal or pending or not attempted:
        raise VerificationError("time sweep transcript is incomplete")
    try:
        if ool.verify("\n".join(sanitized), 7) != ((1, 7), (1, 7)):
            raise VerificationError("AKS OOL profile changed")
    except ool.VerificationError as error:
        raise VerificationError(str(error)) from error
    return accepted


def main() -> None:
    try:
        accepted = verify(sys.stdin.read())
    except (ValueError, VerificationError) as error:
        print(f"AKS time-sweep verification failed: {error}", file=sys.stderr)
        raise SystemExit(1)
    print("verified AKS time sweep: " +
          (f"accepted_class={accepted}" if accepted else "no candidate accepted"))


if __name__ == "__main__":
    main()
