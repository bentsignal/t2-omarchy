#!/usr/bin/env python3
"""Verify one bounded, secret-free ACM create/delete lifecycle transcript."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import re
import sys


class VerificationError(ValueError):
    pass


def _load_ool_verifier():
    path = Path(__file__).with_name("verify-credential-ool-log.py")
    spec = importlib.util.spec_from_file_location("acm_context_ool_verifier", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


ool = _load_ool_verifier()
ENVELOPE = re.compile(
    r"ACM (SCRD-initialization|context-create|context-delete) envelope "
    r"(request|reply): raw=([0-9a-fA-F]{8}) ([0-9a-fA-F]{8}) "
    r"([0-9a-fA-F]{8}) ([0-9a-fA-F]{8})")

STAGES = (
    ("ACM SCRD initialization request:",
     ("endpoint=10", "message_type=1", "length=8", "version=0x28")),
    ("ACM SCRD initialization reply passed strict validation:",
     ("status=0", "length=0")),
    ("ACM context-create request:",
     ("endpoint=10", "message_type=1", "selector=1", "length=8")),
    ("ACM context-create reply passed strict validation:",
     ("status=0", "length=17", "context_bytes=not-logged")),
    ("ACM context-delete request:",
     ("endpoint=10", "message_type=1", "selector=2", "length=24",
      "context_length=16", "context_bytes=not-logged")),
    ("ACM context-delete reply passed strict validation:",
     ("status=0", "length=0")),
)

EXPECTED_ENVELOPES = (
    ("SCRD-initialization", "request", (0x0008010A, 0, 0, 0)),
    ("SCRD-initialization", "reply", (0x0000010A, 0, 0, 0)),
    ("context-create", "request", (0x0008010A, 0, 0, 0)),
    ("context-create", "reply", (0x0011010A, 0, 0, 0)),
    ("context-delete", "request", (0x0018010A, 0, 0, 0)),
    ("context-delete", "reply", (0x0000010A, 0, 0, 0)),
)
STAGE_ENVELOPE_COUNTS = (0, 2, 2, 4, 4, 6)
ENVELOPE_STAGE_COUNTS = (1, 1, 3, 3, 5, 5)


def verify(text: str) -> None:
    if not isinstance(text, str):
        raise VerificationError("ACM context transcript must be text")
    try:
        if ool.verify(text, 10) != ((1, 10), (1, 10)):
            raise VerificationError("ACM OOL profile changed")
    except ool.VerificationError as error:
        raise VerificationError(str(error)) from error

    stage = 0
    envelope = 0
    stopped = False
    for line in text.splitlines():
        if "t2sep_probe 0000:04:00.2:" not in line:
            continue
        if any(secret in line.lower() for secret in
               ("password=", "context=0x", "context_bytes=")) and \
                "context_bytes=not-logged" not in line:
            raise VerificationError("transcript appears to expose secret material")
        match = ENVELOPE.search(line)
        if match:
            if envelope >= len(EXPECTED_ENVELOPES):
                raise VerificationError("unexpected extra ACM envelope")
            if stage != ENVELOPE_STAGE_COUNTS[envelope]:
                raise VerificationError("ACM envelope is outside its lifecycle stage")
            phase, direction = match[1], match[2]
            words = tuple(int(match[index], 16) for index in range(3, 7))
            expected_phase, expected_direction, expected_words = \
                EXPECTED_ENVELOPES[envelope]
            if ((phase, direction) != (expected_phase, expected_direction) or
                    words[:3] != expected_words[:3] or
                    words[3] & ((1 << 18) | (1 << 19)) or
                    (direction == "request" and words[3] != 0)):
                raise VerificationError("ACM envelope changed or is reordered")
            envelope += 1
            continue
        if stage < len(STAGES) and STAGES[stage][0] in line:
            marker, fields = STAGES[stage]
            if envelope != STAGE_ENVELOPE_COUNTS[stage]:
                raise VerificationError("ACM lifecycle stage precedes its envelope")
            if not all(field in line for field in fields):
                raise VerificationError(f"malformed ACM stage: {marker}")
            stage += 1
            continue
        if any(marker in line for marker, _ in STAGES):
            raise VerificationError("ACM lifecycle stage is duplicated or reordered")
        if "issued Apple CPU-stop value 5" in line:
            if stage != len(STAGES) or envelope != len(EXPECTED_ENVELOPES) or stopped:
                raise VerificationError("ACM lifecycle did not complete before CPU stop")
            stopped = True
    if stage != len(STAGES) or envelope != len(EXPECTED_ENVELOPES) or not stopped:
        raise VerificationError("ACM context lifecycle transcript is incomplete")


def main() -> None:
    try:
        verify(sys.stdin.read())
    except (ValueError, VerificationError) as error:
        print(f"ACM context lifecycle verification failed: {error}", file=sys.stderr)
        raise SystemExit(1)
    print("verified ephemeral ACM context create/delete lifecycle")


if __name__ == "__main__":
    main()
