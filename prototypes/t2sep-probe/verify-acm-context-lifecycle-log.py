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
    r"ACM (SCRD-initialization|ping-1d|context-create-(?:24|01)|context-delete) envelope "
    r"(request|reply): raw=([0-9a-fA-F]{8}) ([0-9a-fA-F]{8}) "
    r"([0-9a-fA-F]{8}) ([0-9a-fA-F]{8})")

MARKERS = {
    "ACM SCRD initialization request:":
        ("init-request", ("endpoint=10", "message_type=1", "length=8",
                          "version=0x28")),
    "ACM SCRD initialization reply passed strict validation:":
        ("init-success", ("status=0", "length=0")),
    "ACM ping request:":
        ("ping-request", ("endpoint=10", "message_type=1", "selector=29",
                          "length=8", "expected_reply=0")),
    "ACM ping reply passed strict validation:":
        ("ping-success", ("status=0", "length=0")),
    "ACM context-create request:":
        ("current-request", ("endpoint=10", "message_type=1", "selector=36",
                             "length=12", "subject_uid=", "expected_reply=21")),
    "ACM current context-create returned -3; applying Apple legacy fallback":
        ("fallback", ()),
    "ACM context-create fallback request:":
        ("legacy-request", ("endpoint=10", "message_type=1", "selector=1",
                            "length=12", "subject_uid=", "expected_reply=17")),
    "ACM context-create reply passed strict validation:":
        ("create-success", ("status=0", "context_bytes=not-logged")),
    "ACM context-delete request:":
        ("delete-request", ("endpoint=10", "message_type=1", "selector=2",
                            "length=24", "context_length=16",
                            "context_bytes=not-logged")),
    "ACM context-delete reply passed strict validation:":
        ("delete-success", ("status=0", "length=0")),
}


def envelope_event(phase, direction, words):
    return ("envelope", phase, direction, words[:3])


INIT_PREFIX = (
    ("marker", "init-request"),
    envelope_event("SCRD-initialization", "request", (0x0008010A, 0, 0, 0)),
    envelope_event("SCRD-initialization", "reply", (0x0000010A, 0, 0, 0)),
    ("marker", "init-success"),
    ("marker", "ping-request"),
    envelope_event("ping-1d", "request", (0x0008010A, 0, 0, 0)),
    envelope_event("ping-1d", "reply", (0x0000010A, 0, 0, 0)),
    ("marker", "ping-success"),
    ("marker", "current-request"),
    envelope_event("context-create-24", "request", (0x000C010A, 0, 0, 0)),
)
DELETE_SUFFIX = (
    ("marker", "delete-request"),
    envelope_event("context-delete", "request", (0x0018010A, 0, 0, 0)),
    envelope_event("context-delete", "reply", (0x0000010A, 0, 0, 0)),
    ("marker", "delete-success"),
)
MODERN_EVENTS = INIT_PREFIX + (
    envelope_event("context-create-24", "reply", (0x0015010A, 0, 0, 0)),
    ("marker", "create-success"),
) + DELETE_SUFFIX
FALLBACK_EVENTS = INIT_PREFIX + (
    envelope_event("context-create-24", "reply", (0x0000010A, 0xFFFFFFFD, 0, 0)),
    ("marker", "fallback"),
    ("marker", "legacy-request"),
    envelope_event("context-create-01", "request", (0x000C010A, 0, 0, 0)),
    envelope_event("context-create-01", "reply", (0x0011010A, 0, 0, 0)),
    ("marker", "create-success"),
) + DELETE_SUFFIX


def verify_service(text: str) -> None:
    if not isinstance(text, str):
        raise VerificationError("ACM context transcript must be text")
    events = []
    stopped = False
    subject_uid = None
    for line in text.splitlines():
        if "t2sep_probe 0000:04:00.2:" not in line:
            continue
        if any(secret in line.lower() for secret in
               ("password=", "context=0x", "context_bytes=")) and \
                "context_bytes=not-logged" not in line:
            raise VerificationError("transcript appears to expose secret material")
        match = ENVELOPE.search(line)
        if match:
            phase, direction = match[1], match[2]
            words = tuple(int(match[index], 16) for index in range(3, 7))
            if (words[3] & ((1 << 18) | (1 << 19)) or
                    (direction == "request" and words[3] != 0)):
                raise VerificationError("ACM envelope changed or is reordered")
            events.append(envelope_event(phase, direction, words))
            continue
        found = [value for marker, value in MARKERS.items() if marker in line]
        if found:
            if len(found) != 1:
                raise VerificationError("ACM lifecycle marker is ambiguous")
            name, fields = found[0]
            if not all(field in line for field in fields):
                raise VerificationError(f"malformed ACM stage: {name}")
            if name in ("current-request", "legacy-request"):
                uid_match = re.search(r"subject_uid=([0-9]+)(?:\s|$)", line)
                if not uid_match or int(uid_match[1]) > 0xffffffff:
                    raise VerificationError("ACM context subject UID is malformed")
                if subject_uid is None:
                    subject_uid = int(uid_match[1])
                elif subject_uid != int(uid_match[1]):
                    raise VerificationError("ACM context subject UID changed during fallback")
            if name == "create-success":
                expected_length = ("length=21" if events and events[-1] ==
                                   envelope_event(
                                       "context-create-24", "reply",
                                       (0x0015010A, 0, 0, 0)) else "length=17")
                if expected_length not in line:
                    raise VerificationError("ACM context response length changed")
            events.append(("marker", name))
            continue
        if "issued Apple CPU-stop value 5" in line:
            if tuple(events) not in (MODERN_EVENTS, FALLBACK_EVENTS) or stopped:
                raise VerificationError("ACM lifecycle did not complete before CPU stop")
            stopped = True
    if tuple(events) not in (MODERN_EVENTS, FALLBACK_EVENTS) or not stopped:
        raise VerificationError("ACM context lifecycle transcript is incomplete")


def verify(text: str) -> None:
    if not isinstance(text, str):
        raise VerificationError("ACM context transcript must be text")
    try:
        if ool.verify(text, 10) != ((1, 10), (1, 10)):
            raise VerificationError("ACM OOL profile changed")
    except ool.VerificationError as error:
        raise VerificationError(str(error)) from error
    verify_service(text)


def main() -> None:
    try:
        verify(sys.stdin.read())
    except (ValueError, VerificationError) as error:
        print(f"ACM context lifecycle verification failed: {error}", file=sys.stderr)
        raise SystemExit(1)
    print("verified ephemeral ACM context create/delete lifecycle")


if __name__ == "__main__":
    main()
