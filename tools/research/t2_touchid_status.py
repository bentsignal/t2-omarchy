#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Publish non-authoritative, identifier-free UI status; never an auth verdict."""
from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import time

DIRECTORY = Path("/run/t2-touchid-ui")
STATES = {
    "transport": frozenset(("sleeping", "recovering", "available", "unavailable")),
    "scan": frozenset(("starting", "ready", "idle", "unavailable")),
}


def status_record(channel: str, state: str) -> dict:
    if channel not in STATES or state not in STATES[channel]:
        raise ValueError("invalid Touch ID UI state")
    return {"schema_version": 1, "channel": channel, "state": state, "updated_at": time.time()}


def publish(channel: str, state: str) -> None:
    record = status_record(channel, state)
    # UI failure must not affect real authentication, and unprivileged test
    # invocations must not try to create or alter the runtime state directory.
    if os.geteuid() != 0:
        return
    temporary = None
    try:
        info = DIRECTORY.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise OSError("unsafe status directory")
        fd, temporary = tempfile.mkstemp(prefix=".status-", dir=DIRECTORY)
        with os.fdopen(fd, "w") as stream:
            json.dump(record, stream)
            stream.write("\n")
            os.fchmod(stream.fileno(), 0o644)
        os.replace(temporary, DIRECTORY / f"{channel}.json")
        temporary = None
    except OSError:
        print("Touch ID UI status publication unavailable; authentication unchanged.", file=sys.stderr, flush=True)
    finally:
        if temporary is not None:
            try:
                os.unlink(temporary)
            except OSError:
                pass


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: t2_touchid_status.py transport|scan STATE")
    publish(sys.argv[1], sys.argv[2])
