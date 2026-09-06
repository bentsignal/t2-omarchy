#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bounded event-driven pre-arm wait over the pinned, unchanged GPL probe.

Status 90 is only a candidate early-end marker for the preparation wait, NOT
authentication, actual unlock readiness, or proof of a completed lifecycle.
The original wake/cancel cleanup, actual match, cue, and verdict stay intact.
"""
import hashlib
from pathlib import Path
import runpy
import sys
import time

SOURCE = Path("/opt/t2-touchid/src/bridge-xpc-probe.py")
EXPECTED_SHA256 = "e5c5071f07836394fbfbc48805f7b806a8f37d1482835c34cb95aa38684162c5"


def prearm_marker(events, summarize):
    for event in events:
        value = summarize(event)
        if (
            value.get("method") == "serviceStatus"
            and value.get("common_record_valid") is True
            and value.get("reserved_zero") is True
            and value.get("embedded_type") == "0xe3ff8001"
            and value.get("version") == 1
            and value.get("event_timestamp_present") is True
            and value.get("parsed_ordinal_matches") is True
            and value.get("status_code") == 90
            and value.get("status_data_length") == 0
            and value.get("data_length") == 40
        ):
            return True
    return False


def install_overlay(namespace):
    original = namespace["run_prearm_lifecycle"]
    # runpy's result may not be the functions' globals. This subprocess is
    # synchronous: intercept only inside pre-arm, and restore even on failure.
    scope = original.__globals__
    command = scope["biometric_command"]
    collect = scope["collect_timed_events"]
    summarize = scope["summarize_event"]

    def prearm(sock, user_id, identity_records, seconds, ordinary_timeout):
        seen = False
        started = time.monotonic()

        def observe_command(*args, **kwargs):
            nonlocal seen
            reply, events = command(*args, **kwargs)
            if args[1] == 4 and scope["command_succeeded"](reply):
                seen = prearm_marker(events, summarize)
            return reply, events

        def bounded_collect(sock, seconds, records, user):
            nonlocal seen
            events = []
            deadline = time.monotonic() + seconds
            while not seen:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                # The pinned collector retains framing/ack/error semantics and
                # its 100-ms socket floor. No events are discarded or invented.
                batch = collect(sock, min(0.1, remaining), records, user)
                events.extend(batch)
                seen = prearm_marker(batch, summarize)
            return events

        scope["biometric_command"] = observe_command
        scope["collect_timed_events"] = bounded_collect
        try:
            return original(sock, user_id, identity_records, seconds, ordinary_timeout)
        finally:
            scope["biometric_command"] = command
            scope["collect_timed_events"] = collect
            print(
                f"Touch ID timing: prearm elapsed_ms={(time.monotonic() - started) * 1000:.1f} "
                f"early_marker={str(seen).lower()}", file=sys.stderr, flush=True,
            )

    scope["run_prearm_lifecycle"] = prearm


def main():
    if hashlib.sha256(SOURCE.read_bytes()).hexdigest() != EXPECTED_SHA256:
        raise RuntimeError("bridge probe source changed; review overlay before use")
    namespace = runpy.run_path(str(SOURCE), run_name="_t2_bridge_probe_runtime")
    install_overlay(namespace)
    namespace["main"]()


if __name__ == "__main__":
    main()
