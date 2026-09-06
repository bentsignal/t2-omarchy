#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Overlay error feedback without modifying the pinned external GPL facade.

The original success/identity checks remain authoritative. Missing terminal
results are errors, not evidence of an unrecognized finger. Errors retain
password fallback and must not trigger the negative-match notification.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import runpy
import asyncio
import time

from t2_touchid_status import publish

SOURCE = Path("/opt/t2-touchid/src/t2-fprintd.py")
EXPECTED_SHA256 = "1cf34436fe6ae66e98229864b256b3ef1b5a21a772cb74ed50ed98acc840c336"


def timed_stage(label, original):
    async def wrapped(self, *args, **kwargs):
        started = time.monotonic()
        print(f"Touch ID timing: {label} begin", flush=True)
        outcome = "done"
        try:
            return await original(self, *args, **kwargs)
        except asyncio.CancelledError:
            outcome = "cancelled"
            raise
        except Exception:
            outcome = "failed"
            raise
        finally:
            elapsed_ms = (time.monotonic() - started) * 1000
            print(f"Touch ID timing: {label} {outcome} elapsed_ms={elapsed_ms:.1f}", flush=True)
    return wrapped


def install_overlay(namespace: dict) -> None:
    original_verdict = namespace["verdict_from_result"]
    backend = namespace["T2Backend"]
    original_feedback = backend.notify_feedback
    original_verify = backend.verify
    original_cue = backend.notify_finger_requested

    def verdict(result: object) -> str:
        events = result.get("match_events") if isinstance(result, dict) else None
        if not isinstance(events, list) or not any(
            isinstance(event, dict) and event.get("event_kind") == "match_result"
            for event in events
        ):
            raise RuntimeError("no terminal T2 match result; not a fingerprint rejection")
        return original_verdict(result)

    async def feedback(self, result: str) -> None:
        if result in ("verify-match", "verify-no-match"):
            await original_feedback(self, result)
        else:
            print(
                "Touch ID verification unavailable (transport/protocol error); "
                "no fingerprint-rejection notification sent.",
                flush=True,
            )

    async def verify(self):
        self._t2_verify_started = time.monotonic()
        publish("scan", "starting")
        try:
            result = await original_verify(self)
        except asyncio.CancelledError:
            publish("scan", "idle")
            raise
        except Exception:
            publish("scan", "unavailable")
            raise
        else:
            publish("scan", "idle")
            return result

    async def cue(self):
        # The pinned parser calls this only after its exact accepted-start cue.
        # A running service or a listed enrolled finger is not readiness.
        publish("scan", "ready")
        started = getattr(self, "_t2_verify_started", None)
        if started is not None:
            print(f"Touch ID timing: verify-to-ready elapsed_ms={(time.monotonic() - started) * 1000:.1f}", flush=True)
        await original_cue(self)

    # runpy's returned dictionary is not necessarily the functions' globals.
    backend.verify.__globals__["verdict_from_result"] = verdict
    backend._t2_verdict = staticmethod(verdict)
    backend.verify = verify
    backend.notify_finger_requested = cue
    backend.notify_feedback = feedback
    # Time existing calls, including cached discover() returns; do not change
    # caching, retries, packets, timeout values, or return/exception semantics.
    for name, label in (("discover", "discovery"), ("_run_probe", "probe")):
        if hasattr(backend, name):
            setattr(backend, name, timed_stage(label, getattr(backend, name)))


def main() -> None:
    if hashlib.sha256(SOURCE.read_bytes()).hexdigest() != EXPECTED_SHA256:
        raise RuntimeError("fprintd source changed; review the runtime overlay before use")
    namespace = runpy.run_path(str(SOURCE), run_name="_t2_fprintd_runtime")
    install_overlay(namespace)
    publish("scan", "idle")
    try:
        namespace["main"]()
    finally:
        publish("scan", "unavailable")


if __name__ == "__main__":
    main()
