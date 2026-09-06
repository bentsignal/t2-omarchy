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
import re
import sys
import time

from t2_touchid_status import publish

SOURCE = Path("/opt/t2-touchid/src/t2-fprintd.py")
EXPECTED_SHA256 = "1cf34436fe6ae66e98229864b256b3ef1b5a21a772cb74ed50ed98acc840c336"
DIRECT_DISCOVERY = "/usr/local/libexec/t2-biometric-discover.py"
PROBE_SOURCE = "/opt/t2-touchid/src/bridge-xpc-probe.py"
PROBE_RUNTIME = "/usr/local/libexec/t2-bridge-probe-runtime.py"


def report_prearm_timing(original):
    async def consume(self, stream):
        class ForwardingStream:
            async def readline(inner):
                line = await stream.readline()
                if re.fullmatch(
                    rb"Touch ID timing: prearm elapsed_ms=[0-9]{1,9}\.[0-9] early_marker=(true|false)\n",
                    line,
                ):
                    print(line.decode("ascii").rstrip(), flush=True)
                # Preserve the original cue handling and bounded stderr buffer.
                return line
        return await original(self, ForwardingStream())
    return consume


def event_driven_probe_command(original):
    def command(self, port):
        arguments = original(self, port)
        if arguments.count(PROBE_SOURCE) != 1:
            raise RuntimeError("unexpected bridge probe command; refusing substitution")
        return [PROBE_RUNTIME if value == PROBE_SOURCE else value for value in arguments]
    return command


async def direct_discovery_port():
    process = await asyncio.create_subprocess_exec(
        sys.executable, DIRECT_DISCOVERY,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, _ = await asyncio.wait_for(process.communicate(), 5.0)
        if process.returncode != 0 or len(stdout) > 64:
            raise RuntimeError("direct directory lookup failed")
        value = stdout.strip()
        if not value.isdigit() or not 49152 <= int(value) <= 65535:
            raise RuntimeError("direct directory returned invalid port")
        return int(value)
    finally:
        if process.returncode is None:
            try:
                process.kill()
            except ProcessLookupError:
                pass
            await process.wait()


def prefer_direct_discovery(original):
    async def discover(self):
        if self.port is not None:
            return await original(self)
        try:
            port = await direct_discovery_port()
        except (OSError, RuntimeError, TimeoutError):
            print("Touch ID direct directory unavailable; using original discovery.", flush=True)
            return await original(self)
        self.port = port
        self.port_from_cache = False
        print("Touch ID endpoint obtained from direct directory.", flush=True)
        return port
    return discover


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


def cancel_verification_before_process(original):
    async def stop(self, require_running):
        # Cancel the coroutine before terminating its child. Otherwise child
        # exit can look like a stale-cache failure and launch rediscovery while
        # the original stop method is awaiting process.wait(). No await here:
        # the original backend.cancel must capture self.process before the
        # cancelled probe coroutine runs its finally block and clears it.
        task = self.verify_task
        if task is not None and not task.done():
            task.cancel()
        return await original(self, require_running=require_running)
    return timed_stage("verification-stop", stop)


def install_overlay(namespace: dict) -> None:
    original_verdict = namespace["verdict_from_result"]
    backend = namespace["T2Backend"]
    original_feedback = backend.notify_feedback
    original_verify = backend.verify
    original_cue = backend.notify_finger_requested
    device = namespace.get("FprintDevice")
    if device is not None:
        device._stop_verification = cancel_verification_before_process(device._stop_verification)

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
    if hasattr(backend, "probe_command"):
        backend.probe_command = event_driven_probe_command(backend.probe_command)
    if hasattr(backend, "_consume_probe_stderr"):
        backend._consume_probe_stderr = report_prearm_timing(backend._consume_probe_stderr)
    if hasattr(backend, "discover"):
        backend.discover = prefer_direct_discovery(backend.discover)
    # Existing cached returns and probe retry/authentication semantics remain.
    # Only a cache miss now tries the evidenced directory before a full scan.
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
