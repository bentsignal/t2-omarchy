#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Give the user-owned Touch ID view a bounded pre-freeze preparation window.

Supplement (never replace) Omarchy's secure-lock sleep monitor. No root, device,
credential, unlock, or suspend commands. logind ultimately bounds the inhibitor.
"""
import os
from pathlib import Path
import subprocess
import sys
import time

MATCH = "type='signal',sender='org.freedesktop.login1',interface='org.freedesktop.login1.Manager',member='PrepareForSleep'"


def prepare_ui():
    try:
        result = subprocess.run(
            ["omarchy", "shell", "lock", "prepareTouchIdSleep"],
            capture_output=True, text=True, timeout=1.0,
            env={**os.environ, "OMARCHY_SHELL_IPC_TIMEOUT": "0.8"},
        )
        if result.returncode or result.stdout.strip() != "prepared":
            raise RuntimeError("view did not acknowledge preparation")
        # Allow a few rendering cycles before releasing the delay inhibitor.
        # Not a promise of a displayed frame when outputs/compositor are off.
        time.sleep(0.25)
        print("Touch ID pre-sleep UI acknowledged; render grace complete.", flush=True)
        return True
    except (OSError, RuntimeError, subprocess.TimeoutExpired):
        print("Touch ID pre-sleep UI unavailable; releasing delay, password lock unchanged.", flush=True)
        return False


def monitor():
    process = subprocess.Popen(
        ["dbus-monitor", "--system", MATCH], stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, text=True,
    )
    try:
        for line in process.stdout:
            if line.strip() == "boolean true":
                prepare_ui()
                return
    finally:
        if process.poll() is None:
            process.terminate()
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=1)


def main():
    if sys.argv[1:] == ["--inhibited"]:
        monitor()
        return
    if sys.argv[1:]:
        raise SystemExit("unexpected arguments")
    os.execvp("systemd-inhibit", [
        "systemd-inhibit", "--what=sleep", "--mode=delay", "--who=T2 Touch ID UI",
        "--why=Clear stale fingerprint cue before desktop freezes",
        sys.executable, str(Path(__file__).resolve()), "--inhibited",
    ])


if __name__ == "__main__":
    main()
