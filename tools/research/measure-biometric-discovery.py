#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Time existing read-only RSD discovery without printing private endpoints.

Uses the normal operation lock; sends no BiometricKit enrollment/match commands.
Run in a bounded root service using the installed runtime virtual environment.
"""
import argparse
import asyncio
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--direct", action="store_true", help="measure the evidenced directory shortcut")
    args = parser.parse_args()
    recovery = runpy.run_path(str(Path(__file__).with_name("t2-ncm-recover.py")))
    host, interface, cached_port = recovery["parse_endpoint"](
        recovery["private_read"](recovery["CONFIG"]),
        recovery["private_read"](recovery["PORT"]),
    )
    recovery["validate_target"](interface)
    fd = recovery["lock_operation"](0)
    try:
        if not recovery["transport_reachable"](host, interface, cached_port):
            raise RuntimeError("cached peer unreachable; discovery measurement not started")
        started = time.monotonic()
        if args.direct:
            direct = runpy.run_path(str(Path(__file__).with_name("t2-biometric-discover.py")))
            discovered_port = asyncio.run(direct["query"](host, interface))
            print(json.dumps({"method": "direct-directory", "discovery_seconds": round(time.monotonic() - started, 3), "matches_cached_endpoint": discovered_port == cached_port, "identifiers_redacted": True, "biometric_commands_sent": False}))
            return
        result = subprocess.run(
            [sys.executable, "/opt/t2-touchid/src/discover-biometric-port.py"],
            env={**os.environ, "T2_TOUCHID_HOST": host, "T2_TOUCHID_INTERFACE": interface},
            capture_output=True,
            timeout=40,
            check=False,
        )
        elapsed = time.monotonic() - started
        if result.returncode != 0:
            raise RuntimeError("discovery failed; private subprocess output suppressed")
        discovered_port = int(result.stdout.strip())
        if not 49152 <= discovered_port <= 65535:
            raise RuntimeError("discovery returned invalid port")
        print(json.dumps({"discovery_seconds": round(elapsed, 3), "matches_cached_endpoint": discovered_port == cached_port, "identifiers_redacted": True, "biometric_commands_sent": False}))
    finally:
        os.close(fd)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"Discovery timing stopped ({type(error).__name__}); private details suppressed.", file=sys.stderr)
        raise SystemExit(1)
