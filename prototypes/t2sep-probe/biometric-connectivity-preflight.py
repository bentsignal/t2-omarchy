#!/usr/bin/env python3
"""Read-only proof that the live T2 BiometricKit route is usable."""

from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path
import sys


def _load():
    path = Path(__file__).with_name("coupled-bridge-query.py")
    spec = importlib.util.spec_from_file_location("biometric_preflight_coupled", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


coupled = _load()
CONFIRMATION = "I_UNDERSTAND_THIS_ONLY_QUERIES_THE_T2_BRIDGE_VERSION"
EXPECTED_REPLY = (0, 3)


class PreflightError(RuntimeError):
    pass


def verify(interface: str, timeout: float = 5.0) -> tuple[int, int]:
    original = coupled.LIVE_COUPLED_QUERY_ENABLED
    try:
        coupled.LIVE_COUPLED_QUERY_ENABLED = True
        reply = coupled.live_query(interface, timeout)
    except Exception as error:
        raise PreflightError("T2 BiometricKit connectivity preflight failed") from error
    finally:
        coupled.LIVE_COUPLED_QUERY_ENABLED = original
    if reply != EXPECTED_REPLY:
        raise PreflightError(f"unexpected read-only bridge reply {reply!r}")
    return reply


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--interface", default="enp4s0f1u1")
    parser.add_argument("--confirm", required=True)
    args = parser.parse_args()
    if args.confirm != CONFIRMATION:
        parser.error(f"preflight requires --confirm={CONFIRMATION}")
    status, version = verify(args.interface)
    print(f"T2 BiometricKit preflight passed: status={status} bridge_version={version}")


if __name__ == "__main__":
    main()
