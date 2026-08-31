#!/usr/bin/env python3
"""Read SKS lock state while the kernel holds a verified system keybag."""

from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path
import sys


def _load(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


input_client = _load("authorized_sks_input", "authorized-enrollment-client.py")
probe = _load("authorized_sks_probe", "sks-lock-state-probe.py")
CONFIRMATION = "I_UNDERSTAND_THIS_ONLY_READS_SKS_LOCK_STATE_WITH_AN_AUTHORIZED_BAG"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--user-id", type=int, required=True)
    parser.add_argument("--interface", default="enp4s0f1u1")
    parser.add_argument("--confirm", required=True)
    args = parser.parse_args()
    if args.confirm != CONFIRMATION:
        parser.error(f"live authorized read requires --confirm={CONFIRMATION}")

    credential = input_client.consume_stdin_credential()
    try:
        # Consuming and scrubbing the handoff proves synchronization with the
        # kernel lifecycle. No credential bytes enter the Bridge request.
        probe.LIVE_SKS_LOCK_QUERY_ENABLED = True
        results = probe.live_probe(
            user_id=args.user_id, interface=args.interface)
    finally:
        credential[:] = bytes(len(credential))
        probe.LIVE_SKS_LOCK_QUERY_ENABLED = False
    print("authorized-bag SKS lock state: " + " ".join(
        f"version={item.version},status={item.status},state={item.state},"
        f"output_length={item.output_length}"
        for item in results))


if __name__ == "__main__":
    main()
