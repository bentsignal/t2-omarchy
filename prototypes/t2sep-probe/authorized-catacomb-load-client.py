#!/usr/bin/env python3
"""Load retained catacombs while the kernel holds an authorized system bag."""

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


external = _load("authorized_external_catacomb", "external-catacomb-load-probe.py")
CONFIRMATION = "I_UNDERSTAND_THIS_LOADS_RETAINED_MACOS_CATACOMBS_WITH_AN_AUTHORIZED_BAG"


def consume_stdin_credential() -> None:
    line = bytearray(sys.stdin.buffer.readline(34))
    try:
        if len(line) != 33 or line[-1:] != b"\n":
            raise ValueError("credential handoff had the wrong length")
        try:
            credential = bytearray.fromhex(line[:-1].decode("ascii"))
        except (UnicodeDecodeError, ValueError) as error:
            raise ValueError("credential handoff was not canonical hex") from error
        try:
            if len(credential) != 16:
                raise ValueError("credential handoff decoded to the wrong length")
        finally:
            credential[:] = bytes(len(credential))
    finally:
        line[:] = bytes(len(line))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--user-id", type=int, required=True)
    parser.add_argument("--global-path", type=Path, required=True)
    parser.add_argument("--path", type=Path, required=True)
    parser.add_argument("--interface", default="enp4s0f1u1")
    parser.add_argument("--confirm", required=True)
    args = parser.parse_args()
    if args.confirm != CONFIRMATION:
        parser.error(f"authorized load requires --confirm={CONFIRMATION}")
    consume_stdin_credential()
    external.LIVE_LOAD_ENABLED = True
    try:
        result = external.live_probe(
            user_id=args.user_id, global_path=args.global_path, path=args.path,
            interface=args.interface)
    finally:
        external.LIVE_LOAD_ENABLED = False
    print("authorized catacomb load completed: "
          f"global_status={result.global_load_status} status={result.load_status} "
          f"protected_length={result.protected_length} "
          f"identity_count={result.identity_count}")


if __name__ == "__main__":
    main()
