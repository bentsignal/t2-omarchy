#!/usr/bin/env python3
"""Load one Linux-stored catacomb and perform one bounded Touch ID match."""

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


match = _load("stored_match_probe", "match-authentication-probe.py")
store = _load("stored_match_store", "catacomb-store.py")
CONFIRMATION = "I_UNDERSTAND_THIS_ATTEMPTS_ONE_STORED_FINGERPRINT_MATCH"


def progress(event: tuple[int, int, int]) -> None:
    status, version, length = event
    print(f"match event status={status:#x} version={version} length={length}", flush=True)
    if status == match.NONTERMINAL_READY:
        print("TOUCH NOW: place an enrolled finger flat on Touch ID.", flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--user-id", type=int, required=True)
    parser.add_argument("--path", type=Path, required=True)
    parser.add_argument("--interface", default="enp4s0f1u1")
    parser.add_argument("--confirm", required=True)
    args = parser.parse_args()
    if args.confirm != CONFIRMATION:
        parser.error(f"live stored match requires --confirm={CONFIRMATION}")
    blob = store.load(args.path, expected_user_id=args.user_id)
    match.LIVE_MATCH_ENABLED = True
    try:
        result = match.live_probe(user_id=args.user_id, interface=args.interface,
                                  catacomb_blob=blob, progress=progress)
    finally:
        match.LIVE_MATCH_ENABLED = False
    print("stored fingerprint match completed: "
          f"matched={result.matched} matched_user_id={result.matched_user_id} "
          f"trusted_identity_count={result.trusted_identity_count} "
          f"catacomb_loaded={result.catacomb_loaded} "
          f"cancel_status={result.cancel_status}")
    raise SystemExit(0 if result.matched else 1)


if __name__ == "__main__":
    main()
