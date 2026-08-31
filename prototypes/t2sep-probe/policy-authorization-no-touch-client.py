#!/usr/bin/env python3
"""Consume and scrub one policy-authorized ACM form without biometric I/O."""

from __future__ import annotations

import argparse
import sys


CONFIRMATION = "I_UNDERSTAND_THIS_AUTHORIZES_ENROLLMENT_POLICY_WITHOUT_TOUCH"


def consume_context() -> bytearray:
    line = bytearray(sys.stdin.buffer.readline(34))
    try:
        if len(line) != 33 or line[-1] != 0x0A:
            raise ValueError("ACM handoff had the wrong length")
        try:
            context = bytearray.fromhex(line[:-1].decode("ascii"))
        except (UnicodeDecodeError, ValueError) as error:
            raise ValueError("ACM handoff was not canonical hex") from error
        if len(context) != 16:
            context[:] = bytes(len(context))
            raise ValueError("ACM handoff decoded to the wrong length")
        return context
    finally:
        line[:] = bytes(len(line))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--user-id", type=int, required=True)
    parser.add_argument("--interface", required=True)
    parser.add_argument("--confirm", required=True)
    args = parser.parse_args()
    if args.confirm != CONFIRMATION:
        parser.error(f"authorization-only run requires --confirm={CONFIRMATION}")
    if not 10 <= args.user_id < 0x80000000:
        parser.error("user ID is outside the supported login range")
    context = consume_context()
    context[:] = bytes(len(context))
    print("enrollment policy authorized; no biometric command or touch was requested")


if __name__ == "__main__":
    main()
