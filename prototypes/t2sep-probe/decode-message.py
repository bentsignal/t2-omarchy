#!/usr/bin/env python3
"""Decode one 128-bit Intel T2 SEP FIFO message without accessing hardware."""

from __future__ import annotations

import argparse


def fourcc(value: int) -> str:
    raw = value.to_bytes(4, "little")
    return "".join(chr(byte) if 0x20 <= byte <= 0x7e else "." for byte in raw)


def decode(words: list[int]) -> str:
    word0, word1, word2, word3 = words
    endpoint = word0 & 0xff
    tag = (word0 >> 8) & 0xff
    opcode = (word0 >> 16) & 0xff
    param = (word0 >> 24) & 0xff
    lines = [
        f"endpoint=0x{endpoint:02x} tag=0x{tag:02x} "
        f"opcode=0x{opcode:02x} param=0x{param:02x}",
        f"data=0x{word1:08x} trailing=0x{word2:08x}:0x{word3:08x}",
    ]

    if endpoint != 0xfd:
        return "\n".join(lines)
    if word2 or word3:
        lines.append("discovery=invalid (nonzero trailing words)")
    elif opcode == 0:
        lines.append(
            f"discovery=identity endpoint_id=0x{param:02x} "
            f"name={fourcc(word1)!r} (0x{word1:08x})"
        )
    elif opcode == 1:
        limits = [(word1 >> shift) & 0xff for shift in (0, 8, 16, 24)]
        lines.append(
            f"discovery=ool-limits endpoint_id=0x{param:02x} "
            f"in_pages={limits[0]}..{limits[1]} "
            f"out_pages={limits[2]}..{limits[3]}"
        )
    else:
        lines.append("discovery=unknown-opcode")
    return "\n".join(lines)


def parse_word(value: str) -> int:
    word = int(value, 16)
    if not 0 <= word <= 0xffffffff:
        raise argparse.ArgumentTypeError("each word must fit in 32 bits")
    return word


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("words", nargs=4, type=parse_word, metavar="WORD")
    args = parser.parse_args()
    print(decode(args.words))


if __name__ == "__main__":
    main()
