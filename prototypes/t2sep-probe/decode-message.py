#!/usr/bin/env python3
"""Decode one 128-bit Intel T2 SEP FIFO message without accessing hardware."""

from __future__ import annotations

import argparse
from dataclasses import dataclass


class DiscoveryError(ValueError):
    pass


@dataclass(frozen=True)
class EndpointInfo:
    endpoint_id: int
    name: int
    limits: tuple[int, int, int, int] | None = None


class DiscoveryTable:
    """Fail-closed model of AppleSEPDiscovery's advertisement table."""

    MAX_ENDPOINTS = 253

    def __init__(self) -> None:
        self._by_id: dict[int, EndpointInfo] = {}
        self._ids_by_name: dict[int, int] = {}

    @property
    def endpoints(self) -> tuple[EndpointInfo, ...]:
        return tuple(self._by_id.values())

    def accept(self, words: list[int]) -> EndpointInfo:
        word0, word1, word2, word3 = words
        endpoint = word0 & 0xff
        opcode = (word0 >> 16) & 0xff
        endpoint_id = (word0 >> 24) & 0xff

        if endpoint != 0xfd:
            raise DiscoveryError(f"message is for endpoint 0x{endpoint:02x}, not discovery")
        if word2:
            raise DiscoveryError("discovery message has a nonzero reserved word")

        if opcode == 0:
            if len(self._by_id) >= self.MAX_ENDPOINTS:
                raise DiscoveryError("discovery table is full")
            if endpoint_id in self._by_id:
                raise DiscoveryError(f"duplicate endpoint ID 0x{endpoint_id:02x}")
            if word1 in self._ids_by_name:
                raise DiscoveryError(f"duplicate endpoint name {fourcc(word1)!r}")
            info = EndpointInfo(endpoint_id, word1)
            self._by_id[endpoint_id] = info
            self._ids_by_name[word1] = endpoint_id
            return info

        if opcode == 1:
            info = self._by_id.get(endpoint_id)
            if info is None:
                raise DiscoveryError(f"OOL limits precede endpoint ID 0x{endpoint_id:02x}")
            if info.limits is not None:
                raise DiscoveryError(f"duplicate OOL limits for endpoint ID 0x{endpoint_id:02x}")
            limits = tuple((word1 >> shift) & 0xff for shift in (0, 8, 16, 24))
            updated = EndpointInfo(info.endpoint_id, info.name, limits)
            self._by_id[endpoint_id] = updated
            return updated

        raise DiscoveryError(f"unknown discovery opcode 0x{opcode:02x}")


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
        f"data=0x{word1:08x} reserved=0x{word2:08x} transport=0x{word3:08x}",
    ]

    if endpoint != 0xfd:
        return "\n".join(lines)
    if word2:
        lines.append("discovery=invalid (nonzero reserved word)")
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
