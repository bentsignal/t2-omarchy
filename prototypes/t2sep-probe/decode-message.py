#!/usr/bin/env python3
"""Decode one 128-bit Intel T2 SEP FIFO message without accessing hardware."""

from __future__ import annotations

import argparse
from dataclasses import dataclass


class DiscoveryError(ValueError):
    pass


class ControlMessageError(ValueError):
    pass


PAGE_SIZE = 4096
CONTROL_ENDPOINT = 0
SET_OOL_IN = 2
SET_OOL_OUT = 3
TRANSPORT_ERROR_FLAGS = (1 << 18) | (1 << 19)


def encode_ool_registration(target_endpoint: int, dma_address: int, size: int,
                            *, incoming_to_sep: bool) -> list[int]:
    """Encode, but never send, Intel AppleSEPControl's SET_REMOTE_DMA message."""
    if (isinstance(target_endpoint, bool) or not isinstance(target_endpoint, int)
            or not 1 <= target_endpoint <= 0xFC):
        raise ControlMessageError("target endpoint is outside the service endpoint range")
    if (isinstance(dma_address, bool) or not isinstance(dma_address, int)
            or dma_address < 0 or dma_address % PAGE_SIZE):
        raise ControlMessageError("DMA address must be nonnegative and page aligned")
    page_address = dma_address >> 12
    if page_address > 0xFFFFFFFF:
        raise ControlMessageError("DMA page address does not fit the Intel wire field")
    if (isinstance(size, bool) or not isinstance(size, int)
            or not 0 < size <= 0xFFFFFFFF or size % PAGE_SIZE):
        raise ControlMessageError("OOL size must be a positive page multiple fitting 32 bits")
    if page_address + size // PAGE_SIZE - 1 > 0xFFFFFFFF:
        raise ControlMessageError("OOL DMA range exceeds the Intel page-address field")
    if not isinstance(incoming_to_sep, bool):
        raise ControlMessageError("incoming_to_sep must be boolean")
    opcode = SET_OOL_IN if incoming_to_sep else SET_OOL_OUT
    return [CONTROL_ENDPOINT | opcode << 16 | target_endpoint << 24,
            page_address, size, 0]


def tag_control_request(words: list[int], tag: int) -> list[int]:
    """Insert the nonzero byte tag allocated by AppleSEPControl."""
    if (not isinstance(words, (list, tuple)) or len(words) != 4
            or any(isinstance(word, bool) or not isinstance(word, int)
                   or not 0 <= word <= 0xFFFFFFFF for word in words)):
        raise ControlMessageError("control request must contain exactly four u32 words")
    if words[0] & 0xFF:
        raise ControlMessageError("control request is not for endpoint zero")
    if words[0] & 0xFF00:
        raise ControlMessageError("control request already has a tag")
    if words[3] != 0:
        raise ControlMessageError("host control metadata word must be zero")
    if isinstance(tag, bool) or not isinstance(tag, int) or not 1 <= tag <= 0xFF:
        raise ControlMessageError("control tag must be a nonzero byte")
    tagged = list(words)
    tagged[0] |= tag << 8
    return tagged


def validate_control_reply(request: list[int], response: list[int],
                           *, expected_opcode: int,
                           expected_target: int) -> tuple[int, int, int, int]:
    """Validate a reply when its opcode and target are independently known."""
    for name, words in (("request", request), ("response", response)):
        if (not isinstance(words, (list, tuple)) or len(words) != 4
                or any(isinstance(word, bool) or not isinstance(word, int)
                       or not 0 <= word <= 0xFFFFFFFF for word in words)):
            raise ControlMessageError(f"control {name} must contain exactly four u32 words")
    if (isinstance(expected_opcode, bool) or not isinstance(expected_opcode, int)
            or not 0 <= expected_opcode <= 0xFF):
        raise ControlMessageError("expected reply opcode is not an unsigned byte")
    if (isinstance(expected_target, bool) or not isinstance(expected_target, int)
            or not 0 <= expected_target <= 0xFF):
        raise ControlMessageError("expected reply target is not an unsigned byte")
    request_endpoint = request[0] & 0xFF
    request_tag = (request[0] >> 8) & 0xFF
    request_target = (request[0] >> 24) & 0xFF
    response_endpoint = response[0] & 0xFF
    response_tag = (response[0] >> 8) & 0xFF
    response_opcode = (response[0] >> 16) & 0xFF
    response_target = (response[0] >> 24) & 0xFF
    if request_endpoint or not request_tag:
        raise ControlMessageError("control request is not tagged endpoint zero")
    if response_endpoint != CONTROL_ENDPOINT:
        raise ControlMessageError("control reply is not for endpoint zero")
    if response_tag != request_tag:
        raise ControlMessageError("control reply tag does not match request")
    if request_target != expected_target or response_target != expected_target:
        raise ControlMessageError("control request/reply target is not independently verified")
    if response_opcode != expected_opcode:
        raise ControlMessageError("control reply opcode is not independently verified")
    if response[3] & TRANSPORT_ERROR_FLAGS:
        raise ControlMessageError("control reply has transport error flags")
    if response[1] != 0:
        raise ControlMessageError(f"control reply status is nonzero: 0x{response[1]:08x}")
    return tuple(response)


@dataclass(frozen=True)
class EndpointInfo:
    endpoint_id: int
    name: int
    limits: tuple[int, int, int, int] | None = None


class DiscoveryTable:
    """Fail-closed model of AppleSEPDiscovery's advertisement table."""

    MAX_RECORDS = 64

    def __init__(self, *, max_records: int = MAX_RECORDS) -> None:
        if (isinstance(max_records, bool) or not isinstance(max_records, int)
                or not 1 <= max_records <= self.MAX_RECORDS):
            raise DiscoveryError("discovery record cap must be between 1 and 64")
        self._by_id: dict[int, EndpointInfo] = {}
        self._ids_by_name: dict[int, int] = {}
        self._max_records = max_records
        self._records = 0
        self._awaiting_limits: int | None = None

    @property
    def endpoints(self) -> tuple[EndpointInfo, ...]:
        return tuple(self._by_id.values())

    def accept(self, words: list[int]) -> EndpointInfo:
        if (not isinstance(words, (list, tuple)) or len(words) != 4
                or any(isinstance(word, bool) or not isinstance(word, int)
                       or not 0 <= word <= 0xFFFFFFFF for word in words)):
            raise DiscoveryError("discovery record must contain exactly four u32 words")
        self._records += 1
        if self._records > self._max_records:
            raise DiscoveryError("discovery record cap exceeded")
        word0, word1, word2, word3 = words
        endpoint = word0 & 0xff
        tag = (word0 >> 8) & 0xff
        opcode = (word0 >> 16) & 0xff
        endpoint_id = (word0 >> 24) & 0xff

        if endpoint != 0xfd:
            raise DiscoveryError(f"message is for endpoint 0x{endpoint:02x}, not discovery")
        if tag:
            raise DiscoveryError("discovery message has a nonzero tag")
        if word2:
            raise DiscoveryError("discovery message has a nonzero reserved word")
        if word3 & ((1 << 18) | (1 << 19)):
            raise DiscoveryError("discovery message has transport error flags")
        if not 1 <= endpoint_id <= 0xFC:
            raise DiscoveryError("advertised endpoint ID is outside the service range")

        if opcode == 0:
            if self._awaiting_limits is not None:
                raise DiscoveryError("endpoint identity was not followed by its OOL limits")
            if endpoint_id in self._by_id:
                raise DiscoveryError(f"duplicate endpoint ID 0x{endpoint_id:02x}")
            if word1 in self._ids_by_name:
                raise DiscoveryError(f"duplicate endpoint name {fourcc(word1)!r}")
            if any(not 0x20 <= byte <= 0x7E for byte in word1.to_bytes(4, "little")):
                raise DiscoveryError("endpoint name is not a printable fourcc")
            info = EndpointInfo(endpoint_id, word1)
            self._by_id[endpoint_id] = info
            self._ids_by_name[word1] = endpoint_id
            self._awaiting_limits = endpoint_id
            return info

        if opcode == 1:
            info = self._by_id.get(endpoint_id)
            if info is None:
                raise DiscoveryError(f"OOL limits precede endpoint ID 0x{endpoint_id:02x}")
            if info.limits is not None:
                raise DiscoveryError(f"duplicate OOL limits for endpoint ID 0x{endpoint_id:02x}")
            if self._awaiting_limits != endpoint_id:
                raise DiscoveryError("OOL limits do not immediately follow their identity")
            limits = tuple((word1 >> shift) & 0xff for shift in (0, 8, 16, 24))
            if limits[0] > limits[1] or limits[2] > limits[3]:
                raise DiscoveryError("OOL limits have an inverted range")
            updated = EndpointInfo(info.endpoint_id, info.name, limits)
            self._by_id[endpoint_id] = updated
            self._awaiting_limits = None
            return updated

        raise DiscoveryError(f"unknown discovery opcode 0x{opcode:02x}")

    def finalize_sbio(self, *, send_size: int = 0x4000,
                      receive_size: int = 0x4B000) -> EndpointInfo:
        """Require the exact recovered sbio endpoint and usable OOL limits."""
        if self._awaiting_limits is not None:
            raise DiscoveryError("discovery ended before the final OOL limits record")
        endpoint = self._by_id.get(0x08)
        if endpoint is None or endpoint.name != 0x6F696273:
            raise DiscoveryError("discovery did not advertise sbio at endpoint 0x08")
        try:
            validate_ool_sizes(endpoint, send_size, receive_size)
        except ControlMessageError as error:
            raise DiscoveryError("sbio OOL limits do not cover the recovered buffers") from error
        return endpoint


def validate_ool_sizes(endpoint: EndpointInfo, send_size: int, receive_size: int) -> None:
    """Require page-aligned buffer sizes inside an endpoint's advertised limits."""
    if not isinstance(endpoint, EndpointInfo):
        raise ControlMessageError("endpoint must be EndpointInfo")
    if endpoint.limits is None:
        raise ControlMessageError("endpoint has no advertised OOL limits")
    if (not isinstance(endpoint.limits, tuple) or len(endpoint.limits) != 4
            or any(isinstance(limit, bool) or not isinstance(limit, int)
                   or not 0 <= limit <= 0xFF for limit in endpoint.limits)):
        raise ControlMessageError("endpoint OOL limits are malformed")
    if (isinstance(send_size, bool) or not isinstance(send_size, int)
            or isinstance(receive_size, bool) or not isinstance(receive_size, int)
            or send_size <= 0 or receive_size <= 0
            or send_size % PAGE_SIZE or receive_size % PAGE_SIZE):
        raise ControlMessageError("OOL buffer sizes must be positive page multiples")
    send_pages, receive_pages = send_size // PAGE_SIZE, receive_size // PAGE_SIZE
    in_min, in_max, out_min, out_max = endpoint.limits
    if in_min > in_max or out_min > out_max:
        raise ControlMessageError("endpoint advertised inverted OOL limits")
    if not in_min <= send_pages <= in_max:
        raise ControlMessageError("send buffer is outside advertised OOL_IN limits")
    if not out_min <= receive_pages <= out_max:
        raise ControlMessageError("receive buffer is outside advertised OOL_OUT limits")


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
