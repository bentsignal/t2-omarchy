#!/usr/bin/env python3
"""Fail-closed offline model of the Intel T2 SEP PCI FIFO registers."""

from __future__ import annotations

from dataclasses import dataclass

INBOX_STATUS = 0x108
OUTBOX_STATUS = 0x10C
INBOX_WORDS = (0x810, 0x814, 0x818, 0x81C)
OUTBOX_WORDS = (0x820, 0x824, 0x828, 0x82C)
INBOX_EMPTY = 1 << 17
OUTBOX_FULL = 1 << 16
MESSAGE_ERROR = 1 << 18
MESSAGE_FATAL = 1 << 19
MSI_INBOX_NONEMPTY = 0
MSI_OUTBOX_EMPTY = 1


class FIFOError(ValueError):
    pass


class FIFOUnavailable(FIFOError):
    pass


class FIFOTransportError(FIFOError):
    def __init__(self, flags: int):
        self.flags = flags
        super().__init__(f"SEP FIFO transport flags 0x{flags:08x}")


def _u32(name: str, value: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 0xFFFFFFFF:
        raise FIFOError(f"{name} is not an unsigned 32-bit value")


def _words(values: object) -> tuple[int, int, int, int]:
    if not isinstance(values, (list, tuple)) or len(values) != 4:
        raise FIFOError("FIFO message must contain exactly four words")
    for index, value in enumerate(values):
        _u32(f"FIFO word {index}", value)
    return tuple(values)  # type: ignore[return-value]


@dataclass(frozen=True)
class MMIOAction:
    operation: str
    offset: int
    value: int | None = None


@dataclass(frozen=True)
class ReceivedMessage:
    words: tuple[int, int, int, int]

    @property
    def transport_flags(self) -> int:
        return self.words[3] & (MESSAGE_ERROR | MESSAGE_FATAL)


def decode_msi_vector(vector: int) -> str:
    if isinstance(vector, bool) or not isinstance(vector, int):
        raise FIFOError("MSI vector is not an integer")
    if vector == MSI_INBOX_NONEMPTY:
        return "inbox-nonempty"
    if vector == MSI_OUTBOX_EMPTY:
        return "outbox-empty"
    raise FIFOError("MSI vector is outside the recovered two-vector mapping")


def plan_receive(status: int) -> tuple[MMIOAction, ...]:
    """Plan Apple's four ordered reads; never access MMIO."""
    _u32("inbox status", status)
    if status & INBOX_EMPTY:
        raise FIFOUnavailable("SEP inbox is empty")
    return tuple(MMIOAction("read", offset) for offset in INBOX_WORDS)


def decode_received(values: object) -> ReceivedMessage:
    words = _words(values)
    message = ReceivedMessage(words)
    if message.transport_flags:
        raise FIFOTransportError(message.transport_flags)
    return message


def plan_post(status: int, values: object) -> tuple[MMIOAction, ...]:
    """Plan Apple's three payload writes, zero commit, and status fence read."""
    _u32("outbox status", status)
    if status & OUTBOX_FULL:
        raise FIFOUnavailable("SEP outbox is full")
    words = _words(values)
    if words[3] != 0:
        raise FIFOError("host FIFO word 3 must be zero")
    writes = tuple(
        MMIOAction("write", offset, value)
        for offset, value in zip(OUTBOX_WORDS[:3], words[:3])
    )
    return writes + (
        MMIOAction("write", OUTBOX_WORDS[3], 0),
        MMIOAction("read", OUTBOX_STATUS),
    )
