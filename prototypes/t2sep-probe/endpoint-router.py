#!/usr/bin/env python3
"""Bounded offline model of Intel AppleSEPManager endpoint demultiplexing."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass

MAX_ROUTED_ENDPOINT = 31
RING_STORAGE = 32
RING_CAPACITY = RING_STORAGE - 1
TRANSPORT_ERROR_FLAGS = (1 << 18) | (1 << 19)


class RouterError(ValueError):
    pass


class QueueFull(RouterError):
    pass


def _u32_words(values: object) -> tuple[int, int, int, int]:
    if not isinstance(values, (list, tuple)) or len(values) != 4:
        raise RouterError("routed FIFO record must contain exactly four words")
    for value in values:
        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 0xFFFFFFFF:
            raise RouterError("routed FIFO words must be unsigned 32-bit values")
    return tuple(values)  # type: ignore[return-value]


@dataclass(frozen=True)
class EndpointMessage:
    words: tuple[int, int, int]

    @property
    def endpoint(self) -> int:
        return self.words[0] & 0xFF


class EndpointQueue:
    def __init__(self, endpoint: int):
        if (isinstance(endpoint, bool) or not isinstance(endpoint, int)
                or not 0 <= endpoint <= MAX_ROUTED_ENDPOINT):
            raise RouterError("endpoint is outside the normal routed range")
        self.endpoint = endpoint
        self.enabled = False
        self._messages: deque[EndpointMessage] = deque()

    @property
    def pending(self) -> int:
        return len(self._messages)

    def enable(self) -> None:
        if self.enabled:
            raise RouterError("endpoint queue is already enabled")
        self.enabled = True

    def disable(self) -> None:
        if not self.enabled:
            raise RouterError("endpoint queue is already disabled")
        self.enabled = False

    def enqueue(self, message: EndpointMessage) -> None:
        if not isinstance(message, EndpointMessage) or message.endpoint != self.endpoint:
            raise RouterError("message endpoint does not match queue")
        if len(self._messages) == RING_CAPACITY:
            raise QueueFull("endpoint ring has reached its 31-message capacity")
        self._messages.append(message)

    def dispatch_one(self) -> EndpointMessage | None:
        if not self.enabled or not self._messages:
            return None
        return self._messages.popleft()


class EndpointRouter:
    def __init__(self):
        self._queues: dict[int, EndpointQueue] = {}

    def register(self, endpoint: int) -> EndpointQueue:
        if endpoint in self._queues:
            raise RouterError("endpoint queue is already registered")
        queue = EndpointQueue(endpoint)
        self._queues[endpoint] = queue
        return queue

    def route(self, values: object) -> str:
        words = _u32_words(values)
        if words[3] & TRANSPORT_ERROR_FLAGS:
            raise RouterError("FIFO record has transport error flags")
        endpoint = words[0] & 0xFF
        if endpoint > MAX_ROUTED_ENDPOINT:
            return "dropped-unroutable"
        queue = self._queues.get(endpoint)
        if queue is None:
            return "dropped-unregistered"
        # AppleSEPManager copies only the first 12 bytes into AppleSEPMessage.
        queue.enqueue(EndpointMessage(words[:3]))
        return "queued"
