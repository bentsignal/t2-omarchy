#!/usr/bin/env python3
"""Offline ownership model for SEP endpoint OOL mappings and operations."""

from __future__ import annotations

from dataclasses import dataclass, replace

MAX_OPERATIONS = 0xFFFFFFFF


class LifecycleError(ValueError):
    pass


@dataclass(frozen=True)
class Mapping:
    identifier: str
    direction: str
    current: bool = True
    scrubbed: bool = False


class EndpointLifecycle:
    """Track mappings SEP may retain; never allocate, map, or access hardware."""

    def __init__(self, endpoint: int):
        if (isinstance(endpoint, bool) or not isinstance(endpoint, int)
                or not 1 <= endpoint <= 0xFC):
            raise LifecycleError("endpoint is outside the service range")
        self.endpoint = endpoint
        self.enabled = False
        self.transport_stopped = False
        self.sleep_held = False
        self.operations = 0
        self._mappings: dict[str, Mapping] = {}
        self._current: dict[str, str] = {}

    @property
    def mappings(self) -> tuple[Mapping, ...]:
        return tuple(self._mappings.values())

    @property
    def ready(self) -> bool:
        return (self.enabled and not self.transport_stopped
                and set(self._current) == {"send", "receive"})

    def enable(self) -> None:
        if self.enabled or self.transport_stopped:
            raise LifecycleError("endpoint cannot be enabled from its current state")
        self.enabled = True

    def commit_registration(self, direction: str, identifier: str,
                            *, control_succeeded: bool) -> None:
        if not self.enabled or self.transport_stopped:
            raise LifecycleError("OOL registration requires an enabled endpoint")
        if direction not in ("send", "receive"):
            raise LifecycleError("mapping direction must be send or receive")
        if not isinstance(identifier, str) or not identifier:
            raise LifecycleError("mapping identifier must be a nonempty string")
        if not isinstance(control_succeeded, bool):
            raise LifecycleError("control result must be boolean")
        if identifier in self._mappings:
            raise LifecycleError("mapping identifier is already retained")
        if not control_succeeded:
            return
        previous = self._current.get(direction)
        if previous is not None:
            self._mappings[previous] = replace(
                self._mappings[previous], current=False)
        self._mappings[identifier] = Mapping(identifier, direction)
        self._current[direction] = identifier

    def begin_operation(self) -> None:
        if not self.ready or self.sleep_held:
            raise LifecycleError("endpoint is not available for an operation")
        if self.operations == MAX_OPERATIONS:
            raise LifecycleError("operation counter would overflow")
        self.operations += 1

    def end_operation(self) -> None:
        if self.operations == 0:
            raise LifecycleError("operation counter would underflow")
        self.operations -= 1

    def hold_for_sleep(self) -> None:
        if self.sleep_held or self.transport_stopped:
            raise LifecycleError("endpoint cannot enter sleep hold")
        if self.operations:
            raise LifecycleError("active operations must drain before sleep hold")
        self.sleep_held = True

    def resume(self) -> None:
        if not self.sleep_held or self.transport_stopped:
            raise LifecycleError("endpoint is not sleep-held")
        self.sleep_held = False

    def stop_transport(self) -> None:
        if self.transport_stopped:
            raise LifecycleError("transport is already stopped")
        if self.operations:
            raise LifecycleError("active operations must drain before transport stop")
        self.transport_stopped = True
        self.sleep_held = False

    def scrub(self, identifier: str) -> None:
        if not self.transport_stopped:
            raise LifecycleError("mapping cannot be scrubbed before transport stop")
        mapping = self._mappings.get(identifier)
        if mapping is None:
            raise LifecycleError("mapping is not retained")
        self._mappings[identifier] = replace(mapping, scrubbed=True)

    def release(self, identifier: str) -> None:
        if not self.transport_stopped:
            raise LifecycleError("mapping cannot be released before transport stop")
        mapping = self._mappings.get(identifier)
        if mapping is None:
            raise LifecycleError("mapping is not retained")
        if not mapping.scrubbed:
            raise LifecycleError("mapping must be scrubbed before release")
        if self._current.get(mapping.direction) == identifier:
            del self._current[mapping.direction]
        del self._mappings[identifier]
