#!/usr/bin/env python3
"""Strict, socket-free DNS-SD discovery for the T2 RSD directory endpoint."""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import struct


SERVICE_NAME = "_remoted._tcp.local."
INSTANCE_NAME = "ncm._remoted._tcp.local."
T2_LINK_LOCAL_ADDRESS = "fe80::aede:48ff:fe33:4455"
DNS_HEADER = struct.Struct("!HHHHHH")
TYPE_PTR = 12
TYPE_AAAA = 28
TYPE_SRV = 33
CLASS_IN = 1
MAX_DATAGRAM = 9000
MAX_DATAGRAMS = 16
MAX_TOTAL = 65536
MAX_RECORDS = 64
MAX_POINTERS = 32


class MDNSError(ValueError):
    pass


class MDNSIncompleteError(MDNSError):
    pass


@dataclass(frozen=True)
class DiscoveredRSDService:
    instance: str
    target: str
    port: int
    source_address: str
    server_datagrams: tuple[bytes, ...]


@dataclass(frozen=True)
class DiscoveredRSDEndpoint:
    endpoint: tuple[str, int, int, int]
    evidence: DiscoveredRSDService


def _canonical_name(labels: list[str]) -> str:
    return ".".join(labels).casefold() + "."


def _decode_name(packet: bytes, start: int, *, wire_limit: int | None = None) -> tuple[str, int]:
    if not 0 <= start < len(packet):
        raise MDNSError("DNS name starts outside packet")
    labels: list[str] = []
    cursor = start
    consumed_end: int | None = None
    visited: set[int] = set()
    for _ in range(MAX_POINTERS):
        if cursor >= len(packet):
            raise MDNSError("truncated DNS name")
        length = packet[cursor]
        if length & 0xC0 == 0xC0:
            if cursor + 2 > len(packet):
                raise MDNSError("truncated DNS compression pointer")
            if wire_limit is not None and cursor + 2 > wire_limit:
                raise MDNSError("DNS name exceeds record boundary")
            pointer = ((length & 0x3F) << 8) | packet[cursor + 1]
            if pointer >= len(packet) or pointer in visited:
                raise MDNSError("invalid or cyclic DNS compression pointer")
            visited.add(pointer)
            if consumed_end is None:
                consumed_end = cursor + 2
            cursor = pointer
            continue
        if length & 0xC0:
            raise MDNSError("reserved DNS label encoding")
        cursor += 1
        if length == 0:
            if consumed_end is None:
                consumed_end = cursor
            if wire_limit is not None and consumed_end > wire_limit:
                raise MDNSError("DNS name exceeds record boundary")
            if not labels:
                return ".", consumed_end
            return _canonical_name(labels), consumed_end
        if length > 63 or cursor + length > len(packet):
            raise MDNSError("invalid or truncated DNS label")
        if wire_limit is not None and consumed_end is None and cursor + length > wire_limit:
            raise MDNSError("DNS name exceeds record boundary")
        raw = packet[cursor:cursor + length]
        try:
            label = raw.decode("ascii")
        except UnicodeDecodeError as error:
            raise MDNSError("non-ASCII DNS-SD label") from error
        if not label or any(ord(character) < 0x21 or ord(character) > 0x7E
                            for character in label):
            raise MDNSError("invalid DNS-SD label")
        labels.append(label)
        if sum(len(item) + 1 for item in labels) > 254:
            raise MDNSError("DNS name is too long")
        cursor += length
    raise MDNSError("too many DNS compression pointers")


def _encode_name(name: str) -> bytes:
    if not isinstance(name, str) or not name.endswith("."):
        raise MDNSError("DNS name must be absolute")
    output = bytearray()
    for label in name[:-1].split("."):
        raw = label.encode("ascii")
        if not 1 <= len(raw) <= 63:
            raise MDNSError("DNS label length is invalid")
        output.append(len(raw))
        output += raw
    output.append(0)
    if len(output) > 255:
        raise MDNSError("DNS name is too long")
    return bytes(output)


def build_ptr_query() -> bytes:
    """Build the exact multicast PTR query without opening a socket."""
    return DNS_HEADER.pack(0, 0, 1, 0, 0, 0) + _encode_name(SERVICE_NAME) + struct.pack("!HH", TYPE_PTR, CLASS_IN)


def build_srv_query(*, unicast_response: bool = False) -> bytes:
    """Build macOS remoted's direct named-instance lookup, offline."""
    if not isinstance(unicast_response, bool):
        raise MDNSError("unicast-response selector must be boolean")
    question_class = CLASS_IN | (0x8000 if unicast_response else 0)
    return (DNS_HEADER.pack(0, 0, 1, 0, 0, 0) + _encode_name(INSTANCE_NAME)
            + struct.pack("!HH", TYPE_SRV, question_class))


def _parse_message(packet: bytes) -> tuple[set[str], dict[str, tuple[int, str]], set[tuple[str, str]]]:
    if not isinstance(packet, bytes) or not DNS_HEADER.size <= len(packet) <= MAX_DATAGRAM:
        raise MDNSError("mDNS datagram size is invalid")
    identifier, flags, questions, answers, authority, additional = DNS_HEADER.unpack_from(packet)
    if identifier != 0 or not flags & 0x8000 or flags & 0x0200:
        raise MDNSError("not a complete mDNS response")
    if flags & 0x780F:
        raise MDNSError("mDNS opcode or response code is unsupported")
    record_count = answers + authority + additional
    if questions > 8 or record_count > MAX_RECORDS:
        raise MDNSError("mDNS section count exceeds cap")
    offset = DNS_HEADER.size
    for _ in range(questions):
        _, offset = _decode_name(packet, offset)
        if offset + 4 > len(packet):
            raise MDNSError("truncated mDNS question")
        offset += 4
    pointers: set[str] = set()
    services: dict[str, tuple[int, str]] = {}
    addresses: set[tuple[str, str]] = set()
    for _ in range(record_count):
        owner, offset = _decode_name(packet, offset)
        if offset + 10 > len(packet):
            raise MDNSError("truncated mDNS record")
        record_type, record_class, _ttl, length = struct.unpack_from("!HHIH", packet, offset)
        offset += 10
        end = offset + length
        if end > len(packet) or record_class & 0x7FFF != CLASS_IN:
            raise MDNSError("invalid mDNS record boundary or class")
        if record_type == TYPE_PTR and owner == SERVICE_NAME:
            instance, consumed = _decode_name(packet, offset, wire_limit=end)
            if consumed != end or not instance.endswith("." + SERVICE_NAME):
                raise MDNSError("invalid _remoted PTR target")
            pointers.add(instance)
        elif record_type == TYPE_SRV:
            if length < 7:
                raise MDNSError("truncated SRV record")
            _priority, _weight, port = struct.unpack_from("!HHH", packet, offset)
            target, consumed = _decode_name(packet, offset + 6, wire_limit=end)
            if consumed != end or not 1 <= port <= 65535 or target == ".":
                raise MDNSError("invalid SRV endpoint")
            previous = services.get(owner)
            if previous is not None and previous != (port, target):
                raise MDNSError("conflicting SRV endpoints")
            services[owner] = (port, target)
        elif record_type == TYPE_AAAA:
            if length != 16:
                raise MDNSError("invalid AAAA record")
            addresses.add((owner, str(ipaddress.IPv6Address(packet[offset:end]))))
        offset = end
    if offset != len(packet):
        raise MDNSError("surplus bytes after mDNS message")
    return pointers, services, addresses


class PassiveMDNSDiscovery:
    """Accumulate bounded T2-sourced mDNS datagrams and prove one RSD SRV."""

    def __init__(self) -> None:
        self._pointers: set[str] = set()
        self._services: dict[str, tuple[int, str]] = {}
        self._addresses: set[tuple[str, str]] = set()
        self._datagrams: list[bytes] = []
        self._total = 0

    def feed(self, packet: bytes, *, source_address: str) -> None:
        try:
            canonical_source = str(ipaddress.IPv6Address(source_address.split("%", 1)[0]))
        except (ipaddress.AddressValueError, AttributeError) as error:
            raise MDNSError("invalid mDNS source address") from error
        if canonical_source != T2_LINK_LOCAL_ADDRESS:
            raise MDNSError("mDNS response did not originate from the proven T2 address")
        if len(self._datagrams) >= MAX_DATAGRAMS or self._total + len(packet) > MAX_TOTAL:
            raise MDNSError("mDNS transcript exceeds cap")
        pointers, services, addresses = _parse_message(packet)
        for owner, endpoint in services.items():
            previous = self._services.get(owner)
            if previous is not None and previous != endpoint:
                raise MDNSError("conflicting cross-datagram SRV endpoints")
            self._services[owner] = endpoint
        self._pointers.update(pointers)
        self._addresses.update(addresses)
        self._datagrams.append(packet)
        self._total += len(packet)

    def finish(self) -> DiscoveredRSDService:
        endpoint = self._services.get(INSTANCE_NAME)
        if endpoint is None:
            raise MDNSIncompleteError("mDNS transcript does not yet prove an RSD service")
        if self._pointers and INSTANCE_NAME not in self._pointers:
            raise MDNSError("mDNS PTR evidence conflicts with the named NCM instance")
        port, target = endpoint
        target_addresses = {address for owner, address in self._addresses if owner == target}
        if target_addresses and target_addresses != {T2_LINK_LOCAL_ADDRESS}:
            raise MDNSError("RSD target AAAA conflicts with the proven T2 address")
        return DiscoveredRSDService(INSTANCE_NAME, target, port,
                                    T2_LINK_LOCAL_ADDRESS,
                                    tuple(self._datagrams))


def endpoint_from_transcript(datagrams: tuple[bytes, ...],
                             source_addresses: tuple[str, ...],
                             interface_index: int) -> DiscoveredRSDEndpoint:
    """Validate a complete same-boot transcript and bind its SRV port."""
    if (not isinstance(datagrams, tuple) or not datagrams
            or not isinstance(source_addresses, tuple)
            or len(datagrams) != len(source_addresses)):
        raise MDNSError("mDNS transcript and sources must be equal nonempty tuples")
    if (isinstance(interface_index, bool) or not isinstance(interface_index, int)
            or not 1 <= interface_index < 1 << 32):
        raise MDNSError("interface index is out of range")
    parser = PassiveMDNSDiscovery()
    for packet, source in zip(datagrams, source_addresses, strict=True):
        parser.feed(packet, source_address=source)
    evidence = parser.finish()
    return DiscoveredRSDEndpoint(
        (evidence.source_address, evidence.port, 0, interface_index), evidence)


if __name__ == "__main__":
    print(build_srv_query().hex())
