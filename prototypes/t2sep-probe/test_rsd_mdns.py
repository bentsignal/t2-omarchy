import importlib.util
from pathlib import Path
import random
import struct
import sys
import unittest


MODULE_PATH = Path(__file__).with_name("rsd-mdns.py")
SPEC = importlib.util.spec_from_file_location("rsd_mdns", MODULE_PATH)
mdns = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = mdns
SPEC.loader.exec_module(mdns)


def name(value):
    output = bytearray()
    for label in value.rstrip(".").split("."):
        output.append(len(label))
        output += label.encode()
    return bytes(output) + b"\0"


def record(owner, kind, payload, ttl=120):
    return name(owner) + struct.pack("!HHIH", kind, 1, ttl, len(payload)) + payload


def response(records):
    return struct.pack("!HHHHHH", 0, 0x8400, 0, len(records), 0, 0) + b"".join(records)


SERVICE = "_remoted._tcp.local."
INSTANCE = "ncm._remoted._tcp.local."
TARGET = "t2.local."
SOURCE = "fe80::aede:48ff:fe33:4455"


class MDNSDiscoveryTests(unittest.TestCase):
    def test_exact_query(self):
        self.assertEqual(mdns.build_ptr_query(),
                         struct.pack("!HHHHHH", 0, 0, 1, 0, 0, 0)
                         + name(SERVICE) + struct.pack("!HH", 12, 1))
        self.assertEqual(mdns.build_srv_query(),
                         struct.pack("!HHHHHH", 0, 0, 1, 0, 0, 0)
                         + name(INSTANCE) + struct.pack("!HH", 33, 1))
        self.assertEqual(mdns.build_srv_query(unicast_response=True),
                         struct.pack("!HHHHHH", 0, 0, 1, 0, 0, 0)
                         + name(INSTANCE) + struct.pack("!HH", 33, 0x8001))
        with self.assertRaises(mdns.MDNSError):
            mdns.build_srv_query(unicast_response=1)

    def test_direct_named_srv_needs_no_ptr_browse(self):
        packet = response([record(
            INSTANCE, 33, struct.pack("!HHH", 0, 0, 59602) + name(TARGET))])
        parser = mdns.PassiveMDNSDiscovery()
        parser.feed(packet, source_address=SOURCE)
        self.assertEqual(parser.finish().port, 59602)

    def test_split_transcript_proves_dynamic_port(self):
        first = response([record(SERVICE, 12, name(INSTANCE))])
        second = response([
            record(INSTANCE, 33, struct.pack("!HHH", 0, 0, 59602) + name(TARGET)),
            record(TARGET, 28, bytes.fromhex("fe80000000000000aede48fffe334455")),
        ])
        parser = mdns.PassiveMDNSDiscovery()
        parser.feed(first, source_address=SOURCE + "%en6")
        parser.feed(second, source_address=SOURCE)
        result = parser.finish()
        self.assertEqual(result.port, 59602)
        self.assertEqual(result.instance, INSTANCE.casefold())
        self.assertEqual(result.target, TARGET.casefold())
        self.assertEqual(result.server_datagrams, (first, second))
        plan = mdns.endpoint_from_transcript(
            (first, second), (SOURCE, SOURCE + "%en6"), 7)
        self.assertEqual(plan.endpoint, (SOURCE, 59602, 0, 7))
        self.assertEqual(plan.evidence.server_datagrams, (first, second))

    def test_compressed_ptr_and_srv_names(self):
        service = name(SERVICE)
        header = struct.pack("!HHHHHH", 0, 0x8400, 0, 2, 0, 0)
        service_offset = len(header)
        ptr_owner = service
        instance_wire = b"\x03ncm" + struct.pack("!H", 0xC000 | service_offset)
        ptr = ptr_owner + struct.pack("!HHIH", 12, 1, 120, len(instance_wire)) + instance_wire
        instance_offset = len(header) + len(ptr_owner) + 10
        srv_owner = struct.pack("!H", 0xC000 | instance_offset)
        srv_payload = struct.pack("!HHH", 0, 0, 59602) + name(TARGET)
        packet = header + ptr + srv_owner + struct.pack("!HHIH", 33, 1, 120, len(srv_payload)) + srv_payload
        parser = mdns.PassiveMDNSDiscovery()
        parser.feed(packet, source_address=SOURCE)
        self.assertEqual(parser.finish().port, 59602)

    def test_rejects_wrong_source_conflicts_and_missing_link(self):
        ptr = response([record(SERVICE, 12, name(INSTANCE))])
        srv = response([record(INSTANCE, 33,
                               struct.pack("!HHH", 0, 0, 59602) + name(TARGET))])
        parser = mdns.PassiveMDNSDiscovery()
        with self.assertRaises(mdns.MDNSError):
            parser.feed(ptr, source_address="fe80::1")
        parser.feed(ptr, source_address=SOURCE)
        with self.assertRaises(mdns.MDNSError):
            parser.finish()
        parser.feed(srv, source_address=SOURCE)
        with self.assertRaises(mdns.MDNSError):
            parser.feed(response([record(INSTANCE, 33,
                                         struct.pack("!HHH", 0, 0, 60000)
                                         + name(TARGET))]),
                        source_address=SOURCE)

    def test_rejects_truncation_cycles_surplus_and_bad_port(self):
        malformed = [
            b"",
            struct.pack("!HHHHHH", 1, 0x8400, 0, 0, 0, 0),
            struct.pack("!HHHHHH", 0, 0x8600, 0, 0, 0, 0),
            struct.pack("!HHHHHH", 0, 0x8400, 0, 1, 0, 0) + b"\xc0\x0c"
            + struct.pack("!HHIH", 12, 1, 1, 2) + b"\xc0\x0c",
            response([record(INSTANCE, 33, struct.pack("!HHH", 0, 0, 0) + name(TARGET))]),
            response([]) + b"x",
        ]
        for packet in malformed:
            with self.subTest(packet=packet.hex()[:40]):
                with self.assertRaises(mdns.MDNSError):
                    mdns._parse_message(packet)

    def test_endpoint_handoff_rejects_caller_shape_and_index(self):
        for datagrams, sources, index in (
                ([], (), 1),
                ((), (), 1),
                ((b"x",), (), 1),
                ((b"x",), (SOURCE,), 0),
                ((b"x",), (SOURCE,), True)):
            with self.subTest(datagrams=datagrams, sources=sources, index=index):
                with self.assertRaises(mdns.MDNSError):
                    mdns.endpoint_from_transcript(datagrams, sources, index)

    def test_deterministic_garbage_never_succeeds_or_escapes_protocol_error(self):
        generator = random.Random(0x4D444E53)
        for _ in range(1000):
            packet = generator.randbytes(generator.randrange(0, 257))
            try:
                mdns._parse_message(packet)
            except mdns.MDNSError:
                continue
            self.fail("deterministic garbage unexpectedly parsed as mDNS evidence")


if __name__ == "__main__":
    unittest.main()
