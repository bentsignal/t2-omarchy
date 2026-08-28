import importlib.util
import io
from pathlib import Path
import struct
import sys
import unittest
from unittest import mock


MODULE_PATH = Path(__file__).with_name("rsd-mdns-query.py")
SPEC = importlib.util.spec_from_file_location("rsd_mdns_query", MODULE_PATH)
query = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = query
SPEC.loader.exec_module(query)
mdns = query.mdns


def name(value):
    return b"".join(bytes([len(label)]) + label.encode()
                    for label in value.rstrip(".").split(".")) + b"\0"


def response(records):
    return struct.pack("!HHHHHH", 0, 0x8400, 0, len(records), 0, 0) + b"".join(records)


def record(owner, kind, payload):
    return name(owner) + struct.pack("!HHIH", kind, 1, 120, len(payload)) + payload


class FakeSocket:
    def __init__(self, incoming, *, short_send=False):
        self.incoming = list(incoming)
        self.short_send = short_send
        self.sent = []

    def sendto(self, data, destination):
        self.sent.append((data, destination))
        return len(data) - int(self.short_send)

    def recvfrom(self, size):
        if not self.incoming:
            raise TimeoutError
        return self.incoming.pop(0)


class MDNSQueryTests(unittest.TestCase):
    def test_fragmented_advertisement_binds_endpoint(self):
        service = "_remoted._tcp.local."
        instance = "T2._remoted._tcp.local."
        target = "t2.local."
        source = "fe80::aede:48ff:fe33:4455"
        incoming = [
            (response([record(service, 12, name(instance))]), (source, 5353, 0, 3)),
            (response([record(instance, 33,
                              struct.pack("!HHH", 0, 0, 59602) + name(target))]),
             (source, 5353, 0, 3)),
        ]
        sock = FakeSocket(incoming)
        result = query.capture_socket(sock, 3)
        self.assertEqual(result.endpoint, (source, 59602, 0, 3))
        self.assertEqual(sock.sent,
                         [(mdns.build_ptr_query(), ("ff02::fb", 5353, 0, 3))])

    def test_gate_precedes_interface_and_socket(self):
        self.assertFalse(query.LIVE_MDNS_DISCOVERY_ENABLED)
        with mock.patch.object(query, "verify_t2_interface") as verify:
            with mock.patch.object(query.socket, "socket") as constructor:
                with self.assertRaisesRegex(query.QueryError, "disabled"):
                    query.live_capture("enp4s0f1u1", 2.0)
        verify.assert_not_called()
        constructor.assert_not_called()

    def test_capture_rejects_short_send_wrong_source_and_timeout(self):
        for sock in (FakeSocket([], short_send=True), FakeSocket([])):
            with self.subTest(short=sock.short_send):
                with self.assertRaises(query.QueryError):
                    query.capture_socket(sock, 3)
        empty = response([])
        for source in (("fe80::1", 5353, 0, 3),
                       (mdns.T2_LINK_LOCAL_ADDRESS, 9999, 0, 3),
                       (mdns.T2_LINK_LOCAL_ADDRESS, 5353, 0, 4)):
            with self.subTest(source=source):
                with self.assertRaises(query.QueryError):
                    query.capture_socket(FakeSocket([(empty, source)]), 3)

    def test_offline_main_never_constructs_socket(self):
        with mock.patch.object(sys, "argv", ["rsd-mdns-query.py"]):
            with mock.patch.object(query.socket, "socket") as constructor:
                with mock.patch("sys.stdout", new_callable=io.StringIO) as output:
                    query.main()
        constructor.assert_not_called()
        self.assertIn("offline only", output.getvalue())


if __name__ == "__main__":
    unittest.main()
