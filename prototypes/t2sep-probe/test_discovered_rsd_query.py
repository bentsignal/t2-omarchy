import importlib.util
from pathlib import Path
import struct
import sys
import unittest
import uuid


MODULE_PATH = Path(__file__).with_name("discovered-rsd-query.py")
SPEC = importlib.util.spec_from_file_location("discovered_rsd_query", MODULE_PATH)
composed = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = composed
SPEC.loader.exec_module(composed)
mdns = composed.mdns_query.mdns
rsd = composed.rsd_query.protocol


def name(value):
    return b"".join(bytes([len(label)]) + label.encode()
                    for label in value.rstrip(".").split(".")) + b"\0"


def record(owner, kind, payload):
    return name(owner) + struct.pack("!HHIH", kind, 1, 120, len(payload)) + payload


def mdns_response():
    service = "_remoted._tcp.local."
    instance = "T2._remoted._tcp.local."
    target = "t2.local."
    records = (
        record(service, 12, name(instance)),
        record(instance, 33, struct.pack("!HHH", 0, 0, 59602) + name(target)),
    )
    return struct.pack("!HHHHHH", 0, 0x8400, 0, 2, 0, 0) + b"".join(records)


def directory_transcript(port=49165):
    message = rsd.encode_xpc_message({
        "MessageType": "Handshake",
        "MessagingProtocolVersion": rsd.Int64(3),
        "Properties": {},
        "Services": {
            composed.rsd_query.BIOMETRIC_SERVICE: {
                "Port": str(port), "Properties": {"UsesRemoteXPC": False},
            },
        },
        "UUID": uuid.UUID(int=1),
    }, message_id=0)
    return b"".join((
        rsd.encode_http2_frame(rsd.HTTP2_SETTINGS, 0, 0,
                               struct.pack("!HI", 3, 100)),
        rsd.encode_http2_frame(rsd.HTTP2_DATA, 0, rsd.ROOT_CHANNEL, message),
    ))


class FakeMDNSSocket:
    def __init__(self):
        self.sent = []
        self.incoming = [(mdns_response(),
                          (mdns.T2_LINK_LOCAL_ADDRESS, 5353, 0, 7))]

    def sendto(self, data, destination):
        self.sent.append((data, destination))
        return len(data)

    def recvfrom(self, size):
        return self.incoming.pop(0)


class FakeRSDSocket:
    def __init__(self, incoming):
        self.incoming = bytearray(incoming)
        self.sent = []

    def sendall(self, data):
        self.sent.append(data)

    def recv(self, size):
        result = bytes(self.incoming[:size])
        del self.incoming[:size]
        return result


class SocketContext:
    def __init__(self, sock):
        self.sock = sock

    def __enter__(self):
        return self.sock

    def __exit__(self, *args):
        return False


class DiscoveredRSDQueryTests(unittest.TestCase):
    def test_discovery_port_is_the_only_connector_input(self):
        endpoints = []
        rsd_socket = FakeRSDSocket(directory_transcript())

        def connector(endpoint):
            endpoints.append(endpoint)
            return SocketContext(rsd_socket)

        result = composed.capture_discovered_directory(
            FakeMDNSSocket(), connector, 7, uuid.UUID(int=2))
        self.assertEqual(endpoints,
                         [(mdns.T2_LINK_LOCAL_ADDRESS, 59602, 0, 7)])
        self.assertEqual(result.discovery.evidence.port, 59602)
        self.assertEqual(result.directory.advertised_port, 49165)
        self.assertTrue(result.discovery.evidence.server_datagrams)
        self.assertTrue(result.directory.server_transcript)

    def test_invalid_uuid_and_connector_precede_discovery_io(self):
        for client_uuid, connector in (("uuid", lambda _: None),
                                       (uuid.UUID(int=0), None)):
            sock = FakeMDNSSocket()
            with self.subTest(client_uuid=client_uuid, connector=connector):
                with self.assertRaises(composed.CompositionError):
                    composed.capture_discovered_directory(sock, connector, 7,
                                                          client_uuid)
            self.assertEqual(sock.sent, [])

if __name__ == "__main__":
    unittest.main()
