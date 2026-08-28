from contextlib import AbstractContextManager
import importlib.util
from pathlib import Path
import plistlib
import sys
import unittest
import uuid


MODULE = Path(__file__).with_name("coupled-bridge-query.py")
SPEC = importlib.util.spec_from_file_location("coupled_bridge_query", MODULE)
assert SPEC and SPEC.loader
query = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = query
SPEC.loader.exec_module(query)


class FakeSocket:
    def __init__(self, incoming=b""):
        self.incoming = bytearray(incoming)
        self.sent = bytearray()

    def sendall(self, data):
        self.sent.extend(data)

    def recv(self, size):
        result = self.incoming[:size]
        del self.incoming[:size]
        return bytes(result)


class FakeContext(AbstractContextManager):
    def __init__(self, sock, directory, state):
        self.sock = sock
        self.directory = directory
        self.state = state

    def __enter__(self):
        self.state.append(("service-enter", self.directory.closed))
        return self.sock

    def __exit__(self, *_):
        self.state.append(("service-exit", self.directory.closed))


class DirectorySocket(FakeSocket):
    closed = False


class CoupledQueryTests(unittest.TestCase):
    def test_keeps_directory_alive_through_query(self):
        directory = DirectorySocket()
        service = FakeSocket()
        state = []
        original_capture = query.rsd_query.capture_connected_socket
        original_bridge = query.bridge_query.query_connected_socket
        try:
            query.rsd_query.capture_connected_socket = lambda sock, ident: type(
                "Capture", (), {"advertised_port": 49165})()
            query.bridge_query.query_connected_socket = lambda sock: (0, 3)

            def connector(endpoint):
                self.assertEqual(endpoint[1], 49165)
                return FakeContext(service, directory, state)

            result = query.query_with_open_directory(
                directory, connector, 7, uuid.UUID(int=0))
        finally:
            query.rsd_query.capture_connected_socket = original_capture
            query.bridge_query.query_connected_socket = original_bridge
        self.assertEqual(result, (0, 3))
        self.assertEqual(state, [("service-enter", False), ("service-exit", False)])

    def test_rejects_bad_inputs_and_wraps_transport_error(self):
        with self.assertRaises(query.CoupledQueryError):
            query.query_with_open_directory(FakeSocket(), None, 7, uuid.UUID(int=0))
        with self.assertRaises(query.CoupledQueryError):
            query.query_with_open_directory(FakeSocket(), lambda _: None, 0,
                                            uuid.UUID(int=0))
        original_capture = query.rsd_query.capture_connected_socket
        try:
            query.rsd_query.capture_connected_socket = lambda *_: (_ for _ in ()).throw(
                query.rsd_query.QueryError("bad"))
            with self.assertRaises(query.CoupledQueryError):
                query.query_with_open_directory(FakeSocket(), lambda _: None, 7,
                                                uuid.UUID(int=0))
        finally:
            query.rsd_query.capture_connected_socket = original_capture

    def test_live_source_gate_is_closed(self):
        self.assertFalse(query.LIVE_COUPLED_QUERY_ENABLED)
        with self.assertRaises(query.CoupledQueryError):
            query.live_query("enp4s0f1u1", 1)


if __name__ == "__main__":
    unittest.main()
