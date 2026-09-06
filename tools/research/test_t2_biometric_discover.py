# SPDX-License-Identifier: MIT
import asyncio
from pathlib import Path
import runpy
import unittest
from unittest.mock import AsyncMock, Mock

MODULE = runpy.run_path(str(Path(__file__).with_name("t2-biometric-discover.py")))


class DirectDiscoveryTests(unittest.TestCase):
    def peer(self, port):
        return {"Services": {MODULE["SERVICE"]: {"Port": port}}}

    def test_advertised_port_requires_service_and_dynamic_range(self):
        for value in (49152, 65535, "50123"):
            self.assertEqual(MODULE["advertised_port"](self.peer(value)), int(value))
        for value in (True, False, None, 1.5, [], {}, 49151, 65536, "-1", " 50123", "5e4", "５０１２３"):
            with self.assertRaises(ValueError):
                MODULE["advertised_port"](self.peer(value))
        for peer in (None, [], {}, {"Services": []}, {"Services": {}}, {"Services": {MODULE["SERVICE"]: []}}):
            with self.assertRaises(ValueError):
                MODULE["advertised_port"](peer)

    def test_queries_only_directory_and_closes_connection(self):
        connection = Mock(connect=AsyncMock(), send_device_handshake=AsyncMock(),
                          receive_response=AsyncMock(return_value=self.peer(50123)), close=AsyncMock())
        factory = Mock(return_value=connection)
        self.assertEqual(asyncio.run(MODULE["query"]("fe80::1", "test0", factory)), 50123)
        factory.assert_called_once_with(("fe80::1%test0", 59602))
        connection.connect.assert_awaited_once()
        connection.send_device_handshake.assert_awaited_once()
        connection.receive_response.assert_awaited_once()
        connection.close.assert_awaited_once()

    def test_failure_and_cancel_close_and_propagate(self):
        for error in (RuntimeError("test failure"), asyncio.CancelledError(), TimeoutError()):
            connection = Mock(connect=AsyncMock(side_effect=error), close=AsyncMock())
            with self.assertRaises(type(error)) as caught:
                asyncio.run(MODULE["query"]("fe80::1", "test0", Mock(return_value=connection)))
            self.assertIs(caught.exception, error)
            connection.close.assert_awaited_once()


if __name__ == "__main__":
    unittest.main()
