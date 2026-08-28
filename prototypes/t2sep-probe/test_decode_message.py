#!/usr/bin/env python3

import importlib.util
from pathlib import Path
import sys
import unittest


MODULE_PATH = Path(__file__).with_name("decode-message.py")
SPEC = importlib.util.spec_from_file_location("decode_message", MODULE_PATH)
assert SPEC and SPEC.loader
decode_message = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = decode_message
SPEC.loader.exec_module(decode_message)


class DecodeMessageTests(unittest.TestCase):
    def test_known_control_nop_response(self) -> None:
        result = decode_message.decode([0x00010100, 0, 0, 0x00100100])
        self.assertIn("endpoint=0x00", result)
        self.assertIn("opcode=0x01", result)

    def test_discovery_identity(self) -> None:
        result = decode_message.decode([0x080000FD, 0x6F696273, 0, 0])
        self.assertIn("endpoint_id=0x08", result)
        self.assertIn("name='sbio'", result)

    def test_discovery_ool_limits(self) -> None:
        result = decode_message.decode([0x080100FD, 0x4B014104, 0, 0])
        self.assertIn("in_pages=4..65", result)
        self.assertIn("out_pages=1..75", result)

    def test_discovery_rejects_trailing_payload(self) -> None:
        result = decode_message.decode([0x080000FD, 0x6F696273, 1, 0])
        self.assertIn("discovery=invalid", result)

    def test_discovery_allows_transport_metadata(self) -> None:
        words = [0x080000FD, 0x6F696273, 0, 0x00100100]
        self.assertIn("discovery=identity", decode_message.decode(words))
        self.assertEqual(decode_message.DiscoveryTable().accept(words).endpoint_id, 8)

    def test_discovery_table_accepts_identity_then_limits(self) -> None:
        table = decode_message.DiscoveryTable()
        identity = table.accept([0x080000FD, 0x6F696273, 0, 0])
        limits = table.accept([0x080100FD, 0x4B014104, 0, 0])
        self.assertEqual(identity.name, 0x6F696273)
        self.assertEqual(limits.limits, (4, 65, 1, 75))
        self.assertEqual(table.endpoints, (limits,))

    def test_discovery_table_rejects_non_discovery(self) -> None:
        with self.assertRaisesRegex(decode_message.DiscoveryError, "not discovery"):
            decode_message.DiscoveryTable().accept([0x00010100, 0, 0, 0])

    def test_discovery_table_rejects_ool_before_identity(self) -> None:
        with self.assertRaisesRegex(decode_message.DiscoveryError, "precede"):
            decode_message.DiscoveryTable().accept([0x080100FD, 0x4B014104, 0, 0])

    def test_discovery_table_rejects_duplicate_id(self) -> None:
        table = decode_message.DiscoveryTable()
        table.accept([0x080000FD, 0x6F696273, 0, 0])
        with self.assertRaisesRegex(decode_message.DiscoveryError, "duplicate endpoint ID"):
            table.accept([0x080000FD, 0x74726178, 0, 0])

    def test_discovery_table_rejects_duplicate_name(self) -> None:
        table = decode_message.DiscoveryTable()
        table.accept([0x080000FD, 0x6F696273, 0, 0])
        with self.assertRaisesRegex(decode_message.DiscoveryError, "duplicate endpoint name"):
            table.accept([0x130000FD, 0x6F696273, 0, 0])

    def test_discovery_table_rejects_duplicate_limits(self) -> None:
        table = decode_message.DiscoveryTable()
        table.accept([0x080000FD, 0x6F696273, 0, 0])
        table.accept([0x080100FD, 0x4B014104, 0, 0])
        with self.assertRaisesRegex(decode_message.DiscoveryError, "duplicate OOL"):
            table.accept([0x080100FD, 0x4B014104, 0, 0])

    def test_discovery_table_rejects_unknown_opcode(self) -> None:
        with self.assertRaisesRegex(decode_message.DiscoveryError, "unknown"):
            decode_message.DiscoveryTable().accept([0x080200FD, 0, 0, 0])


if __name__ == "__main__":
    unittest.main()
