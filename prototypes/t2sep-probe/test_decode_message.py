#!/usr/bin/env python3

import importlib.util
from pathlib import Path
import unittest


MODULE_PATH = Path(__file__).with_name("decode-message.py")
SPEC = importlib.util.spec_from_file_location("decode_message", MODULE_PATH)
assert SPEC and SPEC.loader
decode_message = importlib.util.module_from_spec(SPEC)
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


if __name__ == "__main__":
    unittest.main()
