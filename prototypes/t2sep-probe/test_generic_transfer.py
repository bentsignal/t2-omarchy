import importlib.util
import struct
import sys
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location("generic_transfer", Path(__file__).with_name("generic-transfer.py"))
gt = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = gt
SPEC.loader.exec_module(gt)


class GenericTransferTests(unittest.TestCase):
    def test_round_trip(self):
        source = gt.Packet(4, 0, 0, 0x12345678, b"\x03\0\0\0")
        self.assertEqual(gt.decode_packet(source.encode()), source)

    def test_header_is_seven_little_endian_words(self):
        encoded = gt.Packet(4, 0, 0, 7, b"abcd").encode()
        self.assertEqual(struct.unpack("<7I", encoded[:28]), (1, 4, 0, 0, 0, 7, 4))

    def test_sbio_initialization_fixture(self):
        encoded = gt.Packet(4, 0, 0, 0x73, b"\x03\0\0\0").encode()
        self.assertEqual(encoded.hex(),
                         "0100000004000000000000000000000000000000730000000400000003000000")

    def test_continuation_chunk(self):
        source = gt.Packet(10, 4, 2, 9, b"567890")
        self.assertEqual(gt.decode_packet(source.encode()), source)

    def test_rejects_short_header(self):
        with self.assertRaises(gt.ProtocolError): gt.decode_packet(b"\0" * 27)

    def test_rejects_version(self):
        with self.assertRaises(gt.ProtocolError): gt.decode_packet(struct.pack("<7I", 2, 0, 0, 0, 0, 0, 0))

    def test_rejects_reserved_field(self):
        with self.assertRaises(gt.ProtocolError): gt.decode_packet(struct.pack("<7I", 1, 0, 0, 0, 1, 0, 0))

    def test_rejects_size_mismatch(self):
        with self.assertRaises(gt.ProtocolError): gt.decode_packet(struct.pack("<7I", 1, 1, 0, 0, 0, 0, 1))

    def test_rejects_chunk_past_total(self):
        with self.assertRaises(gt.ProtocolError): gt.Packet(3, 1, 0, 0, b"abc").encode()

    def test_mailbox_notification(self):
        word = gt.encode_mailbox_notification(0x1234, 0x89ABCDEF)
        self.assertEqual(word, 0x123489ABCDEFFC00)
        self.assertEqual(gt.decode_mailbox_notification(word), (0x1234, 0x89ABCDEF, 0xFC, 0))

    def test_rejects_mailbox_overflow(self):
        with self.assertRaises(gt.ProtocolError): gt.encode_mailbox_notification(0x10000, 0)

    def test_reassembles_ordered_packets(self):
        stream = gt.Reassembler(8)
        self.assertIsNone(stream.add(gt.MESSAGE_FIRST, gt.Packet(8, 0, 0, 0x73, b"abcd").encode()))
        self.assertEqual(stream.add(gt.MESSAGE_NEXT_IN, gt.Packet(8, 4, 0, 0x73, b"efgh").encode()), b"abcdefgh")

    def test_reassembler_rejects_out_of_order_chunk(self):
        stream = gt.Reassembler(8)
        stream.add(gt.MESSAGE_FIRST, gt.Packet(8, 0, 0, 0x73, b"abcd").encode())
        with self.assertRaises(gt.ProtocolError):
            stream.add(gt.MESSAGE_NEXT_IN, gt.Packet(8, 5, 0, 0x73, b"fgh").encode())

    def test_reassembler_rejects_changed_command(self):
        stream = gt.Reassembler(8)
        stream.add(gt.MESSAGE_FIRST, gt.Packet(8, 0, 0, 0x73, b"abcd").encode())
        with self.assertRaises(gt.ProtocolError):
            stream.add(gt.MESSAGE_NEXT_IN, gt.Packet(8, 4, 0, 0x74, b"efgh").encode())

    def test_reassembler_rejects_oversize_transaction(self):
        with self.assertRaises(gt.ProtocolError):
            gt.Reassembler(7).add(gt.MESSAGE_FIRST, gt.Packet(8, 0, 0, 0x73, b"abcd").encode())


if __name__ == "__main__": unittest.main()
