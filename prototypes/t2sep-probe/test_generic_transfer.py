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

    def test_intel_endpoint_envelope_requires_explicit_third_word(self):
        word = gt.encode_mailbox_notification(0x1234, 0x89ABCDEF)
        record = gt.envelope_endpoint_notification(8, word, 0xA5A5A5A5)
        self.assertEqual(record.words, (0xCDEFFC08, 0x123489AB, 0xA5A5A5A5))
        self.assertEqual(gt.decode_endpoint_notification(record, 8),
                         (0x1234, 0x89ABCDEF, 0xFC, 0))

    def test_intel_endpoint_envelope_fails_closed(self):
        word = gt.encode_mailbox_notification(1, 0x73)
        for endpoint in (0, 0x20, True):
            with self.assertRaises(gt.ProtocolError):
                gt.envelope_endpoint_notification(endpoint, word, 0)
        with self.assertRaises(gt.ProtocolError):
            gt.envelope_endpoint_notification(8, word | 1, 0)
        with self.assertRaises(gt.ProtocolError):
            gt.envelope_endpoint_notification(8, word, 0x100000000)
        record = gt.envelope_endpoint_notification(8, word, 0)
        with self.assertRaises(gt.ProtocolError):
            gt.decode_endpoint_notification(record, 9)

    def test_rejects_mailbox_overflow(self):
        with self.assertRaises(gt.ProtocolError): gt.encode_mailbox_notification(0x10000, 0)

    def test_strict_notification_decoder(self):
        word = gt.encode_mailbox_notification(4, 0x73, gt.MESSAGE_NEXT_IN)
        self.assertEqual(gt.decode_generic_notification(word), gt.Notification(4, 0x73, 0xFD))
        with self.assertRaises(gt.ProtocolError): gt.decode_generic_notification(word | 1)
        with self.assertRaises(gt.ProtocolError): gt.decode_generic_notification((word & ~0xFF00) | 0x8000)

    def test_sequence_tracker_and_wrap(self):
        tracker = gt.SequenceTracker()
        tracker.accept(gt.Notification(0xFFFF, 0x73, gt.MESSAGE_FIRST))
        tracker.accept(gt.Notification(0, 0x73, gt.MESSAGE_NEXT_IN))
        with self.assertRaises(gt.ProtocolError):
            tracker.accept(gt.Notification(0, 0x73, gt.MESSAGE_NEXT_IN))

    def test_notification_and_packet_command_must_match(self):
        raw = gt.Packet(4, 0, 0, 0x73, b"data").encode()
        word = gt.encode_mailbox_notification(1, 0x73)
        notification, packet = gt.decode_notified_packet(word, raw)
        self.assertEqual((notification.command, packet.command), (0x73, 0x73))
        with self.assertRaises(gt.ProtocolError):
            gt.decode_notified_packet(gt.encode_mailbox_notification(1, 0x74), raw)
        with self.assertRaises(gt.ProtocolError):
            gt.decode_notified_packet(gt.encode_mailbox_notification(1, 0x73, gt.MESSAGE_NEXT_OUT), raw)

    def test_error_code_location_and_minimum_size(self):
        raw = bytearray(29)
        struct.pack_into("<I", raw, 16, 0xE00002C2)
        self.assertEqual(gt.decode_error_code(bytes(raw)), 0xE00002C2)
        with self.assertRaises(gt.ProtocolError): gt.decode_error_code(bytes(28))

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

    def test_reassembler_rejects_every_record_after_completion(self):
        stream = gt.Reassembler(4)
        self.assertEqual(
            stream.add(gt.MESSAGE_FIRST, gt.Packet(4, 0, 0, 0x73, b"data").encode()),
            b"data",
        )
        with self.assertRaisesRegex(gt.ProtocolError, "after completion"):
            stream.add(gt.MESSAGE_NEXT_IN, gt.Packet(4, 4, 0, 0x73, b"").encode())

    def test_coupled_inbound_transaction_validates_sequence_and_command(self):
        transaction = gt.InboundTransaction(8)
        first = gt.Packet(8, 0, 0, 0x73, b"abcd").encode()
        second = gt.Packet(8, 4, 0, 0x73, b"efgh").encode()
        self.assertIsNone(transaction.accept(
            gt.encode_mailbox_notification(10, 0x73, gt.MESSAGE_FIRST), first
        ))
        self.assertEqual(transaction.accept(
            gt.encode_mailbox_notification(11, 0x73, gt.MESSAGE_NEXT_IN), second
        ), b"abcdefgh")

        skipped = gt.InboundTransaction(8)
        skipped.accept(gt.encode_mailbox_notification(10, 0x73), first)
        with self.assertRaisesRegex(gt.ProtocolError, "sequence"):
            skipped.accept(gt.encode_mailbox_notification(12, 0x73, gt.MESSAGE_NEXT_IN), second)

    def test_coupled_inbound_transaction_surfaces_remote_error(self):
        raw = bytearray(29)
        struct.pack_into("<I", raw, 16, 0xE00002C2)
        transaction = gt.InboundTransaction(8)
        with self.assertRaises(gt.RemoteError) as raised:
            transaction.accept(
                gt.encode_mailbox_notification(1, 0x73, gt.MESSAGE_ERROR), bytes(raw)
            )
        self.assertEqual(raised.exception.code, 0xE00002C2)

    def test_outbound_planner_uses_recovered_handshake_and_capacity(self):
        transaction = gt.OutboundTransaction(b"abcdefghij", 0x73, 2, 32, 0xFFFF)
        first = transaction.first()
        self.assertEqual(gt.decode_mailbox_notification(first.notification_word),
                         (0xFFFF, 0x73, gt.MESSAGE_FIRST, 0))
        self.assertEqual(gt.decode_packet(first.packet),
                         gt.Packet(10, 0, 2, 0x73, b"abcd"))
        self.assertFalse(transaction.complete)

        second = transaction.accept_next_request(
            gt.encode_mailbox_notification(10, 0x73, gt.MESSAGE_NEXT_OUT))
        self.assertEqual(gt.decode_mailbox_notification(second.notification_word),
                         (0, 0x73, gt.MESSAGE_NEXT_IN, 0))
        self.assertEqual(gt.decode_packet(second.packet).payload, b"efgh")
        final = transaction.accept_next_request(
            gt.encode_mailbox_notification(11, 0x73, gt.MESSAGE_NEXT_OUT))
        self.assertEqual(gt.decode_packet(final.packet),
                         gt.Packet(10, 8, 2, 0x73, b"ij"))
        self.assertTrue(transaction.complete)

    def test_outbound_planner_rejects_invalid_state_and_requests(self):
        transaction = gt.OutboundTransaction(b"abcde", 7, 0, 32)
        with self.assertRaisesRegex(gt.ProtocolError, "not started"):
            transaction.accept_next_request(
                gt.encode_mailbox_notification(1, 7, gt.MESSAGE_NEXT_OUT))
        transaction.first()
        with self.assertRaisesRegex(gt.ProtocolError, "already"):
            transaction.first()
        with self.assertRaisesRegex(gt.ProtocolError, "message type"):
            transaction.accept_next_request(
                gt.encode_mailbox_notification(1, 7, gt.MESSAGE_NEXT_IN))

        changed = gt.OutboundTransaction(b"abcde", 7, 0, 32)
        changed.first()
        with self.assertRaisesRegex(gt.ProtocolError, "command"):
            changed.accept_next_request(
                gt.encode_mailbox_notification(1, 8, gt.MESSAGE_NEXT_OUT))

    def test_outbound_planner_rejects_sequence_and_post_completion(self):
        transaction = gt.OutboundTransaction(b"abcdefghij", 7, 0, 32)
        transaction.first()
        transaction.accept_next_request(
            gt.encode_mailbox_notification(4, 7, gt.MESSAGE_NEXT_OUT))
        with self.assertRaisesRegex(gt.ProtocolError, "sequence"):
            transaction.accept_next_request(
                gt.encode_mailbox_notification(6, 7, gt.MESSAGE_NEXT_OUT))

        complete = gt.OutboundTransaction(b"data", 7, 0, 64)
        complete.first()
        with self.assertRaisesRegex(gt.ProtocolError, "after completion"):
            complete.accept_next_request(
                gt.encode_mailbox_notification(1, 7, gt.MESSAGE_NEXT_OUT))

    def test_outbound_planner_validates_inputs_and_copies_packet_bytes(self):
        for capacity in (0, 28):
            with self.assertRaises(gt.ProtocolError):
                gt.OutboundTransaction(b"x", 1, 0, capacity)
        for bad in (True, -1, 0x10000):
            with self.assertRaises(gt.ProtocolError):
                gt.OutboundTransaction(b"x", 1, 0, 29, bad)
        with self.assertRaises(gt.ProtocolError):
            gt.OutboundTransaction(bytearray(b"x"), 1, 0, 29)

        source = b"abc"
        record = gt.OutboundTransaction(source, 1, 0, 64).first()
        self.assertEqual(gt.decode_packet(record.packet).payload, b"abc")

    def test_transaction_session_couples_upload_and_response_sequences(self):
        session = gt.TransactionSession(b"abcdef", 0x73, 0, 32, 16, 0xFFFF)
        first = session.start()
        self.assertEqual(gt.decode_mailbox_notification(first.notification_word),
                         (0xFFFF, 0x73, gt.MESSAGE_FIRST, 0))
        self.assertEqual(gt.decode_packet(first.packet).payload, b"abcd")

        upload = session.accept(
            gt.encode_mailbox_notification(20, 0x73, gt.MESSAGE_NEXT_OUT))
        self.assertEqual(gt.decode_mailbox_notification(upload.outbound.notification_word),
                         (0, 0x73, gt.MESSAGE_NEXT_IN, 0))
        self.assertEqual(gt.decode_packet(upload.outbound.packet).payload, b"ef")

        response_first = gt.Packet(6, 0, 0, 0x73, b"wxyz").encode()
        request_more = session.accept(
            gt.encode_mailbox_notification(21, 0x73, gt.MESSAGE_FIRST), response_first)
        self.assertIsNone(request_more.response)
        self.assertIsNone(request_more.outbound.packet)
        self.assertEqual(gt.decode_mailbox_notification(
            request_more.outbound.notification_word),
            (1, 0x73, gt.MESSAGE_NEXT_OUT, 0))

        response_last = gt.Packet(6, 4, 0, 0x73, b"12").encode()
        finished = session.accept(
            gt.encode_mailbox_notification(22, 0x73, gt.MESSAGE_NEXT_IN), response_last)
        self.assertEqual(finished.response, b"wxyz12")
        self.assertIsNone(finished.outbound)
        self.assertTrue(session.complete)

    def test_transaction_session_rejects_early_response_and_late_request(self):
        early = gt.TransactionSession(b"abcde", 7, 0, 32, 8)
        early.start()
        with self.assertRaisesRegex(gt.ProtocolError, "before request upload"):
            early.accept(gt.encode_mailbox_notification(1, 7, gt.MESSAGE_FIRST),
                         gt.Packet(1, 0, 0, 7, b"x").encode())

        uploaded = gt.TransactionSession(b"x", 7, 0, 32, 8)
        uploaded.start()
        with self.assertRaisesRegex(gt.ProtocolError, "after request completion"):
            uploaded.accept(gt.encode_mailbox_notification(1, 7, gt.MESSAGE_NEXT_OUT))

    def test_transaction_session_rejects_cross_type_sequence_gaps_atomically(self):
        session = gt.TransactionSession(b"abcde", 7, 0, 32, 8)
        session.start()
        session.accept(gt.encode_mailbox_notification(4, 7, gt.MESSAGE_NEXT_OUT))
        packet = gt.Packet(4, 0, 0, 7, b"data").encode()
        with self.assertRaisesRegex(gt.ProtocolError, "sequence"):
            session.accept(gt.encode_mailbox_notification(6, 7, gt.MESSAGE_FIRST), packet)
        self.assertEqual(session.inbound.data, b"")
        self.assertEqual(session.accept(
            gt.encode_mailbox_notification(5, 7, gt.MESSAGE_FIRST), packet
        ).response, b"data")

    def test_transaction_session_surfaces_errors_and_validates_context(self):
        session = gt.TransactionSession(b"abcde", 7, 0, 32, 8)
        with self.assertRaisesRegex(gt.ProtocolError, "not started"):
            session.accept(gt.encode_mailbox_notification(1, 7, gt.MESSAGE_NEXT_OUT))
        session.start()
        with self.assertRaisesRegex(gt.ProtocolError, "must not carry"):
            session.accept(gt.encode_mailbox_notification(1, 7, gt.MESSAGE_NEXT_OUT), b"")

        raw = bytearray(29)
        struct.pack_into("<I", raw, 16, 0xE00002C2)
        with self.assertRaises(gt.RemoteError) as raised:
            session.accept(gt.encode_mailbox_notification(1, 7, gt.MESSAGE_ERROR), bytes(raw))
        self.assertEqual(raised.exception.code, 0xE00002C2)

    def test_exact_sbio_initialization_transaction_and_empty_reply(self):
        session = gt.sbio_initialization_session(initial_sequence=9)
        first = session.start()
        self.assertEqual(gt.decode_mailbox_notification(first.notification_word),
                         (9, 0x73, gt.MESSAGE_FIRST, 0))
        self.assertEqual(first.packet.hex(),
                         "0100000004000000000000000000000000000000730000000400000003000000")
        reply = gt.Packet(0, 0, 0, 0x73, b"").encode()
        result = session.accept(
            gt.encode_mailbox_notification(40, 0x73, gt.MESSAGE_FIRST), reply)
        self.assertEqual(result.response, b"")
        self.assertTrue(session.complete)

    def test_sbio_initialization_rejects_any_reply_payload(self):
        session = gt.sbio_initialization_session()
        session.start()
        reply = gt.Packet(1, 0, 0, 0x73, b"x").encode()
        with self.assertRaisesRegex(gt.ProtocolError, "configured maximum"):
            session.accept(
                gt.encode_mailbox_notification(1, 0x73, gt.MESSAGE_FIRST), reply)

    def test_strict_python_types_fail_with_protocol_errors(self):
        invalid_packets = (bytearray(28), "packet", None)
        for raw in invalid_packets:
            with self.assertRaises(gt.ProtocolError):
                gt.decode_packet(raw)
        with self.assertRaises(gt.ProtocolError):
            gt.Packet(1, 0, 0, 0, "x").encode()
        for bad in (True, "1", None):
            with self.assertRaises(gt.ProtocolError):
                gt.encode_mailbox_notification(bad, 0)
            with self.assertRaises(gt.ProtocolError):
                gt.decode_mailbox_notification(bad)
        with self.assertRaises(gt.ProtocolError):
            gt.SequenceTracker().accept("not-a-notification")
        for notification in (
                gt.Notification(True, 0, gt.MESSAGE_FIRST),
                gt.Notification(0, True, gt.MESSAGE_FIRST),
                gt.Notification(0, 0, 1)):
            with self.assertRaises(gt.ProtocolError):
                gt.SequenceTracker().accept(notification)


if __name__ == "__main__": unittest.main()
