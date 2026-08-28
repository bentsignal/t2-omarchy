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

    def test_tagged_control_request_and_observed_nop_ack(self) -> None:
        request = decode_message.tag_control_request([0, 0, 0, 0], 1)
        self.assertEqual(request, [0x00000100, 0, 0, 0])
        self.assertEqual(decode_message.validate_control_reply(
            request, [0x00010100, 0, 0, 0x00100100],
            expected_opcode=1, expected_target=0
        ), (0x00010100, 0, 0, 0x00100100))

    def test_control_reply_coupling_fails_closed(self) -> None:
        request = decode_message.tag_control_request(
            decode_message.encode_ool_registration(
                8, 0x100000, 0x4000, incoming_to_sep=True), 7)
        valid = [0x08010700, 0, 0xAABBCCDD, 0]
        self.assertEqual(decode_message.validate_control_reply(
            request, valid, expected_opcode=1, expected_target=8), tuple(valid))
        mutations = (
            [0x08010800, 0, 0, 0],
            [0x09010700, 0, 0, 0],
            [0x08020700, 0, 0, 0],
            [0x08010701, 0, 0, 0],
            [0x08010700, 1, 0, 0],
            [0x08010700, 0, 0, 1 << 18],
        )
        for response in mutations:
            with self.assertRaises(decode_message.ControlMessageError):
                decode_message.validate_control_reply(
                    request, response, expected_opcode=1, expected_target=8)

    def test_control_tag_and_reply_types_are_strict(self) -> None:
        for tag in (True, 0, 0x100, None):
            with self.assertRaises(decode_message.ControlMessageError):
                decode_message.tag_control_request([0, 0, 0, 0], tag)
        with self.assertRaises(decode_message.ControlMessageError):
            decode_message.tag_control_request([0x100, 0, 0, 0], 1)
        with self.assertRaises(decode_message.ControlMessageError):
            decode_message.validate_control_reply(
                [0x100, 0, 0, 0], [0x10100, 0, 0, 0],
                expected_opcode=True, expected_target=0)

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
        table.accept([0x080100FD, 0x4B014104, 0, 0])
        with self.assertRaisesRegex(decode_message.DiscoveryError, "duplicate endpoint ID"):
            table.accept([0x080000FD, 0x74726178, 0, 0])

    def test_discovery_table_rejects_duplicate_name(self) -> None:
        table = decode_message.DiscoveryTable()
        table.accept([0x080000FD, 0x6F696273, 0, 0])
        table.accept([0x080100FD, 0x4B014104, 0, 0])
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

    def test_intel_ool_registration_wire_format(self) -> None:
        self.assertEqual(
            decode_message.encode_ool_registration(8, 0x12345000, 0x4000, incoming_to_sep=True),
            [0x08020000, 0x12345, 0x4000, 0],
        )
        self.assertEqual(
            decode_message.encode_ool_registration(8, 0xABC000, 0x4B000, incoming_to_sep=False),
            [0x08030000, 0xABC, 0x4B000, 0],
        )

    def test_ool_registration_rejects_unsafe_ranges(self) -> None:
        invalid = (
            (0, 0x1000, 0x1000),
            (0xFD, 0x1000, 0x1000),
            (8, 0x1001, 0x1000),
            (8, 0x1000, 0),
            (8, 0x1000, 0x1001),
            (8, 0x100000000000, 0x1000),
            (8, 0xFFFFFFFF000, 0x2000),
            (True, 0x1000, 0x1000),
            (8, True, 0x1000),
            (8, 0x1000, True),
        )
        for endpoint, address, size in invalid:
            with self.subTest(endpoint=endpoint, address=address, size=size):
                with self.assertRaises(decode_message.ControlMessageError):
                    decode_message.encode_ool_registration(
                        endpoint, address, size, incoming_to_sep=True
                    )
        with self.assertRaises(decode_message.ControlMessageError):
            decode_message.encode_ool_registration(
                8, 0x1000, 0x1000, incoming_to_sep=1
            )

    def test_sbio_buffer_sizes_match_advertised_limits(self) -> None:
        endpoint = decode_message.EndpointInfo(8, 0x6F696273, (4, 65, 1, 75))
        decode_message.validate_ool_sizes(endpoint, 0x4000, 0x4B000)
        for send, receive in ((0x3000, 0x4B000), (0x4000, 0x4C000), (1, 0x1000)):
            with self.subTest(send=send, receive=receive):
                with self.assertRaises(decode_message.ControlMessageError):
                    decode_message.validate_ool_sizes(endpoint, send, receive)
        malformed = (
            "endpoint",
            decode_message.EndpointInfo(8, 0x6F696273, (4, 1, 1, 75)),
            decode_message.EndpointInfo(8, 0x6F696273, (4, 65, 1)),
            decode_message.EndpointInfo(8, 0x6F696273, (4, 65, 1, True)),
        )
        for value in malformed:
            with self.assertRaises(decode_message.ControlMessageError):
                decode_message.validate_ool_sizes(value, 0x4000, 0x4B000)

    def test_discovery_requires_immediate_limits_and_valid_ranges(self) -> None:
        table = decode_message.DiscoveryTable()
        table.accept([0x080000FD, 0x6F696273, 0, 0])
        with self.assertRaisesRegex(decode_message.DiscoveryError, "not followed"):
            table.accept([0x130000FD, 0x74726178, 0, 0])

        table = decode_message.DiscoveryTable()
        table.accept([0x080000FD, 0x6F696273, 0, 0])
        with self.assertRaisesRegex(decode_message.DiscoveryError, "precede"):
            table.accept([0x130100FD, 0x01010101, 0, 0])

        table = decode_message.DiscoveryTable()
        table.accept([0x080000FD, 0x6F696273, 0, 0])
        with self.assertRaisesRegex(decode_message.DiscoveryError, "inverted"):
            table.accept([0x080100FD, 0x01020104, 0, 0])

    def test_discovery_rejects_bad_record_shape_tags_names_and_transport(self) -> None:
        malformed = (
            [],
            [0x080000FD, 0, 0],
            [0x080000FD, 0, 0, 0, 0],
            [0x080000FD, 0, 0, True],
            [0x080000FD, 0, 0, 1 << 32],
            [0x080001FD, 0x6F696273, 0, 0],
            [0x000000FD, 0x6F696273, 0, 0],
            [0xFD0000FD, 0x6F696273, 0, 0],
            [0x080000FD, 0x00696273, 0, 0],
            [0x080000FD, 0x6F696273, 0, 1 << 18],
        )
        for record in malformed:
            with self.subTest(record=record):
                with self.assertRaises(decode_message.DiscoveryError):
                    decode_message.DiscoveryTable().accept(record)

    def test_discovery_record_cap_and_finalize_sbio(self) -> None:
        with self.assertRaises(decode_message.DiscoveryError):
            decode_message.DiscoveryTable(max_records=0)
        table = decode_message.DiscoveryTable(max_records=2)
        table.accept([0x080000FD, 0x6F696273, 0, 0])
        table.accept([0x080100FD, 0x4B014104, 0, 0])
        self.assertEqual(table.finalize_sbio().endpoint_id, 8)
        with self.assertRaisesRegex(decode_message.DiscoveryError, "cap"):
            table.accept([0x130000FD, 0x74726178, 0, 0])

        incomplete = decode_message.DiscoveryTable()
        incomplete.accept([0x080000FD, 0x6F696273, 0, 0])
        with self.assertRaisesRegex(decode_message.DiscoveryError, "final"):
            incomplete.finalize_sbio()

        wrong_limits = decode_message.DiscoveryTable()
        wrong_limits.accept([0x080000FD, 0x6F696273, 0, 0])
        wrong_limits.accept([0x080100FD, 0x01010101, 0, 0])
        with self.assertRaisesRegex(decode_message.DiscoveryError, "buffers"):
            wrong_limits.finalize_sbio()


if __name__ == "__main__":
    unittest.main()
