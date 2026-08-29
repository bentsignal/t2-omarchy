import importlib.util
from pathlib import Path
import sys
import unittest


MODULE = Path(__file__).with_name("acm-transport.py")
SPEC = importlib.util.spec_from_file_location("acm_transport", MODULE)
assert SPEC and SPEC.loader
acm = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = acm
SPEC.loader.exec_module(acm)


class ACMTransportTests(unittest.TestCase):
    def test_exact_layout_and_decode(self):
        wire = acm.encode_envelope(1, 0x11, 0)
        self.assertEqual(wire.hex(), "0a0111000000000000000000")
        self.assertEqual(acm.decode_envelope(wire), acm.ACMEnvelope(1, 0x11, 0))

    def test_correlated_bounded_reply(self):
        request = acm.decode_envelope(acm.encode_envelope(1, 0, 42))
        reply = acm.encode_envelope(1, 17, 0)
        self.assertEqual(acm.validate_reply(request, reply, maximum_reply=17),
                         acm.ACMEnvelope(1, 17, 0))

    def test_success_reply_requires_zero_status_and_exact_payload(self):
        request = acm.decode_envelope(acm.encode_envelope(1, 8, 0))
        acm.validate_success_reply(
            request, acm.encode_envelope(1, 17, 0), bytes(17),
            expected_length=17)
        bad = (
            (acm.encode_envelope(1, 17, 1), bytes(17)),
            (acm.encode_envelope(1, 16, 0), bytes(16)),
            (acm.encode_envelope(1, 17, 0), bytes(16)),
            (acm.encode_envelope(2, 17, 0), bytes(17)),
        )
        for envelope, payload in bad:
            with self.subTest(envelope=envelope.hex(), length=len(payload)):
                with self.assertRaises(acm.ACMTransportError):
                    acm.validate_success_reply(
                        request, envelope, payload, expected_length=17)
        with self.assertRaises(acm.ACMTransportError):
            acm.validate_success_reply(
                request, acm.encode_envelope(1, 17, 0), "not bytes",
                expected_length=17)

    def test_rejects_invalid_fields(self):
        for args in ((-1, 0, 0), (256, 0, 0), (1, 0x4001, 0),
                     (1, 0, -1), (1, 0, 0x100000000)):
            with self.assertRaises(acm.ACMTransportError):
                acm.encode_envelope(*args)

    def test_rejects_bad_reply(self):
        request = acm.decode_envelope(acm.encode_envelope(1, 0, 0))
        bad = [b"", bytes.fromhex("0b0111000000000000000000"),
               bytes.fromhex("0a0111000000000001000000"),
               acm.encode_envelope(2, 17, 0), acm.encode_envelope(1, 18, 0)]
        for wire in bad:
            with self.subTest(wire=wire.hex()):
                with self.assertRaises(acm.ACMTransportError):
                    acm.validate_reply(request, wire, maximum_reply=17)

    def test_exact_scrd_initialization_precedes_commands(self):
        envelope, payload = acm.scrd_initialization_envelope()
        self.assertEqual(payload, b"DRCS\n\x28\0\0")
        self.assertEqual(acm.decode_envelope(envelope),
                         acm.ACMEnvelope(1, 8, 0))

    def test_context_create_plan_is_exact_and_ordered(self):
        plan = acm.ContextCreatePlan()
        with self.assertRaises(acm.ACMTransportError):
            plan.context_request()
        init_envelope, init_payload = plan.initialize()
        self.assertEqual(init_payload, b"DRCS\n\x28\0\0")
        self.assertEqual(acm.decode_envelope(init_envelope).payload_length, 8)
        self.assertFalse(plan.initialized)
        with self.assertRaises(acm.ACMTransportError):
            plan.context_request()
        plan.accept_initialization_reply(acm.encode_envelope(1, 0, 0), b"")
        self.assertTrue(plan.initialized)
        envelope, payload = plan.context_request()
        self.assertEqual(payload, b"DRCS\x01\0\0\x01")
        self.assertEqual(acm.decode_envelope(envelope), acm.ACMEnvelope(1, 8, 0))
        with self.assertRaises(acm.ACMTransportError):
            plan.accept_context_response(acm.encode_envelope(1, 16, 0), bytes(16))
        response = bytearray(range(17))
        plan.accept_context_response(acm.encode_envelope(1, 17, 0), response)
        self.assertTrue(plan.context_created)
        with self.assertRaises(acm.ACMTransportError):
            plan.context_request()
        command = bytearray(24)
        delete_envelope = plan.delete_request(response, command)
        self.assertEqual(command[:8], b"DRCS\x02\0\x10\x01")
        self.assertEqual(command[8:], response[:16])
        self.assertEqual(acm.decode_envelope(delete_envelope),
                         acm.ACMEnvelope(1, 24, 0))
        plan.accept_delete_response(acm.encode_envelope(1, 0, 0), b"")
        self.assertTrue(plan.context_deleted)
        acm.scrub_context_material(response, command)
        self.assertEqual(response, bytearray(17))
        self.assertEqual(command, bytearray(24))

    def test_context_plan_rejects_failed_or_reordered_replies(self):
        plan = acm.ContextCreatePlan()
        with self.assertRaises(acm.ACMTransportError):
            plan.accept_initialization_reply(acm.encode_envelope(1, 0, 0), b"")
        plan.initialize()
        with self.assertRaises(acm.ACMTransportError):
            plan.accept_initialization_reply(acm.encode_envelope(1, 0, 7), b"")
        self.assertFalse(plan.initialized)
        plan.accept_initialization_reply(acm.encode_envelope(1, 0, 0), b"")
        with self.assertRaises(acm.ACMTransportError):
            plan.accept_context_response(acm.encode_envelope(1, 17, 0),
                                         bytearray(17))
        plan.context_request()
        with self.assertRaises(acm.ACMTransportError):
            plan.context_request()

    def test_delete_requires_mutable_exact_buffers_and_order(self):
        plan = acm.ContextCreatePlan()
        command = bytearray(24)
        with self.assertRaises(acm.ACMTransportError):
            plan.delete_request(bytearray(17), command)
        plan.initialize()
        plan.accept_initialization_reply(acm.encode_envelope(1, 0, 0), b"")
        plan.context_request()
        response = bytearray(range(17))
        with self.assertRaises(acm.ACMTransportError):
            plan.accept_context_response(acm.encode_envelope(1, 17, 0), bytes(17))
        plan.accept_context_response(acm.encode_envelope(1, 17, 0), response)
        for bad_response, bad_command in (
                (bytes(17), bytearray(24)),
                (bytearray(16), bytearray(24)),
                (bytearray(17), bytes(24)),
                (bytearray(17), bytearray(23))):
            with self.subTest(response=type(bad_response),
                              command=type(bad_command), length=len(bad_command)):
                with self.assertRaises(acm.ACMTransportError):
                    plan.delete_request(bad_response, bad_command)
        plan.delete_request(response, command)
        with self.assertRaises(acm.ACMTransportError):
            plan.delete_request(response, bytearray(24))
        with self.assertRaises(acm.ACMTransportError):
            plan.accept_delete_response(acm.encode_envelope(1, 1, 0), b"x")
        self.assertFalse(plan.context_deleted)
        plan.accept_delete_response(acm.encode_envelope(1, 0, 0), b"")
        with self.assertRaises(acm.ACMTransportError):
            plan.accept_delete_response(acm.encode_envelope(1, 0, 0), b"")

    def test_scrub_rejects_immutable_or_wrong_sized_material(self):
        for response, command in ((bytes(17), bytearray(24)),
                                  (bytearray(17), bytes(24)),
                                  (bytearray(16), bytearray(24)),
                                  (bytearray(17), bytearray(25))):
            with self.subTest(response=type(response), command=type(command)):
                with self.assertRaises(acm.ACMTransportError):
                    acm.scrub_context_material(response, command)


if __name__ == "__main__":
    unittest.main()
