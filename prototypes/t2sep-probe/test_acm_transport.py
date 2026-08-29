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
        envelope, payload = acm.scrd_initialization_envelope(3)
        self.assertEqual(payload, b"DRCS\n\x03\0\0")
        self.assertEqual(acm.decode_envelope(envelope),
                         acm.ACMEnvelope(1, 8, 0))
        with self.assertRaises(acm.ACMTransportError):
            acm.scrd_initialization_payload(256)

    def test_context_create_plan_is_exact_and_ordered(self):
        plan = acm.ContextCreatePlan()
        with self.assertRaises(acm.ACMTransportError):
            plan.context_request()
        init_envelope, init_payload = plan.initialize(3)
        self.assertEqual(init_payload, b"DRCS\n\x03\0\0")
        self.assertEqual(acm.decode_envelope(init_envelope).payload_length, 8)
        envelope, payload = plan.context_request()
        self.assertEqual(payload, b"DRCS\x01\0\0\x01")
        self.assertEqual(acm.decode_envelope(envelope), acm.ACMEnvelope(1, 8, 0))
        with self.assertRaises(acm.ACMTransportError):
            plan.accept_context_response_length(16)
        plan.accept_context_response_length(17)
        self.assertTrue(plan.context_created)
        with self.assertRaises(acm.ACMTransportError):
            plan.context_request()


if __name__ == "__main__":
    unittest.main()
