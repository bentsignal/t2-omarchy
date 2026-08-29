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


if __name__ == "__main__":
    unittest.main()
