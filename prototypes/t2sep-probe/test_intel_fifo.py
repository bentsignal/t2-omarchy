import importlib.util
import sys
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location("intel_fifo", Path(__file__).with_name("intel-fifo.py"))
fifo = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = fifo
SPEC.loader.exec_module(fifo)


class IntelFIFOTests(unittest.TestCase):
    def test_receive_plan_uses_exact_pop_order(self):
        self.assertEqual(fifo.plan_receive(0), tuple(
            fifo.MMIOAction("read", offset) for offset in (0x810, 0x814, 0x818, 0x81C)
        ))
        with self.assertRaises(fifo.FIFOUnavailable):
            fifo.plan_receive(1 << 17)

    def test_post_plan_zeros_commit_word_and_reads_fence(self):
        self.assertEqual(fifo.plan_post(0, [1, 2, 3, 0]), (
            fifo.MMIOAction("write", 0x820, 1),
            fifo.MMIOAction("write", 0x824, 2),
            fifo.MMIOAction("write", 0x828, 3),
            fifo.MMIOAction("write", 0x82C, 0),
            fifo.MMIOAction("read", 0x10C),
        ))
        with self.assertRaises(fifo.FIFOUnavailable):
            fifo.plan_post(1 << 16, [1, 2, 3, 0])
        with self.assertRaisesRegex(fifo.FIFOError, "word 3"):
            fifo.plan_post(0, [1, 2, 3, 4])

    def test_receive_transport_flags_fail_closed(self):
        self.assertEqual(fifo.decode_received([1, 2, 3, 0]).words, (1, 2, 3, 0))
        for flag in (1 << 18, 1 << 19, (1 << 18) | (1 << 19)):
            with self.assertRaises(fifo.FIFOTransportError) as raised:
                fifo.decode_received([1, 2, 3, flag])
            self.assertEqual(raised.exception.flags, flag)

    def test_unrelated_status_and_metadata_bits_are_preserved(self):
        self.assertEqual(len(fifo.plan_receive(0x80000000)), 4)
        self.assertEqual(len(fifo.plan_post(0x80000000, [1, 2, 3, 0])), 5)
        self.assertEqual(fifo.decode_received([1, 2, 3, 0x80000000]).words[3],
                         0x80000000)

    def test_strict_shapes_and_python_types(self):
        for value in (True, -1, 0x100000000, None):
            with self.assertRaises(fifo.FIFOError):
                fifo.plan_receive(value)
            with self.assertRaises(fifo.FIFOError):
                fifo.plan_post(value, [0, 0, 0, 0])
        for values in (None, [0] * 3, [0] * 5, [0, 0, 0, True]):
            with self.assertRaises(fifo.FIFOError):
                fifo.decode_received(values)


if __name__ == "__main__":
    unittest.main()
