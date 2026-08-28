#!/usr/bin/env python3
"""Source-level regression checks for the privileged OOL capture boundary."""

from pathlib import Path
import unittest


SOURCE = Path(__file__).with_name("t2sep_probe.c").read_text()


class KernelOolSafetyTests(unittest.TestCase):
    def test_capture_requires_discovery_and_confirmation(self) -> None:
        self.assertIn(
            "if (apple_capture_ool_acks &&\n"
            "\t    (!apple_collect_discovery ||\n"
            "\t     ool_ack_confirmation != T2SEP_OOL_CONFIRMATION))",
            SOURCE,
        )

    def test_registration_is_bounded_and_tag_correlated(self) -> None:
        self.assertIn("for (i = 0; i < 500; i++)", SOURCE)
        self.assertIn("((response[0] >> 8) & 0xff) != tag", SOURCE)
        self.assertIn("response[1] != 0", SOURCE)
        self.assertIn("t2sep_capture_one_ool_ack(pdev, bar4, 2, 2", SOURCE)
        self.assertIn("t2sep_capture_one_ool_ack(pdev, bar4, 3, 3", SOURCE)

    def test_stop_precedes_scrub_and_free(self) -> None:
        function = SOURCE.index("static int t2sep_apple_start_cpu_probe")
        stop = SOURCE.index("iowrite32(5, bar4 + T2SEP_INTEL_CPU_STOP)", function)
        scrub = SOURCE.index("memzero_explicit(in_buffer", stop)
        free = SOURCE.index("dma_free_coherent", scrub)
        self.assertLess(stop, scrub)
        self.assertLess(scrub, free)


if __name__ == "__main__":
    unittest.main()
