import importlib.util
from pathlib import Path
import struct
import sys
import tempfile
import unittest


MODULE_PATH = Path(__file__).with_name("analyze-macos-t2-capture.py")
SPEC = importlib.util.spec_from_file_location("analyze_macos_t2_capture", MODULE_PATH)
capture = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = capture
SPEC.loader.exec_module(capture)


def ethernet_ipv6_tcp(source_port=58783, destination_port=49152, flags=0x12):
    ethernet = bytes.fromhex("acde48001122acde4833445586dd")
    source = bytes.fromhex("fe80000000000000aede48fffe334455")
    destination = bytes.fromhex("fe80000000000000aede48fffe3344aa")
    tcp = struct.pack("!HHIIHHHH", source_port, destination_port, 0, 0,
                      (5 << 12) | flags, 0, 0, 0)
    ipv6 = bytes.fromhex("60000000") + struct.pack("!HBB", len(tcp), 6, 64)
    return ethernet + ipv6 + source + destination + tcp


def pcap(records):
    result = bytearray(bytes.fromhex("d4c3b2a1") +
                       struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1))
    for packet in records:
        result += struct.pack("<IIII", 0, 0, len(packet), len(packet)) + packet
    return bytes(result)


class CaptureAnalysisTests(unittest.TestCase):
    def test_extracts_wire_endpoint_and_interesting_flow(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "en5.pcap"
            path.write_bytes(pcap([ethernet_ipv6_tcp()]))
            result = capture.analyze(Path(temporary))["pcaps"][0]
        self.assertEqual(result["packet_count"], 1)
        self.assertEqual(result["ethernet_sources"], ["ac:de:48:33:44:55"])
        self.assertEqual(result["ipv6_sources"], ["fe80::aede:48ff:fe33:4455"])
        self.assertEqual(result["interesting_flows"][0]["source_port"], 58783)
        self.assertEqual(result["tcp_resets"], 0)

    def test_rejects_bad_lengths_and_non_ethernet(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "bad.pcap"
            path.write_bytes(bytes.fromhex("d4c3b2a1") +
                             struct.pack("<HHIIII", 2, 4, 0, 0, 64, 101))
            with self.assertRaises(capture.CaptureError):
                capture.summarize_pcap(path)
            path.write_bytes(pcap([b"short"])[:-1])
            with self.assertRaises(capture.CaptureError):
                capture.summarize_pcap(path)

    def test_rejects_capture_directory_symlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            real = root / "real"
            real.mkdir()
            alias = root / "alias"
            alias.symlink_to(real, target_is_directory=True)
            with self.assertRaises(capture.CaptureError):
                capture.analyze(alias)

    def test_summarizes_bounded_runtime_text(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "tcp-listeners-before.txt").write_text(
                "tcp6 0 0 *.58783 *.* LISTEN\n")
            (root / "tcp-processes-after.txt").write_text(
                "remoted 42 root 9u IPv6 TCP *:52032 (LISTEN)\n")
            (root / "unified-log.ndjson").write_text(
                '{"eventMessage":"Biometric service opened"}\n')
            result = capture.analyze(root)
        self.assertEqual(result["interesting_listener_lines"]
                         ["tcp-listeners-before.txt"],
                         ["tcp6 0 0 *.58783 *.* LISTEN"])
        self.assertEqual(result["interesting_listener_lines"]
                         ["tcp-processes-after.txt"],
                         ["remoted 42 root 9u IPv6 TCP *:52032 (LISTEN)"])
        self.assertEqual(len(result["activation_log_lines"]), 1)


if __name__ == "__main__":
    unittest.main()
